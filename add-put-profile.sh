#!/bin/bash

# Add PUT method to /player/profile endpoint

API_ID="bb5nb3l00b"
REGION="eu-north-1"
LAMBDA_ARN="arn:aws:lambda:eu-north-1:799904911021:function:hive-invasion-backend"
ACCOUNT_ID="799904911021"

# Get /player/profile resource ID
echo "Getting /player/profile resource ID..."
PROFILE_ID=$(aws apigateway get-resources \
  --rest-api-id $API_ID \
  --region $REGION \
  --query 'items[?path==`/player/profile`].id' \
  --output text)

echo "Profile Resource ID: $PROFILE_ID"

if [ -z "$PROFILE_ID" ]; then
  echo "ERROR: /player/profile resource not found!"
  exit 1
fi

# Add PUT method to /player/profile
echo "Adding PUT to /player/profile..."
aws apigateway put-method \
  --rest-api-id $API_ID \
  --resource-id $PROFILE_ID \
  --http-method PUT \
  --authorization-type NONE \
  --region $REGION

# Add Lambda integration for PUT
echo "Adding Lambda integration for PUT..."
aws apigateway put-integration \
  --rest-api-id $API_ID \
  --resource-id $PROFILE_ID \
  --http-method PUT \
  --type AWS_PROXY \
  --integration-http-method POST \
  --uri "arn:aws:apigateway:$REGION:lambda:path/2015-03-31/functions/$LAMBDA_ARN/invocations" \
  --region $REGION

# Update OPTIONS CORS headers to include PUT
echo "Updating OPTIONS CORS headers to include PUT..."
aws apigateway put-integration-response \
  --rest-api-id $API_ID \
  --resource-id $PROFILE_ID \
  --http-method OPTIONS \
  --status-code 200 \
  --response-parameters '{"method.response.header.Access-Control-Allow-Headers":"'"'"'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token'"'"'","method.response.header.Access-Control-Allow-Methods":"'"'"'GET,PUT,OPTIONS'"'"'","method.response.header.Access-Control-Allow-Origin":"'"'"'*'"'"'"}' \
  --region $REGION

# Add Lambda permission for PUT
echo "Adding Lambda permission for PUT..."
aws lambda add-permission \
  --function-name hive-invasion-backend \
  --statement-id apigateway-put-player-profile-$(date +%s) \
  --action lambda:InvokeFunction \
  --principal apigateway.amazonaws.com \
  --source-arn "arn:aws:execute-api:$REGION:$ACCOUNT_ID:$API_ID/*/PUT/player/profile" \
  --region $REGION 2>/dev/null || echo "Permission may already exist (OK)"

# Deploy to prod stage
echo "Deploying to prod stage..."
aws apigateway create-deployment \
  --rest-api-id $API_ID \
  --stage-name prod \
  --region $REGION

echo ""
echo "✅ PUT method added to /player/profile"
echo "✅ CORS updated to allow GET,PUT,OPTIONS"
echo "✅ Deployed to prod stage"
echo ""
echo "Test with:"
echo "  PUT https://bb5nb3l00b.execute-api.eu-north-1.amazonaws.com/prod/player/profile"
