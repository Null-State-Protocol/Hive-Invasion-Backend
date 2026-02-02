#!/bin/bash
set -e

API_ID="bb5nb3l00b"
REGION="eu-north-1"
LAMBDA_ARN="arn:aws:lambda:${REGION}:799904911021:function:hive-invasion-backend"

# Get root resource ID
ROOT_ID=$(aws apigateway get-resources --rest-api-id $API_ID --region $REGION --query 'items[?path==`/`].id' --output text)

echo "Creating /session resource..."
SESSION_ID=$(aws apigateway create-resource \
  --rest-api-id $API_ID \
  --region $REGION \
  --parent-id $ROOT_ID \
  --path-part session \
  --query 'id' \
  --output text)

echo "Creating /session/{proxy+} resource..."
SESSION_PROXY_ID=$(aws apigateway create-resource \
  --rest-api-id $API_ID \
  --region $REGION \
  --parent-id $SESSION_ID \
  --path-part '{proxy+}' \
  --query 'id' \
  --output text)

echo "Adding ANY method..."
aws apigateway put-method \
  --rest-api-id $API_ID \
  --region $REGION \
  --resource-id $SESSION_PROXY_ID \
  --http-method ANY \
  --authorization-type NONE \
  --request-parameters method.request.path.proxy=true

echo "Setting up Lambda integration..."
aws apigateway put-integration \
  --rest-api-id $API_ID \
  --region $REGION \
  --resource-id $SESSION_PROXY_ID \
  --http-method ANY \
  --type AWS_PROXY \
  --integration-http-method POST \
  --uri "arn:aws:apigateway:${REGION}:lambda:path/2015-03-31/functions/${LAMBDA_ARN}/invocations"

echo "Adding OPTIONS for CORS..."
aws apigateway put-method \
  --rest-api-id $API_ID \
  --region $REGION \
  --resource-id $SESSION_PROXY_ID \
  --http-method OPTIONS \
  --authorization-type NONE

aws apigateway put-integration \
  --rest-api-id $API_ID \
  --region $REGION \
  --resource-id $SESSION_PROXY_ID \
  --http-method OPTIONS \
  --type MOCK \
  --request-templates '{"application/json":"{\"statusCode\":200}"}'

aws apigateway put-integration-response \
  --rest-api-id $API_ID \
  --region $REGION \
  --resource-id $SESSION_PROXY_ID \
  --http-method OPTIONS \
  --status-code 200 \
  --response-parameters '{"method.response.header.Access-Control-Allow-Headers":"'"'"'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token'"'"'","method.response.header.Access-Control-Allow-Methods":"'"'"'GET,POST,PUT,DELETE,OPTIONS'"'"'","method.response.header.Access-Control-Allow-Origin":"'"'"'*'"'"'"}'

aws apigateway put-method-response \
  --rest-api-id $API_ID \
  --region $REGION \
  --resource-id $SESSION_PROXY_ID \
  --http-method OPTIONS \
  --status-code 200 \
  --response-parameters '{"method.response.header.Access-Control-Allow-Headers":false,"method.response.header.Access-Control-Allow-Methods":false,"method.response.header.Access-Control-Allow-Origin":false}'

echo "Deploying to prod..."
aws apigateway create-deployment \
  --rest-api-id $API_ID \
  --region $REGION \
  --stage-name prod

echo "✅ Session routes configured!"
