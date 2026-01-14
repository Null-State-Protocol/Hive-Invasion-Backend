#!/bin/bash

# API Gateway Endpoint Setup Script
# Run this in AWS CloudShell

API_ID="bb5nb3l00b"
REGION="eu-north-1"
LAMBDA_ARN="arn:aws:lambda:eu-north-1:799904911021:function:hive-invasion-backend"
ACCOUNT_ID="799904911021"

# Get root resource ID
ROOT_ID=$(aws apigateway get-resources --rest-api-id $API_ID --region $REGION --query 'items[?path==`/`].id' --output text)
echo "Root Resource ID: $ROOT_ID"

# ==================== CREATE /player ====================
echo "Creating /player resource..."
PLAYER_RESOURCE=$(aws apigateway create-resource \
  --rest-api-id $API_ID \
  --parent-id $ROOT_ID \
  --path-part player \
  --region $REGION)

PLAYER_ID=$(echo $PLAYER_RESOURCE | jq -r '.id')
echo "Player Resource ID: $PLAYER_ID"

# Add OPTIONS to /player
echo "Adding OPTIONS to /player..."
aws apigateway put-method \
  --rest-api-id $API_ID \
  --resource-id $PLAYER_ID \
  --http-method OPTIONS \
  --authorization-type NONE \
  --region $REGION

aws apigateway put-integration \
  --rest-api-id $API_ID \
  --resource-id $PLAYER_ID \
  --http-method OPTIONS \
  --type MOCK \
  --request-templates '{"application/json": "{\"statusCode\": 200}"}' \
  --region $REGION

aws apigateway put-method-response \
  --rest-api-id $API_ID \
  --resource-id $PLAYER_ID \
  --http-method OPTIONS \
  --status-code 200 \
  --response-parameters '{"method.response.header.Access-Control-Allow-Headers":true,"method.response.header.Access-Control-Allow-Methods":true,"method.response.header.Access-Control-Allow-Origin":true}' \
  --region $REGION

aws apigateway put-integration-response \
  --rest-api-id $API_ID \
  --resource-id $PLAYER_ID \
  --http-method OPTIONS \
  --status-code 200 \
  --response-parameters '{"method.response.header.Access-Control-Allow-Headers":"'\''Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token'\''","method.response.header.Access-Control-Allow-Methods":"'\''GET,OPTIONS'\''","method.response.header.Access-Control-Allow-Origin":"'\''*'\''"}' \
  --region $REGION

# ==================== CREATE /player/profile ====================
echo "Creating /player/profile resource..."
PROFILE_RESOURCE=$(aws apigateway create-resource \
  --rest-api-id $API_ID \
  --parent-id $PLAYER_ID \
  --path-part profile \
  --region $REGION)

PROFILE_ID=$(echo $PROFILE_RESOURCE | jq -r '.id')
echo "Profile Resource ID: $PROFILE_ID"

# Add GET to /player/profile
echo "Adding GET to /player/profile..."
aws apigateway put-method \
  --rest-api-id $API_ID \
  --resource-id $PROFILE_ID \
  --http-method GET \
  --authorization-type NONE \
  --region $REGION

aws apigateway put-integration \
  --rest-api-id $API_ID \
  --resource-id $PROFILE_ID \
  --http-method GET \
  --type AWS_PROXY \
  --integration-http-method POST \
  --uri "arn:aws:apigateway:$REGION:lambda:path/2015-03-31/functions/$LAMBDA_ARN/invocations" \
  --region $REGION

# Add OPTIONS to /player/profile
echo "Adding OPTIONS to /player/profile..."
aws apigateway put-method \
  --rest-api-id $API_ID \
  --resource-id $PROFILE_ID \
  --http-method OPTIONS \
  --authorization-type NONE \
  --region $REGION

aws apigateway put-integration \
  --rest-api-id $API_ID \
  --resource-id $PROFILE_ID \
  --http-method OPTIONS \
  --type MOCK \
  --request-templates '{"application/json": "{\"statusCode\": 200}"}' \
  --region $REGION

aws apigateway put-method-response \
  --rest-api-id $API_ID \
  --resource-id $PROFILE_ID \
  --http-method OPTIONS \
  --status-code 200 \
  --response-parameters '{"method.response.header.Access-Control-Allow-Headers":true,"method.response.header.Access-Control-Allow-Methods":true,"method.response.header.Access-Control-Allow-Origin":true}' \
  --region $REGION

aws apigateway put-integration-response \
  --rest-api-id $API_ID \
  --resource-id $PROFILE_ID \
  --http-method OPTIONS \
  --status-code 200 \
  --response-parameters '{"method.response.header.Access-Control-Allow-Headers":"'\''Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token'\''","method.response.header.Access-Control-Allow-Methods":"'\''GET,OPTIONS'\''","method.response.header.Access-Control-Allow-Origin":"'\''*'\''"}' \
  --region $REGION

# ==================== CREATE /player/achievements ====================
echo "Creating /player/achievements resource..."
ACHIEVEMENTS_RESOURCE=$(aws apigateway create-resource \
  --rest-api-id $API_ID \
  --parent-id $PLAYER_ID \
  --path-part achievements \
  --region $REGION)

ACHIEVEMENTS_ID=$(echo $ACHIEVEMENTS_RESOURCE | jq -r '.id')
echo "Achievements Resource ID: $ACHIEVEMENTS_ID"

# Add GET to /player/achievements
echo "Adding GET to /player/achievements..."
aws apigateway put-method \
  --rest-api-id $API_ID \
  --resource-id $ACHIEVEMENTS_ID \
  --http-method GET \
  --authorization-type NONE \
  --region $REGION

aws apigateway put-integration \
  --rest-api-id $API_ID \
  --resource-id $ACHIEVEMENTS_ID \
  --http-method GET \
  --type AWS_PROXY \
  --integration-http-method POST \
  --uri "arn:aws:apigateway:$REGION:lambda:path/2015-03-31/functions/$LAMBDA_ARN/invocations" \
  --region $REGION

# Add OPTIONS to /player/achievements
echo "Adding OPTIONS to /player/achievements..."
aws apigateway put-method \
  --rest-api-id $ACHIEVEMENTS_ID \
  --resource-id $ACHIEVEMENTS_ID \
  --http-method OPTIONS \
  --authorization-type NONE \
  --region $REGION

aws apigateway put-integration \
  --rest-api-id $API_ID \
  --resource-id $ACHIEVEMENTS_ID \
  --http-method OPTIONS \
  --type MOCK \
  --request-templates '{"application/json": "{\"statusCode\": 200}"}' \
  --region $REGION

aws apigateway put-method-response \
  --rest-api-id $API_ID \
  --resource-id $ACHIEVEMENTS_ID \
  --http-method OPTIONS \
  --status-code 200 \
  --response-parameters '{"method.response.header.Access-Control-Allow-Headers":true,"method.response.header.Access-Control-Allow-Methods":true,"method.response.header.Access-Control-Allow-Origin":true}' \
  --region $REGION

aws apigateway put-integration-response \
  --rest-api-id $API_ID \
  --resource-id $ACHIEVEMENTS_ID \
  --http-method OPTIONS \
  --status-code 200 \
  --response-parameters '{"method.response.header.Access-Control-Allow-Headers":"'\''Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token'\''","method.response.header.Access-Control-Allow-Methods":"'\''GET,OPTIONS'\''","method.response.header.Access-Control-Allow-Origin":"'\''*'\''"}' \
  --region $REGION

# ==================== CREATE /leaderboard ====================
echo "Creating /leaderboard resource..."
LEADERBOARD_RESOURCE=$(aws apigateway create-resource \
  --rest-api-id $API_ID \
  --parent-id $ROOT_ID \
  --path-part leaderboard \
  --region $REGION)

LEADERBOARD_ID=$(echo $LEADERBOARD_RESOURCE | jq -r '.id')
echo "Leaderboard Resource ID: $LEADERBOARD_ID"

# Add OPTIONS to /leaderboard
echo "Adding OPTIONS to /leaderboard..."
aws apigateway put-method \
  --rest-api-id $API_ID \
  --resource-id $LEADERBOARD_ID \
  --http-method OPTIONS \
  --authorization-type NONE \
  --region $REGION

aws apigateway put-integration \
  --rest-api-id $API_ID \
  --resource-id $LEADERBOARD_ID \
  --http-method OPTIONS \
  --type MOCK \
  --request-templates '{"application/json": "{\"statusCode\": 200}"}' \
  --region $REGION

aws apigateway put-method-response \
  --rest-api-id $API_ID \
  --resource-id $LEADERBOARD_ID \
  --http-method OPTIONS \
  --status-code 200 \
  --response-parameters '{"method.response.header.Access-Control-Allow-Headers":true,"method.response.header.Access-Control-Allow-Methods":true,"method.response.header.Access-Control-Allow-Origin":true}' \
  --region $REGION

aws apigateway put-integration-response \
  --rest-api-id $API_ID \
  --resource-id $LEADERBOARD_ID \
  --http-method OPTIONS \
  --status-code 200 \
  --response-parameters '{"method.response.header.Access-Control-Allow-Headers":"'\''Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token'\''","method.response.header.Access-Control-Allow-Methods":"'\''GET,OPTIONS'\''","method.response.header.Access-Control-Allow-Origin":"'\''*'\''"}' \
  --region $REGION

# ==================== CREATE /leaderboard/rank ====================
echo "Creating /leaderboard/rank resource..."
RANK_RESOURCE=$(aws apigateway create-resource \
  --rest-api-id $API_ID \
  --parent-id $LEADERBOARD_ID \
  --path-part rank \
  --region $REGION)

RANK_ID=$(echo $RANK_RESOURCE | jq -r '.id')
echo "Rank Resource ID: $RANK_ID"

# Add GET to /leaderboard/rank
echo "Adding GET to /leaderboard/rank..."
aws apigateway put-method \
  --rest-api-id $API_ID \
  --resource-id $RANK_ID \
  --http-method GET \
  --authorization-type NONE \
  --region $REGION

aws apigateway put-integration \
  --rest-api-id $API_ID \
  --resource-id $RANK_ID \
  --http-method GET \
  --type AWS_PROXY \
  --integration-http-method POST \
  --uri "arn:aws:apigateway:$REGION:lambda:path/2015-03-31/functions/$LAMBDA_ARN/invocations" \
  --region $REGION

# Add OPTIONS to /leaderboard/rank
echo "Adding OPTIONS to /leaderboard/rank..."
aws apigateway put-method \
  --rest-api-id $API_ID \
  --resource-id $RANK_ID \
  --http-method OPTIONS \
  --authorization-type NONE \
  --region $REGION

aws apigateway put-integration \
  --rest-api-id $API_ID \
  --resource-id $RANK_ID \
  --http-method OPTIONS \
  --type MOCK \
  --request-templates '{"application/json": "{\"statusCode\": 200}"}' \
  --region $REGION

aws apigateway put-method-response \
  --rest-api-id $API_ID \
  --resource-id $RANK_ID \
  --http-method OPTIONS \
  --status-code 200 \
  --response-parameters '{"method.response.header.Access-Control-Allow-Headers":true,"method.response.header.Access-Control-Allow-Methods":true,"method.response.header.Access-Control-Allow-Origin":true}' \
  --region $REGION

aws apigateway put-integration-response \
  --rest-api-id $API_ID \
  --resource-id $RANK_ID \
  --http-method OPTIONS \
  --status-code 200 \
  --response-parameters '{"method.response.header.Access-Control-Allow-Headers":"'\''Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token'\''","method.response.header.Access-Control-Allow-Methods":"'\''GET,OPTIONS'\''","method.response.header.Access-Control-Allow-Origin":"'\''*'\''"}' \
  --region $REGION

# ==================== CREATE /leaderboard/{period} ====================
echo "Creating /leaderboard/{period} resource..."
PERIOD_RESOURCE=$(aws apigateway create-resource \
  --rest-api-id $API_ID \
  --parent-id $LEADERBOARD_ID \
  --path-part "{period}" \
  --region $REGION)

PERIOD_ID=$(echo $PERIOD_RESOURCE | jq -r '.id')
echo "Period Resource ID: $PERIOD_ID"

# Add GET to /leaderboard/{period}
echo "Adding GET to /leaderboard/{period}..."
aws apigateway put-method \
  --rest-api-id $API_ID \
  --resource-id $PERIOD_ID \
  --http-method GET \
  --authorization-type NONE \
  --request-parameters '{"method.request.path.period":true}' \
  --region $REGION

aws apigateway put-integration \
  --rest-api-id $API_ID \
  --resource-id $PERIOD_ID \
  --http-method GET \
  --type AWS_PROXY \
  --integration-http-method POST \
  --uri "arn:aws:apigateway:$REGION:lambda:path/2015-03-31/functions/$LAMBDA_ARN/invocations" \
  --region $REGION

# Add OPTIONS to /leaderboard/{period}
echo "Adding OPTIONS to /leaderboard/{period}..."
aws apigateway put-method \
  --rest-api-id $API_ID \
  --resource-id $PERIOD_ID \
  --http-method OPTIONS \
  --authorization-type NONE \
  --region $REGION

aws apigateway put-integration \
  --rest-api-id $API_ID \
  --resource-id $PERIOD_ID \
  --http-method OPTIONS \
  --type MOCK \
  --request-templates '{"application/json": "{\"statusCode\": 200}"}' \
  --region $REGION

aws apigateway put-method-response \
  --rest-api-id $API_ID \
  --resource-id $PERIOD_ID \
  --http-method OPTIONS \
  --status-code 200 \
  --response-parameters '{"method.response.header.Access-Control-Allow-Headers":true,"method.response.header.Access-Control-Allow-Methods":true,"method.response.header.Access-Control-Allow-Origin":true}' \
  --region $REGION

aws apigateway put-integration-response \
  --rest-api-id $API_ID \
  --resource-id $PERIOD_ID \
  --http-method OPTIONS \
  --status-code 200 \
  --response-parameters '{"method.response.header.Access-Control-Allow-Headers":"'\''Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token'\''","method.response.header.Access-Control-Allow-Methods":"'\''GET,OPTIONS'\''","method.response.header.Access-Control-Allow-Origin":"'\''*'\''"}' \
  --region $REGION

# ==================== ADD LAMBDA PERMISSIONS ====================
echo "Adding Lambda invoke permissions..."

# Permission for /player/profile
aws lambda add-permission \
  --function-name hive-invasion-backend \
  --statement-id apigateway-player-profile-get \
  --action lambda:InvokeFunction \
  --principal apigateway.amazonaws.com \
  --source-arn "arn:aws:execute-api:$REGION:$ACCOUNT_ID:$API_ID/*/GET/player/profile" \
  --region $REGION

# Permission for /player/achievements
aws lambda add-permission \
  --function-name hive-invasion-backend \
  --statement-id apigateway-player-achievements-get \
  --action lambda:InvokeFunction \
  --principal apigateway.amazonaws.com \
  --source-arn "arn:aws:execute-api:$REGION:$ACCOUNT_ID:$API_ID/*/GET/player/achievements" \
  --region $REGION

# Permission for /leaderboard/rank
aws lambda add-permission \
  --function-name hive-invasion-backend \
  --statement-id apigateway-leaderboard-rank-get \
  --action lambda:InvokeFunction \
  --principal apigateway.amazonaws.com \
  --source-arn "arn:aws:execute-api:$REGION:$ACCOUNT_ID:$API_ID/*/GET/leaderboard/rank" \
  --region $REGION

# Permission for /leaderboard/{period}
aws lambda add-permission \
  --function-name hive-invasion-backend \
  --statement-id apigateway-leaderboard-period-get \
  --action lambda:InvokeFunction \
  --principal apigateway.amazonaws.com \
  --source-arn "arn:aws:execute-api:$REGION:$ACCOUNT_ID:$API_ID/*/GET/leaderboard/*" \
  --region $REGION

# ==================== DEPLOY API ====================
echo "Deploying API to prod stage..."
aws apigateway create-deployment \
  --rest-api-id $API_ID \
  --stage-name prod \
  --region $REGION

echo "Done! API endpoints created and deployed."
echo ""
echo "Test endpoints:"
echo "  GET https://bb5nb3l00b.execute-api.eu-north-1.amazonaws.com/prod/player/profile"
echo "  GET https://bb5nb3l00b.execute-api.eu-north-1.amazonaws.com/prod/player/achievements"
echo "  GET https://bb5nb3l00b.execute-api.eu-north-1.amazonaws.com/prod/leaderboard/rank"
echo "  GET https://bb5nb3l00b.execute-api.eu-north-1.amazonaws.com/prod/leaderboard/daily"
