#!/bin/bash

# Create DynamoDB Tables for Hive Invasion Backend

set -e

REGION="eu-north-1"

echo "🐝 Creating DynamoDB Tables for Hive Invasion"
echo "=============================================="
echo ""

# Users table
echo "📊 Creating users table..."
aws dynamodb create-table \
    --table-name hive_users \
    --attribute-definitions \
        AttributeName=user_id,AttributeType=S \
    --key-schema \
        AttributeName=user_id,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST \
    --region $REGION \
    --no-cli-pager

# User emails table
echo "📊 Creating user_emails table..."
aws dynamodb create-table \
    --table-name hive_user_emails \
    --attribute-definitions \
        AttributeName=email,AttributeType=S \
    --key-schema \
        AttributeName=email,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST \
    --region $REGION \
    --no-cli-pager

# User wallets table
echo "📊 Creating user_wallets table..."
aws dynamodb create-table \
    --table-name hive_user_wallets \
    --attribute-definitions \
        AttributeName=wallet_address,AttributeType=S \
    --key-schema \
        AttributeName=wallet_address,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST \
    --region $REGION \
    --no-cli-pager

# Sessions table
echo "📊 Creating sessions table..."
aws dynamodb create-table \
    --table-name hive_sessions \
    --attribute-definitions \
        AttributeName=session_token,AttributeType=S \
    --key-schema \
        AttributeName=session_token,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST \
    --region $REGION \
    --no-cli-pager

# Player data table
echo "📊 Creating player_data table..."
aws dynamodb create-table \
    --table-name hive_player_data \
    --attribute-definitions \
        AttributeName=user_id,AttributeType=S \
    --key-schema \
        AttributeName=user_id,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST \
    --region $REGION \
    --no-cli-pager

# Achievements table
echo "📊 Creating achievements table..."
aws dynamodb create-table \
    --table-name hive_achievements \
    --attribute-definitions \
        AttributeName=user_id,AttributeType=S \
        AttributeName=achievement_id,AttributeType=S \
    --key-schema \
        AttributeName=user_id,KeyType=HASH \
        AttributeName=achievement_id,KeyType=RANGE \
    --billing-mode PAY_PER_REQUEST \
    --region $REGION \
    --no-cli-pager

# Leaderboard tables
echo "📊 Creating leaderboard tables..."
for period in daily weekly alltime; do
    aws dynamodb create-table \
        --table-name hive_leaderboard_${period} \
        --attribute-definitions \
            AttributeName=user_id,AttributeType=S \
            AttributeName=score,AttributeType=N \
        --key-schema \
            AttributeName=user_id,KeyType=HASH \
            AttributeName=score,KeyType=RANGE \
        --billing-mode PAY_PER_REQUEST \
        --region $REGION \
        --no-cli-pager
done

# Logs table
echo "📊 Creating logs table..."
aws dynamodb create-table \
    --table-name hive_logs \
    --attribute-definitions \
        AttributeName=log_id,AttributeType=S \
    --key-schema \
        AttributeName=log_id,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST \
    --region $REGION \
    --no-cli-pager

# Analytics table
echo "📊 Creating analytics table..."
aws dynamodb create-table \
    --table-name hive_analytics \
    --attribute-definitions \
        AttributeName=event_id,AttributeType=S \
    --key-schema \
        AttributeName=event_id,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST \
    --region $REGION \
    --no-cli-pager

# Rate limiting table
echo "📊 Creating rate_limits table..."
aws dynamodb create-table \
    --table-name hive_rate_limits \
    --attribute-definitions \
        AttributeName=identifier,AttributeType=S \
        AttributeName=timestamp,AttributeType=N \
    --key-schema \
        AttributeName=identifier,KeyType=HASH \
        AttributeName=timestamp,KeyType=RANGE \
    --billing-mode PAY_PER_REQUEST \
    --region $REGION \
    --no-cli-pager

echo ""
echo "⏰ Enabling TTL for temporary tables..."

# Enable TTL for logs (90 days retention)
aws dynamodb update-time-to-live \
    --table-name hive_logs \
    --time-to-live-specification "Enabled=true, AttributeName=ttl" \
    --region $REGION \
    --no-cli-pager 2>/dev/null || echo "  ⚠️  TTL config for hive_logs (may need manual setup)"

# Enable TTL for rate limits (1 hour)
aws dynamodb update-time-to-live \
    --table-name hive_rate_limits \
    --time-to-live-specification "Enabled=true, AttributeName=ttl" \
    --region $REGION \
    --no-cli-pager 2>/dev/null || echo "  ⚠️  TTL config for hive_rate_limits (may need manual setup)"

echo ""
echo "✅ All DynamoDB tables created successfully!"
echo ""
echo "📝 Tables created:"
echo "   - hive_users"
echo "   - hive_user_emails"
echo "   - hive_user_wallets"
echo "   - hive_sessions"
echo "   - hive_player_data"
echo "   - hive_achievements"
echo "   - hive_leaderboard_daily"
echo "   - hive_leaderboard_weekly"
echo "   - hive_leaderboard_alltime"
echo "   - hive_logs"
echo "   - hive_analytics"
echo "   - hive_rate_limits (with TTL)"
echo ""
echo "⏳ Tables are being created. This may take a few minutes."
echo "   Check status: aws dynamodb list-tables --region $REGION"
