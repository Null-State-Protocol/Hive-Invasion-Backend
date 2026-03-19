#!/bin/bash

# Hive Invasion Backend - Lambda Deployment Script
# This script packages and deploys the Lambda function to AWS

set -e  # Exit on error

echo "🐝 Hive Invasion Backend - Lambda Deployment"
echo "============================================="
echo ""

# Configuration
FUNCTION_NAME="hive-invasion-backend"
REGION="eu-north-1"
RUNTIME="python3.11"
HANDLER="lambda_function.lambda_handler"
MEMORY_SIZE=512
TIMEOUT=30

# Check if AWS CLI is installed
if ! command -v aws &> /dev/null; then
    echo "❌ AWS CLI not installed. Please install it first:"
    echo "   brew install awscli"
    exit 1
fi

# Check if AWS credentials are configured
if ! aws sts get-caller-identity &> /dev/null; then
    echo "❌ AWS credentials not configured. Run:"
    echo "   aws configure"
    exit 1
fi

echo "✅ AWS CLI configured"
echo ""

# Clean previous builds
echo "🧹 Cleaning previous builds..."
rm -f lambda-deploy.zip
rm -rf package/
# Remove stale named deploy zips (fix1, fix2, ... archive zips) — keep only lambda-deploy.zip
rm -f lambda_deploy_*.zip lambda_package.zip
rm -rf lambda_package/
echo ""

# Create package directory
echo "📦 Creating deployment package..."
mkdir -p package
echo ""

# Install dependencies using Docker (for Linux compatibility)
echo "📥 Installing Python dependencies for Linux..."
if command -v docker &> /dev/null; then
    echo "   Using Docker for Linux-compatible build..."
    docker run --rm -v "$PWD":/var/task -w /var/task public.ecr.aws/lambda/python:3.11 \
        pip install -r requirements.txt -t package/ --no-cache-dir
else
    echo "   ⚠️  Docker not found, using local pip (may cause compatibility issues)..."
    pip3 install -r requirements.txt -t package/ --platform manylinux2014_x86_64 --only-binary=:all: --no-cache-dir || \
    pip3 install -r requirements.txt -t package/ --no-cache-dir
fi
echo ""

# Copy source files (explicitly listed — test/migration/broken files excluded)
echo "📋 Copying source files..."
SOURCE_FILES="
    analytics.py
    config.py
    contract_adapter.py
    decorators.py
    dust_rewards.py
    email_auth.py
    email_service.py
    jwt_handler.py
    lambda_function.py
    logger.py
    models.py
    responses.py
    security.py
    validation.py
    wallet_auth.py
"
for f in $SOURCE_FILES; do
    f=$(echo $f | xargs)  # trim whitespace
    [ -z "$f" ] && continue
    if [ -f "$f" ]; then
        cp "$f" package/
        echo "   ✅ $f"
    else
        echo "   ⚠️  $f bulunamadı, atlandı"
    fi
done
echo ""

# Create deployment zip
echo "📦 Creating ZIP archive..."
cd package
zip -r ../lambda-deploy.zip . \
    -x "*.pyc" \
    -x "*/__pycache__/*" \
    -x "*__pycache__*" \
    -x "*.dist-info/*" \
    -x "*/tests/*" \
    -x "*/test/*" \
    -x "*_test.py" \
    -x "test_*.py"
cd ..
echo ""

# Get zip size
ZIP_SIZE=$(du -h lambda-deploy.zip | cut -f1)
echo "📦 Package size: $ZIP_SIZE"
echo ""

# Check if Lambda function exists
echo "🔍 Checking if Lambda function exists..."
if aws lambda get-function --function-name $FUNCTION_NAME --region $REGION &> /dev/null; then
    echo "♻️  Updating existing function..."
    
    # Update function code
    aws lambda update-function-code \
        --function-name $FUNCTION_NAME \
        --zip-file fileb://lambda-deploy.zip \
        --region $REGION \
        --no-cli-pager
    
    echo ""
    echo "⏳ Waiting for update to complete..."
    aws lambda wait function-updated \
        --function-name $FUNCTION_NAME \
        --region $REGION
    
    echo ""
    echo "✅ Lambda function updated successfully!"
    
else
    echo "🆕 Creating new Lambda function..."
    echo ""
    echo "⚠️  You need to create the Lambda function manually first:"
    echo ""
    echo "1. Go to AWS Lambda Console: https://console.aws.amazon.com/lambda"
    echo "2. Click 'Create function'"
    echo "3. Choose 'Author from scratch'"
    echo "4. Function name: $FUNCTION_NAME"
    echo "5. Runtime: Python 3.11"
    echo "6. Architecture: x86_64"
    echo "7. Create a new role with basic Lambda permissions"
    echo "8. Click 'Create function'"
    echo ""
    echo "Then run this script again to deploy the code."
    echo ""
    exit 1
fi

# Update environment variables
echo "🔧 Setting environment variables..."

# Read existing JWT_SECRET to preserve active sessions
echo "🔑 Reading existing JWT_SECRET from Lambda..."
EXISTING_JWT_SECRET=$(aws lambda get-function-configuration \
    --function-name $FUNCTION_NAME \
    --region $REGION \
    --query 'Environment.Variables.JWT_SECRET' \
    --output text 2>/dev/null)

if [ -z "$EXISTING_JWT_SECRET" ] || [ "$EXISTING_JWT_SECRET" = "None" ]; then
    echo "   ⚠️  No existing JWT_SECRET found, generating new one..."
    EXISTING_JWT_SECRET=$(openssl rand -hex 32)
else
    echo "   ✅ Using existing JWT_SECRET (active sessions preserved)"
fi

# NOTE: AWS_REGION is a reserved Lambda env key — do NOT include it.
# Use Python to build the JSON payload, avoiding shell quoting/interpolation issues.
python3 - <<PYEOF
import subprocess, json, sys

env_vars = {
    "TABLE_USERS": "hive_users",
    "TABLE_USER_EMAILS": "hive_user_emails",
    "TABLE_USER_WALLETS": "hive_user_wallets",
    "TABLE_SESSIONS": "hive_sessions",
    "TABLE_PLAYER_DATA": "hive_player_data",
    "TABLE_ACHIEVEMENTS": "hive_achievements",
    "TABLE_LEADERBOARD_DAILY": "hive_leaderboard_daily",
    "TABLE_LEADERBOARD_WEEKLY": "hive_leaderboard_weekly",
    "TABLE_LEADERBOARD_ALLTIME": "hive_leaderboard_alltime",
    "TABLE_LOGS": "hive_logs",
    "TABLE_ANALYTICS": "hive_analytics",
    "TABLE_EMAIL_VERIFICATION": "hive_email_verification",
    "TABLE_PASSWORD_RESET": "hive_password_reset",
    "TABLE_DUST_REWARDS": "hive_dust_rewards",
    "JWT_SECRET": "$EXISTING_JWT_SECRET",
    "JWT_ACCESS_TOKEN_EXPIRE_MINUTES": "60",
    "JWT_REFRESH_TOKEN_EXPIRE_DAYS": "30",
    "ENVIRONMENT": "production",
    "LOG_LEVEL": "INFO",
    "KEY_PURCHASE_ENABLED": "true",
    "SOMNIA_RPC_MAINNET": "https://api.infra.mainnet.somnia.network/",
    "SOMNIA_TREASURY_WALLET": "0xEbD49456f4b448E9455bDD89B42e7EFD24567D60",
    "SENDER_EMAIL": "noreply@hiveinvasion.games",
    "ENABLE_EMAIL_VERIFICATION": "true",
    "ALLOWED_ORIGINS": "https://hiveinvasion.io,https://www.hiveinvasion.io,https://hive-invasion-website.kagan-fa3.workers.dev",
}

result = subprocess.run([
    "aws", "lambda", "update-function-configuration",
    "--function-name", "$FUNCTION_NAME",
    "--region", "$REGION",
    "--environment", json.dumps({"Variables": env_vars}),
    "--no-cli-pager"
], capture_output=True, text=True)

if result.returncode == 0:
    data = json.loads(result.stdout)
    count = len(data.get("Environment", {}).get("Variables", {}))
    print(f"   ✅ {count} env var set edildi.")
else:
    print("   ❌ Env var hatasi:", result.stderr[:300], file=sys.stderr)
    sys.exit(1)
PYEOF

echo "✅ Environment variables set"
echo ""

# Get function URL
echo "🔗 Lambda Function Details:"
echo "   Name: $FUNCTION_NAME"
echo "   Region: $REGION"
echo "   Runtime: $RUNTIME"
echo "   Memory: ${MEMORY_SIZE}MB"
echo "   Timeout: ${TIMEOUT}s"
echo ""

echo "✅ Deployment complete!"
echo ""
echo "📝 Next steps:"
echo "   1. Create API Gateway and link to this Lambda"
echo "   2. Update config.js in frontend with API URL"
echo "   3. Create DynamoDB tables (see create-tables.sh)"
echo "   4. Test endpoints with Postman or curl"
echo ""
echo "🐝 Happy coding!"
