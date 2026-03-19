#!/bin/bash

# Configure AWS WAF rate limiting for /auth/register
# 50 req/min is implemented as 250 req/5-min (WAF rate window)

set -euo pipefail

API_ID="${1:-bb5nb3l00b}"
STAGE_NAME="${2:-prod}"
REGION="${3:-eu-north-1}"
WEB_ACL_NAME="${4:-hive-invasion-register-rate-limit-50rpm}"
RATE_PER_MIN="${5:-50}"

if ! [[ "$RATE_PER_MIN" =~ ^[0-9]+$ ]]; then
  echo "❌ RATE_PER_MIN must be a positive integer"
  exit 1
fi

RATE_LIMIT_5MIN=$((RATE_PER_MIN * 5))
if [ "$RATE_LIMIT_5MIN" -lt 10 ]; then
  echo "❌ WAF rate limit must be >= 10 requests per 5 minutes"
  exit 1
fi

RESOURCE_ARN="arn:aws:apigateway:${REGION}::/restapis/${API_ID}/stages/${STAGE_NAME}"
RULE_NAME="RateLimitAuthRegister${RATE_PER_MIN}PerMin"

TMP_RULES_FILE=$(mktemp)
trap 'rm -f "$TMP_RULES_FILE"' EXIT

REGISTER_PATH_B64="L2F1dGgvcmVnaXN0ZXI="

cat > "$TMP_RULES_FILE" <<EOF
[
  {
    "Name": "${RULE_NAME}",
    "Priority": 1,
    "Action": {"Block": {}},
    "Statement": {
      "RateBasedStatement": {
        "Limit": ${RATE_LIMIT_5MIN},
        "AggregateKeyType": "IP",
        "ScopeDownStatement": {
          "ByteMatchStatement": {
            "SearchString": "${REGISTER_PATH_B64}",
            "FieldToMatch": {"UriPath": {}},
            "TextTransformations": [
              {"Priority": 0, "Type": "NONE"}
            ],
            "PositionalConstraint": "ENDS_WITH"
          }
        }
      }
    },
    "VisibilityConfig": {
      "SampledRequestsEnabled": true,
      "CloudWatchMetricsEnabled": true,
      "MetricName": "${RULE_NAME}"
    }
  }
]
EOF

echo "🔐 AWS WAF setup started"
echo "   API_ID: ${API_ID}"
echo "   STAGE: ${STAGE_NAME}"
echo "   REGION: ${REGION}"
echo "   LIMIT: ${RATE_PER_MIN}/min (${RATE_LIMIT_5MIN}/5min per IP)"
echo ""

aws sts get-caller-identity --no-cli-pager >/dev/null
aws apigateway get-stage \
  --rest-api-id "$API_ID" \
  --stage-name "$STAGE_NAME" \
  --region "$REGION" \
  --no-cli-pager >/dev/null

WEB_ACL_ARN=$(aws wafv2 list-web-acls \
  --scope REGIONAL \
  --region "$REGION" \
  --query "WebACLs[?Name=='${WEB_ACL_NAME}'].ARN | [0]" \
  --output text \
  --no-cli-pager)

WEB_ACL_ID=$(aws wafv2 list-web-acls \
  --scope REGIONAL \
  --region "$REGION" \
  --query "WebACLs[?Name=='${WEB_ACL_NAME}'].Id | [0]" \
  --output text \
  --no-cli-pager)

if [ "$WEB_ACL_ARN" = "None" ] || [ -z "$WEB_ACL_ARN" ]; then
  echo "🆕 Creating Web ACL: ${WEB_ACL_NAME}"

  CREATE_OUTPUT=$(aws wafv2 create-web-acl \
    --name "$WEB_ACL_NAME" \
    --scope REGIONAL \
    --default-action Allow={} \
    --visibility-config "SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName=${WEB_ACL_NAME}" \
    --rules "file://${TMP_RULES_FILE}" \
    --region "$REGION" \
    --output json \
    --no-cli-pager)

  WEB_ACL_ARN=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["Summary"]["ARN"])' <<< "$CREATE_OUTPUT")
  WEB_ACL_ID=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["Summary"]["Id"])' <<< "$CREATE_OUTPUT")
else
  echo "♻️  Updating existing Web ACL: ${WEB_ACL_NAME}"

  LOCK_TOKEN=$(aws wafv2 get-web-acl \
    --name "$WEB_ACL_NAME" \
    --scope REGIONAL \
    --id "$WEB_ACL_ID" \
    --region "$REGION" \
    --query 'LockToken' \
    --output text \
    --no-cli-pager)

  aws wafv2 update-web-acl \
    --name "$WEB_ACL_NAME" \
    --scope REGIONAL \
    --id "$WEB_ACL_ID" \
    --default-action Allow={} \
    --visibility-config "SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName=${WEB_ACL_NAME}" \
    --rules "file://${TMP_RULES_FILE}" \
    --lock-token "$LOCK_TOKEN" \
    --region "$REGION" \
    --no-cli-pager >/dev/null
fi

CURRENT_WEB_ACL_ARN=$(aws wafv2 get-web-acl-for-resource \
  --resource-arn "$RESOURCE_ARN" \
  --region "$REGION" \
  --query 'WebACL.ARN' \
  --output text \
  --no-cli-pager 2>/dev/null || true)

if [ -n "$CURRENT_WEB_ACL_ARN" ] && [ "$CURRENT_WEB_ACL_ARN" != "None" ] && [ "$CURRENT_WEB_ACL_ARN" != "$WEB_ACL_ARN" ]; then
  echo "↔️  Replacing existing Web ACL association"
  aws wafv2 disassociate-web-acl \
    --resource-arn "$RESOURCE_ARN" \
    --region "$REGION" \
    --no-cli-pager >/dev/null
fi

if [ "$CURRENT_WEB_ACL_ARN" != "$WEB_ACL_ARN" ]; then
  aws wafv2 associate-web-acl \
    --web-acl-arn "$WEB_ACL_ARN" \
    --resource-arn "$RESOURCE_ARN" \
    --region "$REGION" \
    --no-cli-pager >/dev/null
fi

echo "✅ WAF rate limiting configured"
echo "   Web ACL: ${WEB_ACL_NAME}"
echo "   Web ACL ARN: ${WEB_ACL_ARN}"
echo "   Stage ARN: ${RESOURCE_ARN}"
echo "   Rule: ${RULE_NAME} (${RATE_PER_MIN}/min per IP on */auth/register)"
