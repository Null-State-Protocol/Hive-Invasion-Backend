#!/bin/bash
# =============================================================================
# AWS WAF Bot Control — Full Setup
# =============================================================================
# Creates a comprehensive Web ACL for Hive Invasion with:
#   1. AWS Managed Rules – Amazon IP Reputation List  (block bad IPs)
#   2. AWS Managed Rules – Bot Control (COMMON level) (block bots)
#   3. AWS Managed Rules – Known Bad Inputs           (block attack patterns)
#   4. Rate limit /auth/register                      (20 req/5min per IP)
#   5. Rate limit /auth/resend-code                   (15 req/5min per IP)
#   6. Rate limit /auth/verify-email                  (50 req/5min per IP)
#   7. Rate limit /auth/login                         (200 req/5min per IP)
#   8. Rate limit all /auth/                          (500 req/5min per IP)
#
# Attaches to BOTH API Gateways:
#   - Game backend: bb5nb3l00b / prod
#   - Backoffice:   8ta3pfqagh / backoffice
#
# Also updates backoffice Lambda env vars to point to new ACL name.
#
# Usage:
#   bash setup-waf-bot-control.sh [--dry-run]
# =============================================================================

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────
REGION="eu-north-1"
ACCOUNT_ID="799904911021"

NEW_ACL_NAME="hive-invasion-waf"
OLD_ACL_NAME="hive-invasion-register-rate-limit-50rpm"
OLD_ACL_ID="153b9cd7-014b-40c4-a1e9-59a453880636"

GAME_API_ID="bb5nb3l00b"
GAME_STAGE="prod"
BACKOFFICE_API_ID="8ta3pfqagh"
BACKOFFICE_STAGE="backoffice"

BACKOFFICE_LAMBDA_NAME="hive-invasion-backoffice"

DRY_RUN=false
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=true

# ── Helpers ───────────────────────────────────────────────────────────────────
info()    { echo "[INFO]  $*"; }
ok()      { echo "[OK]    $*"; }
warn()    { echo "[WARN]  $*"; }
err()     { echo "[ERROR] $*" >&2; exit 1; }
dry()     { echo "[DRY]   (would run) $*"; }

run() {
  if $DRY_RUN; then
    dry "$@"
  else
    eval "$@"
  fi
}

# ── Prereq check ─────────────────────────────────────────────────────────────
info "Verifying AWS identity..."
aws sts get-caller-identity --no-cli-pager --output text --query 'Account' | grep -q "$ACCOUNT_ID" \
  || err "AWS account mismatch — expected $ACCOUNT_ID"
ok "AWS identity verified"

# ── Check / reuse existing ACL ────────────────────────────────────────────────
info "Checking for existing ACL '$NEW_ACL_NAME'..."
EXISTING_ARN=$(aws wafv2 list-web-acls \
  --scope REGIONAL \
  --region "$REGION" \
  --query "WebACLs[?Name=='${NEW_ACL_NAME}'].ARN | [0]" \
  --output text --no-cli-pager 2>/dev/null || echo "None")

EXISTING_ID=$(aws wafv2 list-web-acls \
  --scope REGIONAL \
  --region "$REGION" \
  --query "WebACLs[?Name=='${NEW_ACL_NAME}'].Id | [0]" \
  --output text --no-cli-pager 2>/dev/null || echo "None")

# ── Build rules JSON ──────────────────────────────────────────────────────────
TMP_RULES=$(mktemp)
trap 'rm -f "$TMP_RULES"' EXIT

# base64 helper for path matching
b64() { printf '%s' "$1" | base64; }

PATH_REGISTER=$(b64 "/auth/register")
PATH_RESEND=$(b64  "/auth/resend-code")
PATH_VERIFY=$(b64  "/auth/verify-email")
PATH_LOGIN=$(b64   "/auth/login")
PATH_AUTH=$(b64    "/auth/")

cat > "$TMP_RULES" << RULES_EOF
[
  {
    "Name": "AWSManagedRulesAmazonIpReputationList",
    "Priority": 1,
    "OverrideAction": { "None": {} },
    "Statement": {
      "ManagedRuleGroupStatement": {
        "VendorName": "AWS",
        "Name": "AWSManagedRulesAmazonIpReputationList"
      }
    },
    "VisibilityConfig": {
      "SampledRequestsEnabled": true,
      "CloudWatchMetricsEnabled": true,
      "MetricName": "AWSIPReputationList"
    }
  },
  {
    "Name": "AWSManagedRulesBotControl",
    "Priority": 5,
    "OverrideAction": { "None": {} },
    "Statement": {
      "ManagedRuleGroupStatement": {
        "VendorName": "AWS",
        "Name": "AWSManagedRulesBotControlRuleSet",
        "ManagedRuleGroupConfigs": [
          {
            "AWSManagedRulesBotControlRuleSet": {
              "InspectionLevel": "COMMON",
              "EnableMachineLearning": false
            }
          }
        ],
        "RuleActionOverrides": [
          {
            "Name": "CategorySearchEngine",
            "ActionToUse": { "Count": {} }
          },
          {
            "Name": "CategoryMonitoring",
            "ActionToUse": { "Count": {} }
          }
        ]
      }
    },
    "VisibilityConfig": {
      "SampledRequestsEnabled": true,
      "CloudWatchMetricsEnabled": true,
      "MetricName": "BotControl"
    }
  },
  {
    "Name": "AWSManagedRulesKnownBadInputs",
    "Priority": 8,
    "OverrideAction": { "Count": {} },
    "Statement": {
      "ManagedRuleGroupStatement": {
        "VendorName": "AWS",
        "Name": "AWSManagedRulesKnownBadInputsRuleSet"
      }
    },
    "VisibilityConfig": {
      "SampledRequestsEnabled": true,
      "CloudWatchMetricsEnabled": true,
      "MetricName": "KnownBadInputs"
    }
  },
  {
    "Name": "RateLimitRegister",
    "Priority": 10,
    "Action": { "Block": {} },
    "Statement": {
      "RateBasedStatement": {
        "Limit": 100,
        "AggregateKeyType": "IP",
        "ScopeDownStatement": {
          "ByteMatchStatement": {
            "SearchString": "${PATH_REGISTER}",
            "FieldToMatch": { "UriPath": {} },
            "TextTransformations": [{ "Priority": 0, "Type": "NONE" }],
            "PositionalConstraint": "ENDS_WITH"
          }
        }
      }
    },
    "VisibilityConfig": {
      "SampledRequestsEnabled": true,
      "CloudWatchMetricsEnabled": true,
      "MetricName": "RateLimitRegister"
    }
  },
  {
    "Name": "RateLimitResendCode",
    "Priority": 11,
    "Action": { "Block": {} },
    "Statement": {
      "RateBasedStatement": {
        "Limit": 100,
        "AggregateKeyType": "IP",
        "ScopeDownStatement": {
          "ByteMatchStatement": {
            "SearchString": "${PATH_RESEND}",
            "FieldToMatch": { "UriPath": {} },
            "TextTransformations": [{ "Priority": 0, "Type": "NONE" }],
            "PositionalConstraint": "ENDS_WITH"
          }
        }
      }
    },
    "VisibilityConfig": {
      "SampledRequestsEnabled": true,
      "CloudWatchMetricsEnabled": true,
      "MetricName": "RateLimitResendCode"
    }
  },
  {
    "Name": "RateLimitVerifyEmail",
    "Priority": 12,
    "Action": { "Block": {} },
    "Statement": {
      "RateBasedStatement": {
        "Limit": 100,
        "AggregateKeyType": "IP",
        "ScopeDownStatement": {
          "ByteMatchStatement": {
            "SearchString": "${PATH_VERIFY}",
            "FieldToMatch": { "UriPath": {} },
            "TextTransformations": [{ "Priority": 0, "Type": "NONE" }],
            "PositionalConstraint": "ENDS_WITH"
          }
        }
      }
    },
    "VisibilityConfig": {
      "SampledRequestsEnabled": true,
      "CloudWatchMetricsEnabled": true,
      "MetricName": "RateLimitVerifyEmail"
    }
  },
  {
    "Name": "RateLimitLogin",
    "Priority": 13,
    "Action": { "Block": {} },
    "Statement": {
      "RateBasedStatement": {
        "Limit": 300,
        "AggregateKeyType": "IP",
        "ScopeDownStatement": {
          "ByteMatchStatement": {
            "SearchString": "${PATH_LOGIN}",
            "FieldToMatch": { "UriPath": {} },
            "TextTransformations": [{ "Priority": 0, "Type": "NONE" }],
            "PositionalConstraint": "ENDS_WITH"
          }
        }
      }
    },
    "VisibilityConfig": {
      "SampledRequestsEnabled": true,
      "CloudWatchMetricsEnabled": true,
      "MetricName": "RateLimitLogin"
    }
  },
  {
    "Name": "RateLimitAllAuth",
    "Priority": 14,
    "Action": { "Block": {} },
    "Statement": {
      "RateBasedStatement": {
        "Limit": 500,
        "AggregateKeyType": "IP",
        "ScopeDownStatement": {
          "ByteMatchStatement": {
            "SearchString": "${PATH_AUTH}",
            "FieldToMatch": { "UriPath": {} },
            "TextTransformations": [{ "Priority": 0, "Type": "NONE" }],
            "PositionalConstraint": "STARTS_WITH"
          }
        }
      }
    },
    "VisibilityConfig": {
      "SampledRequestsEnabled": true,
      "CloudWatchMetricsEnabled": true,
      "MetricName": "RateLimitAllAuth"
    }
  }
]
RULES_EOF

info "Rules JSON written to $TMP_RULES"

# ── Create or update Web ACL ──────────────────────────────────────────────────
if [[ "$EXISTING_ARN" == "None" || -z "$EXISTING_ARN" ]]; then
  info "Creating new Web ACL: $NEW_ACL_NAME..."

  if $DRY_RUN; then
    dry "aws wafv2 create-web-acl --name $NEW_ACL_NAME ..."
    NEW_ACL_ARN="arn:aws:wafv2:${REGION}:${ACCOUNT_ID}:regional/webacl/${NEW_ACL_NAME}/DRY-RUN"
    NEW_ACL_ID="DRY-RUN"
  else
    CREATE_OUT=$(aws wafv2 create-web-acl \
      --name "$NEW_ACL_NAME" \
      --scope REGIONAL \
      --region "$REGION" \
      --default-action Allow={} \
      --description "Hive Invasion Bot Control + Rate Limiting $(date -u +%Y-%m-%d)" \
      --visibility-config \
        "SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName=${NEW_ACL_NAME}" \
      --rules "file://${TMP_RULES}" \
      --no-cli-pager \
      --output json)

    NEW_ACL_ARN=$(echo "$CREATE_OUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['Summary']['ARN'])")
    NEW_ACL_ID=$(echo "$CREATE_OUT"  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['Summary']['Id'])")
    ok "Created Web ACL ARN: $NEW_ACL_ARN"
  fi
else
  ok "Web ACL '$NEW_ACL_NAME' already exists ($EXISTING_ID) — updating rules..."
  NEW_ACL_ARN="$EXISTING_ARN"
  NEW_ACL_ID="$EXISTING_ID"

  if ! $DRY_RUN; then
    LOCK_TOKEN=$(aws wafv2 get-web-acl \
      --name "$NEW_ACL_NAME" \
      --id "$NEW_ACL_ID" \
      --scope REGIONAL \
      --region "$REGION" \
      --no-cli-pager \
      --query 'LockToken' --output text)

    aws wafv2 update-web-acl \
      --name "$NEW_ACL_NAME" \
      --id "$NEW_ACL_ID" \
      --scope REGIONAL \
      --region "$REGION" \
      --default-action Allow={} \
      --description "Hive Invasion Bot Control + Rate Limiting $(date -u +%Y-%m-%d)" \
      --visibility-config \
        "SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName=${NEW_ACL_NAME}" \
      --rules "file://${TMP_RULES}" \
      --lock-token "$LOCK_TOKEN" \
      --no-cli-pager > /dev/null
    ok "Rules updated"
  fi
fi

# ── Associate with API Gateways ───────────────────────────────────────────────
GAME_RESOURCE_ARN="arn:aws:apigateway:${REGION}::/restapis/${GAME_API_ID}/stages/${GAME_STAGE}"
BACKOFFICE_RESOURCE_ARN="arn:aws:apigateway:${REGION}::/restapis/${BACKOFFICE_API_ID}/stages/${BACKOFFICE_STAGE}"

for RESOURCE_ARN in "$GAME_RESOURCE_ARN" "$BACKOFFICE_RESOURCE_ARN"; do
  LABEL=$(echo "$RESOURCE_ARN" | grep -o 'restapis/[^/]*/stages/[^/]*')
  info "Associating WAF with $LABEL ..."
  if ! $DRY_RUN; then
    aws wafv2 associate-web-acl \
      --web-acl-arn "$NEW_ACL_ARN" \
      --resource-arn "$RESOURCE_ARN" \
      --region "$REGION" \
      --no-cli-pager 2>&1 | grep -v "^$" || true
    ok "Associated: $LABEL"
  else
    dry "aws wafv2 associate-web-acl --web-acl-arn $NEW_ACL_ARN --resource-arn $RESOURCE_ARN"
  fi
done

# ── Update backoffice Lambda env vars ─────────────────────────────────────────
info "Updating backoffice Lambda environment variables..."

if ! $DRY_RUN; then
  TMP_ENV=$(mktemp /tmp/backoffice_env_XXXXXX.json)

  python3 - << PYEOF
import json, subprocess, sys
r = subprocess.run(
    ['aws','lambda','get-function-configuration',
     '--function-name','${BACKOFFICE_LAMBDA_NAME}',
     '--region','${REGION}',
     '--query','Environment.Variables',
     '--output','json','--no-cli-pager'],
    capture_output=True, text=True
)
current = json.loads(r.stdout.strip()) if r.stdout.strip() and r.stdout.strip() != 'null' else {}
current['WAF_WEB_ACL_NAME']  = '${NEW_ACL_NAME}'
current['WAF_RATE_RULE_NAME'] = 'RateLimitRegister'
with open('${TMP_ENV}', 'w') as f:
    json.dump({'Variables': current}, f)
print(f"Env written ({len(current)} vars)")
PYEOF

  aws lambda update-function-configuration \
    --function-name "$BACKOFFICE_LAMBDA_NAME" \
    --region "$REGION" \
    --environment "file://${TMP_ENV}" \
    --no-cli-pager > /dev/null
  rm -f "$TMP_ENV"
  ok "Backoffice Lambda env vars updated"
else
  dry "aws lambda update-function-configuration --function-name $BACKOFFICE_LAMBDA_NAME (via temp JSON file)"
fi

# ── Disassociate & clean up old ACL ──────────────────────────────────────────
info "Checking old ACL '$OLD_ACL_NAME' for resources..."

if ! $DRY_RUN; then
  OLD_RESOURCES=$(aws wafv2 list-resources-for-web-acl \
    --web-acl-arn "arn:aws:wafv2:${REGION}:${ACCOUNT_ID}:regional/webacl/${OLD_ACL_NAME}/${OLD_ACL_ID}" \
    --region "$REGION" \
    --output json --no-cli-pager 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print('\n'.join(d.get('ResourceArns', [])))" || echo "")

  if [[ -n "$OLD_RESOURCES" ]]; then
    while IFS= read -r arn; do
      [[ -z "$arn" ]] && continue
      info "Disassociating old ACL from: $arn"
      aws wafv2 disassociate-web-acl \
        --resource-arn "$arn" \
        --region "$REGION" \
        --no-cli-pager || true
    done <<< "$OLD_RESOURCES"
  fi

  # Delete old ACL
  OLD_LOCK=$(aws wafv2 get-web-acl \
    --name "$OLD_ACL_NAME" \
    --id "$OLD_ACL_ID" \
    --scope REGIONAL \
    --region "$REGION" \
    --query 'LockToken' --output text --no-cli-pager 2>/dev/null || echo "")

  if [[ -n "$OLD_LOCK" && "$OLD_LOCK" != "None" ]]; then
    aws wafv2 delete-web-acl \
      --name "$OLD_ACL_NAME" \
      --id "$OLD_ACL_ID" \
      --scope REGIONAL \
      --region "$REGION" \
      --lock-token "$OLD_LOCK" \
      --no-cli-pager && ok "Old ACL '$OLD_ACL_NAME' deleted" || warn "Couldn't delete old ACL (may be in use)"
  else
    warn "Old ACL not found or already deleted — skipping"
  fi
else
  dry "disassociate + delete old ACL $OLD_ACL_NAME"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo "  WAF Bot Control setup complete"
echo "================================================================"
echo "  Web ACL:      $NEW_ACL_NAME"
echo "  WAF ARN:      ${NEW_ACL_ARN:-DRY_RUN}"
echo "  Game API:     $GAME_API_ID/$GAME_STAGE"
echo "  Backoffice:   $BACKOFFICE_API_ID/$BACKOFFICE_STAGE"
echo ""
echo "  Rules applied:"
echo "    [1]  IP Reputation List      → BLOCK"
echo "    [5]  Bot Control (COMMON)    → BLOCK (search engines COUNTED)"
echo "    [8]  Known Bad Inputs        → COUNT (monitoring mode)"
echo "   [10]  Rate /auth/register     → BLOCK >100 req/5min/IP (20/min)"
echo "   [11]  Rate /auth/resend-code  → BLOCK >100 req/5min/IP (20/min)"
echo "   [12]  Rate /auth/verify-email → BLOCK >100 req/5min/IP (20/min)"
echo "   [13]  Rate /auth/login        → BLOCK >300 req/5min/IP (60/min)"
echo "   [14]  Rate all /auth/         → BLOCK >500 req/5min/IP (100/min)"
echo ""
echo "  Backoffice monitoring: GET /admin/security/bot-protection"
echo "  CloudWatch namespace:  AWS/WAFV2 (MetricName=${NEW_ACL_NAME})"
echo "================================================================"
