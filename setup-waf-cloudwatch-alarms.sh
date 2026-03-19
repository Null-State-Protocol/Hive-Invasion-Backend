#!/bin/bash
# =============================================================================
# CloudWatch Alarms — WAF Bot Control Monitoring
# =============================================================================
# Creates alarms for:
#   1. High bot traffic (Bot Control blocks > threshold)
#   2. Auth rate limit hits (rapid signup/login attacks)
#   3. IP reputation blocks (bad actor IPs)
#   4. Overall WAF blocks spike
#
# Usage:
#   bash setup-waf-cloudwatch-alarms.sh [SNS_TOPIC_ARN]
#
# SNS_TOPIC_ARN is optional. If provided, alarms will send notifications there.
# =============================================================================

set -euo pipefail

REGION="eu-north-1"
ACL_NAME="hive-invasion-waf"
SNS_ARN="${1:-}"

info() { echo "[INFO]  $*"; }
ok()   { echo "[OK]    $*"; }

create_alarm() {
  local name="$1"
  local desc="$2"
  local metric="$3"
  local rule="$4"
  local threshold="$5"
  local period="${6:-300}"
  local eval_periods="${7:-2}"

  local alarm_actions=""
  if [[ -n "$SNS_ARN" ]]; then
    alarm_actions="--alarm-actions $SNS_ARN --ok-actions $SNS_ARN"
  fi

  aws cloudwatch put-metric-alarm \
    --alarm-name "$name" \
    --alarm-description "$desc" \
    --namespace "AWS/WAFV2" \
    --metric-name "$metric" \
    --dimensions \
      "Name=WebACL,Value=${ACL_NAME}" \
      "Name=Region,Value=${REGION}" \
      "Name=Rule,Value=${rule}" \
    --statistic Sum \
    --period "$period" \
    --evaluation-periods "$eval_periods" \
    --threshold "$threshold" \
    --comparison-operator GreaterThanOrEqualToThreshold \
    --treat-missing-data notBreaching \
    --region "$REGION" \
    --no-cli-pager \
    $alarm_actions \
    2>&1 | grep -v "^$" || true

  ok "Alarm created: $name"
}

info "Creating CloudWatch alarms for WAF ($ACL_NAME)..."

# ── Bot Control: high block count ─────────────────────────────────────────────
# Alarm if Bot Control blocks >= 50 requests in a 5-minute window (2x in a row)
create_alarm \
  "hive-waf-bot-control-blocks" \
  "High Bot Control blocks — possible bot attack on Hive Invasion" \
  "BlockedRequests" \
  "AWSManagedRulesBotControl" \
  50 300 2

# ── Auth register rate limit hits ─────────────────────────────────────────────
# Alarm if /auth/register rate limit triggers at all (any hit = suspicious)
create_alarm \
  "hive-waf-rate-limit-register" \
  "Rate limit hit on /auth/register — possible signup spam attack" \
  "BlockedRequests" \
  "RateLimitRegister" \
  1 300 1

# ── Resend-code rate limit ─────────────────────────────────────────────────────
create_alarm \
  "hive-waf-rate-limit-resend" \
  "Rate limit hit on /auth/resend-code — email verification abuse" \
  "BlockedRequests" \
  "RateLimitResendCode" \
  1 300 1

# ── IP Reputation blocks ───────────────────────────────────────────────────────
create_alarm \
  "hive-waf-ip-reputation-blocks" \
  "IP Reputation blocks — bad actor IPs attempting access" \
  "BlockedRequests" \
  "AWSManagedRulesAmazonIpReputationList" \
  20 300 2

# ── Total WAF blocks spike ─────────────────────────────────────────────────────
# Uses ALL rules (no Rule dimension = total)
aws cloudwatch put-metric-alarm \
  --alarm-name "hive-waf-total-blocks-spike" \
  --alarm-description "Total WAF blocks spike — review AWS WAF console" \
  --namespace "AWS/WAFV2" \
  --metric-name "BlockedRequests" \
  --dimensions \
    "Name=WebACL,Value=${ACL_NAME}" \
    "Name=Region,Value=${REGION}" \
    "Name=Rule,Value=ALL" \
  --statistic Sum \
  --period 300 \
  --evaluation-periods 2 \
  --threshold 200 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --treat-missing-data notBreaching \
  --region "$REGION" \
  --no-cli-pager \
  ${SNS_ARN:+--alarm-actions $SNS_ARN --ok-actions $SNS_ARN} \
  2>&1 | grep -v "^$" || true
ok "Alarm created: hive-waf-total-blocks-spike"

echo ""
echo "================================================================"
echo "  CloudWatch Alarms created"
echo "================================================================"
echo "  hive-waf-bot-control-blocks     >= 50 blocks/5min (x2)"
echo "  hive-waf-rate-limit-register    >= 1 block/5min  (x1)"
echo "  hive-waf-rate-limit-resend      >= 1 block/5min  (x1)"
echo "  hive-waf-ip-reputation-blocks   >= 20 blocks/5min (x2)"
echo "  hive-waf-total-blocks-spike     >= 200 blocks/5min (x2)"
if [[ -n "$SNS_ARN" ]]; then
  echo "  SNS notifications → $SNS_ARN"
else
  echo "  SNS: not configured (pass ARN as first arg to enable notifications)"
fi
echo "  View: https://${REGION}.console.aws.amazon.com/cloudwatch/home?region=${REGION}#alarmsV2:"
echo "================================================================"
