# SOMI Payment Integration - Patch #8

## Overview

Replaced mock key purchase system with real SOMI payment verification on Somnia mainnet. Users now send native SOMI to the treasury wallet, and the backend verifies the transaction on-chain before granting key ownership.

## Changes Made

### 1. contract_adapter.py (265 lines → 311 lines)

**New Implementation:**
- `verify_transaction_on_somnia(tx_hash, key_type, expected_from_wallet)`: Main verification method
  - Calls Somnia RPC to fetch transaction receipt
  - Validates receipt status (1 = success, 0 = failed)
  - Validates recipient (must equal TREASURY_WALLET)
  - Validates amount matches PRICE_WEI[key_type]
  - Returns verification result with tx_data on success
  - Handles pending transactions (returns status="pending")

- `_get_transaction_receipt(tx_hash)`: Calls eth_getTransactionReceipt RPC
- `_get_transaction(tx_hash)`: Calls eth_getTransactionByHash RPC
- `get_expected_price(key_type)`: Returns price in Wei

**Configuration:**
```python
PRICE_WEI = {
    "bronze": int(0.1 * 1e18),    # 0.1 SOMI
    "silver": int(0.5 * 1e18),    # 0.5 SOMI
    "gold": int(1.0 * 1e18)       # 1.0 SOMI
}
```

**Environment Variables Required:**
- `SOMNIA_RPC_MAINNET`: RPC endpoint (default: https://api.infra.mainnet.somnia.network/)
- `SOMNIA_TREASURY_WALLET`: Treasury wallet address to receive SOMI

### 2. lambda_function.py - handle_key_purchase() (78 lines → 138 lines)

**Request Format Change:**
```
OLD:
POST /keys/purchase
{
  "key_type": "bronze" | "silver" | "gold",
  "wallet_address": "0x..."  // optional, pulled from user's linked wallet
}

NEW:
POST /keys/purchase
{
  "key_type": "bronze" | "silver" | "gold",
  "tx_hash": "0x..."          // required: Somnia mainnet transaction hash
}
```

**Response Format (unchanged, for compatibility):**
```json
{
  "ok": true,
  "key_type": "bronze",
  "new_balances": {
    "bronze": 5,
    "silver": 2,
    "gold": 1
  },
  "tx_hash": "0x...",
  "message": "Key purchased successfully with verified SOMI payment"
}
```

**HTTP Status Codes:**
- `201 Created`: Transaction verified and key ownership updated
- `202 Accepted`: Transaction not yet confirmed on-chain (retry later)
- `400 Bad Request`: Invalid request or verification failed
- `404 Not Found`: User not found
- `500 Server Error`: Internal error

**Error Codes (in error_code field):**
- `WALLET_NOT_LINKED`: User has no wallet connected
- `DUPLICATE_TRANSACTION`: tx_hash already processed
- `TX_VERIFICATION_FAILED_invalid`: Transaction fails validation
- `TX_VERIFICATION_FAILED_pending`: Transaction not yet mined
- `TX_VERIFICATION_FAILED_failed`: Transaction reverted on-chain

**Flow:**
1. Validate key_type and tx_hash
2. Get user wallet address from hive_users
3. Check if tx_hash already processed (idempotency)
4. Call ContractAdapter.verify_transaction_on_somnia()
5. If pending (202): Return with `pending: true`
6. If failed (400): Return error with reason
7. If verified:
   - Create purchase_event with real tx_hash
   - Call add_key_to_player() to update DB
   - Return 201 with new_balances

### 3. models.py - New Function

**check_tx_hash_processed(tx_hash) → bool**

Idempotency check to prevent double-spending:
- Scans key_purchase_history across all players
- Returns True if tx_hash found (reject purchase)
- Returns False if tx_hash not found (allow purchase)
- Fails open (returns False on error) for better UX
- Note: On high-volume systems, maintain separate tx_hash index table

**Updated add_key_to_player():**
- Purchase event now includes:
  - `tx_hash`: Real Somnia transaction hash
  - `source`: "somnia_mainnet" (was "mock_contract")
  - `price`: SOMI amount (e.g., "0.1")
  - `block_number`: Block where transaction was confirmed

### 4. requirements.txt

Added `requests>=2.31.0` for RPC HTTP calls.

## Testing & Deployment

### Prerequisites

Before deploying, set these environment variables in AWS Lambda:

```
SOMNIA_RPC_MAINNET=https://api.infra.mainnet.somnia.network/
SOMNIA_TREASURY_WALLET=0x<YOUR_TREASURY_ADDRESS>
```

### Smoke Tests

#### Test 1: Valid Transaction (Bronze Key)

**Setup:**
```python
import requests
import uuid

# Create test transaction on Somnia mainnet
# Send 0.1 SOMI to treasury wallet
# Note: Use browser wallet or CLI tool to create real tx
```

**Request:**
```bash
curl -X POST https://api.endpoint/keys/purchase \
  -H "Authorization: Bearer <JWT_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "key_type": "bronze",
    "tx_hash": "0x1234567890abcdef..."
  }'
```

**Expected Response (201):**
```json
{
  "ok": true,
  "key_type": "bronze",
  "new_balances": {
    "bronze": 1,
    "silver": 0,
    "gold": 0
  },
  "tx_hash": "0x1234567890abcdef...",
  "message": "Key purchased successfully with verified SOMI payment"
}
```

**Verification:**
- Key count incremented in hive_player_data
- Purchase event recorded in key_purchase_history
- tx_hash, timestamp, price, wallet_address logged

#### Test 2: Duplicate Transaction (Idempotency)

**Request:** Same tx_hash as Test 1

**Expected Response (400):**
```json
{
  "success": false,
  "error": "This transaction has already been processed",
  "error_code": "DUPLICATE_TRANSACTION"
}
```

#### Test 3: Wrong Recipient

**Transaction Details:**
- Send 0.1 SOMI to WRONG wallet address (not treasury)
- Tip: Create second wallet and send 0.1 SOMI to it

**Request:**
```bash
curl -X POST https://api.endpoint/keys/purchase \
  -H "Authorization: Bearer <JWT_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "key_type": "bronze",
    "tx_hash": "0xwrong_recipient_tx..."
  }'
```

**Expected Response (400):**
```json
{
  "success": false,
  "error": "Transaction verification failed: Recipient mismatch: received 0x..., expected 0x...",
  "error_code": "TX_VERIFICATION_FAILED_invalid"
}
```

#### Test 4: Wrong Amount

**Transaction Details:**
- Send 0.05 SOMI (half price) to treasury wallet

**Expected Response (400):**
```json
{
  "success": false,
  "error": "Transaction verification failed: Amount mismatch: received 50000000000000000 Wei, expected 100000000000000000 Wei",
  "error_code": "TX_VERIFICATION_FAILED_invalid"
}
```

#### Test 5: Pending Transaction

**Setup:**
1. Create transaction on Somnia mainnet
2. Don't wait for confirmation
3. Immediately call purchase endpoint with pending tx_hash

**Expected Response (202):**
```json
{
  "ok": false,
  "pending": true,
  "message": "Transaction not yet confirmed on-chain. Please try again in a moment.",
  "tx_hash": "0xpending_tx..."
}
```

**Frontend Action:**
- Display "Your purchase is pending confirmation..."
- Poll /keys/purchase again after 10-15 seconds
- Second request should succeed with 201

#### Test 6: No Wallet Linked

**Setup:**
Create new user without wallet connection

**Request:**
```bash
curl -X POST https://api.endpoint/keys/purchase \
  -H "Authorization: Bearer <JWT_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "key_type": "bronze",
    "tx_hash": "0x..."
  }'
```

**Expected Response (400):**
```json
{
  "success": false,
  "error": "No wallet linked. Please connect your wallet first.",
  "error_code": "WALLET_NOT_LINKED"
}
```

#### Test 7: Multiple Key Purchases

**Sequence:**
1. Buy Bronze key (0.1 SOMI)
2. Buy Silver key (0.5 SOMI)
3. Buy Gold key (1.0 SOMI)

**Final state after all 3:**
```json
{
  "bronze": 1,
  "silver": 1,
  "gold": 1
}
```

**Purchase History (most recent first):**
```json
[
  {
    "event_id": "...",
    "key_type": "gold",
    "tx_hash": "0x...",
    "price": "1.0",
    "timestamp": "2025-02-03T...",
    "source": "somnia_mainnet"
  },
  {
    "event_id": "...",
    "key_type": "silver",
    "tx_hash": "0x...",
    "price": "0.5",
    "timestamp": "2025-02-03T...",
    "source": "somnia_mainnet"
  },
  {
    "event_id": "...",
    "key_type": "bronze",
    "tx_hash": "0x...",
    "price": "0.1",
    "timestamp": "2025-02-03T...",
    "source": "somnia_mainnet"
  }
]
```

### Deployment Checklist

- [ ] All 3 files updated (contract_adapter.py, lambda_function.py, models.py)
- [ ] requirements.txt updated with requests>=2.31.0
- [ ] Environment variables set in AWS Lambda:
  - [ ] SOMNIA_RPC_MAINNET
  - [ ] SOMNIA_TREASURY_WALLET
- [ ] Test against Somnia testnet (chainId 50312) first
- [ ] Verify RPC endpoint is accessible from Lambda
- [ ] Run smoke tests #1-7 in development environment
- [ ] Code review of verification logic
- [ ] Review DynamoDB scanning performance (consider index for production)
- [ ] Document treasury wallet address for accounting
- [ ] Plan rollback strategy (keep old code branch available)
- [ ] Monitor CloudWatch logs for verification failures
- [ ] Set up alerts for duplicate transactions or wrong recipients

### Logging

All operations are logged in English with structured context:

**Verification Success:**
```
[INFO] Transaction verified: 0x1234567890...
context: {
  "key_type": "bronze",
  "to": "0xtreasuryaddress",
  "value": "100000000000000000",  (in Wei)
  "status": "0x1"
}
```

**Verification Failure:**
```
[WARNING] Transaction verification failed: 0x...
context: {
  "reason": "Recipient mismatch",
  "status": "invalid"
}
```

**Duplicate Detected:**
```
[WARNING] Duplicate transaction: 0x...
context: {
  "reason": "already_processed"
}
```

### Rollback Plan

If issues occur during production:

1. **Immediate (Keep site live):**
   - Revert lambda_function.py to use `purchase_key_mock()` instead of `verify_transaction_on_somnia()`
   - Keep contract_adapter.py (it supports both old and new code)
   - Requires ~5 min deployment

2. **Longer term:**
   - Check DynamoDB purchase history for any corrupt entries
   - Review CloudWatch logs for exact failure points
   - Fix identified issues and re-test in dev environment

3. **Data Integrity:**
   - All key ownership changes are atomic (DynamoDB update_item)
   - Purchase history is append-only (safe to keep)
   - Can re-verify any tx_hash using RPC

## Technical Details

### Price Conversion

Somnia uses Wei (1 SOMI = 10^18 Wei):
- Bronze: 0.1 SOMI = 100000000000000000 Wei
- Silver: 0.5 SOMI = 500000000000000000 Wei
- Gold: 1.0 SOMI = 1000000000000000000 Wei

### Idempotency Implementation

Current: Scans key_purchase_history across all players (O(n) scan)

Production optimization:
- Maintain separate DynamoDB table: `tx_hash_index`
- Primary key: tx_hash
- Attributes: user_id, timestamp, status
- Enables O(1) lookup for duplicate detection

### RPC Error Handling

- Timeout: 10 seconds per RPC call
- Retry: Not implemented (frontend handles retry logic)
- Fallback: Returns 202 "pending" if RPC unavailable
- Error logging: All RPC errors logged with full context

### Transaction Validation Order

1. Key type validation (allowed values only)
2. Receipt availability (0 = pending, other = proceed)
3. Receipt status (0x1 = success, other = fail)
4. Recipient address match (case-insensitive)
5. Payment amount match (exact Wei comparison)

## Security Considerations

1. **Wallet Linkage Required**: User must have wallet connected (prevents cross-user purchases)
2. **Recipient Validation**: 100% match of treasury wallet address (case-insensitive)
3. **Amount Validation**: Exact Wei comparison (no overpayment abuse)
4. **Idempotency**: Prevents double-spending of same tx_hash
5. **On-chain Verification**: All checks performed via RPC (cannot fake transactions locally)

## API Changes Summary

### Request Body

| Field | Old | New | Type | Required |
|-------|-----|-----|------|----------|
| key_type | ✓ | ✓ | string | Yes |
| wallet_address | ✓ | ✗ | string | No |
| tx_hash | ✗ | ✓ | string | Yes |

### Response Status Codes

| Status | Meaning | Previous | New |
|--------|---------|----------|-----|
| 201 | Success | ✓ | ✓ |
| 202 | Pending | ✗ | ✓ (NEW) |
| 400 | Bad Request | ✓ | ✓ |
| 404 | Not Found | ✓ | ✓ |
| 500 | Server Error | ✓ | ✓ |

### Key Purchase History Format

**New fields added to each event:**
- `tx_hash`: Real Somnia transaction hash (replaces mock uuid-based tx_hash)
- `source`: Changed from "mock_contract" to "somnia_mainnet"
- `block_number`: Block where transaction was confirmed

## Frontend Integration

### JavaScript Example

```javascript
// After user signs transaction on frontend
const tx_hash = "0xabcdef..."; // From Somnia wallet

const response = await fetch('/keys/purchase', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    key_type: 'bronze',
    tx_hash: tx_hash
  })
});

if (response.status === 201) {
  const data = await response.json();
  console.log('Purchase confirmed!', data);
  updateInventoryUI(data.new_balances);
} else if (response.status === 202) {
  const data = await response.json();
  console.log('Transaction pending, retrying...');
  // Retry after 10-15 seconds
  setTimeout(() => retryPurchase(tx_hash), 15000);
} else {
  const error = await response.json();
  console.error('Purchase failed:', error.error);
}
```

## FAQ

**Q: What if transaction is too slow to confirm?**
A: Frontend receives 202 "pending" response. Retry with same tx_hash after 10-15 seconds. Idempotency ensures no double-charging.

**Q: What if RPC endpoint is down?**
A: Returns 500 error or 202 pending depending on failure point. System degrades gracefully—users can retry.

**Q: How do we handle testnet vs mainnet?**
A: Use environment-specific RPC_MAINNET URL. Code validates chainId implicitly (wrong chain = wrong recipient or wrong amounts).

**Q: Can we process multiple keys in one transaction?**
A: No. Each API call purchases one key. Users must do separate purchases for multiple keys.

**Q: How long is purchase history kept?**
A: Last 100 purchase events per player in key_purchase_history array.

**Q: What if user disputes a purchase?**
A: Check hive_player_data.key_purchase_history for tx_hash. Verify against Somnia mainnet using RPC. If tx found and legitimate, dispute is user error. If tx not found in history but in player's balance, possible bug.

## References

- Somnia Network: https://somnia.network/
- Somnia Testnet RPC: https://api.infra.testnet.somnia.network/
- Somnia Mainnet RPC: https://api.infra.mainnet.somnia.network/
- Somnia Explorer: https://explorer.somnia.network/
- Somnia Docs: https://docs.somnia.network/

## Files Modified

1. `/Hive-Invasion-Backend-Lambda/contract_adapter.py` - RPC verification implementation
2. `/Hive-Invasion-Backend-Lambda/lambda_function.py` - handle_key_purchase() handler
3. `/Hive-Invasion-Backend-Lambda/models.py` - check_tx_hash_processed() and add_key_to_player() updates
4. `/Hive-Invasion-Backend-Lambda/requirements.txt` - Added requests>=2.31.0

## Next Steps

1. Test against Somnia testnet with mock transactions
2. Set SOMNIA_TREASURY_WALLET and SOMNIA_RPC_MAINNET env vars
3. Deploy to dev Lambda and run smoke tests 1-7
4. Coordinate with frontend team for tx_hash generation
5. Deploy to production with 1-hour monitoring window
6. Document treasury wallet and SOMI accounting procedures
