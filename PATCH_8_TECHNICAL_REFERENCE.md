# Patch #8 - Technical Reference & API Specification

## Architecture Overview

### Before (Mock System)
```
Frontend              Backend                DynamoDB
   |                    |                        |
   ├─ POST /keys/purchase
   |    {key_type, wallet_address}
   |                    |
   |              generate_mock_tx_hash()
   |              (uuid-based, fake)
   |                    |
   |              add_key_to_player()────────────────► UPDATE keys_owned
   |                    |                              UPDATE key_purchase_history
   |                    |
   |◄── 201 {tx_hash, new_balances}
   |
   └─ Display "Purchase confirmed"
```

### After (Real SOMI)
```
Frontend (Somnia Wallet)     Backend (Lambda)          Somnia RPC           DynamoDB
         |                          |                        |                  |
         ├─ User sends 0.1 SOMI
         |  to treasury
         |
         ├─ Get tx_hash
         |
         ├─ POST /keys/purchase
         |  {key_type, tx_hash}
         |                          |
         |                   check_tx_hash_processed()
         |                   (scan history)
         |                          |
         |                   verify_transaction_on_somnia()
         |                          |
         |                          ├─ eth_getTransactionReceipt────────► {status: 0x1, ...}
         |                          |
         |                          ├─ eth_getTransactionByHash────────► {to, from, value, ...}
         |                          |
         |                          ├─ Validate:
         |                          |  • receipt.status == 0x1 ✓
         |                          |  • tx.to == treasury ✓
         |                          |  • tx.value == 0.1 SOMI in Wei ✓
         |                          |
         |                          ├─ add_key_to_player()───────────────► UPDATE keys_owned
         |                          |                                      UPDATE key_purchase_history
         |                          |
         |◄────────────────── 201 {tx_hash, new_balances}
         |
         └─ Display "Key purchased! Tx verified on Somnia"
```

## API Endpoint Specification

### POST /keys/purchase

**Summary:** Purchase a game key with verified SOMI payment

**Authentication:** Required (Bearer token)

**Request Body:**
```json
{
  "key_type": "bronze|silver|gold",
  "tx_hash": "0x..."
}
```

**Response: 201 Created**
```json
{
  "ok": true,
  "key_type": "bronze",
  "new_balances": {
    "bronze": 5,
    "silver": 2,
    "gold": 1
  },
  "tx_hash": "0x1234567890abcdef...",
  "message": "Key purchased successfully with verified SOMI payment"
}
```

**Response: 202 Accepted (Pending)**
```json
{
  "ok": false,
  "pending": true,
  "message": "Transaction not yet confirmed on-chain. Please try again in a moment.",
  "tx_hash": "0x..."
}
```

**Response: 400 Bad Request (Duplicate)**
```json
{
  "success": false,
  "error": "This transaction has already been processed",
  "error_code": "DUPLICATE_TRANSACTION"
}
```

**Response: 400 Bad Request (Verification Failed)**
```json
{
  "success": false,
  "error": "Transaction verification failed: Recipient mismatch: received 0x..., expected 0x...",
  "error_code": "TX_VERIFICATION_FAILED_invalid"
}
```

**Response: 400 Bad Request (Wallet Not Linked)**
```json
{
  "success": false,
  "error": "No wallet linked. Please connect your wallet first.",
  "error_code": "WALLET_NOT_LINKED"
}
```

**Response: 404 Not Found**
```json
{
  "success": false,
  "error": "User not found",
  "error_code": "USER_NOT_FOUND"
}
```

**Response: 500 Server Error**
```json
{
  "success": false,
  "error": "Internal server error"
}
```

## Data Models

### Purchase Event (Stored in DynamoDB)

```json
{
  "event_id": "550e8400-e29b-41d4-a716-446655440000",
  "user_id": "user-uuid",
  "wallet_address": "0xabcdef1234567890...",
  "key_type": "bronze",
  "timestamp": "2025-02-03T15:30:45.123456Z",
  "tx_hash": "0x1234567890abcdef...",
  "status": "confirmed",
  "price": "0.1",
  "source": "somnia_mainnet",
  "block_number": 12345678
}
```

### Key Ownership (Stored in hive_player_data)

```json
{
  "user_id": "user-uuid",
  "keys_owned": {
    "bronze": 5,
    "silver": 2,
    "gold": 1
  },
  "key_purchase_history": [
    { "event_id": "...", "key_type": "gold", "tx_hash": "0x...", "timestamp": "..." },
    { "event_id": "...", "key_type": "silver", "tx_hash": "0x...", "timestamp": "..." },
    { "event_id": "...", "key_type": "bronze", "tx_hash": "0x...", "timestamp": "..." }
  ]
}
```

## Price Mapping

| Key Type | SOMI | Wei | Hex |
|----------|------|-----|-----|
| bronze | 0.1 | 100000000000000000 | 0x16345785d8a0000 |
| silver | 0.5 | 500000000000000000 | 0x6f05b59d3b20000 |
| gold | 1.0 | 1000000000000000000 | 0xde0b6b3a7640000 |

## RPC Specification

### eth_getTransactionReceipt

**Purpose:** Get receipt of a completed transaction

**Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "eth_getTransactionReceipt",
  "params": ["0x1234567890abcdef..."],
  "id": 1
}
```

**Response (Success):**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "blockNumber": "0xbdd",
    "transactionHash": "0x1234567890abcdef...",
    "status": "0x1",
    "from": "0xuser...",
    "to": "0xtreasury...",
    "contractAddress": null,
    "cumulativeGasUsed": "0x1234",
    "gasUsed": "0x5678",
    "logs": []
  },
  "id": 1
}
```

**Response (Pending):**
```json
{
  "jsonrpc": "2.0",
  "result": null,
  "id": 1
}
```

### eth_getTransactionByHash

**Purpose:** Get transaction details

**Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "eth_getTransactionByHash",
  "params": ["0x1234567890abcdef..."],
  "id": 1
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "blockNumber": "0xbdd",
    "from": "0xuser...",
    "to": "0xtreasury...",
    "value": "0x16345785d8a0000",
    "gas": "0x5208",
    "gasPrice": "0x3b9aca00",
    "hash": "0x1234567890abcdef...",
    "input": "0x",
    "nonce": "0x2",
    "transactionIndex": "0x5"
  },
  "id": 1
}
```

## Verification Algorithm

```python
def verify_transaction_on_somnia(tx_hash, key_type, expected_from_wallet=None):
    # Step 1: Validate input
    if key_type not in PRICE_WEI:
        return {verified: False, status: "invalid", reason: "Invalid key type"}
    
    # Step 2: Get transaction receipt
    receipt = _get_transaction_receipt(tx_hash)
    if receipt is None:
        return {verified: False, status: "pending", reason: "Transaction not yet confirmed"}
    
    # Step 3: Check receipt status (0x1 = success)
    if receipt['status'] != '0x1':
        return {verified: False, status: "failed", reason: "Transaction failed on-chain"}
    
    # Step 4: Get full transaction details
    tx = _get_transaction(tx_hash)
    if tx is None:
        return {verified: False, status: "invalid", reason: "Could not retrieve transaction"}
    
    # Step 5: Verify recipient is treasury wallet
    if tx['to'].lower() != TREASURY_WALLET.lower():
        return {verified: False, status: "invalid", reason: "Recipient mismatch"}
    
    # Step 6: Verify amount matches expected price
    tx_value = int(tx['value'], 16)  # Convert hex to int
    expected_price = PRICE_WEI[key_type]
    if tx_value != expected_price:
        return {verified: False, status: "invalid", reason: "Amount mismatch"}
    
    # Step 7: All checks passed!
    return {
        verified: True,
        status: "success",
        reason: "Transaction verified and valid",
        tx_data: {
            to: tx['to'],
            from: tx['from'],
            value: str(tx_value),
            status: 1,
            blockNumber: int(receipt['blockNumber'], 16)
        }
    }
```

## Error Codes Reference

| Code | HTTP | Meaning | Frontend Action |
|------|------|---------|-----------------|
| WALLET_NOT_LINKED | 400 | User has no wallet connected | Show "Connect wallet" dialog |
| DUPLICATE_TRANSACTION | 400 | Transaction already processed | Show error, don't retry |
| TX_VERIFICATION_FAILED_invalid | 400 | Tx failed validation (amount/recipient) | Show error, don't retry |
| TX_VERIFICATION_FAILED_pending | 202 | Tx not yet mined | Retry after 15 seconds |
| TX_VERIFICATION_FAILED_failed | 400 | Tx reverted on-chain | Show error, user can retry |
| USER_NOT_FOUND | 404 | User record missing | Contact support |
| None (empty error) | 500 | Internal server error | Retry after 30 seconds |

## State Transitions

### Valid Purchase Flow
```
User Sends Tx
     ↓
Frontend Polls RPC
     ↓
Tx Appears in Mempool
     ↓
Miner Includes Tx
     ↓
Receipt Available (status 0x1)
     ↓
Frontend Calls /keys/purchase
     ↓
Backend Verifies All 5 Checks ✓
     ↓
DynamoDB Updated (keys_owned, history)
     ↓
Return 201 "Purchase confirmed"
     ↓
Frontend Displays Key in Inventory
```

### Pending Flow
```
Frontend Calls /keys/purchase
     ↓
Tx Not Yet Mined (receipt = null)
     ↓
Return 202 "Pending"
     ↓
Frontend Waits 10-15 seconds
     ↓
Frontend Retries with Same tx_hash
     ↓
Eventually Tx Appears → 201 Success
```

### Duplicate Detection Flow
```
First Purchase
   ↓
TX1 Verified & Recorded
   ↓
User Accidentally Retries with TX1
   ↓
check_tx_hash_processed(TX1) → True
   ↓
Return 400 "DUPLICATE_TRANSACTION"
   ↓
User's Balance NOT Changed
```

## Configuration

### Environment Variables

```bash
# Somnia RPC Endpoint
SOMNIA_RPC_MAINNET=https://api.infra.mainnet.somnia.network/

# Treasury Wallet Address (receives SOMI)
SOMNIA_TREASURY_WALLET=0x1234567890abcdef1234567890abcdef12345678

# Optional: Testnet for development
SOMNIA_RPC_TESTNET=https://api.infra.testnet.somnia.network/
SOMNIA_TESTNET_CHAIN_ID=50312  # vs 5031 for mainnet
```

### Lambda Configuration

- **Memory:** 256 MB (adequate for RPC calls)
- **Timeout:** 30 seconds (10s per RPC call, with buffer)
- **Layers:** boto3, requests, web3 (via requirements.txt)
- **VPC:** Not required (RPC is public HTTP)

## Performance Considerations

### Latency Breakdown

| Operation | Time | Notes |
|-----------|------|-------|
| Input validation | <1ms | Synchronous |
| check_tx_hash_processed() | 100-500ms | DynamoDB scan (first 100 users) |
| eth_getTransactionReceipt | 100-1000ms | RPC call to Somnia |
| eth_getTransactionByHash | 100-1000ms | RPC call to Somnia |
| Validation checks | <1ms | Local computation |
| add_key_to_player() | 10-100ms | DynamoDB update |
| **Total** | **300-2500ms** | Most requests <1s |

### Scalability Notes

**Current Bottleneck:** `check_tx_hash_processed()` scans key_purchase_history across all players

**At Scale (1M+ players):**
- Consider separate `tx_hash_index` table (DynamoDB global secondary index)
- Key: tx_hash, Value: user_id + timestamp
- Converts O(n) scan to O(1) lookup

**RPC Rate Limits:**
- Somnia infra endpoint: Unknown (likely very high)
- Timeout: 10 seconds per call
- Retry: None (frontend handles)

## Testing Checklist

### Unit Tests
- [ ] `verify_transaction_on_somnia()` with valid tx_hash
- [ ] `verify_transaction_on_somnia()` with invalid key type
- [ ] `verify_transaction_on_somnia()` with pending tx (receipt = null)
- [ ] `verify_transaction_on_somnia()` with failed receipt (status = 0x0)
- [ ] `verify_transaction_on_somnia()` with wrong recipient
- [ ] `verify_transaction_on_somnia()` with wrong amount
- [ ] `check_tx_hash_processed()` returns True for existing tx_hash
- [ ] `check_tx_hash_processed()` returns False for new tx_hash

### Integration Tests
- [ ] POST /keys/purchase with valid tx_hash → 201
- [ ] POST /keys/purchase with duplicate tx_hash → 400
- [ ] POST /keys/purchase with pending tx_hash → 202
- [ ] POST /keys/purchase with wrong amount tx_hash → 400
- [ ] POST /keys/purchase with no wallet linked → 400
- [ ] Verify DynamoDB keys_owned incremented
- [ ] Verify DynamoDB key_purchase_history updated
- [ ] Verify logs are in English

### E2E Tests (via testnet)
- [ ] User sends 0.1 SOMI → Gets bronze key
- [ ] User sends 0.5 SOMI → Gets silver key
- [ ] User sends 1.0 SOMI → Gets gold key
- [ ] User sends wrong amount → Gets rejected
- [ ] User sends to wrong address → Gets rejected
- [ ] Same tx_hash twice → Second gets rejected
- [ ] Pending tx → Retry succeeds

## Security

### Input Validation
- tx_hash: 0x-prefixed string, 66 characters (32 bytes)
- key_type: "bronze", "silver", or "gold" (lowercase)
- user_id: From JWT token (cannot be forged)

### Verification Integrity
- All checks performed on-chain via RPC (immutable)
- Cannot be bypassed locally
- Treasury wallet is immutable (hardcoded as env var)
- Price is immutable (hardcoded in PRICE_WEI)

### Idempotency
- Each tx_hash can only grant keys once
- Prevents double-spending attack
- Even if API called 10x with same tx_hash, user only gets key once

### Rate Limiting
- None implemented (handled at API Gateway level)
- DynamoDB writes: On-demand billing (scales automatically)

## Monitoring & Alerting

### Key Metrics

```
verification_success_rate = successful_purchases / total_attempts
verification_latency_p99 = percentile(latency, 99)
duplicate_rate = duplicate_attempts / total_attempts
wrong_recipient_attempts = attempts_with_wrong_to_address
wrong_amount_attempts = attempts_with_wrong_value
```

### CloudWatch Alarms

```
IF verification_success_rate < 95%
  THEN alert("Purchase verification failing")

IF verification_latency_p99 > 5000ms
  THEN alert("RPC latency degraded")

IF wrong_recipient_attempts > 10/hour
  THEN alert("Potential attack: wrong recipient")
```

## References

- Somnia Docs: https://docs.somnia.network/
- Somnia Mainnet Explorer: https://explorer.somnia.network/
- JSON-RPC Spec: https://www.jsonrpc.org/specification
- Ethereum RPC Methods: https://ethereum.org/en/developers/docs/apis/json-rpc/

---

**Last Updated:** February 3, 2025  
**Patch:** #8 - SOMI Payment Integration  
**Status:** Ready for Production
