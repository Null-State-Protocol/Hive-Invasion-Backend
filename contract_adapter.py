"""
Contract Adapter - Somnia Network Payment Verification
This module verifies SOMI token transfers on Somnia mainnet via RPC.
"""

import uuid
import os
import requests
from datetime import datetime, timezone
from logger import logger


class ContractAdapter:
    """
    Somnia payment verification adapter.
    Verifies SOMI native transfers to treasury wallet via RPC.
    """
    
    # Somnia Treasury Wallet (case-insensitive, will be normalized)
    TREASURY_WALLET = os.environ.get("SOMNIA_TREASURY_WALLET", "0x0000000000000000000000000000000000000000").lower()
    
    # Somnia RPC Endpoints
    SOMNIA_RPC_MAINNET = os.environ.get("SOMNIA_RPC_MAINNET", "https://api.infra.mainnet.somnia.network/")
    SOMNIA_CHAIN_ID_MAINNET = 5031
    SOMNIA_CHAIN_ID_TESTNET = 50312
    
    # Key prices in Wei (1 SOMI = 10^18 Wei)
    PRICE_WEI = {
        "bronze": int(0.1 * 1e18),    # 0.1 SOMI
        "silver": int(0.5 * 1e18),    # 0.5 SOMI
        "gold": int(1.0 * 1e18)       # 1.0 SOMI
    }
    
    @staticmethod
    def get_expected_price(key_type):
        """Get price in Wei for key type"""
        key_type = key_type.lower()
        if key_type not in ContractAdapter.PRICE_WEI:
            return None
        return ContractAdapter.PRICE_WEI[key_type]
    
    @staticmethod
    def verify_transaction_on_somnia(tx_hash, key_type, expected_from_wallet=None):
        """
        Verify SOMI payment transaction on Somnia mainnet.
        
        Args:
            tx_hash: Transaction hash (0x-prefixed)
            key_type: "bronze", "silver", or "gold"
            expected_from_wallet: Optional wallet address that should have sent (for logging)
        
        Returns:
            dict: {
                "verified": bool,
                "status": "success" | "pending" | "failed" | "invalid",
                "reason": str,
                "tx_data": {
                    "to": str,
                    "from": str,
                    "value": str (Wei),
                    "status": int (0 or 1),
                    "blockNumber": int
                } if verified
            }
        """
        try:
            # Validate key type
            if key_type.lower() not in ContractAdapter.PRICE_WEI:
                return {
                    "verified": False,
                    "status": "invalid",
                    "reason": f"Invalid key type: {key_type}"
                }
            
            expected_price = ContractAdapter.get_expected_price(key_type)
            
            # Normalize tx_hash
            tx_hash = tx_hash.strip()
            if not tx_hash.startswith("0x"):
                tx_hash = "0x" + tx_hash
            
            # Call RPC to get transaction receipt
            logger.info(
                f"Verifying SOMI transaction: {tx_hash} for {key_type}",
                context={"rpc": ContractAdapter.SOMNIA_RPC_MAINNET}
            )
            
            receipt = ContractAdapter._get_transaction_receipt(tx_hash)
            
            if receipt is None:
                logger.warning(
                    f"Transaction not found or pending: {tx_hash}",
                    context={"reason": "receipt_not_found"}
                )
                return {
                    "verified": False,
                    "status": "pending",
                    "reason": "Transaction not yet confirmed on chain"
                }
            
            # Check receipt status (1 = success, 0 = failed)
            status = receipt.get("status")
            if status != "0x1":
                logger.warning(
                    f"Transaction failed on-chain: {tx_hash}",
                    context={"status": status}
                )
                return {
                    "verified": False,
                    "status": "failed",
                    "reason": f"Transaction failed on-chain (status: {status})"
                }
            
            # Get full transaction details
            tx = ContractAdapter._get_transaction(tx_hash)
            if tx is None:
                return {
                    "verified": False,
                    "status": "invalid",
                    "reason": "Could not retrieve transaction details"
                }
            
            # Validate recipient (must be our treasury wallet)
            tx_to = (tx.get("to") or "").lower()
            treasury = ContractAdapter.TREASURY_WALLET.lower()
            
            if tx_to != treasury:
                logger.warning(
                    f"Wrong recipient: {tx_to}, expected {treasury}",
                    context={"tx_hash": tx_hash}
                )
                return {
                    "verified": False,
                    "status": "invalid",
                    "reason": f"Recipient mismatch: received {tx_to}, expected {treasury}"
                }
            
            # Validate sender (must match user's linked wallet)
            if expected_from_wallet:
                tx_from = (tx.get("from") or "").lower()
                expected_from = expected_from_wallet.lower()
                
                if tx_from != expected_from:
                    logger.warning(
                        f"Wrong sender: {tx_from}, expected {expected_from}",
                        context={"tx_hash": tx_hash}
                    )
                    return {
                        "verified": False,
                        "status": "invalid",
                        "reason": f"Sender mismatch: tx sent from {tx_from}, but user wallet is {expected_from}"
                    }
            
            # Validate amount
            tx_value = int(tx.get("value", "0x0"), 16)  # Convert hex to int
            
            if tx_value != expected_price:
                logger.warning(
                    f"Wrong amount: {tx_value} Wei, expected {expected_price}",
                    context={"tx_hash": tx_hash, "key_type": key_type}
                )
                return {
                    "verified": False,
                    "status": "invalid",
                    "reason": f"Amount mismatch: received {tx_value} Wei, expected {expected_price} Wei"
                }
            
            # Validate chain ID (verify we're on Somnia mainnet)
            # Note: We could also check chainId from transaction if available
            
            logger.info(
                f"Transaction verified: {tx_hash}",
                context={
                    "key_type": key_type,
                    "to": tx_to,
                    "value": tx_value,
                    "status": status
                }
            )
            
            return {
                "verified": True,
                "status": "success",
                "reason": "Transaction verified and valid",
                "tx_data": {
                    "to": tx_to,
                    "from": (tx.get("from") or "").lower(),
                    "value": str(tx_value),
                    "status": 1,
                    "blockNumber": int(receipt.get("blockNumber", "0x0"), 16)
                }
            }
            
        except Exception as e:
            logger.error(f"Transaction verification error: {str(e)}", error=e)
            return {
                "verified": False,
                "status": "invalid",
                "reason": f"Verification error: {str(e)}"
            }
    
    @staticmethod
    def _get_transaction_receipt(tx_hash):
        """
        Fetch transaction receipt from Somnia RPC.
        
        Returns:
            dict: Receipt object or None if not found/pending
        """
        try:
            payload = {
                "jsonrpc": "2.0",
                "method": "eth_getTransactionReceipt",
                "params": [tx_hash],
                "id": 1
            }
            
            response = requests.post(
                ContractAdapter.SOMNIA_RPC_MAINNET,
                json=payload,
                timeout=10
            )
            response.raise_for_status()
            
            data = response.json()
            if data.get("error"):
                logger.warning(f"RPC error: {data.get('error')}")
                return None
            
            return data.get("result")  # None if pending, dict if found
            
        except requests.exceptions.RequestException as e:
            logger.error(f"RPC request error: {str(e)}", error=e)
            return None
    
    @staticmethod
    def _get_transaction(tx_hash):
        """
        Fetch transaction details from Somnia RPC.
        
        Returns:
            dict: Transaction object or None if not found
        """
        try:
            payload = {
                "jsonrpc": "2.0",
                "method": "eth_getTransactionByHash",
                "params": [tx_hash],
                "id": 1
            }
            
            response = requests.post(
                ContractAdapter.SOMNIA_RPC_MAINNET,
                json=payload,
                timeout=10
            )
            response.raise_for_status()
            
            data = response.json()
            if data.get("error"):
                logger.warning(f"RPC error: {data.get('error')}")
                return None
            
            return data.get("result")
            
        except requests.exceptions.RequestException as e:
            logger.error(f"RPC request error: {str(e)}", error=e)
            return None
    
    @staticmethod
    def generate_mock_tx_hash():
        """Generate a mock transaction hash for testing"""
        return f"0x{uuid.uuid4().hex}{uuid.uuid4().hex[:8]}"
    
    @staticmethod
    def purchase_key_mock(user_id, wallet_address, key_type):
        """
        DEPRECATED: Mock key purchase (kept for backward compatibility).
        Use verify_transaction_on_somnia instead.
        """
        try:
            valid_keys = ["bronze", "silver", "gold"]
            if key_type.lower() not in valid_keys:
                return False, None, f"Invalid key type. Must be one of: {', '.join(valid_keys)}"
            
            key_type = key_type.lower()
            tx_hash = ContractAdapter.generate_mock_tx_hash()
            timestamp = datetime.now(timezone.utc).isoformat()
            
            purchase_event = {
                "event_id": str(uuid.uuid4()),
                "user_id": user_id,
                "wallet_address": wallet_address,
                "key_type": key_type,
                "timestamp": timestamp,
                "tx_hash": tx_hash,
                "status": "confirmed",
                "price": str(ContractAdapter.PRICE_WEI[key_type] / 1e18),
                "source": "mock_contract"
            }
            
            logger.info(
                f"Mock key purchase (deprecated): {key_type}",
                context={"tx_hash": tx_hash}
            )
            
            return True, purchase_event, None
            
        except Exception as e:
            logger.error(f"Mock purchase error: {str(e)}", error=e)
            return False, None, "Purchase simulation failed"
    
    @staticmethod
    def get_owned_keys_mock(user_id, wallet_address, keys_owned_data=None):
        """Mock ownership check (kept for backward compatibility)"""
        if keys_owned_data is None:
            keys_owned_data = {}
        
        return {
            "bronze": keys_owned_data.get("bronze", 0),
            "silver": keys_owned_data.get("silver", 0),
            "gold": keys_owned_data.get("gold", 0),
            "source": "somnia_db",
        }

