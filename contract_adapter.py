"""
Contract Adapter - Somnia Network Payment Verification
This module verifies SOMI token transfers on Somnia mainnet via RPC.
"""

import uuid
import os
import requests
from datetime import datetime, timezone
from logger import logger


class VerifyErrorCodes:
    RPC_UNREACHABLE = "RPC_UNREACHABLE"
    RECEIPT_NOT_FOUND = "RECEIPT_NOT_FOUND"
    RECEIPT_MISSING_BLOCK = "RECEIPT_MISSING_BLOCK"
    TX_FAILED_ONCHAIN = "TX_FAILED_ONCHAIN"
    TX_NOT_FOUND = "TX_NOT_FOUND"
    TO_MISMATCH = "TO_MISMATCH"
    FROM_MISMATCH = "FROM_MISMATCH"
    VALUE_MISMATCH = "VALUE_MISMATCH"
    RPC_ERROR = "RPC_ERROR"


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

    _CONFIG_LOGGED = False
    
    # Key prices in Wei (1 SOMI = 10^18 Wei)
    PRICE_WEI = {
        "bronze": 100000000000000000,   # 0.1 SOMI
        "silver": 500000000000000000,   # 0.5 SOMI
        "gold": 1000000000000000000     # 1.0 SOMI
    }
    
    @staticmethod
    def log_config_once():
        if not ContractAdapter._CONFIG_LOGGED:
            print(f"[Config] Loaded: true {ContractAdapter.TREASURY_WALLET}")
            ContractAdapter._CONFIG_LOGGED = True

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
                raise ValueError(f"Invalid key type: {key_type}")

            expected_price = ContractAdapter.get_expected_price(key_type)

            # Normalize tx_hash
            tx_hash = tx_hash.strip()
            if not tx_hash:
                raise ValueError("Empty tx_hash")
            if not tx_hash.startswith("0x"):
                tx_hash = "0x" + tx_hash

            treasury = ContractAdapter.TREASURY_WALLET.lower()

            try:
                receipt = ContractAdapter._get_transaction_receipt(tx_hash)
            except ValueError as e:
                raise ValueError(str(e))

            if receipt is None:
                raise ValueError(VerifyErrorCodes.RECEIPT_NOT_FOUND)

            # Check receipt status (1 = success, 0 = failed)
            status = receipt.get("status")
            if status != "0x1":
                raise ValueError(VerifyErrorCodes.TX_FAILED_ONCHAIN)

            if not receipt.get("blockNumber"):
                raise ValueError(VerifyErrorCodes.RECEIPT_MISSING_BLOCK)

            # Get full transaction details
            try:
                tx = ContractAdapter._get_transaction(tx_hash)
            except ValueError as e:
                raise ValueError(str(e))

            if tx is None:
                raise ValueError(VerifyErrorCodes.TX_NOT_FOUND)

            # Validate recipient (must be our treasury wallet)
            tx_to = (tx.get("to") or "").lower()

            if tx_to != treasury:
                raise ValueError(f"{VerifyErrorCodes.TO_MISMATCH} expected={treasury} got={tx_to}")

            # Validate sender (must match user's linked wallet)
            if expected_from_wallet:
                tx_from = (tx.get("from") or "").lower()
                expected_from = expected_from_wallet.lower()

                if tx_from != expected_from:
                    raise ValueError(f"{VerifyErrorCodes.FROM_MISMATCH} expected={expected_from} got={tx_from}")

            # Validate amount
            tx_value = int(tx.get("value", "0x0"), 16)  # Convert hex to int

            if tx_value != expected_price:
                raise ValueError(f"{VerifyErrorCodes.VALUE_MISMATCH} expected={expected_price} got={tx_value}")

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
            raise
    
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
                err = data.get("error") or {}
                code = err.get("code", "unknown")
                message = err.get("message", "RPC_ERROR")
                raise ValueError(f"RPC_ERROR {code}: {message}")
            
            return data.get("result")  # None if pending, dict if found
            
        except requests.exceptions.RequestException:
            raise ValueError(VerifyErrorCodes.RPC_UNREACHABLE)
    
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
                err = data.get("error") or {}
                code = err.get("code", "unknown")
                message = err.get("message", VerifyErrorCodes.RPC_ERROR)
                raise ValueError(f"{VerifyErrorCodes.RPC_ERROR} {code}: {message}")
            
            return data.get("result")
            
        except requests.exceptions.RequestException:
            raise ValueError(VerifyErrorCodes.RPC_UNREACHABLE)
    
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
            
            return True, purchase_event, None
            
        except Exception as e:
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

