"""
Contract Adapter - Mock Layer for Key Purchases
This module provides a mock implementation of smart contract interactions.
In production, replace these functions with actual Web3/blockchain calls.
"""

import uuid
from datetime import datetime, timezone
from logger import logger


class ContractAdapter:
    """
    Mock contract adapter for key purchases.
    Future: Replace with real Web3 contract calls to on-chain NFT contract.
    """
    
    # Mock contract address (for future use)
    MOCK_CONTRACT_ADDRESS = "0x0000000000000000000000000000000000000000"
    
    # Key prices (mock - will be on-chain later)
    KEY_PRICES = {
        "bronze": "0.001",  # ETH equivalent
        "silver": "0.005",
        "gold": "0.01"
    }
    
    @staticmethod
    def generate_mock_tx_hash():
        """Generate a mock transaction hash"""
        return f"0x{uuid.uuid4().hex}{uuid.uuid4().hex[:8]}"
    
    @staticmethod
    def purchase_key_mock(user_id, wallet_address, key_type):
        """
        Mock key purchase.
        
        In production, this will:
        1. Call smart contract's purchaseKey() function
        2. Wait for transaction confirmation
        3. Verify event logs
        4. Return real tx_hash
        
        For now, simulates success and returns mock data.
        
        Args:
            user_id: User ID making purchase
            wallet_address: Wallet address
            key_type: "bronze", "silver", or "gold"
            
        Returns:
            tuple: (success: bool, data: dict, error: str)
        """
        try:
            # Validate key type
            valid_keys = ["bronze", "silver", "gold"]
            if key_type.lower() not in valid_keys:
                return False, None, f"Invalid key type. Must be one of: {', '.join(valid_keys)}"
            
            key_type = key_type.lower()
            
            # Generate mock transaction data
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
                "price": ContractAdapter.KEY_PRICES[key_type],
                "source": "mock_contract"
            }
            
            logger.info(
                f"Mock key purchase: {key_type} for {wallet_address}",
                context={"tx_hash": tx_hash, "user_id": user_id}
            )
            
            return True, purchase_event, None
            
        except Exception as e:
            logger.error(f"Mock purchase error: {str(e)}", error=e)
            return False, None, "Purchase simulation failed"
    
    @staticmethod
    def get_owned_keys_mock(user_id, wallet_address, keys_owned_data=None):
        """
        Mock ownership check.
        
        In production, this will query the smart contract's balanceOf() function
        for each key type NFT.
        
        For now, returns ownership from DB data (passed in).
        
        Args:
            user_id: User ID
            wallet_address: Wallet address
            keys_owned_data: Dict with bronze/silver/gold counts from DB
            
        Returns:
            dict: Ownership counts for each key type
        """
        if keys_owned_data is None:
            keys_owned_data = {}
        
        return {
            "bronze": keys_owned_data.get("bronze", 0),
            "silver": keys_owned_data.get("silver", 0),
            "gold": keys_owned_data.get("gold", 0),
            "source": "mock_db",
            "contract_address": ContractAdapter.MOCK_CONTRACT_ADDRESS
        }
    
    @staticmethod
    def verify_signature_mock(message, signature, wallet_address):
        """
        Mock signature verification.
        
        In production, use Web3.py to verify ECDSA signature.
        For now, always returns True (trusting frontend).
        
        Args:
            message: Message that was signed
            signature: Signature string
            wallet_address: Expected signer address
            
        Returns:
            bool: True if valid (mock always returns True)
        """
        # Mock: Trust the frontend for now
        # In production: Use eth_account.messages and recover_message
        logger.info(
            f"Mock signature verification for {wallet_address}",
            context={"message": message[:50]}
        )
        return True
