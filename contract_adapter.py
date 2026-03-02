"""
Contract Adapter - Somnia Network Payment Verification
This module supports both payment systems:
1. Direct SOMI transfers to treasury wallet (legacy)
2. KeyPayments v2 contract-based purchases (new)
"""

import uuid
import os
import requests
from datetime import datetime, timezone
from logger import logger
from decimal import Decimal


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
    CONTRACT_ERROR = "CONTRACT_ERROR"
    PURCHASE_NOT_FOUND = "PURCHASE_NOT_FOUND"
    INVALID_PRODUCT_ID = "INVALID_PRODUCT_ID"


class PaymentModes:
    """Payment system modes"""
    LEGACY_DIRECT_TRANSFER = "legacy_direct_transfer"  # Direct SOMI to treasury
    KEYPAYMENTS_V2_CONTRACT = "keypayments_v2_contract"  # New contract-based system
    DUAL_MODE = "dual_mode"  # Support both systems in development


class ContractAdapter:
    # Event signature hash for Purchased event
    # keccak256("Purchased(uint256,address,uint256,uint256,bytes32)")
    PURCHASED_EVENT_SIGNATURE = "0x51e3d88d9c50fd64749cfb37943d1af37c757ecf6b459752cb41654733a5ecce"

    """
    Somnia payment verification adapter.
    Supports both payment systems:
    - Legacy: Direct SOMI transfers to treasury wallet via RPC
    - New: KeyPayments v2 contract-based purchases
    """
    
    # ===== LEGACY SYSTEM (Direct SOMI Transfer) =====
    # Somnia Treasury Wallet (case-insensitive, will be normalized)
    TREASURY_WALLET = os.environ.get("SOMNIA_TREASURY_WALLET", "0x0000000000000000000000000000000000000000").lower()
    
    # ===== NEW SYSTEM (KeyPayments v2 Contract) =====
    # KeyPayments v2 Contract Address on Somnia Mainnet
    KEYPAYMENTS_V2_ADDRESS = os.environ.get(
        "KEYPAYMENTS_V2_ADDRESS", 
        "0xE16bD577Cf5890Db5368139132A7412614bf62ff"  # Mainnet address
    ).lower()
    
    # Product ID mapping (Bronze=1, Silver=2, Gold=3)
    PRODUCT_ID_MAP = {
        "bronze": 1,
        "silver": 2,
        "gold": 3
    }
    
    # Reverse mapping (for logs and debugging)
    PRODUCT_NAME_MAP = {
        1: "bronze",
        2: "silver",
        3: "gold"
    }
    
    # Somnia RPC Endpoints
    SOMNIA_RPC_MAINNET = os.environ.get("SOMNIA_RPC_MAINNET", "https://api.infra.mainnet.somnia.network/")
    SOMNIA_CHAIN_ID_MAINNET = 5031
    SOMNIA_CHAIN_ID_TESTNET = 50312

    _CONFIG_LOGGED = False
    
    # Key prices in Wei (1 SOMI = 10^18 Wei)
    # Must match contract prices
    PRICE_WEI = {
        "bronze": int(0.1 * 1e18),     # 0.1 SOMI (Bronze Key on contract)
        "silver": int(0.2 * 1e18),     # 0.2 SOMI (Silver Key on contract)
        "gold": int(0.3 * 1e18)        # 0.3 SOMI (Gold Key on contract)
    }
    
    # Payment mode (set via environment or default to dual mode for development)
    PAYMENT_MODE = os.environ.get("PAYMENT_MODE", PaymentModes.DUAL_MODE)
    
    @staticmethod
    def log_config_once():
        if not ContractAdapter._CONFIG_LOGGED:
            mode_str = f"[{ContractAdapter.PAYMENT_MODE}]"
            treasury = ContractAdapter.TREASURY_WALLET[:8] + "..." if ContractAdapter.TREASURY_WALLET else "NOT_SET"
            contract = ContractAdapter.KEYPAYMENTS_V2_ADDRESS[:8] + "..." if ContractAdapter.KEYPAYMENTS_V2_ADDRESS else "NOT_SET"
            print(f"[Config] Payment System: {mode_str} | Treasury: {treasury} | Contract: {contract}")
            ContractAdapter._CONFIG_LOGGED = True

    @staticmethod
    def get_expected_price(key_type):
        """Get price in Wei for key type"""
        key_type = key_type.lower()
        if key_type not in ContractAdapter.PRICE_WEI:
            return None
        return ContractAdapter.PRICE_WEI[key_type]
    
    @staticmethod
    def get_product_id(key_type):
        """Get product ID for key type (for contract-based purchases)"""
        key_type = key_type.lower()
        return ContractAdapter.PRODUCT_ID_MAP.get(key_type)
    
    @staticmethod
    def verify_contract_purchase(tx_hash, product_id, expected_buyer=None):
        """
        Verify KeyPayments v2 contract purchase via transaction receipt.
        
        Args:
            tx_hash: Transaction hash (0x-prefixed)
            product_id: Product ID (1=bronze, 2=silver, 3=gold)
            expected_buyer: Optional wallet address that should have purchased
        
        Returns:
            dict: {
                "verified": bool,
                "status": "success" | "pending" | "failed" | "invalid",
                "reason": str,
                "purchase_data": {
                    "purchaseId": int,
                    "buyer": str,
                    "productId": int,
                    "paidWei": str,
                    "orderId": str,
                    "blockNumber": int
                } if verified
            }
        """
        try:
            logger.info("Contract purchase verification started", context={
                "tx_hash": tx_hash,
                "product_id": product_id,
                "expected_buyer": expected_buyer
            })
            
            # Validate product ID
            if product_id not in ContractAdapter.PRODUCT_NAME_MAP:
                logger.error("Invalid product ID", context={"product_id": product_id})
                raise ValueError(f"Invalid product ID: {product_id}")
            
            # Normalize tx_hash
            tx_hash = tx_hash.strip()
            if not tx_hash:
                logger.error("Empty transaction hash provided")
                raise ValueError("Empty tx_hash")
            if not tx_hash.startswith("0x"):
                tx_hash = "0x" + tx_hash
                logger.debug("Normalized tx_hash", context={"tx_hash": tx_hash})
            
            try:
                logger.debug("Fetching transaction receipt", context={"tx_hash": tx_hash})
                receipt = ContractAdapter._get_transaction_receipt(tx_hash)
            except ValueError as e:
                logger.error("Failed to get transaction receipt", context={"tx_hash": tx_hash, "error": str(e)})
                raise ValueError(str(e))
            
            if receipt is None:
                logger.warning("Transaction receipt not found (pending)", context={"tx_hash": tx_hash})
                return {
                    "verified": False,
                    "status": "pending",
                    "reason": "Transaction not yet confirmed on-chain"
                }
            
            # Check receipt status (1 = success, 0 = failed)
            status = receipt.get("status")
            logger.debug("Transaction status", context={"tx_hash": tx_hash, "status": status})
            if status != "0x1":
                logger.warning("Transaction failed on-chain", context={"tx_hash": tx_hash, "status": status})
                return {
                    "verified": False,
                    "status": "failed",
                    "reason": "Transaction failed on-chain"
                }
            
            if not receipt.get("blockNumber"):
                logger.error("Receipt missing block number", context={"tx_hash": tx_hash})
                return {
                    "verified": False,
                    "status": "invalid",
                    "reason": "Receipt missing block number"
                }
            
            # Validate recipient is KeyPayments v2 contract
            tx_to = (receipt.get("to") or "").lower()
            contract = ContractAdapter.KEYPAYMENTS_V2_ADDRESS.lower()
            logger.debug("Transaction recipient", context={"tx_hash": tx_hash, "to": tx_to, "contract": contract})
            
            if tx_to != contract:
                logger.warning("Transaction not to KeyPayments v2 contract", context={
                    "tx_hash": tx_hash,
                    "expected": contract,
                    "actual": tx_to
                })
                return {
                    "verified": False,
                    "status": "invalid",
                    "reason": f"Transaction not to contract: expected {contract}, got {tx_to}"
                }
            
            # Parse logs to find Purchased event
            # Purchased event signature: Purchased(purchaseId, buyer, productId, paidWei, orderId)
            # Topic: keccak256("Purchased(uint256,address,uint256,uint256,bytes32)")
            purchased_event = ContractAdapter._find_purchased_event(receipt, product_id, expected_buyer)
            
            if not purchased_event:
                logger.warning("Purchased event not found in receipt", context={
                    "tx_hash": tx_hash,
                    "product_id": product_id,
                    "expected_buyer": expected_buyer
                })
                return {
                    "verified": False,
                    "status": "invalid",
                    "reason": "Purchased event not found in transaction logs"
                }
            
            logger.info("Contract purchase verified", context={
                "tx_hash": tx_hash,
                "product_id": product_id,
                "buyer": purchased_event.get("buyer"),
                "paid_wei": purchased_event.get("paidWei")
            })
            
            return {
                "verified": True,
                "status": "success",
                "reason": "Transaction verified and Purchased event found",
                "purchase_data": {
                    "purchaseId": purchased_event.get("purchaseId"),
                    "buyer": purchased_event.get("buyer"),
                    "productId": purchased_event.get("productId"),
                    "paidWei": purchased_event.get("paidWei"),
                    "orderId": purchased_event.get("orderId"),
                    "blockNumber": int(receipt.get("blockNumber", "0x0"), 16)
                }
            }
        
        except Exception as e:
            logger.error("Contract purchase verification failed", error=e, context={
                "tx_hash": tx_hash,
                "product_id": product_id,
                "error_type": type(e).__name__,
                "error_message": str(e)
            })
            return {
                "verified": False,
                "status": "invalid",
                "reason": f"Verification error: {str(e)}"
            }
    
    @staticmethod
    def _find_purchased_event(receipt, expected_product_id, expected_buyer=None):
        """
        Parse receipt logs to find Purchased event from KeyPayments v2 contract.
        
        Purchased event signature:
        event Purchased(
            uint256 indexed purchaseId,
            address indexed buyer,
            uint256 indexed productId,
            uint256 paidWei,
            bytes32 orderId
        )
        
        Log format:
        - topics[0] = keccak256("Purchased(uint256,address,uint256,uint256,bytes32)")
        - topics[1] = purchaseId (uint256)
        - topics[2] = buyer (address)
        - topics[3] = productId (uint256)
        - data = paidWei (uint256) + orderId (bytes32) packed
        
        Returns:
            dict with purchaseId, buyer, productId, paidWei, orderId or None if not found
        """
        try:
            logs = receipt.get("logs", [])
            if not logs:
                logger.debug("No logs in receipt")
                return None
            
            contract = ContractAdapter.KEYPAYMENTS_V2_ADDRESS.lower()
            
            for log in logs:
                # Check if log is from our contract
                log_address = (log.get("address") or "").lower()
                
                if log_address != contract:
                    continue
                
                topics = log.get("topics", [])
                data = log.get("data", "")
                
                # Purchased event has exactly 4 topics (signature + 3 indexed params)
                if len(topics) < 4:
                    logger.debug("Log has insufficient topics for Purchased event", context={
                        "topics_count": len(topics)
                    })
                    continue

                # Verify event signature in topics[0]
                event_sig = (topics[0] or "").lower()
                expected_sig = ContractAdapter.PURCHASED_EVENT_SIGNATURE.lower()
                if event_sig != expected_sig:
                    logger.debug("Event signature mismatch", context={
                        "expected": expected_sig,
                        "actual": event_sig
                    })
                    continue
                
                try:
                    # Parse indexed parameters
                    # topics[1] = purchaseId (uint256)
                    purchase_id = int(topics[1], 16)
                    
                    # topics[2] = buyer (address, 20 bytes)
                    # Address is stored in 32-byte field, address is last 20 bytes
                    buyer_hex = topics[2]
                    if buyer_hex.startswith("0x"):
                        buyer_hex = buyer_hex[2:]
                    # Remove leading zeros to get address
                    buyer = "0x" + buyer_hex[-40:].lstrip("0") or "0x0"
                    
                    # topics[3] = productId (uint256)
                    product_id = int(topics[3], 16)
                    
                    # Parse non-indexed parameters from data field
                    # data = paidWei (uint256 = 32 bytes) + orderId (bytes32 = 32 bytes)
                    data_hex = data
                    if data_hex.startswith("0x"):
                        data_hex = data_hex[2:]
                    
                    # Validate data length (should be at least 128 hex chars for 2 uint256/bytes32)
                    if len(data_hex) < 128:
                        logger.warning("Purchased event data too short", context={
                            "expected_min": 128,
                            "actual": len(data_hex)
                        })
                        continue
                    
                    # paidWei = first 64 hex chars (32 bytes)
                    paid_wei = int(data_hex[0:64], 16)
                    # orderId = next 64 hex chars (32 bytes)
                    order_id = "0x" + data_hex[64:128]
                    
                    # Validate product ID matches
                    if product_id != expected_product_id:
                        logger.debug("Purchased event product ID mismatch", context={
                            "expected": expected_product_id,
                            "actual": product_id
                        })
                        continue
                    
                    # Validate buyer matches if provided
                    if expected_buyer:
                        expected_buyer_lower = expected_buyer.lower()
                        buyer_lower = buyer.lower()
                        if buyer_lower != expected_buyer_lower:
                            logger.debug("Purchased event buyer mismatch", context={
                                "expected": expected_buyer_lower,
                                "actual": buyer_lower
                            })
                            continue
                    
                    logger.debug("Purchased event found", context={
                        "purchase_id": purchase_id,
                        "buyer": buyer,
                        "product_id": product_id,
                        "paid_wei": paid_wei
                    })
                    
                    return {
                        "purchaseId": purchase_id,
                        "buyer": buyer,
                        "productId": product_id,
                        "paidWei": str(paid_wei),
                        "orderId": order_id
                    }
                
                except (ValueError, IndexError) as pe:
                    logger.debug("Error parsing Purchased event log", context={
                        "error": str(pe),
                        "topics_count": len(topics),
                        "data_length": len(data)
                    })
                    continue
            
            logger.debug("No matching Purchased event found", context={
                "expected_product_id": expected_product_id,
                "expected_buyer": expected_buyer,
                "contract": contract
            })
            return None
        
        except Exception as e:
            logger.error("Error finding Purchased event", error=e, context={
                "error_type": type(e).__name__,
                "error_message": str(e)
            })
            return None
    
    @staticmethod
    def verify_transaction_on_somnia(tx_hash, key_type, expected_from_wallet=None):
        """
        [LEGACY] Verify SOMI payment transaction (direct transfer to treasury wallet).
        
        This method is kept for backward compatibility with the legacy payment system.
        For new deployments, use verify_contract_purchase() or verify_purchase() for smart selection.
        
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
            logger.info("Payment verification started", context={
                "tx_hash": tx_hash,
                "key_type": key_type,
                "expected_from_wallet": expected_from_wallet
            })
            
            # Validate key type
            if key_type.lower() not in ContractAdapter.PRICE_WEI:
                logger.error("Invalid key type for payment verification", context={"key_type": key_type})
                raise ValueError(f"Invalid key type: {key_type}")

            expected_price = ContractAdapter.get_expected_price(key_type)
            logger.debug("Expected price calculated", context={"key_type": key_type, "expected_price_wei": expected_price})

            # Normalize tx_hash
            tx_hash = tx_hash.strip()
            if not tx_hash:
                logger.error("Empty transaction hash provided")
                raise ValueError("Empty tx_hash")
            if not tx_hash.startswith("0x"):
                tx_hash = "0x" + tx_hash
                logger.debug("Normalized tx_hash", context={"tx_hash": tx_hash})

            treasury = ContractAdapter.TREASURY_WALLET.lower()
            logger.debug("Treasury wallet", context={"treasury": treasury})

            try:
                logger.debug("Fetching transaction receipt", context={"tx_hash": tx_hash})
                receipt = ContractAdapter._get_transaction_receipt(tx_hash)
            except ValueError as e:
                logger.error("Failed to get transaction receipt", context={"tx_hash": tx_hash, "error": str(e)})
                raise ValueError(str(e))

            if receipt is None:
                logger.warning("Transaction receipt not found", context={"tx_hash": tx_hash})
                raise ValueError(VerifyErrorCodes.RECEIPT_NOT_FOUND)

            # Check receipt status (1 = success, 0 = failed)
            status = receipt.get("status")
            logger.debug("Transaction status", context={"tx_hash": tx_hash, "status": status})
            if status != "0x1":
                logger.warning("Transaction failed on-chain", context={"tx_hash": tx_hash, "status": status})
                raise ValueError(VerifyErrorCodes.TX_FAILED_ONCHAIN)

            if not receipt.get("blockNumber"):
                logger.error("Receipt missing block number", context={"tx_hash": tx_hash})
                raise ValueError(VerifyErrorCodes.RECEIPT_MISSING_BLOCK)

            # Get full transaction details
            try:
                logger.debug("Fetching full transaction details", context={"tx_hash": tx_hash})
                tx = ContractAdapter._get_transaction(tx_hash)
            except ValueError as e:
                logger.error("Failed to get transaction details", context={"tx_hash": tx_hash, "error": str(e)})
                raise ValueError(str(e))

            if tx is None:
                logger.error("Transaction not found", context={"tx_hash": tx_hash})
                raise ValueError(VerifyErrorCodes.TX_NOT_FOUND)

            # Validate recipient (must be our treasury wallet)
            tx_to = (tx.get("to") or "").lower()
            logger.debug("Transaction recipient", context={"tx_hash": tx_hash, "to": tx_to, "expected": treasury})

            if tx_to != treasury:
                logger.warning("Transaction recipient mismatch", context={
                    "tx_hash": tx_hash,
                    "expected": treasury,
                    "actual": tx_to
                })
                raise ValueError(f"{VerifyErrorCodes.TO_MISMATCH} expected={treasury} got={tx_to}")

            # Validate sender (must match user's linked wallet)
            if expected_from_wallet:
                tx_from = (tx.get("from") or "").lower()
                expected_from = expected_from_wallet.lower()
                logger.debug("Transaction sender", context={"tx_hash": tx_hash, "from": tx_from, "expected": expected_from})

                if tx_from != expected_from:
                    logger.warning("Transaction sender mismatch", context={
                        "tx_hash": tx_hash,
                        "expected": expected_from,
                        "actual": tx_from
                    })
                    raise ValueError(f"{VerifyErrorCodes.FROM_MISMATCH} expected={expected_from} got={tx_from}")

            # Validate amount
            tx_value = int(tx.get("value", "0x0"), 16)  # Convert hex to int
            logger.debug("Transaction value", context={"tx_hash": tx_hash, "value_wei": tx_value, "expected_wei": expected_price})

            if tx_value != expected_price:
                logger.warning("Transaction value mismatch", context={
                    "tx_hash": tx_hash,
                    "expected_wei": expected_price,
                    "actual_wei": tx_value,
                    "key_type": key_type
                })
                raise ValueError(f"{VerifyErrorCodes.VALUE_MISMATCH} expected={expected_price} got={tx_value}")

            logger.info("Payment verification successful", context={
                "tx_hash": tx_hash,
                "key_type": key_type,
                "from": tx.get("from"),
                "to": tx_to,
                "value_wei": tx_value
            })
            
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
            reason = str(e)
            logger.error("Payment verification failed", error=e, context={
                "tx_hash": tx_hash,
                "key_type": key_type,
                "expected_from_wallet": expected_from_wallet,
                "error_type": type(e).__name__,
                "error_message": reason
            })
            # Return error dict instead of raising (for consistency with docstring)
            return {
                "verified": False,
                "status": "invalid",
                "reason": reason,
                "tx_data": None
            }
    
    @staticmethod
    def _get_transaction_receipt(tx_hash):
        """
        Fetch transaction receipt from Somnia RPC.
        
        Returns:
            dict: Receipt object or None if not found/pending
        """
        try:
            logger.debug("Fetching transaction receipt from RPC", context={"tx_hash": tx_hash})
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
                logger.error("RPC error fetching transaction receipt", context={"tx_hash": tx_hash, "error_code": code, "error_message": message})
                raise ValueError(f"RPC_ERROR {code}: {message}")
            
            result = data.get("result")
            if result:
                logger.debug("Transaction receipt retrieved", context={"tx_hash": tx_hash})
            else:
                logger.debug("Transaction receipt not found (pending)", context={"tx_hash": tx_hash})
            return result  # None if pending, dict if found
            
        except requests.exceptions.RequestException as e:
            logger.error("RPC unreachable for transaction receipt", error=e, context={"tx_hash": tx_hash, "rpc_endpoint": ContractAdapter.SOMNIA_RPC_MAINNET})
            raise ValueError(VerifyErrorCodes.RPC_UNREACHABLE)
    
    @staticmethod
    def _get_transaction(tx_hash):
        """
        Fetch transaction details from Somnia RPC.
        
        Returns:
            dict: Transaction object or None if not found
        """
        try:
            logger.debug("Fetching transaction details from RPC", context={"tx_hash": tx_hash})
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
                logger.error("RPC error fetching transaction", context={"tx_hash": tx_hash, "error_code": code, "error_message": message})
                raise ValueError(f"{VerifyErrorCodes.RPC_ERROR} {code}: {message}")
            
            result = data.get("result")
            if result:
                logger.debug("Transaction details retrieved", context={"tx_hash": tx_hash})
            else:
                logger.warning("Transaction not found", context={"tx_hash": tx_hash})
            return result
            
        except requests.exceptions.RequestException as e:
            logger.error("RPC unreachable for transaction", error=e, context={"tx_hash": tx_hash, "rpc_endpoint": ContractAdapter.SOMNIA_RPC_MAINNET})
            raise ValueError(VerifyErrorCodes.RPC_UNREACHABLE)
    
    @staticmethod
    def verify_purchase(tx_hash, key_type, expected_buyer=None):
        """
        Unified purchase verification that automatically selects between payment systems.
        
        In DUAL_MODE (development), tries contract first, falls back to legacy.
        In KEYPAYMENTS_V2_CONTRACT mode, uses only contract.
        In LEGACY_DIRECT_TRANSFER mode, uses only legacy system.
        
        Args:
            tx_hash: Transaction hash (0x-prefixed)
            key_type: "bronze", "silver", or "gold"
            expected_buyer: Optional wallet address for contract verification
        
        Returns:
            dict: {
                "verified": bool,
                "status": "success" | "pending" | "failed" | "invalid",
                "reason": str,
                "system": "contract" | "legacy",
                "tx_data" or "purchase_data": (system-specific data)
            }
        """
        mode = ContractAdapter.PAYMENT_MODE.lower()
        product_id = ContractAdapter.get_product_id(key_type)
        
        if product_id is None:
            return {
                "verified": False,
                "status": "invalid",
                "reason": f"Invalid key type: {key_type}",
                "system": None
            }
        
        # Try contract system first in dual mode
        if mode == PaymentModes.DUAL_MODE or mode == PaymentModes.KEYPAYMENTS_V2_CONTRACT:
            logger.info("Attempting contract-based verification", context={
                "tx_hash": tx_hash[:12] + "...",
                "key_type": key_type
            })
            result = ContractAdapter.verify_contract_purchase(tx_hash, product_id, expected_buyer)
            result["system"] = "contract"
            
            if result["verified"] or result["status"] != "invalid" or mode == PaymentModes.KEYPAYMENTS_V2_CONTRACT:
                return result
            
            # Only fallback to legacy if in dual mode and contract verification returned "invalid"
            if mode != PaymentModes.DUAL_MODE:
                return result
        
        # Fall back to legacy system (or use exclusively if in LEGACY mode)
        if mode == PaymentModes.DUAL_MODE or mode == PaymentModes.LEGACY_DIRECT_TRANSFER:
            logger.info("Attempting legacy SOMI transfer verification", context={
                "tx_hash": tx_hash[:12] + "...",
                "key_type": key_type
            })
            try:
                legacy_result = ContractAdapter.verify_transaction_on_somnia(tx_hash, key_type, expected_buyer)
                legacy_result["system"] = "legacy"
                return legacy_result
            except Exception as e:
                return {
                    "verified": False,
                    "status": "invalid",
                    "reason": str(e),
                    "system": "legacy"
                }
        
        # Should not reach here
        return {
            "verified": False,
            "status": "invalid",
            "reason": f"Unknown payment mode: {mode}",
            "system": None
        }
    
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

