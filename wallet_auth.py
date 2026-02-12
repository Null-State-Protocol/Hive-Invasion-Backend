"""
Wallet-based authentication
Sign-in with MetaMask, WalletConnect, etc.
"""

import uuid
import time
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

import boto3
from botocore.exceptions import ClientError

from config import config
from models import User, UserWallet, now_iso
from security import SignatureValidator, is_valid_wallet_address
from jwt_handler import JWTHandler
from logger import logger


class WalletAuthService:
    """Wallet authentication service"""
    
    def __init__(self):
        self.dynamodb = boto3.resource('dynamodb', region_name=config.AWS_REGION)
        self.users_table = self.dynamodb.Table(config.TABLE_USERS)
        self.user_wallets_table = self.dynamodb.Table(config.TABLE_USER_WALLETS)
    
    def get_message_to_sign(self, wallet_address: str) -> Tuple[bool, Optional[Dict], Optional[str]]:
        """
        Get message to sign for wallet authentication
        
        Returns:
            (success, data, error_message)
        """
        try:
            wallet_address = wallet_address.lower()
            
            if not is_valid_wallet_address(wallet_address):
                return False, None, "Invalid wallet address"
            
            timestamp = int(time.time())
            message = SignatureValidator.create_message_to_sign(wallet_address, timestamp)
            
            return True, {
                "message": message,
                "timestamp": timestamp,
                "wallet_address": wallet_address
            }, None
        
        except Exception as e:
            logger.error("Failed to create message to sign", error=e)
            return False, None, "Failed to create signature message"
    
    def authenticate_wallet(
        self,
        wallet_address: str,
        signature: str,
        message: str
    ) -> Tuple[bool, Optional[Dict], Optional[str]]:
        """
        Authenticate user with wallet signature
        
        Returns:
            (success, auth_data, error_message)
        """
        try:
            wallet_address = wallet_address.lower()
            
            if not is_valid_wallet_address(wallet_address):
                return False, None, "Invalid wallet address"
            
            # Extract and verify timestamp from message (replay attack prevention)
            import re
            match = re.search(r'Timestamp: (\d+)', message)
            if not match:
                logger.warning("Message missing timestamp", context={"wallet": wallet_address})
                return False, None, "Invalid message format"
            
            timestamp = int(match.group(1))
            current_time = int(time.time())
            
            # Check if timestamp is within 5 minutes (300 seconds)
            time_diff = abs(current_time - timestamp)
            if time_diff > 300:
                logger.warning(
                    "Message timestamp expired or invalid",
                    context={"wallet": wallet_address, "time_diff": time_diff}
                )
                return False, None, "Message expired. Please request a new signature."
            
            # Verify signature
            is_valid = SignatureValidator.verify_eth_signature(message, signature, wallet_address)
            if not is_valid:
                logger.warning(
                    "Invalid wallet signature",
                    context={"wallet_address": wallet_address}
                )
                return False, None, "Invalid signature"
            
            # Check if wallet is linked to an existing user
            response = self.user_wallets_table.get_item(
                Key={"wallet_address": wallet_address}
            )
            
            if "Item" in response:
                # Existing user
                user_id = response["Item"]["user_id"]
                
                # Get user data
                user_response = self.users_table.get_item(Key={"user_id": user_id})
                if "Item" not in user_response:
                    return False, None, "User not found"
                
                user_data = user_response["Item"]
                
                # Check if account is active
                if not user_data.get("is_active", True):
                    return False, None, "Account is deactivated"
                
                # Update last login
                self.users_table.update_item(
                    Key={"user_id": user_id},
                    UpdateExpression="SET last_login_at = :now",
                    ExpressionAttributeValues={":now": now_iso()}
                )
                
                user = User(**user_data)
                is_new_user = False
            
            else:
                # New wallet - create user
                user_id = str(uuid.uuid4())
                now = now_iso()
                
                user = User(
                    user_id=user_id,
                    email=None,
                    password_hash=None,
                    created_at=now,
                    updated_at=now,
                    email_verified=False,
                    is_active=True,
                    last_login_at=now
                )
                
                # Store user
                self.users_table.put_item(Item=user.to_db_item())
                
                # Link wallet
                self.user_wallets_table.put_item(Item={
                    "wallet_address": wallet_address,
                    "user_id": user_id,
                    "linked_at": now,
                    "is_primary": True
                })
                
                is_new_user = True
                
                logger.info(
                    "New user created via wallet",
                    context={"user_id": user_id, "wallet_address": wallet_address}
                )
            
            # Create auth tokens
            tokens = JWTHandler.create_token_pair(user_id)
            
            return True, {
                "user": user.to_dict(),
                "tokens": tokens,
                "wallet_address": wallet_address,
                "is_new_user": is_new_user
            }, None
        
        except Exception as e:
            logger.error("Wallet authentication failed", error=e)
            return False, None, "Authentication failed"
    
    def link_wallet_to_user(
        self,
        user_id: str,
        wallet_address: str,
        signature: str,
        message: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Link a wallet to an existing user account
        
        Returns:
            (success, error_message)
        """
        try:
            wallet_address = wallet_address.lower()
            
            if not is_valid_wallet_address(wallet_address):
                return False, "Invalid wallet address"
            
            # Verify signature
            is_valid = SignatureValidator.verify_eth_signature(message, signature, wallet_address)
            if not is_valid:
                return False, "Invalid signature"
            
            # Check if wallet is already linked
            response = self.user_wallets_table.get_item(
                Key={"wallet_address": wallet_address}
            )
            
            if "Item" in response:
                existing_user_id = response["Item"]["user_id"]
                if existing_user_id == user_id:
                    # Ensure user record is updated even if legacy records are out of sync
                    self.users_table.update_item(
                        Key={"user_id": user_id},
                        UpdateExpression="SET wallet_address = :wallet",
                        ExpressionAttributeValues={":wallet": wallet_address}
                    )
                    return True, None
                else:
                    return False, "Wallet already linked to another account"

            # Check if user already has a different wallet linked (legacy/old binding)
            user_response = self.users_table.get_item(Key={"user_id": user_id})
            if "Item" in user_response:
                existing_wallet = user_response["Item"].get("wallet_address")
                if existing_wallet and existing_wallet != wallet_address:
                    try:
                        # Remove old wallet mapping for this user
                        self.user_wallets_table.delete_item(
                            Key={"wallet_address": existing_wallet}
                        )
                    except Exception:
                        # Non-fatal: continue with new link
                        pass
            
            # Link wallet
            self.user_wallets_table.put_item(Item={
                "wallet_address": wallet_address,
                "user_id": user_id,
                "linked_at": now_iso(),
                "is_primary": False
            })
            
            # Update user record with wallet_address
            self.users_table.update_item(
                Key={"user_id": user_id},
                UpdateExpression="SET wallet_address = :wallet",
                ExpressionAttributeValues={":wallet": wallet_address}
            )
            
            logger.info(
                "Wallet linked to user",
                context={"user_id": user_id, "wallet_address": wallet_address}
            )
            
            return True, None
        
        except Exception as e:
            logger.error("Wallet linking failed", error=e)
            return False, "Failed to link wallet"
    
    def unlink_wallet(self, user_id: str, wallet_address: str) -> Tuple[bool, Optional[str]]:
        """
        Unlink a wallet from user account
        
        Returns:
            (success, error_message)
        """
        try:
            wallet_address = wallet_address.lower()
            
            # Check if wallet belongs to user
            response = self.user_wallets_table.get_item(
                Key={"wallet_address": wallet_address}
            )
            
            if "Item" not in response:
                return False, "Wallet not found"
            
            if response["Item"]["user_id"] != user_id:
                return False, "Wallet does not belong to you"
            
            # Don't allow unlinking if it's the only authentication method
            user_response = self.users_table.get_item(Key={"user_id": user_id})
            if "Item" not in user_response:
                return False, "User not found"
            
            has_email = bool(user_response["Item"].get("email"))
            
            # Count linked wallets
            wallets_response = self.user_wallets_table.query(
                IndexName="UserWalletsIndex",
                KeyConditionExpression="user_id = :user_id",
                ExpressionAttributeValues={":user_id": user_id}
            )
            
            wallet_count = len(wallets_response.get("Items", []))
            
            if not has_email and wallet_count <= 1:
                return False, "Cannot unlink your only authentication method. Add an email first."
            
            # Unlink wallet
            self.user_wallets_table.delete_item(
                Key={"wallet_address": wallet_address}
            )
            
            logger.info(
                "Wallet unlinked",
                context={"user_id": user_id, "wallet_address": wallet_address}
            )
            
            return True, None
        
        except Exception as e:
            logger.error("Wallet unlinking failed", error=e)
            return False, "Failed to unlink wallet"
    
    def get_user_wallets(self, user_id: str) -> list:
        """Get all wallets linked to a user"""
        try:
            response = self.user_wallets_table.query(
                IndexName="UserWalletsIndex",
                KeyConditionExpression="user_id = :user_id",
                ExpressionAttributeValues={":user_id": user_id}
            )
            
            return response.get("Items", [])
        
        except Exception as e:
            logger.error("Failed to get user wallets", error=e)
            return []
