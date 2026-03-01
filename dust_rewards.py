"""
Dust Rewards Service
Handle legacy test dust reward claims when users link wallets
"""

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from datetime import datetime, timezone
from decimal import Decimal
from typing import Dict, Optional, Tuple

from config import config
from models import now_iso
from logger import logger


class DustRewardsService:
    """Service for managing dust reward claims"""
    
    def __init__(self):
        self.dynamodb = boto3.resource('dynamodb', region_name=config.AWS_REGION)
        self.dust_rewards_table = self.dynamodb.Table(config.TABLE_DUST_REWARDS)
        self.player_resources_table = self.dynamodb.Table(config.TABLE_PLAYER_RESOURCES)
    
    def check_reward(self, wallet_address: str) -> Tuple[bool, Optional[Dict], Optional[str]]:
        """
        Check if a wallet has unclaimed dust rewards
        
        Args:
            wallet_address: Ethereum wallet address
            
        Returns:
            (has_reward, reward_data, error_message)
        """
        try:
            wallet_address = wallet_address.lower()
            logger.info("Checking dust reward", context={"wallet_address": wallet_address})
            
            response = self.dust_rewards_table.get_item(
                Key={"wallet_address": wallet_address}
            )
            
            if "Item" not in response:
                logger.debug("No dust reward found", context={"wallet_address": wallet_address})
                return False, None, None
            
            reward_data = response["Item"]
            claimed = reward_data.get("claimed", False)
            dust_amount = int(reward_data.get("dust_amount", 0))
            
            if claimed:
                logger.debug("Dust reward already claimed", context={
                    "wallet_address": wallet_address,
                    "claimed_at": reward_data.get("claimed_at"),
                    "claimed_by": reward_data.get("claimed_by_user_id")
                })
                return False, {
                    "claimed": True,
                    "dust_amount": dust_amount,
                    "claimed_at": reward_data.get("claimed_at"),
                    "claimed_by_user_id": reward_data.get("claimed_by_user_id")
                }, None
            
            logger.info("Unclaimed dust reward found", context={
                "wallet_address": wallet_address,
                "dust_amount": dust_amount
            })
            
            return True, {
                "claimed": False,
                "dust_amount": dust_amount,
                "wallet_address": wallet_address
            }, None
            
        except Exception as e:
            logger.error("Failed to check dust reward", error=e, context={"wallet_address": wallet_address})
            return False, None, "Failed to check reward"
    
    def claim_reward(self, wallet_address: str, user_id: str) -> Tuple[bool, Optional[Dict], Optional[str]]:
        """
        Claim dust reward for a wallet and add to user's resource balance
        
        Args:
            wallet_address: Ethereum wallet address
            user_id: User ID claiming the reward
            
        Returns:
            (success, claim_data, error_message)
        """
        try:
            wallet_address = wallet_address.lower()
            logger.info("Claiming dust reward", context={
                "wallet_address": wallet_address,
                "user_id": user_id
            })
            
            # Check if reward exists and is unclaimed
            has_reward, reward_data, error = self.check_reward(wallet_address)
            
            if error:
                return False, None, error
            
            if not has_reward:
                if reward_data and reward_data.get("claimed"):
                    return False, None, "Reward already claimed"
                else:
                    return False, None, "No reward available for this wallet"
            
            dust_amount = reward_data["dust_amount"]
            now = now_iso()
            
            # Mark reward as claimed (atomic operation to prevent double-claiming)
            try:
                self.dust_rewards_table.update_item(
                    Key={"wallet_address": wallet_address},
                    UpdateExpression="SET claimed = :true, claimed_at = :now, claimed_by_user_id = :user_id",
                    ConditionExpression="claimed = :false",  # Only update if not already claimed
                    ExpressionAttributeValues={
                        ":true": True,
                        ":false": False,
                        ":now": now,
                        ":user_id": user_id
                    }
                )
            except ClientError as e:
                if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
                    logger.warning("Reward already claimed (race condition)", context={
                        "wallet_address": wallet_address,
                        "user_id": user_id
                    })
                    return False, None, "Reward already claimed"
                raise
            
            # Add dust to user's resource balance
            try:
                # Get current DUST balance
                response = self.player_resources_table.get_item(
                    Key={
                        "user_id": user_id,
                        "resource_type": "DUST"
                    }
                )
                
                if "Item" in response:
                    # Update existing balance
                    current_balance = int(response["Item"].get("quantity", 0))
                    new_balance = current_balance + dust_amount
                    
                    self.player_resources_table.update_item(
                        Key={
                            "user_id": user_id,
                            "resource_type": "DUST"
                        },
                        UpdateExpression="SET quantity = :new_balance, updated_at = :now",
                        ExpressionAttributeValues={
                            ":new_balance": Decimal(str(new_balance)),
                            ":now": now
                        }
                    )
                else:
                    # Create new DUST resource
                    self.player_resources_table.put_item(Item={
                        "user_id": user_id,
                        "resource_type": "DUST",
                        "quantity": Decimal(str(dust_amount)),
                        "created_at": now,
                        "updated_at": now
                    })
                
                logger.info("Dust reward claimed successfully", context={
                    "wallet_address": wallet_address,
                    "user_id": user_id,
                    "dust_amount": dust_amount
                })
                
                return True, {
                    "wallet_address": wallet_address,
                    "dust_amount": dust_amount,
                    "claimed_at": now,
                    "user_id": user_id
                }, None
                
            except Exception as resource_error:
                # Rollback claim if resource update fails
                logger.error("Failed to add dust to resources, rolling back", error=resource_error, context={
                    "wallet_address": wallet_address,
                    "user_id": user_id
                })
                
                # Rollback claim
                try:
                    self.dust_rewards_table.update_item(
                        Key={"wallet_address": wallet_address},
                        UpdateExpression="SET claimed = :false REMOVE claimed_at, claimed_by_user_id",
                        ExpressionAttributeValues={":false": False}
                    )
                except Exception:
                    logger.error("Failed to rollback claim", context={
                        "wallet_address": wallet_address,
                        "user_id": user_id
                    })
                
                return False, None, "Failed to add dust to your account"
            
        except Exception as e:
            logger.error("Failed to claim dust reward", error=e, context={
                "wallet_address": wallet_address,
                "user_id": user_id
            })
            return False, None, "Failed to claim reward"
