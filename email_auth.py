"""
Email-based authentication
Registration, login, password reset, email verification
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional, Tuple

import boto3
from botocore.exceptions import ClientError

from config import config
from models import User, EmailVerification, PasswordReset, now_iso
from security import PasswordHasher, TokenGenerator, is_valid_email
from validation import Validator, ValidationError
from jwt_handler import JWTHandler
from logger import logger
from email_service import EmailService


class EmailAuthService:
    """Email authentication service"""
    
    def __init__(self):
        self.dynamodb = boto3.resource('dynamodb', region_name=config.AWS_REGION)
        self.users_table = self.dynamodb.Table(config.TABLE_USERS)
        self.user_emails_table = self.dynamodb.Table(config.TABLE_USER_EMAILS)
        self.verification_table = self.dynamodb.Table(config.TABLE_EMAIL_VERIFICATION)
        self.password_reset_table = self.dynamodb.Table(config.TABLE_PASSWORD_RESET)
        self.email_service = EmailService()
    
    def register(
        self,
        email: str,
        password: str,
        send_verification: bool = True
    ) -> Tuple[bool, Optional[Dict], Optional[str]]:
        """
        Register a new user with email and password
        
        Returns:
            (success, user_data, error_message)
        """
        try:
            print(f"[REGISTER] Starting registration for {email}")
            
            # Validate email
            email = email.lower().strip()
            if not is_valid_email(email):
                print(f"[REGISTER] Invalid email: {email}")
                return False, None, "Invalid email address"
            
            # Validate password strength
            is_strong, password_error = PasswordHasher.validate_password_strength(password)
            if not is_strong:
                print(f"[REGISTER] Password validation failed: {password_error}")
                return False, None, password_error
            
            # Check if email already exists
            try:
                print(f"[REGISTER] Checking if email exists...")
                response = self.user_emails_table.get_item(Key={"email": email})
                if "Item" in response:
                    print(f"[REGISTER] Email already registered")
                    return False, None, "Email already registered"
            except ClientError as e:
                print(f"[REGISTER] Error checking email: {e}")
                pass
            
            # Create user
            print(f"[REGISTER] Creating user...")
            user_id = str(uuid.uuid4())
            password_hash = PasswordHasher.hash_password(password)
            now = now_iso()
            
            print(f"[REGISTER] Creating User object...")
            user = User(
                user_id=user_id,
                email=email,
                password_hash=password_hash,
                created_at=now,
                updated_at=now,
                email_verified=not config.ENABLE_EMAIL_VERIFICATION,
                is_active=True
            )
            
            # Store in users table
            print(f"[REGISTER] Storing in users table...")
            self.users_table.put_item(Item=user.to_db_item())
            
            # Store email -> user_id mapping
            print(f"[REGISTER] Storing email mapping...")
            self.user_emails_table.put_item(Item={
                "email": email,
                "user_id": user_id,
                "created_at": now
            })
            
            logger.info(
                "User registered",
                context={"user_id": user_id, "email": email}
            )
            
            # Send verification email if enabled
            if config.ENABLE_EMAIL_VERIFICATION and send_verification:
                print(f"[REGISTER] Sending verification email...")
                self._send_verification_email(email, user_id)
            
            # Create auth tokens
            print(f"[REGISTER] Creating JWT tokens...")
            tokens = JWTHandler.create_token_pair(user_id)
            
            print(f"[REGISTER] Registration successful!")
            return True, {
                "user": user.to_dict(),
                "tokens": tokens,
                "email_verification_required": config.ENABLE_EMAIL_VERIFICATION
            }, None
        
        except Exception as e:
            print(f"[REGISTER] Exception occurred: {type(e).__name__}: {str(e)}")
            import traceback
            print(f"[REGISTER] Traceback: {traceback.format_exc()}")
            logger.error("Registration failed", error=e)
            return False, None, "Registration failed. Please try again."
    
    def login(
        self,
        email: str,
        password: str
    ) -> Tuple[bool, Optional[Dict], Optional[str]]:
        """
        Authenticate user with email and password
        
        Returns:
            (success, auth_data, error_message)
        """
        try:
            email = email.lower().strip()
            
            # Get user_id from email
            response = self.user_emails_table.get_item(Key={"email": email})
            if "Item" not in response:
                return False, None, "Invalid email or password"
            
            user_id = response["Item"]["user_id"]
            
            # Get user data
            response = self.users_table.get_item(Key={"user_id": user_id})
            if "Item" not in response:
                return False, None, "User not found"
            
            user_data = response["Item"]
            
            # Check if account is active
            if not user_data.get("is_active", True):
                return False, None, "Account is deactivated"
            
            # Check email verification (if enabled)
            if config.ENABLE_EMAIL_VERIFICATION:
                if not user_data.get("email_verified", False):
                    logger.warning("Login attempt with unverified email", context={"email": email})
                    return False, None, "Please verify your email address before logging in. Check your inbox for the verification link."
            
            # Verify password
            password_hash = user_data.get("password_hash")
            if not password_hash or not PasswordHasher.verify_password(password, password_hash):
                logger.warning("Failed login attempt", context={"email": email})
                return False, None, "Invalid email or password"
            
            # Update last login
            self.users_table.update_item(
                Key={"user_id": user_id},
                UpdateExpression="SET last_login_at = :now",
                ExpressionAttributeValues={":now": now_iso()}
            )
            
            # Create user object
            user = User(**user_data)
            
            # Create auth tokens
            tokens = JWTHandler.create_token_pair(user_id)
            
            logger.info("User logged in", context={"user_id": user_id})
            
            return True, {
                "user": user.to_dict(),
                "tokens": tokens
            }, None
        
        except Exception as e:
            logger.error("Login failed", error=e)
            return False, None, "Login failed. Please try again."
    
    def request_password_reset(self, email: str) -> Tuple[bool, Optional[str]]:
        """
        Request password reset
        
        Returns:
            (success, error_message)
        """
        try:
            email = email.lower().strip()
            
            # Get user_id from email
            response = self.user_emails_table.get_item(Key={"email": email})
            if "Item" not in response:
                # Don't reveal if email exists
                return True, None
            
            user_id = response["Item"]["user_id"]
            
            # Generate reset token
            reset_token = TokenGenerator.generate_token(32)
            now = now_iso()
            expires = (datetime.now(timezone.utc) + timedelta(hours=config.PASSWORD_RESET_EXPIRE_HOURS)).isoformat()
            
            # Store reset token
            self.password_reset_table.put_item(Item={
                "token": reset_token,  # Primary key
                "email": email,
                "user_id": user_id,
                "created_at": now,
                "expires_at": expires,
                "is_used": False
            })
            
            # Send reset email
            try:
                logger.info(f"Sending password reset email to {email}")
                self.email_service.send_password_reset_email(email, reset_token)
                logger.info(f"Password reset email sent successfully to {email}")
            except Exception as email_error:
                logger.error(f"Failed to send password reset email to {email}", error=email_error, context={
                    "error_type": type(email_error).__name__,
                    "error_message": str(email_error)
                })
                # Continue anyway - token is stored
            
            logger.info("Password reset requested", context={"email": email})
            
            return True, None
        
        except Exception as e:
            import traceback
            logger.error("Password reset request failed", error=e, context={
                "error_type": type(e).__name__,
                "error_message": str(e),
                "traceback": traceback.format_exc()
            })
            return False, "Failed to process request"
    
    def reset_password(
        self,
        reset_token: str,
        new_password: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Reset password using reset token
        
        Returns:
            (success, error_message)
        """
        try:
            # Validate new password
            is_strong, password_error = PasswordHasher.validate_password_strength(new_password)
            if not is_strong:
                return False, password_error
            
            # Find reset token using primary key
            response = self.password_reset_table.get_item(Key={"token": reset_token})
            
            if "Item" not in response:
                return False, "Invalid or expired reset token"
            
            reset_data = response["Item"]
            
            # Check if already used
            if reset_data.get("is_used"):
                return False, "Reset token already used"
            
            # Check if expired
            expires_at = datetime.fromisoformat(reset_data["expires_at"])
            if expires_at < datetime.now(timezone.utc):
                return False, "Reset token has expired"
            
            # Update password
            user_id = reset_data["user_id"]
            password_hash = PasswordHasher.hash_password(new_password)
            
            self.users_table.update_item(
                Key={"user_id": user_id},
                UpdateExpression="SET password_hash = :hash, updated_at = :now",
                ExpressionAttributeValues={
                    ":hash": password_hash,
                    ":now": now_iso()
                }
            )
            
            # Mark token as used
            self.password_reset_table.update_item(
                Key={"token": reset_token},  # Use token as primary key
                UpdateExpression="SET is_used = :true",
                ExpressionAttributeValues={":true": True}
            )
            
            logger.info("Password reset successful", context={"user_id": user_id})
            
            return True, None
        
        except Exception as e:
            logger.error("Password reset failed", error=e)
            return False, "Failed to reset password"
    
    def verify_email(self, verification_token: str) -> Tuple[bool, Optional[str]]:
        """
        Verify email using verification token
        
        Returns:
            (success, error_message)
        """
        try:
            # Get verification token directly (token is partition key)
            response = self.verification_table.get_item(
                Key={"token": verification_token}
            )
            
            verification_data = response.get("Item")
            if not verification_data:
                return False, "Invalid verification token"
            
            # Check if already used
            if verification_data.get("is_used"):
                return False, "Email already verified"
            
            # Check if expired
            expires_at = datetime.fromisoformat(verification_data["expires_at"])
            if expires_at < datetime.now(timezone.utc):
                return False, "Verification token has expired"
            
            # Update user
            user_id = verification_data["user_id"]
            self.users_table.update_item(
                Key={"user_id": user_id},
                UpdateExpression="SET email_verified = :true, updated_at = :now",
                ExpressionAttributeValues={
                    ":true": True,
                    ":now": now_iso()
                }
            )
            
            # Mark token as used
            self.verification_table.update_item(
                Key={"token": verification_token},
                UpdateExpression="SET is_used = :true",
                ExpressionAttributeValues={":true": True}
            )
            
            logger.info("Email verified", context={"user_id": user_id})
            
            return True, None
        
        except Exception as e:
            logger.error("Email verification failed", error=e)
            return False, "Failed to verify email"
    
    def _send_verification_email(self, email: str, user_id: str):
        """Send verification email"""
        verification_token = TokenGenerator.generate_token(32)
        now = now_iso()
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=config.EMAIL_VERIFICATION_EXPIRE_HOURS)).isoformat()
        
        # Store verification token (token is partition key)
        self.verification_table.put_item(Item={
            "token": verification_token,
            "email": email,
            "user_id": user_id,
            "created_at": now,
            "expires_at": expires_at,
            "is_used": False
        })
        
        # Send verification email via SES using EmailService instance
        send_success = self.email_service.send_verification_email(email, verification_token)
        if send_success:
            logger.info(
                "Verification email sent successfully",
                context={"email": email, "user_id": user_id}
            )
        else:
            logger.error(
                "Failed to send verification email",
                context={"email": email, "user_id": user_id}
            )
