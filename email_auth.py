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
        Register a new user with email and password (both required)
        Email verification is required before account is fully activated
        
        Returns:
            (success, user_data, error_message)
        """
        try:
            logger.info("Registration started", context={"email": email, "send_verification": send_verification})
            print(f"[REGISTER] Starting registration for {email}")
            
            # Validate email
            email = email.lower().strip()
            if not is_valid_email(email):
                logger.warning("Registration failed - invalid email", context={"email": email})
                print(f"[REGISTER] Invalid email: {email}")
                return False, None, "Invalid email address"
            
            # Validate password strength (required)
            is_strong, password_error = PasswordHasher.validate_password_strength(password)
            if not is_strong:
                logger.warning("Registration failed - weak password", context={"email": email, "error": password_error})
                print(f"[REGISTER] Password validation failed: {password_error}")
                return False, None, password_error
            
            # Check if email already exists
            try:
                logger.debug("Checking if email exists", context={"email": email})
                print(f"[REGISTER] Checking if email exists...")
                response = self.user_emails_table.get_item(Key={"email": email})
                if "Item" in response:
                    # Email exists - check if verified
                    existing_user_id = response["Item"]["user_id"]
                    user_response = self.users_table.get_item(Key={"user_id": existing_user_id})
                    if user_response.get("Item", {}).get("email_verified"):
                        logger.info("Registration attempt with existing verified email", context={"email": email, "user_id": existing_user_id})
                        print(f"[REGISTER] Email already registered and verified")
                        return False, None, "Email already registered"
                    else:
                        # Email exists but not verified - resend code
                        logger.info("Resending verification code for unverified email", context={"email": email, "user_id": existing_user_id})
                        print(f"[REGISTER] Email exists but not verified - resending code")
                        self._send_verification_email(email, existing_user_id, resend=True)
                        return True, {
                            "user": {"user_id": existing_user_id, "email": email},
                            "email_verification_required": True,
                            "message": "Verification code resent"
                        }, None
            except ClientError as e:
                logger.error("Error checking email existence", error=e, context={"email": email})
                print(f"[REGISTER] Error checking email: {e}")
                pass
            
            # Create user
            logger.debug("Creating new user", context={"email": email})
            print(f"[REGISTER] Creating user...")
            user_id = str(uuid.uuid4())
            password_hash = PasswordHasher.hash_password(password)
            now = now_iso()
            
            logger.debug("Creating User object", context={"user_id": user_id, "email": email})
            print(f"[REGISTER] Creating User object...")
            user = User(
                user_id=user_id,
                email=email,
                password_hash=password_hash,
                created_at=now,
                updated_at=now,
                email_verified=not config.ENABLE_EMAIL_VERIFICATION,
                require_email_verification=config.ENABLE_EMAIL_VERIFICATION,
                is_active=True
            )
            
            # Store in users table
            logger.debug("Storing user in database", context={"user_id": user_id})
            print(f"[REGISTER] Storing in users table...")
            self.users_table.put_item(Item=user.to_db_item())
            
            # Store email -> user_id mapping
            logger.debug("Storing email mapping", context={"email": email, "user_id": user_id})
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
                logger.info("Sending verification email", context={"user_id": user_id, "email": email})
                print(f"[REGISTER] Sending verification email...")
                self._send_verification_email(email, user_id)
            
            logger.info("User registration successful", context={"user_id": user_id, "email": email, "email_verification_required": config.ENABLE_EMAIL_VERIFICATION})
            print(f"[REGISTER] Registration successful!")
            return True, {
                "user": {"user_id": user_id, "email": email},
                "email_verification_required": config.ENABLE_EMAIL_VERIFICATION
            }, None
        
        except Exception as e:
            print(f"[REGISTER] Exception occurred: {type(e).__name__}: {str(e)}")
            import traceback
            print(f"[REGISTER] Traceback: {traceback.format_exc()}")
            logger.error("Registration failed with exception", error=e, context={
                "email": email,
                "error_type": type(e).__name__,
                "traceback": traceback.format_exc()
            })
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
            logger.info("Login attempt started", context={"email": email})
            email = email.lower().strip()
            
            # Get user_id from email
            logger.debug("Looking up user by email", context={"email": email})
            response = self.user_emails_table.get_item(Key={"email": email})
            if "Item" not in response:
                logger.warning("Login failed - email not found", context={"email": email})
                return False, None, "Invalid email or password"
            
            user_id = response["Item"]["user_id"]
            
            # Get user data
            logger.debug("Fetching user data", context={"user_id": user_id})
            response = self.users_table.get_item(Key={"user_id": user_id})
            if "Item" not in response:
                logger.error("Login failed - user data not found", context={"user_id": user_id, "email": email})
                return False, None, "User not found"
            
            user_data = response["Item"]
            
            # Check if account is active
            if not user_data.get("is_active", True):
                logger.warning("Login attempt on deactivated account", context={"user_id": user_id, "email": email})
                return False, None, "Account is deactivated"
            
            # Verify password first (before email verification check)
            logger.debug("Verifying password", context={"user_id": user_id})
            password_hash = user_data.get("password_hash")
            if not password_hash or not PasswordHasher.verify_password(password, password_hash):
                logger.warning("Failed login attempt - invalid password", context={"user_id": user_id, "email": email})
                return False, None, "Invalid email or password"
            
            # Check if 2-step login is required (user-specific setting or global config)
            require_verification = user_data.get("require_email_verification", config.ENABLE_EMAIL_VERIFICATION)
            if require_verification:
                # For 2-step login, ALWAYS require email verification on each login
                # Return special error that triggers verification code flow
                logger.info("2-step login required", context={"user_id": user_id, "email": email})
                return False, None, "2-step verification required. Please verify your email."
            
            # Update last login
            logger.debug("Updating last login timestamp", context={"user_id": user_id})
            self.users_table.update_item(
                Key={"user_id": user_id},
                UpdateExpression="SET last_login_at = :now",
                ExpressionAttributeValues={":now": now_iso()}
            )
            
            # Create user object
            user = User(**user_data)
            
            # Create auth tokens
            logger.debug("Creating auth tokens", context={"user_id": user_id})
            tokens = JWTHandler.create_token_pair(user_id)
            
            logger.info("User logged in successfully", context={"user_id": user_id, "email": email})
            
            return True, {
                "user": user.to_dict(),
                "tokens": tokens
            }, None
        
        except Exception as e:
            import traceback
            logger.error("Login failed with exception", error=e, context={
                "email": email,
                "error_type": type(e).__name__,
                "traceback": traceback.format_exc()
            })
            return False, None, "Login failed. Please try again."
    
    def request_password_reset(self, email: str) -> Tuple[bool, Optional[str]]:
        """
        Request password reset with 4-digit code
        
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
            
            # Generate 4-digit reset code
            reset_code = TokenGenerator.generate_verification_code(length=4)
            # Generate a unique token for DynamoDB primary key
            reset_token = TokenGenerator.generate_token(32)
            now = now_iso()
            expires = (datetime.now(timezone.utc) + timedelta(hours=config.PASSWORD_RESET_EXPIRE_HOURS)).isoformat()
            
            # Store reset code (token as primary key for DB compatibility, email for lookups)
            self.password_reset_table.put_item(Item={
                "token": reset_token,  # Primary key (required by existing table)
                "email": email,
                "code": reset_code,
                "user_id": user_id,
                "created_at": now,
                "expires_at": expires,
                "is_used": False
            })
            
            # Send reset email with 4-digit code
            try:
                logger.info(f"Sending password reset code to {email}")
                self.email_service.send_password_reset_code_email(email, reset_code)
                logger.info(f"Password reset code sent successfully to {email}")
            except Exception as email_error:
                logger.error(f"Failed to send password reset email to {email}", error=email_error, context={
                    "error_type": type(email_error).__name__,
                    "error_message": str(email_error)
                })
                # Continue anyway - code is stored
            
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
        email: str,
        reset_code: str,
        new_password: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Reset password using 4-digit code
        
        Returns:
            (success, error_message)
        """
        try:
            email = email.lower().strip()
            
            # Validate new password
            is_strong, password_error = PasswordHasher.validate_password_strength(new_password)
            if not is_strong:
                return False, password_error
            
            # Find reset code by scanning for email (since token is primary key)
            response = self.password_reset_table.scan(
                FilterExpression="email = :email AND is_used = :false",
                ExpressionAttributeValues={
                    ":email": email,
                    ":false": False
                }
            )
            
            if not response.get("Items"):
                return False, "Invalid or expired reset code"
            
            # Get the most recent reset code for this email
            reset_data = sorted(response["Items"], key=lambda x: x.get("created_at", ""), reverse=True)[0]
            
            # Check if code matches
            if reset_data.get("code") != reset_code:
                return False, "Invalid reset code"
            
            # Check if expired
            expires_at = datetime.fromisoformat(reset_data["expires_at"])
            if expires_at < datetime.now(timezone.utc):
                return False, "Reset code has expired"
            
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
            
            # Mark code as used
            self.password_reset_table.update_item(
                Key={"token": reset_data["token"]},  # Use token as primary key
                UpdateExpression="SET is_used = :true",
                ExpressionAttributeValues={":true": True}
            )
            
            logger.info("Password reset successful", context={"user_id": user_id, "email": email})
            
            return True, None
        
        except Exception as e:
            logger.error("Password reset failed", error=e)
            return False, "Failed to reset password"
    
    def verify_email(self, email: str, verification_code: str, return_token: bool = False) -> Tuple[bool, Optional[Dict], Optional[str]]:
        """
        Verify email using 4-digit code
        
        Args:
            email: User email
            verification_code: 4-digit verification code
            return_token: If True, returns JWT tokens for immediate login (2-step login flow)
                         If False, just marks email as verified (registration flow)
        
        Returns:
            (success, data, error_message)
            - For registration: (True, None, None)
            - For 2-step login: (True, {user, tokens}, None)
        """
        try:
            email = email.lower().strip()
            verification_code = verification_code.strip()
            
            # Get verification data by email (email is partition key)
            response = self.verification_table.get_item(
                Key={"email": email}
            )
            
            verification_data = response.get("Item")
            if not verification_data:
                return False, None, "No verification code found for this email"
            
            # Check if already used
            if verification_data.get("is_used"):
                return False, None, "Email already verified"
            
            # Check if expired
            expires_at = datetime.fromisoformat(verification_data["expires_at"])
            if expires_at < datetime.now(timezone.utc):
                return False, None, "Verification code has expired. Please request a new one."
            
            # Verify code
            if verification_data.get("code") != verification_code:
                return False, None, "Invalid verification code"
            
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
            
            # Mark code as used
            self.verification_table.update_item(
                Key={"email": email},
                UpdateExpression="SET is_used = :true",
                ExpressionAttributeValues={":true": True}
            )
            
            logger.info("Email verified", context={"user_id": user_id, "email": email, "return_token": return_token})
            
            # If return_token is True, generate JWT tokens for 2-step login
            if return_token:
                # Get full user data
                user_response = self.users_table.get_item(Key={"user_id": user_id})
                if "Item" not in user_response:
                    return False, None, "User not found"
                
                user_data = user_response["Item"]
                user = User(**user_data)
                
                # Update last login
                self.users_table.update_item(
                    Key={"user_id": user_id},
                    UpdateExpression="SET last_login_at = :now",
                    ExpressionAttributeValues={":now": now_iso()}
                )
                
                # Create auth tokens
                tokens = JWTHandler.create_token_pair(user_id)
                
                return True, {
                    "user": user.to_dict(),
                    "tokens": tokens
                }, None
            
            # Registration flow - just return success
            return True, None, None
        
        except Exception as e:
            logger.error("Email verification failed", error=e)
            return False, None, "Failed to verify email"
    
    def resend_verification_code(self, email: str) -> Tuple[bool, Optional[str]]:
        """\n        Resend verification code (same code, not a new one)
        
        Returns:
            (success, error_message)
        """
        try:
            email = email.lower().strip()
            
            # Get existing verification data
            response = self.verification_table.get_item(
                Key={"email": email}
            )
            
            verification_data = response.get("Item")
            if not verification_data:
                return False, "No verification code found. Please register first."
            
            # Check if already verified
            if verification_data.get("is_used"):
                return False, "Email already verified"
            
            # Check if expired
            expires_at = datetime.fromisoformat(verification_data["expires_at"])
            if expires_at < datetime.now(timezone.utc):
                # Generate new code if expired
                user_id = verification_data["user_id"]
                self._send_verification_email(email, user_id, resend=True)
                return True, None
            
            # Resend same code
            verification_code = verification_data.get("code")
            send_success = self.email_service.send_verification_code_email(email, verification_code)
            
            if send_success:
                logger.info(
                    "Verification code resent",
                    context={"email": email, "user_id": verification_data["user_id"]}
                )
                return True, None
            else:
                logger.error(
                    "Failed to resend verification code",
                    context={"email": email}
                )
                return False, "Failed to resend verification code"
        
        except Exception as e:
            logger.error("Resend verification code failed", error=e)
            return False, "Failed to resend verification code"
    
    def complete_registration(self, email: str, password: str) -> Tuple[bool, Optional[Dict], Optional[str]]:
        """
        Complete registration by setting password after email verification
        
        Returns:
            (success, auth_data, error_message)
        """
        try:
            email = email.lower().strip()
            
            # Validate password
            is_strong, password_error = PasswordHasher.validate_password_strength(password)
            if not is_strong:
                return False, None, password_error
            
            # Get user by email
            response = self.user_emails_table.get_item(Key={"email": email})
            if "Item" not in response:
                return False, None, "User not found"
            
            user_id = response["Item"]["user_id"]
            
            # Get user data
            user_response = self.users_table.get_item(Key={"user_id": user_id})
            if "Item" not in user_response:
                return False, None, "User not found"
            
            user_data = user_response["Item"]
            
            # Check if email is verified
            if not user_data.get("email_verified"):
                return False, None, "Please verify your email first"
            
            # Update password
            password_hash = PasswordHasher.hash_password(password)
            self.users_table.update_item(
                Key={"user_id": user_id},
                UpdateExpression="SET password_hash = :hash, updated_at = :now",
                ExpressionAttributeValues={
                    ":hash": password_hash,
                    ":now": now_iso()
                }
            )
            
            # Create auth tokens
            tokens = JWTHandler.create_token_pair(user_id)
            
            # Get updated user
            user = User(**user_data)
            
            logger.info("Registration completed", context={"user_id": user_id, "email": email})
            
            return True, {
                "user": user.to_dict(),
                "tokens": tokens
            }, None
        
        except Exception as e:
            logger.error("Complete registration failed", error=e)
            return False, None, "Failed to complete registration"
    
    def _send_verification_email(self, email: str, user_id: str, resend: bool = False):
        """Send verification email with 4-digit code"""
        from security import TokenGenerator
        
        # Generate 4-digit verification code
        verification_code = TokenGenerator.generate_verification_code(length=4)
        now = now_iso()
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=config.EMAIL_VERIFICATION_EXPIRE_HOURS)).isoformat()
        
        # Store verification code (email is partition key)
        self.verification_table.put_item(Item={
            "email": email,
            "code": verification_code,
            "user_id": user_id,
            "created_at": now,
            "expires_at": expires_at,
            "is_used": False
        })
        
        # Send verification email via SES with 4-digit code
        send_success = self.email_service.send_verification_code_email(email, verification_code)
        if send_success:
            logger.info(
                "Verification code sent successfully",
                context={"email": email, "user_id": user_id, "resend": resend}
            )
        else:
            logger.error(
                "Failed to send verification code",
                context={"email": email, "user_id": user_id}
            )
    
    def request_password_change_verification(self, user_id: str, email: str) -> Tuple[bool, Optional[str]]:
        """
        Request a verification code for authenticated password change
        Sends 4-digit code to user's email
        
        Args:
            user_id: Authenticated user ID
            email: User's email address
        
        Returns:
            (success, error_message)
        """
        try:
            email = email.lower().strip()
            
            # Verify user exists and email matches
            user_response = self.users_table.get_item(Key={"user_id": user_id})
            if "Item" not in user_response:
                return False, "User not found"
            
            user_data = user_response["Item"]
            if user_data.get("email", "").lower() != email:
                return False, "Email does not match user account"
            
            # Generate 4-digit verification code
            verification_code = TokenGenerator.generate_verification_code(length=4)
            now = now_iso()
            expires_at = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()
            
            # Store verification code in email_verification table
            # Using email as primary key (same table as registration verification)
            self.verification_table.put_item(Item={
                "email": email,
                "code": verification_code,
                "user_id": user_id,
                "created_at": now,
                "expires_at": expires_at,
                "is_used": False,
                "purpose": "password_change"  # To distinguish from registration
            })
            
            # Send verification email
            try:
                send_success = self.email_service.send_verification_code_email(
                    email, 
                    verification_code
                )
                if send_success:
                    logger.info(
                        "Password change verification code sent",
                        context={"email": email, "user_id": user_id}
                    )
                else:
                    logger.error(
                        "Failed to send password change verification code",
                        context={"email": email, "user_id": user_id}
                    )
                    return False, "Failed to send verification code"
            except Exception as email_error:
                logger.error(
                    "Failed to send password change verification email",
                    error=email_error,
                    context={"email": email, "user_id": user_id}
                )
                return False, "Failed to send verification code"
            
            return True, None
        
        except Exception as e:
            logger.error("Request password change verification failed", error=e)
            return False, "Failed to request verification code"
    
    def confirm_password_change_with_code(
        self, 
        user_id: str, 
        email: str, 
        verification_code: str, 
        new_password: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Confirm password change with verification code
        
        Args:
            user_id: Authenticated user ID
            email: User's email address
            verification_code: 4-digit verification code
            new_password: New password
        
        Returns:
            (success, error_message)
        """
        try:
            email = email.lower().strip()
            verification_code = verification_code.strip()
            
            # Validate new password strength
            is_strong, password_error = PasswordHasher.validate_password_strength(new_password)
            if not is_strong:
                return False, password_error
            
            # Verify user exists and email matches
            user_response = self.users_table.get_item(Key={"user_id": user_id})
            if "Item" not in user_response:
                return False, "User not found"
            
            user_data = user_response["Item"]
            if user_data.get("email", "").lower() != email:
                return False, "Email does not match user account"
            
            # Get verification data
            response = self.verification_table.get_item(Key={"email": email})
            verification_data = response.get("Item")
            
            if not verification_data:
                return False, "No verification code found. Please request a new code."
            
            # Check if already used
            if verification_data.get("is_used"):
                return False, "Verification code already used. Please request a new code."
            
            # Check if expired
            expires_at = datetime.fromisoformat(verification_data["expires_at"])
            if expires_at < datetime.now(timezone.utc):
                return False, "Verification code has expired. Please request a new code."
            
            # Verify code matches
            if verification_data.get("code") != verification_code:
                return False, "Invalid verification code"
            
            # Verify the verification code belongs to this user
            if verification_data.get("user_id") != user_id:
                return False, "Verification code does not match user"
            
            # Update password
            password_hash = PasswordHasher.hash_password(new_password)
            self.users_table.update_item(
                Key={"user_id": user_id},
                UpdateExpression="SET password_hash = :hash, updated_at = :now",
                ExpressionAttributeValues={
                    ":hash": password_hash,
                    ":now": now_iso()
                }
            )
            
            # Mark verification code as used
            self.verification_table.update_item(
                Key={"email": email},
                UpdateExpression="SET is_used = :true",
                ExpressionAttributeValues={":true": True}
            )
            
            logger.info(
                "Password changed successfully with verification code",
                context={"user_id": user_id, "email": email}
            )
            
            return True, None
        
        except Exception as e:
            logger.error("Confirm password change failed", error=e)
            return False, "Failed to change password"
