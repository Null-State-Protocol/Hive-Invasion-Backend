"""
Email-based authentication
Registration, login, password reset, email verification
"""

import re
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


BLOCKED_EMAIL_DOMAINS = {
    'rambler.ru', 'kubi91.icu', 'mailnull.com', 'guerrillamail.com',
    'tempmail.com', 'throwaway.email', 'yopmail.com', 'trashmail.com',
    'sharklasers.com', 'guerrillamailblock.com', 'grr.la', 'guerrillamail.info',
    'spam4.me', 'dispostable.com', 'mailinator.com', 'maildrop.cc',
    'fakeinbox.com', 'tempr.email', 'discard.email', 'spamgourmet.com',
    'sharebot.net', 'razeny.com', 'moneylogtips.com', 'btcmod.com',
    'edudingy.cfd', 'coffeepancakewafflebacon.com',
    # Bot/spam domains seen in attack (18 Mar 2026)
    'mail.ru', 'list.ru', 'inbox.ru', 'bk.ru', 'internet.ru',
    'email.com', 'gamil.com',  # common typo-squat domains
    # Bot domains seen in attack (19 Mar 2026)
    'maxric.com', 'tgvis.com', 'steveix.com', 'anypsd.com',
    'cevipsa.com', 'cpav3.com', 'tenvil.com', 'amozix.com',
    'nuclene.com', 'chromomail.com', 'bolivianomail.com',
    'fexpost.com', 'daymailonline.com', 'spamex.com', 'yevme.com',
}

BLOCKED_EMAIL_DOMAIN_SUFFIXES = (
    '.mailinator.com',
    '.guerrillamail.com',
    '.guerrillamailblock.com',
    '.spamgourmet.com',
    '.trashmail.com',
    '.yopmail.com',
    '.tempmail.com',
    '.maildrop.cc',
    '.mailnull.com',
)

BLOCKED_EMAIL_TLDS = {
    '.icu', '.cfd', '.tk', '.ml', '.ga', '.cf', '.gq', '.buzz', '.click', '.top'
}


# Bot username pattern: 8+ lowercase letters + exactly 4 digits (e.g. smartfire8842, luckywolf4878)
# Only applied for non-major email providers to avoid false positives on real users.
_BOT_USERNAME_RE = re.compile(r'^[a-z]{8,}\d{4}$')
_MAJOR_EMAIL_PROVIDERS = {
    'gmail.com', 'googlemail.com',
    'hotmail.com', 'hotmail.co.uk', 'hotmail.fr',
    'outlook.com', 'outlook.jp', 'live.com', 'msn.com',
    'yahoo.com', 'yahoo.co.uk', 'yahoo.fr', 'yahoo.jp',
    'icloud.com', 'me.com', 'mac.com',
    'proton.me', 'protonmail.com',
    'yandex.com', 'yandex.ru',
}


def is_bot_username(local_part: str, domain: str) -> bool:
    """Return True when username matches known bot generation pattern.
    Only active for non-major email providers to avoid false positives."""
    if domain.lower() in _MAJOR_EMAIL_PROVIDERS:
        return False
    return bool(_BOT_USERNAME_RE.match(local_part.lower()))


def get_email_domain_block_reason(email_domain: str) -> Optional[str]:
    """Return reason string when an email domain should be blocked."""
    if not email_domain:
        return None

    domain = email_domain.lower().strip()

    if domain in BLOCKED_EMAIL_DOMAINS:
        return f"domain:{domain}"

    for suffix in BLOCKED_EMAIL_DOMAIN_SUFFIXES:
        if domain.endswith(suffix):
            return f"suffix:{suffix}"

    if '.' in domain:
        tld = f".{domain.rsplit('.', 1)[-1]}"
        if tld in BLOCKED_EMAIL_TLDS:
            return f"tld:{tld}"

    return None


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
        Account is NOT created until email is verified with the code
        
        Flow:
        1. Validate email and password
        2. Store pending registration in verification table
        3. Send verification code
        4. User must call verify_email() to complete registration
        
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
            
            # Block disposable/spam email domains (exact + suffix + TLD)
            email_domain = email.split('@')[1].lower() if '@' in email else ''
            block_reason = get_email_domain_block_reason(email_domain)
            if block_reason:
                logger.warning(
                    "Registration blocked - disposable/spam email domain",
                    context={"email": email, "domain": email_domain, "reason": block_reason}
                )
                print(f"[REGISTER] Blocked domain ({block_reason}): {email_domain}")
                return False, None, "Registration not allowed from this email provider."

            # Block obvious bot usernames: word+digits pattern (e.g. smartfire8842)
            email_local = email.split('@')[0] if '@' in email else email
            if is_bot_username(email_local, email_domain):
                logger.warning(
                    "Registration blocked - bot username pattern",
                    context={"email": email, "local": email_local}
                )
                print(f"[REGISTER] Blocked bot pattern username: {email_local}")
                return False, None, "Registration not allowed from this email provider."

            # Validate password strength (required)
            is_strong, password_error = PasswordHasher.validate_password_strength(password)
            if not is_strong:
                logger.warning("Registration failed - weak password", context={"email": email, "error": password_error})
                print(f"[REGISTER] Password validation failed: {password_error}")
                return False, None, password_error
            
            # Check if email already exists as verified user
            try:
                logger.debug("Checking if email exists", context={"email": email})
                print(f"[REGISTER] Checking if email exists...")
                response = self.user_emails_table.get_item(Key={"email": email})
                if "Item" in response:
                    # Email is in the email-mapping table. But check if the actual
                    # user account exists in hive_users — partial failures can leave
                    # an orphan email-mapping entry with no backing user record.
                    mapped_user_id = response["Item"].get("user_id")
                    user_exists = False
                    if mapped_user_id:
                        try:
                            ur = self.users_table.get_item(Key={"user_id": mapped_user_id})
                            user_exists = "Item" in ur
                        except Exception:
                            pass

                    if user_exists:
                        # Fully registered account — cannot re-register
                        logger.info("Registration attempt with existing email", context={"email": email})
                        print(f"[REGISTER] Email already registered")
                        return False, None, "An account with this email already exists. Please log in or use the forgot password option."
                    else:
                        # Orphan mapping (partial account creation failure) — clean it up
                        # and allow re-registration so the user is not permanently blocked.
                        logger.warning(
                            "Orphan email mapping found — no backing user record, cleaning up",
                            context={"email": email, "orphan_user_id": mapped_user_id}
                        )
                        print(f"[REGISTER] Orphan email mapping detected, removing and allowing re-registration")
                        try:
                            self.user_emails_table.delete_item(Key={"email": email})
                        except Exception:
                            pass
            except ClientError as e:
                logger.error("Error checking email existence", error=e, context={"email": email})
                print(f"[REGISTER] Error checking email: {e}")
                pass

            # Rate limit / resend logic for unverified pending registrations.
            # - < 60 s  : too soon, ask user to wait
            # - 60 s – 24 h : resend a fresh code (covers expired codes too)
            # - expired  : fall through to fresh registration
            try:
                existing_pending = self.verification_table.get_item(Key={"email": email}).get("Item")
            except Exception:
                existing_pending = None  # DB error — proceed to fresh registration

            if existing_pending and not existing_pending.get("is_used"):
                created_at_str = existing_pending.get("created_at", "")
                try:
                    created_at_dt = datetime.fromisoformat(created_at_str.replace("Z", "+00:00"))
                    seconds_ago = (datetime.now(timezone.utc) - created_at_dt).total_seconds()
                except Exception:
                    seconds_ago = 9999  # parse error — treat as old

                if seconds_ago < 60:  # Hard cooldown — too soon
                    wait = int(60 - seconds_ago)
                    logger.warning("Registration rate limited", context={"email": email, "wait_seconds": wait})
                    print(f"[REGISTER] Rate limited, wait {wait}s for {email}")
                    return False, None, f"Verification email already sent. Please check your inbox (and spam folder) or wait {wait} seconds."

                # 60 s or more: resend a fresh code
                # (covers both the 60s-5min window AND expired codes where user retries)
                try:
                    from security import TokenGenerator
                    new_code = TokenGenerator.generate_verification_code(length=4)
                    new_now = now_iso()
                    new_expires = (datetime.now(timezone.utc) + timedelta(hours=config.EMAIL_VERIFICATION_EXPIRE_HOURS)).isoformat()
                    # Keep same user_id + password_hash from the existing pending record
                    self.verification_table.update_item(
                        Key={"email": email},
                        UpdateExpression="SET #code = :code, created_at = :now, expires_at = :exp, is_used = :f",
                        ExpressionAttributeNames={"#code": "code"},
                        ExpressionAttributeValues={
                            ":code": new_code,
                            ":now": new_now,
                            ":exp": new_expires,
                            ":f": False,
                        }
                    )
                    print(f"[REGISTER] Resending verification code to {email}...")
                    send_success = self.email_service.send_verification_code_email(email, new_code)
                    logger.info("Verification code resent on re-registration attempt", context={"email": email, "seconds_since_last": int(seconds_ago)})
                    if send_success:
                        print(f"[REGISTER] Resend OK for {email}")
                        return True, {
                            "email": email,
                            "message": "A new verification code has been sent to your email. Please check your inbox and spam folder.",
                            "email_verification_required": True,
                            "resent": True
                        }, None
                    else:
                        print(f"[REGISTER] Resend FAILED (email_service returned False) for {email}")
                        logger.error("Failed to resend verification email", context={"email": email})
                        return False, None, "Failed to send verification email. Please try again."
                except Exception as resend_err:
                    import traceback
                    print(f"[REGISTER] Resend exception for {email}: {resend_err}")
                    logger.error("Exception during verification resend", error=resend_err, context={
                        "email": email,
                        "traceback": traceback.format_exc()
                    })
                    return False, None, "Failed to send verification email. Please try again."
            
            # Generate temporary user_id for pending registration
            logger.debug("Creating pending registration", context={"email": email})
            print(f"[REGISTER] Creating pending registration...")
            user_id = str(uuid.uuid4())
            password_hash = PasswordHasher.hash_password(password)
            
            # Generate 4-digit verification code
            from security import TokenGenerator
            verification_code = TokenGenerator.generate_verification_code(length=4)
            now = now_iso()
            expires_at = (datetime.now(timezone.utc) + timedelta(hours=config.EMAIL_VERIFICATION_EXPIRE_HOURS)).isoformat()
            
            # Store pending registration in verification table
            # IMPORTANT: Account is NOT created yet - only pending data stored
            logger.debug("Storing pending registration", context={"email": email, "user_id": user_id})
            print(f"[REGISTER] Storing pending registration data...")
            self.verification_table.put_item(Item={
                "email": email,
                "code": verification_code,
                "user_id": user_id,
                "password_hash": password_hash,  # Store hashed password for account creation later
                "created_at": now,
                "expires_at": expires_at,
                "is_used": False,
                "purpose": "registration"  # Distinguish from login verification
            })
            
            logger.info(
                "Pending registration created",
                context={"user_id": user_id, "email": email}
            )
            
            # Send verification email
            if send_verification:
                logger.info("Sending verification email", context={"user_id": user_id, "email": email})
                print(f"[REGISTER] Sending verification email...")
                send_success = self.email_service.send_verification_code_email(email, verification_code)
                if not send_success:
                    logger.error("Failed to send verification code", context={"email": email})
                    return False, None, "Failed to send verification code. Please try again."
            
            logger.info("Registration pending verification", context={"user_id": user_id, "email": email})
            print(f"[REGISTER] Verification code sent! Account will be created after verification.")
            return True, {
                "email": email,
                "message": "Verification code sent. Please check your email to complete registration.",
                "email_verification_required": True
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
                return False, None, "Email not found. Please register first."
            
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
            
            # Check if 2-step login is required (user-specific opt-in ONLY, not global default)
            # Default is False - users must explicitly have require_email_verification=True to get 2-step
            require_verification = user_data.get("require_email_verification", False)
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
                send_success = self.email_service.send_password_reset_code_email(email, reset_code)
                if send_success:
                    logger.info(f"Password reset code sent successfully to {email}")
                else:
                    logger.error(
                        "Failed to send password reset code",
                        context={"email": email, "user_id": user_id}
                    )
                    return False, "Failed to send reset code"
            except Exception as email_error:
                logger.error(f"Failed to send password reset email to {email}", error=email_error, context={
                    "error_type": type(email_error).__name__,
                    "error_message": str(email_error)
                })
                return False, "Failed to send reset code"
            
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
        Verify email using 4-digit code and CREATE the account
        
        Args:
            email: User email
            verification_code: 4-digit verification code
            return_token: If True, returns JWT tokens for immediate login (2-step login flow)
                         If False, just creates account (registration flow)
        
        Returns:
            (success, data, error_message)
            - For registration: (True, {user, tokens}, None) - account created
            - For 2-step login: (True, {user, tokens}, None) - login successful
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
                return False, None, "Verification code already used"
            
            # Check if expired
            expires_at = datetime.fromisoformat(verification_data["expires_at"])
            if expires_at < datetime.now(timezone.utc):
                return False, None, "Verification code has expired. Please register again."
            
            # Verify code
            if verification_data.get("code") != verification_code:
                return False, None, "Invalid verification code"
            
            user_id = verification_data["user_id"]
            purpose = verification_data.get("purpose", "login")
            
            # REGISTRATION FLOW: Create the account now
            if purpose == "registration":
                logger.info("Creating account after verification", context={"user_id": user_id, "email": email})
                print(f"[VERIFY] Creating account for {email}...")
                
                # Get password hash from verification data
                password_hash = verification_data.get("password_hash")
                if not password_hash:
                    logger.error("No password hash found in verification data", context={"email": email})
                    return False, None, "Invalid verification data. Please register again."
                
                now = now_iso()
                
                # Create user account NOW (after verification)
                user = User(
                    user_id=user_id,
                    email=email,
                    password_hash=password_hash,
                    created_at=now,
                    updated_at=now,
                    email_verified=True,  # Already verified
                    require_email_verification=False,  # No need to verify again
                    is_active=True,
                    last_login_at=now
                )
                
                # Store in users table
                logger.debug("Storing user in database", context={"user_id": user_id})
                print(f"[VERIFY] Storing user in database...")
                self.users_table.put_item(Item=user.to_db_item())
                
                # Initialize player data with no starter keys
                logger.debug("Initializing player data for new user", context={"user_id": user_id})
                try:
                    player_table = self.dynamodb.Table("hive_player_data")
                    player_table.put_item(Item={
                        "user_id": user_id,
                        "level": 1,
                        "total_score": 0,
                        "games_played": 0,
                        "games_won": 0,
                        "highest_wave": 0,
                        "dust_count": 0,
                        "gems": 0,
                        "chest_opened": 0,
                        "high_score": 0,
                        "keys_owned": {
                            "bronze": 0,
                            "silver": 0,
                            "gold": 0
                        },
                        "created_at": now
                    })
                    logger.debug("Player data initialized with no starter keys", context={"user_id": user_id})
                except Exception as e:
                    logger.error("Failed to initialize player data", error=e, context={"user_id": user_id})
                    # Don't fail account creation if player data init fails - it can be created later
                
                # Store email -> user_id mapping
                logger.debug("Storing email mapping", context={"email": email, "user_id": user_id})
                self.user_emails_table.put_item(Item={
                    "email": email,
                    "user_id": user_id,
                    "created_at": now
                })
                
                # Mark code as used and verified
                self.verification_table.update_item(
                    Key={"email": email},
                    UpdateExpression="SET is_used = :true, verified_status = :verified, verified_at = :now",
                    ExpressionAttributeValues={
                        ":true": True,
                        ":verified": "verified",
                        ":now": now
                    }
                )
                
                # Create auth tokens for immediate login
                tokens = JWTHandler.create_token_pair(user_id)
                
                logger.info("Account created and verified successfully", context={"user_id": user_id, "email": email})
                print(f"[VERIFY] Account created successfully!")
                
                return True, {
                    "user": user.to_dict(),
                    "tokens": tokens,
                    "message": "Account created successfully!"
                }, None
            
            # 2-STEP LOGIN FLOW: User already exists, just verify and login
            else:
                logger.info("2-step login verification", context={"user_id": user_id, "email": email})
                
                # Update user email_verified
                self.users_table.update_item(
                    Key={"user_id": user_id},
                    UpdateExpression="SET email_verified = :true, last_login_at = :now, updated_at = :now",
                    ExpressionAttributeValues={
                        ":true": True,
                        ":now": now_iso()
                    }
                )
                
                # Mark code as used and verified
                now = now_iso()
                self.verification_table.update_item(
                    Key={"email": email},
                    UpdateExpression="SET is_used = :true, verified_status = :verified, verified_at = :now",
                    ExpressionAttributeValues={
                        ":true": True,
                        ":verified": "verified",
                        ":now": now
                    }
                )
                
                # Get full user data
                user_response = self.users_table.get_item(Key={"user_id": user_id})
                if "Item" not in user_response:
                    return False, None, "User not found"
                
                user_data = user_response["Item"]
                user = User(**user_data)
                
                # Create auth tokens
                tokens = JWTHandler.create_token_pair(user_id)
                
                logger.info("Email verified and logged in", context={"user_id": user_id, "email": email})
                
                return True, {
                    "user": user.to_dict(),
                    "tokens": tokens
                }, None
        
        except Exception as e:
            logger.error("Email verification failed", error=e)
            import traceback
            print(f"[VERIFY] Exception: {traceback.format_exc()}")
            return False, None, "Failed to verify email"
    
    def resend_verification_code(self, email: str) -> Tuple[bool, Optional[str]]:
        """
        Resend verification code (generate new code if expired)
        
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

            # Rate limit: max 5 resends per session, 60s cooldown between resends
            MAX_RESENDS = 5
            RESEND_COOLDOWN_SECONDS = 60
            resend_count = int(verification_data.get("resend_count", 0))
            last_resend_at = verification_data.get("last_resend_at")

            if resend_count >= MAX_RESENDS:
                logger.warning("Resend limit reached", context={"email": email, "resend_count": resend_count})
                return False, "Too many code requests. Please wait and try registering again later."

            if last_resend_at:
                try:
                    last_dt = datetime.fromisoformat(last_resend_at.replace("Z", "+00:00"))
                    seconds_since = (datetime.now(timezone.utc) - last_dt).total_seconds()
                    if seconds_since < RESEND_COOLDOWN_SECONDS:
                        wait = int(RESEND_COOLDOWN_SECONDS - seconds_since)
                        return False, f"Please wait {wait} seconds before requesting a new code."
                except Exception:
                    pass
            
            user_id = verification_data["user_id"]
            password_hash = verification_data.get("password_hash")  # For registration flow
            purpose = verification_data.get("purpose", "login")
            
            # Check if expired
            expires_at = datetime.fromisoformat(verification_data["expires_at"])
            if expires_at < datetime.now(timezone.utc):
                # Generate new code if expired
                from security import TokenGenerator
                verification_code = TokenGenerator.generate_verification_code(length=4)
                now = now_iso()
                new_expires_at = (datetime.now(timezone.utc) + timedelta(hours=config.EMAIL_VERIFICATION_EXPIRE_HOURS)).isoformat()
                
                # Update with new code and expiry
                update_expr = "SET code = :code, expires_at = :expires, created_at = :now"
                expr_values = {
                    ":code": verification_code,
                    ":expires": new_expires_at,
                    ":now": now
                }
                
                # Keep password_hash if this is a registration
                if password_hash:
                    update_expr += ", password_hash = :hash, purpose = :purpose"
                    expr_values[":hash"] = password_hash
                    expr_values[":purpose"] = purpose
                
                self.verification_table.update_item(
                    Key={"email": email},
                    UpdateExpression=update_expr,
                    ExpressionAttributeValues=expr_values
                )
            else:
                # Use existing code
                verification_code = verification_data.get("code")
            
            # Send verification email
            send_success = self.email_service.send_verification_code_email(email, verification_code)
            
            if send_success:
                # Update resend tracking in DynamoDB
                try:
                    self.verification_table.update_item(
                        Key={"email": email},
                        UpdateExpression="SET resend_count = :rc, last_resend_at = :ts",
                        ExpressionAttributeValues={
                            ":rc": resend_count + 1,
                            ":ts": datetime.now(timezone.utc).isoformat()
                        }
                    )
                except Exception:
                    pass  # Don't fail the resend if tracking update fails
                logger.info(
                    "Verification code resent",
                    context={"email": email, "user_id": user_id, "resend_count": resend_count + 1}
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
