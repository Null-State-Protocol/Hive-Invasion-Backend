""" 
Security utilities for password hashing, encryption, and validation
"""

import secrets
import hashlib
import hmac
import base64
from typing import Optional, Tuple
from datetime import datetime, timezone

from config import config
from logger import logger


class PasswordHasher:
    """Secure password hashing using PBKDF2"""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password using PBKDF2-HMAC-SHA256"""
        logger.debug("Hashing password")
        salt = secrets.token_bytes(32)
        iterations = 100000
        dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
        # Store as: iterations:salt:hash (all base64 encoded)
        return f"{iterations}:{base64.b64encode(salt).decode()}:{base64.b64encode(dk).decode()}"
    
    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        """Verify a password against a hash"""
        try:
            logger.debug("Verifying password")
            parts = hashed.split(':')
            if len(parts) != 3:
                logger.warning("Invalid password hash format")
                return False
            iterations = int(parts[0])
            salt = base64.b64decode(parts[1])
            stored_hash = base64.b64decode(parts[2])
            dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
            is_valid = hmac.compare_digest(dk, stored_hash)
            if not is_valid:
                logger.debug("Password verification failed")
            return is_valid
        except Exception as e:
            logger.error("Password verification error", error=e)
            return False
    
    @staticmethod
    def validate_password_strength(password: str) -> Tuple[bool, Optional[str]]:
        """
        Validate password strength
        Returns: (is_valid, error_message)
        """
        logger.debug("Validating password strength")
        
        if len(password) < config.PASSWORD_MIN_LENGTH:
            logger.debug(f"Password too short: {len(password)} < {config.PASSWORD_MIN_LENGTH}")
            return False, f"Password must be at least {config.PASSWORD_MIN_LENGTH} characters"
        
        if config.PASSWORD_REQUIRE_UPPERCASE and not any(c.isupper() for c in password):
            logger.debug("Password missing uppercase letter")
            return False, "Password must contain at least one uppercase letter"
        
        if config.PASSWORD_REQUIRE_LOWERCASE and not any(c.islower() for c in password):
            logger.debug("Password missing lowercase letter")
            return False, "Password must contain at least one lowercase letter"
        
        if config.PASSWORD_REQUIRE_DIGIT and not any(c.isdigit() for c in password):
            logger.debug("Password missing digit")
            return False, "Password must contain at least one digit"
        
        if config.PASSWORD_REQUIRE_SPECIAL:
            special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
            if not any(c in special_chars for c in password):
                logger.debug("Password missing special character")
                return False, "Password must contain at least one special character"
        
        # Check for common weak passwords
        weak_passwords = {"password", "12345678", "qwerty", "admin", "letmein"}
        if password.lower() in weak_passwords:
            logger.warning("Weak password detected")
            return False, "Password is too common"
        
        logger.debug("Password strength validation passed")
        return True, None


class TokenGenerator:
    """Generate secure tokens for various purposes"""
    
    @staticmethod
    def generate_token(length: int = 32) -> str:
        """Generate a secure random token"""
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def generate_verification_code(length: int = 6) -> str:
        """Generate a numeric verification code"""
        return ''.join(str(secrets.randbelow(10)) for _ in range(length))
    
    @staticmethod
    def generate_session_token() -> str:
        """Generate a session token"""
        return secrets.token_urlsafe(48)


class SignatureValidator:
    """Validate signatures for wallet authentication"""
    
    @staticmethod
    def create_message_to_sign(wallet_address: str, timestamp: int) -> str:
        """Create a message for wallet signing"""
        return f"Sign this message to authenticate with Hive Invasion.\n\nWallet: {wallet_address}\nTimestamp: {timestamp}\n\nThis request will not trigger a blockchain transaction or cost any gas fees."
    
    @staticmethod
    def verify_eth_signature(message: str, signature: str, wallet_address: str) -> bool:
        """
        Verify an Ethereum signature
        Note: This is a placeholder. In production, use web3.py or eth_account
        """
        try:
            logger.debug("Verifying Ethereum signature", context={"wallet_address": wallet_address})
            # TODO: Implement proper Ethereum signature verification
            # from eth_account.messages import encode_defunct
            # from web3.auto import w3
            # 
            # message_hash = encode_defunct(text=message)
            # recovered_address = w3.eth.account.recover_message(message_hash, signature=signature)
            # return recovered_address.lower() == wallet_address.lower()
            
            # For now, return True if signature is non-empty (placeholder)
            is_valid = len(signature) > 0 and len(wallet_address) == 42
            if not is_valid:
                logger.warning("Signature verification failed", context={"wallet_address": wallet_address})
            return is_valid
        except Exception as e:
            logger.error("Signature verification error", error=e, context={"wallet_address": wallet_address})
            return False


class DataEncryption:
    """Encrypt sensitive data before storing in database"""
    
    @staticmethod
    def hash_data(data: str, salt: Optional[str] = None) -> str:
        """Hash data using SHA-256"""
        if salt:
            data = f"{data}{salt}"
        return hashlib.sha256(data.encode('utf-8')).hexdigest()
    
    @staticmethod
    def create_hmac(data: str, secret: str) -> str:
        """Create HMAC signature"""
        return hmac.new(
            secret.encode('utf-8'),
            data.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
    
    @staticmethod
    def verify_hmac(data: str, signature: str, secret: str) -> bool:
        """Verify HMAC signature"""
        expected = DataEncryption.create_hmac(data, secret)
        return hmac.compare_digest(expected, signature)


class SecurityHeaders:
    """Security headers for API responses"""
    
    @staticmethod
    def get_headers(origin: str = "*") -> dict:
        """Get security headers"""
        headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "Referrer-Policy": "strict-origin-when-cross-origin",
        }
        
        # CORS headers - Use provided origin, default to wildcard
        headers.update({
            "Access-Control-Allow-Origin": origin or "*",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With, Accept, Origin",
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Max-Age": "86400",
        })
        
        return headers


def sanitize_input(text: str, max_length: int = 1000) -> str:
    """Sanitize user input"""
    if not text:
        return ""
    
    # Trim whitespace
    text = text.strip()
    
    # Limit length
    if len(text) > max_length:
        text = text[:max_length]
    
    # Remove null bytes
    text = text.replace('\x00', '')
    
    return text


def is_valid_email(email: str) -> bool:
    """Basic email validation"""
    if not email or len(email) > 254:
        logger.debug("Email validation failed - length check", context={"length": len(email) if email else 0})
        return False
    
    if '@' not in email:
        logger.debug("Email validation failed - missing @")
        return False
    
    local, domain = email.rsplit('@', 1)
    
    if len(local) == 0 or len(local) > 64:
        logger.debug("Email validation failed - invalid local part length", context={"local_length": len(local)})
        return False
    
    if len(domain) == 0 or '.' not in domain:
        logger.debug("Email validation failed - invalid domain")
        return False
    
    # Basic character validation
    import re
    email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    is_valid = bool(email_pattern.match(email))
    if not is_valid:
        logger.debug("Email validation failed - pattern mismatch", context={"email": email})
    return is_valid


def is_valid_wallet_address(address: str) -> bool:
    """Validate Ethereum wallet address with checksum validation"""
    if not address:
        logger.debug("Wallet address validation failed - empty address")
        return False
    
    # Check if it's a valid Ethereum address format
    if not address.startswith('0x'):
        logger.debug("Wallet address validation failed - missing 0x prefix")
        return False
    
    if len(address) != 42:
        logger.debug("Wallet address validation failed - incorrect length", context={"length": len(address)})
        return False
    
    # Check if all characters after 0x are hex
    try:
        int(address[2:], 16)
        # Try to use Web3 for checksum validation if available
        try:
            from web3 import Web3
            return Web3.is_address(address)
        except ImportError:
            # Fallback to basic validation
            logger.debug("Web3 not available - using basic wallet address validation")
            return True
    except ValueError:
        logger.debug("Wallet address validation failed - invalid hex characters")
        return False
