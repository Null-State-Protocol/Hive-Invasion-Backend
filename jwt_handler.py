"""
JWT Token Handler for authentication
"""

import jwt
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional, Tuple

from config import config
from logger import logger


class TokenType:
    """Token types"""
    ACCESS = "access"
    REFRESH = "refresh"


class JWTHandler:
    """Handle JWT token creation and verification"""
    
    @staticmethod
    def create_access_token(user_id: str, additional_claims: Optional[Dict] = None) -> str:
        """
        Create an access token
        
        Args:
            user_id: User identifier
            additional_claims: Additional JWT claims
        
        Returns:
            JWT token string
        """
        now = datetime.now(timezone.utc)
        expires = now + timedelta(minutes=config.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
        
        payload = {
            "sub": user_id,
            "type": TokenType.ACCESS,
            "iat": now,
            "exp": expires,
            "jti": str(uuid.uuid4())
        }
        
        if additional_claims:
            payload.update(additional_claims)
        
        token = jwt.encode(payload, config.JWT_SECRET, algorithm=config.JWT_ALGORITHM)
        
        logger.debug(
            "Access token created",
            context={"user_id": user_id, "expires_at": expires.isoformat()}
        )
        
        return token
    
    @staticmethod
    def create_refresh_token(user_id: str) -> str:
        """
        Create a refresh token
        
        Args:
            user_id: User identifier
        
        Returns:
            JWT token string
        """
        now = datetime.now(timezone.utc)
        expires = now + timedelta(days=config.JWT_REFRESH_TOKEN_EXPIRE_DAYS)
        
        payload = {
            "sub": user_id,
            "type": TokenType.REFRESH,
            "iat": now,
            "exp": expires,
            "jti": str(uuid.uuid4())
        }
        
        token = jwt.encode(payload, config.JWT_SECRET, algorithm=config.JWT_ALGORITHM)
        
        logger.debug(
            "Refresh token created",
            context={"user_id": user_id, "expires_at": expires.isoformat()}
        )
        
        return token
    
    @staticmethod
    def verify_token(token: str, expected_type: Optional[str] = None) -> Tuple[bool, Optional[Dict], Optional[str]]:
        """
        Verify a JWT token
        
        Args:
            token: JWT token string
            expected_type: Expected token type (access/refresh)
        
        Returns:
            Tuple of (is_valid, payload, error_message)
        """
        try:
            payload = jwt.decode(
                token,
                config.JWT_SECRET,
                algorithms=[config.JWT_ALGORITHM]
            )
            
            # Check token type if specified
            if expected_type and payload.get("type") != expected_type:
                return False, None, f"Invalid token type. Expected {expected_type}"
            
            # Check if token is expired (jwt.decode already does this, but let's be explicit)
            exp = payload.get("exp")
            if exp and datetime.fromtimestamp(exp, timezone.utc) < datetime.now(timezone.utc):
                return False, None, "Token has expired"
            
            return True, payload, None
        
        except jwt.ExpiredSignatureError:
            return False, None, "Token has expired"
        
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {str(e)}")
            return False, None, "Invalid token"
        
        except Exception as e:
            logger.error(f"Token verification error: {str(e)}", error=e)
            return False, None, "Token verification failed"
    
    @staticmethod
    def get_user_id_from_token(token: str) -> Optional[str]:
        """
        Extract user ID from token without full verification
        Used for logging purposes only
        """
        try:
            # Decode without verification (unsafe, only for logging)
            payload = jwt.decode(
                token,
                options={"verify_signature": False}
            )
            return payload.get("sub")
        except Exception:
            return None
    
    @staticmethod
    def create_token_pair(user_id: str) -> Dict[str, str]:
        """
        Create both access and refresh tokens
        
        Returns:
            Dict with 'access_token' and 'refresh_token'
        """
        return {
            "access_token": JWTHandler.create_access_token(user_id),
            "refresh_token": JWTHandler.create_refresh_token(user_id),
            "token_type": "Bearer",
            "expires_in": config.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60  # in seconds
        }
