"""
Decorators for authentication and authorization
"""

from functools import wraps
from typing import Callable, Optional

from responses import APIResponse, get_origin, get_auth_token
from jwt_handler import JWTHandler, TokenType
from logger import logger


def require_auth(token_type: str = TokenType.ACCESS):
    """
    Decorator to require authentication
    Verifies JWT token and adds user_id to event context
    
    Usage:
        @require_auth()
        def my_handler(event, context, user_id):
            # user_id is guaranteed to be present
            pass
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(event, context=None):
            origin = get_origin(event)
            token = get_auth_token(event)
            
            if not token:
                logger.warning("Missing authentication token")
                return APIResponse.unauthorized("Authentication required", origin)
            
            is_valid, payload, error = JWTHandler.verify_token(token, token_type)
            
            if not is_valid:
                logger.warning(f"Invalid token: {error}")
                return APIResponse.unauthorized(error or "Invalid token", origin)
            
            user_id = payload.get("sub")
            if not user_id:
                logger.warning("Token missing user ID")
                return APIResponse.unauthorized("Invalid token payload", origin)
            
            # Add user_id to event for downstream use
            event["_authenticated_user_id"] = user_id
            event["_token_payload"] = payload
            
            # Call the original function with user_id as an additional parameter
            return func(event, context, user_id=user_id)
        
        return wrapper
    return decorator


def optional_auth():
    """
    Decorator for optional authentication
    Adds user_id to event if token is present and valid, otherwise continues without it
    
    Usage:
        @optional_auth()
        def my_handler(event, context, user_id=None):
            if user_id:
                # User is authenticated
                pass
            else:
                # Anonymous access
                pass
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(event, context=None):
            token = get_auth_token(event)
            user_id = None
            
            if token:
                is_valid, payload, _ = JWTHandler.verify_token(token, TokenType.ACCESS)
                if is_valid:
                    user_id = payload.get("sub")
                    event["_authenticated_user_id"] = user_id
                    event["_token_payload"] = payload
            
            return func(event, context, user_id=user_id)
        
        return wrapper
    return decorator


def rate_limit(max_requests: int, window_seconds: int = 60):
    """
    Decorator for rate limiting using DynamoDB
    
    Args:
        max_requests: Maximum requests per window
        window_seconds: Time window in seconds
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(event, context=None):
            from config import config
            import boto3
            import time
            from responses import APIResponse, get_origin
            
            # Skip if rate limiting is disabled
            if not config.ENABLE_RATE_LIMITING:
                return func(event, context)
            
            # Get identifier (user_id or IP)
            user_id = event.get('_authenticated_user_id')
            ip = event.get('requestContext', {}).get('identity', {}).get('sourceIp', 'unknown')
            identifier = user_id or f"ip:{ip}"
            
            try:
                dynamodb = boto3.resource('dynamodb', region_name=config.AWS_REGION)
                table = dynamodb.Table('hive_rate_limits')
                
                current_time = int(time.time())
                window_start = current_time - window_seconds
                
                # Query recent requests
                response = table.query(
                    KeyConditionExpression='identifier = :id AND #ts > :start',
                    ExpressionAttributeNames={'#ts': 'timestamp'},
                    ExpressionAttributeValues={
                        ':id': identifier,
                        ':start': window_start
                    }
                )
                
                request_count = len(response.get('Items', []))
                
                if request_count >= max_requests:
                    logger.warning(
                        f"Rate limit exceeded for {identifier}",
                        context={"count": request_count, "limit": max_requests}
                    )
                    return APIResponse.error(
                        "Too many requests. Please try again later.",
                        status_code=429,
                        error_code="RATE_LIMIT_EXCEEDED",
                        origin=get_origin(event)
                    )
                
                # Log this request
                table.put_item(Item={
                    'identifier': identifier,
                    'timestamp': current_time,
                    'ttl': current_time + 3600,  # Auto-delete after 1 hour
                    'path': event.get('path', 'unknown')
                })
                
            except Exception as e:
                # If rate limiting fails, log but don't block the request
                logger.error("Rate limiting error", error=e)
            
            return func(event, context)
        return wrapper
    return decorator
    from collections import defaultdict
    from datetime import datetime, timezone, timedelta
    
    # In-memory store (will reset on Lambda cold start)
    request_counts = defaultdict(list)
    
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(event, context=None, **kwargs):
            from responses import get_ip_address, get_origin
            
            if not config.ENABLE_RATE_LIMITING:
                return func(event, context, **kwargs)
            
            origin = get_origin(event)
            
            # Use IP address + user_id (if authenticated) as rate limit key
            ip_address = get_ip_address(event)
            user_id = event.get("_authenticated_user_id", "anonymous")
            rate_key = f"{ip_address}:{user_id}"
            
            now = datetime.now(timezone.utc)
            cutoff = now - timedelta(seconds=window_seconds)
            
            # Remove old timestamps
            request_counts[rate_key] = [
                ts for ts in request_counts[rate_key] if ts > cutoff
            ]
            
            # Check if rate limit exceeded
            if len(request_counts[rate_key]) >= max_requests:
                logger.warning(
                    f"Rate limit exceeded",
                    context={"ip": ip_address, "user_id": user_id, "limit": max_requests}
                )
                return APIResponse.rate_limited(
                    f"Too many requests. Maximum {max_requests} requests per {window_seconds} seconds.",
                    origin
                )
            
            # Add current timestamp
            request_counts[rate_key].append(now)
            
            return func(event, context, **kwargs)
        
        return wrapper
    return decorator


def log_request():
    """
    Decorator to automatically log requests
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(event, context=None, **kwargs):
            from datetime import datetime
            
            start_time = datetime.now(timezone.utc)
            user_id = event.get("_authenticated_user_id")
            
            logger.log_request(event, user_id)
            
            try:
                result = func(event, context, **kwargs)
                
                # Log response
                duration = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
                status_code = result.get("statusCode", 200)
                request_id = event.get("requestContext", {}).get("requestId")
                
                logger.log_response(status_code, request_id, duration)
                
                return result
            
            except Exception as e:
                logger.error(
                    f"Request handler error: {str(e)}",
                    user_id=user_id,
                    error=e
                )
                raise
        
        return wrapper
    return decorator


# Import config here to avoid circular import
from config import config
