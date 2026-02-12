"""
HTTP Response utilities
"""

import json
from typing import Any, Dict, Optional
from decimal import Decimal
from datetime import datetime

from security import SecurityHeaders


def inject_cors_headers(response: Dict, origin: str = "*") -> Dict:
    """
    Ensures CORS headers are present in every response.
    This is the SINGLE point where CORS is guaranteed to be added.
    
    Args:
        response: Lambda response dict with statusCode, headers, body
        origin: Request origin for CORS
    
    Returns:
        Response dict with guaranteed CORS headers
    """
    if not isinstance(response, dict):
        return response
    
    # Ensure headers dict exists
    if "headers" not in response:
        response["headers"] = {}
    
    # Inject CORS headers (will override any existing ones)
    cors_headers = {
        "Access-Control-Allow-Origin": origin or "*",
        "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With, Accept, Origin",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Max-Age": "86400",
    }
    
    response["headers"].update(cors_headers)
    return response


class DecimalEncoder(json.JSONEncoder):
    """JSON encoder that handles Decimal and datetime objects"""
    
    def default(self, obj):
        if isinstance(obj, Decimal):
            return int(obj) if obj % 1 == 0 else float(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


class APIResponse:
    """Standardized API response builder"""
    
    @staticmethod
    def success(data: Any, status_code: int = 200, headers: Optional[Dict] = None, origin: str = "*") -> Dict:
        """
        Create a success response
        
        Args:
            data: Response data
            status_code: HTTP status code (default: 200)
            headers: Additional headers
            origin: CORS origin
        
        Returns:
            Lambda response dict
        """
        response_headers = SecurityHeaders.get_headers(origin)
        response_headers["Content-Type"] = "application/json"
        
        if headers:
            response_headers.update(headers)
        
        body = {
            "success": True,
            "data": data
        }
        
        return {
            "statusCode": status_code,
            "headers": response_headers,
            "body": json.dumps(body, cls=DecimalEncoder)
        }
    
    @staticmethod
    def error(
        message: str,
        status_code: int = 400,
        error_code: Optional[str] = None,
        details: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        origin: str = "*"
    ) -> Dict:
        """
        Create an error response
        
        Args:
            message: Error message
            status_code: HTTP status code (default: 400)
            error_code: Machine-readable error code
            details: Additional error details
            headers: Additional headers
            origin: CORS origin
        
        Returns:
            Lambda response dict
        """
        response_headers = SecurityHeaders.get_headers(origin)
        response_headers["Content-Type"] = "application/json"
        
        if headers:
            response_headers.update(headers)
        
        body = {
            "success": False,
            "error": {
                "message": message,
                "code": error_code or f"ERROR_{status_code}"
            }
        }
        
        if details:
            body["error"]["details"] = details
        
        return {
            "statusCode": status_code,
            "headers": response_headers,
            "body": json.dumps(body, cls=DecimalEncoder)
        }
    
    @staticmethod
    def validation_error(field: str, message: str, origin: str = "*") -> Dict:
        """Create a validation error response"""
        return APIResponse.error(
            message="Validation error",
            status_code=400,
            error_code="VALIDATION_ERROR",
            details={"field": field, "message": message},
            origin=origin
        )
    
    @staticmethod
    def unauthorized(message: str = "Unauthorized", origin: str = "*") -> Dict:
        """Create an unauthorized response"""
        return APIResponse.error(
            message=message,
            status_code=401,
            error_code="UNAUTHORIZED",
            origin=origin
        )
    
    @staticmethod
    def forbidden(message: str = "Forbidden", origin: str = "*") -> Dict:
        """Create a forbidden response"""
        return APIResponse.error(
            message=message,
            status_code=403,
            error_code="FORBIDDEN",
            origin=origin
        )
    
    @staticmethod
    def not_found(resource: str = "Resource", origin: str = "*") -> Dict:
        """Create a not found response"""
        return APIResponse.error(
            message=f"{resource} not found",
            status_code=404,
            error_code="NOT_FOUND",
            origin=origin
        )
    
    @staticmethod
    def rate_limited(message: str = "Too many requests", origin: str = "*") -> Dict:
        """Create a rate limit response"""
        return APIResponse.error(
            message=message,
            status_code=429,
            error_code="RATE_LIMITED",
            origin=origin
        )
    
    @staticmethod
    def server_error(message: str = "Internal server error", origin: str = "*") -> Dict:
        """Create a server error response"""
        return APIResponse.error(
            message=message,
            status_code=500,
            error_code="INTERNAL_ERROR",
            origin=origin
        )
    
    @staticmethod
    def options(origin: str = "*") -> Dict:
        """Create an OPTIONS (CORS preflight) response"""
        return {
            "statusCode": 200,
            "headers": SecurityHeaders.get_headers(origin),
            "body": ""
        }


def get_origin(event: Dict) -> str:
    """Extract origin from Lambda event"""
    headers = event.get("headers", {}) or {}
    return headers.get("origin") or headers.get("Origin") or "*"


def get_auth_token(event: Dict) -> Optional[str]:
    """Extract JWT token from Authorization header"""
    headers = event.get("headers", {}) or {}
    auth_header = headers.get("authorization") or headers.get("Authorization")
    
    if not auth_header:
        return None
    
    # Support "Bearer <token>" format
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    
    return auth_header


def get_request_id(event: Dict) -> str:
    """Extract request ID from Lambda event"""
    request_context = event.get("requestContext", {})
    return request_context.get("requestId", "unknown")


def get_ip_address(event: Dict) -> str:
    """Extract client IP address from Lambda event"""
    request_context = event.get("requestContext", {})
    
    # API Gateway v2
    http_context = request_context.get("http", {})
    if "sourceIp" in http_context:
        return http_context["sourceIp"]
    
    # API Gateway v1
    identity = request_context.get("identity", {})
    return identity.get("sourceIp", "unknown")


def get_user_agent(event: Dict) -> str:
    """Extract user agent from Lambda event"""
    headers = event.get("headers", {}) or {}
    return headers.get("user-agent") or headers.get("User-Agent") or "unknown"
