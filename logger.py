"""
Custom logging system using DynamoDB (CloudWatch alternative)
Structured logging with queryable storage
"""

import json
import uuid
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from enum import Enum
import traceback

import boto3
from botocore.exceptions import ClientError

from config import config

# Configure standard Python logger for CloudWatch
cloudwatch_logger = logging.getLogger()
cloudwatch_logger.setLevel(logging.DEBUG)  # Always capture all levels for CloudWatch


class LogLevel(Enum):
    """Log levels"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class Logger:
    """
    Custom logger that writes to DynamoDB
    
    Table Schema:
        log_id (PK) - UUID
        timestamp (SK) - ISO timestamp
        level - DEBUG/INFO/WARNING/ERROR/CRITICAL
        message - Log message
        context - JSON context data
        user_id - Optional user identifier
        request_id - Request identifier
        ip_address - Client IP
        error_trace - Stack trace for errors
        ttl - Expiration timestamp (for auto-cleanup)
    """
    
    def __init__(self, context: Optional[Dict] = None):
        """
        Initialize logger
        
        Args:
            context: Default context to include in all logs
        """
        self.dynamodb = boto3.resource('dynamodb', region_name=config.AWS_REGION)
        self.table = self.dynamodb.Table(config.TABLE_LOGS)
        self.default_context = context or {}
    
    def _should_log_to_db(self, level: LogLevel) -> bool:
        """Check if log level should be written to DynamoDB based on config"""
        level_hierarchy = {
            "DEBUG": 0,
            "INFO": 1,
            "WARNING": 2,
            "ERROR": 3,
            "CRITICAL": 4
        }
        configured_level = level_hierarchy.get(config.LOG_LEVEL, 1)  # Default to INFO
        current_level = level_hierarchy.get(level.value, 1)
        return current_level >= configured_level
    
    def _write_log(
        self,
        level: LogLevel,
        message: str,
        context: Optional[Dict] = None,
        user_id: Optional[str] = None,
        request_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        error: Optional[Exception] = None
    ):
        """Write log entry to CloudWatch and optionally to DynamoDB"""
        try:
            now = datetime.now(timezone.utc)
            log_id = str(uuid.uuid4())
            
            # Merge contexts
            merged_context = {**self.default_context}
            if context:
                merged_context.update(context)
            
            # Build log data
            log_data = {
                "level": level.value,
                "message": message,
                "log_id": log_id,
                **merged_context
            }
            
            if user_id:
                log_data["user_id"] = user_id
            if request_id:
                log_data["request_id"] = request_id
            if ip_address:
                log_data["ip_address"] = ip_address
            if error:
                log_data["error_type"] = type(error).__name__
                log_data["error_message"] = str(error)
            
            # ALWAYS log to CloudWatch (via Python logging) regardless of LOG_LEVEL
            # This ensures all logs appear in CloudWatch
            if level == LogLevel.DEBUG:
                cloudwatch_logger.debug(json.dumps(log_data))
            elif level == LogLevel.INFO:
                cloudwatch_logger.info(json.dumps(log_data))
            elif level == LogLevel.WARNING:
                cloudwatch_logger.warning(json.dumps(log_data))
            elif level == LogLevel.ERROR:
                cloudwatch_logger.error(json.dumps(log_data))
            elif level == LogLevel.CRITICAL:
                cloudwatch_logger.critical(json.dumps(log_data))
            
            # Only write to DynamoDB if log level meets threshold
            if self._should_log_to_db(level):
                # Calculate TTL (retention period)
                ttl = int(now.timestamp()) + (config.LOG_RETENTION_DAYS * 86400)
                
                item = {
                    "log_id": log_id,
                    "timestamp": int(now.timestamp() * 1000),  # Unix timestamp in milliseconds
                    "created_at": now.isoformat(),  # ISO string for readability
                    "level": level.value,
                    "message": message,
                    "context": merged_context,
                    "ttl": ttl
                }
                
                if user_id:
                    item["user_id"] = user_id
                
                if request_id:
                    item["request_id"] = request_id
                
                if ip_address:
                    item["ip_address"] = ip_address
                
                if error:
                    item["error_type"] = type(error).__name__
                    item["error_message"] = str(error)
                    item["error_trace"] = traceback.format_exc()
                
                # Write to DynamoDB
                self.table.put_item(Item=item)
            
        except Exception as e:
            # Fallback to CloudWatch if DynamoDB write fails
            cloudwatch_logger.error(f"[LOGGER ERROR] Failed to write log: {e}")
            cloudwatch_logger.log(
                logging.ERROR if level in [LogLevel.ERROR, LogLevel.CRITICAL] else logging.INFO,
                f"[{level.value}] {message}"
            )
    
    def debug(self, message: str, **kwargs):
        """Log debug message (always to CloudWatch, conditionally to DynamoDB)"""
        context = kwargs.pop('context', {})
        # Put any extra kwargs into context
        extra_kwargs = {k: v for k, v in kwargs.items() if k not in ['user_id', 'request_id', 'ip_address', 'error']}
        if extra_kwargs:
            context = {**context, **extra_kwargs}
            kwargs = {k: v for k, v in kwargs.items() if k in ['user_id', 'request_id', 'ip_address', 'error']}
        self._write_log(LogLevel.DEBUG, message, context=context, **kwargs)
    
    def info(self, message: str, **kwargs):
        """Log info message (always to CloudWatch, conditionally to DynamoDB)"""
        context = kwargs.pop('context', {})
        # Put any extra kwargs into context
        extra_kwargs = {k: v for k, v in kwargs.items() if k not in ['user_id', 'request_id', 'ip_address', 'error']}
        if extra_kwargs:
            context = {**context, **extra_kwargs}
            kwargs = {k: v for k, v in kwargs.items() if k in ['user_id', 'request_id', 'ip_address', 'error']}
        self._write_log(LogLevel.INFO, message, context=context, **kwargs)
    
    def warning(self, message: str, **kwargs):
        """Log warning message (always to CloudWatch, conditionally to DynamoDB)"""
        context = kwargs.pop('context', {})
        # Put any extra kwargs into context
        extra_kwargs = {k: v for k, v in kwargs.items() if k not in ['user_id', 'request_id', 'ip_address', 'error']}
        if extra_kwargs:
            context = {**context, **extra_kwargs}
            kwargs = {k: v for k, v in kwargs.items() if k in ['user_id', 'request_id', 'ip_address', 'error']}
        self._write_log(LogLevel.WARNING, message, context=context, **kwargs)
    
    def error(self, message: str, **kwargs):
        """Log error message (always to CloudWatch, conditionally to DynamoDB)"""
        context = kwargs.pop('context', {})
        # Put any extra kwargs into context
        extra_kwargs = {k: v for k, v in kwargs.items() if k not in ['user_id', 'request_id', 'ip_address', 'error']}
        if extra_kwargs:
            context = {**context, **extra_kwargs}
            kwargs = {k: v for k, v in kwargs.items() if k in ['user_id', 'request_id', 'ip_address', 'error']}
        self._write_log(LogLevel.ERROR, message, context=context, **kwargs)
    
    def critical(self, message: str, **kwargs):
        """Log critical message (always to CloudWatch, conditionally to DynamoDB)"""
        context = kwargs.pop('context', {})
        # Put any extra kwargs into context
        extra_kwargs = {k: v for k, v in kwargs.items() if k not in ['user_id', 'request_id', 'ip_address', 'error']}
        if extra_kwargs:
            context = {**context, **extra_kwargs}
            kwargs = {k: v for k, v in kwargs.items() if k in ['user_id', 'request_id', 'ip_address', 'error']}
        self._write_log(LogLevel.CRITICAL, message, context=context, **kwargs)
    
    def log_request(self, event: Dict, user_id: Optional[str] = None):
        """Log API request"""
        method = event.get("httpMethod") or event.get("requestContext", {}).get("http", {}).get("method")
        path = event.get("path") or event.get("rawPath")
        request_id = event.get("requestContext", {}).get("requestId")
        
        from responses import get_ip_address, get_user_agent
        
        self.info(
            f"{method} {path}",
            context={
                "method": method,
                "path": path,
                "user_agent": get_user_agent(event)
            },
            user_id=user_id,
            request_id=request_id,
            ip_address=get_ip_address(event)
        )
    
    def log_response(self, status_code: int, request_id: Optional[str] = None, duration_ms: Optional[float] = None):
        """Log API response"""
        context = {"status_code": status_code}
        if duration_ms:
            context["duration_ms"] = duration_ms
        
        self.info(
            f"Response {status_code}",
            context=context,
            request_id=request_id
        )


class LogQuery:
    """Query logs from DynamoDB"""
    
    def __init__(self):
        self.dynamodb = boto3.resource('dynamodb', region_name=config.AWS_REGION)
        self.table = self.dynamodb.Table(config.TABLE_LOGS)
    
    def get_logs_by_user(
        self,
        user_id: str,
        level: Optional[LogLevel] = None,
        limit: int = 100
    ) -> list:
        """Get logs for a specific user"""
        try:
            # Requires GSI on user_id
            query_params = {
                "IndexName": "UserLogsIndex",
                "KeyConditionExpression": "user_id = :user_id",
                "ExpressionAttributeValues": {":user_id": user_id},
                "ScanIndexForward": False,
                "Limit": limit
            }
            
            if level:
                query_params["FilterExpression"] = "#level = :level"
                query_params["ExpressionAttributeNames"] = {"#level": "level"}
                query_params["ExpressionAttributeValues"][":level"] = level.value
            
            response = self.table.query(**query_params)
            return response.get("Items", [])
        
        except ClientError as e:
            print(f"Error querying logs: {e}")
            return []
    
    def get_logs_by_request(self, request_id: str) -> list:
        """Get all logs for a specific request"""
        try:
            # Requires GSI on request_id
            response = self.table.query(
                IndexName="RequestLogsIndex",
                KeyConditionExpression="request_id = :request_id",
                ExpressionAttributeValues={":request_id": request_id},
                ScanIndexForward=True
            )
            return response.get("Items", [])
        
        except ClientError as e:
            print(f"Error querying logs: {e}")
            return []
    
    def get_errors(self, hours: int = 24, limit: int = 100) -> list:
        """Get recent error logs"""
        try:
            from datetime import timedelta
            since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
            
            # Requires GSI on level + timestamp
            response = self.table.query(
                IndexName="LevelLogsIndex",
                KeyConditionExpression="#level = :level AND #ts >= :since",
                ExpressionAttributeNames={
                    "#level": "level",
                    "#ts": "timestamp"
                },
                ExpressionAttributeValues={
                    ":level": "ERROR",
                    ":since": since
                },
                ScanIndexForward=False,
                Limit=limit
            )
            return response.get("Items", [])
        
        except ClientError as e:
            print(f"Error querying errors: {e}")
            return []


# Global logger instance
logger = Logger()
