"""
Configuration Management for Hive Invasion Backend
Environment-based configuration with secure defaults
"""

import os
from typing import Optional

class Config:
    """Base configuration"""
    
    # AWS Configuration
    AWS_REGION = os.getenv("AWS_REGION", "eu-north-1")
    
    # DynamoDB Tables
    TABLE_USERS = os.getenv("TABLE_USERS", "hive_users")
    TABLE_USER_WALLETS = os.getenv("TABLE_USER_WALLETS", "hive_user_wallets")
    TABLE_USER_EMAILS = os.getenv("TABLE_USER_EMAILS", "hive_user_emails")
    TABLE_SESSIONS = os.getenv("TABLE_SESSIONS", "hive_sessions")
    TABLE_PLAYER_DATA = os.getenv("TABLE_PLAYER_DATA", "hive_player_data")
    TABLE_ACHIEVEMENTS = os.getenv("TABLE_ACHIEVEMENTS", "hive_achievements")
    TABLE_LEADERBOARD_DAILY = os.getenv("TABLE_LEADERBOARD_DAILY", "hive_leaderboard_daily")
    TABLE_LEADERBOARD_WEEKLY = os.getenv("TABLE_LEADERBOARD_WEEKLY", "hive_leaderboard_weekly")
    TABLE_LEADERBOARD_ALLTIME = os.getenv("TABLE_LEADERBOARD_ALLTIME", "hive_leaderboard_alltime")
    TABLE_LOGS = os.getenv("TABLE_LOGS", "hive_logs")
    TABLE_ANALYTICS = os.getenv("TABLE_ANALYTICS", "hive_analytics")
    TABLE_EMAIL_VERIFICATION = os.getenv("TABLE_EMAIL_VERIFICATION", "hive_email_verification")
    TABLE_PASSWORD_RESET = os.getenv("TABLE_PASSWORD_RESET", "hive_password_reset")
    
    # JWT Configuration
    JWT_SECRET = os.getenv("JWT_SECRET", "CHANGE_ME_IN_PRODUCTION")  # Must be set in Lambda env
    JWT_ALGORITHM = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "60"))  # 1 hour
    JWT_REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("JWT_REFRESH_TOKEN_EXPIRE_DAYS", "30"))  # 30 days
    
    # Security
    PASSWORD_MIN_LENGTH = 8
    PASSWORD_REQUIRE_UPPERCASE = True
    PASSWORD_REQUIRE_LOWERCASE = True
    PASSWORD_REQUIRE_DIGIT = True
    PASSWORD_REQUIRE_SPECIAL = False
    BCRYPT_ROUNDS = 12
    
    # Rate Limiting (requests per minute)
    RATE_LIMIT_AUTH = int(os.getenv("RATE_LIMIT_AUTH", "5"))  # 5 auth attempts per minute
    RATE_LIMIT_GAME = int(os.getenv("RATE_LIMIT_GAME", "60"))  # 60 game requests per minute
    RATE_LIMIT_ANALYTICS = int(os.getenv("RATE_LIMIT_ANALYTICS", "120"))  # 120 analytics events per minute
    
    # Email Configuration
    EMAIL_VERIFICATION_EXPIRE_HOURS = 24
    PASSWORD_RESET_EXPIRE_HOURS = 1
    SENDER_EMAIL = os.getenv("SENDER_EMAIL", "noreply@hiveinvasion.games")
    FRONTEND_URL = os.getenv("FRONTEND_URL", "https://hive-invasion-website.kagan-fa3.workers.dev")
    
    # Account Deletion (GDPR compliance)
    TABLE_DELETED_ACCOUNTS = os.getenv("TABLE_DELETED_ACCOUNTS", "hive_deleted_accounts")
    PASSWORD_RESET_EXPIRE_MINUTES = 30
    EMAIL_FROM = os.getenv("EMAIL_FROM", "noreply@hiveinvasion.com")
    EMAIL_PROVIDER = os.getenv("EMAIL_PROVIDER", "ses")  # ses or sendgrid
    SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY", "")
    
    # CORS
    ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")
    
    # Game Configuration
    MAX_ACHIEVEMENT_COUNT = 50
    MAX_SKILL_LOCATIONS = 20
    LEADERBOARD_TOP_COUNT = 100
    LEADERBOARD_CACHE_TTL_SECONDS = 300  # 5 minutes
    
    # Logging
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    LOG_RETENTION_DAYS = 90
    
    # Feature Flags
    ENABLE_EMAIL_VERIFICATION = os.getenv("ENABLE_EMAIL_VERIFICATION", "false").lower() == "true"
    ENABLE_RATE_LIMITING = os.getenv("ENABLE_RATE_LIMITING", "true").lower() == "true"
    ENABLE_ANALYTICS = os.getenv("ENABLE_ANALYTICS", "true").lower() == "true"
    ENABLE_FRAUD_DETECTION = os.getenv("ENABLE_FRAUD_DETECTION", "true").lower() == "true"
    
    # API Versioning
    API_VERSION = "v1"
    
    @classmethod
    def validate(cls) -> list[str]:
        """Validate configuration and return list of errors"""
        errors = []
        
        # JWT Secret validation
        if cls.JWT_SECRET == "CHANGE_ME_IN_PRODUCTION":
            if cls.is_production():
                errors.append("CRITICAL: JWT_SECRET must be set in production!")
            else:
                errors.append("WARNING: JWT_SECRET is using default value (development only)")
        
        if len(cls.JWT_SECRET) < 32:
            errors.append("CRITICAL: JWT_SECRET must be at least 32 characters for security")
        
        # Email configuration
        if cls.ENABLE_EMAIL_VERIFICATION and not cls.EMAIL_FROM:
            errors.append("EMAIL_FROM must be set when email verification is enabled")
        
        # CORS validation
        if cls.is_production() and "*" in cls.ALLOWED_ORIGINS:
            errors.append("WARNING: CORS wildcard (*) should not be used in production")
        
        return errors
    
    @classmethod
    def is_production(cls) -> bool:
        """Check if running in production environment"""
        return os.getenv("ENVIRONMENT", "dev").lower() in ("production", "prod")


class DevelopmentConfig(Config):
    """Development configuration"""
    LOG_LEVEL = "DEBUG"
    ENABLE_EMAIL_VERIFICATION = False  # Email verification kapali varsayilan
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES = 1440  # 24 hours for easier dev


class ProductionConfig(Config):
    """Production configuration with stricter security"""
    PASSWORD_REQUIRE_SPECIAL = True
    BCRYPT_ROUNDS = 14
    ENABLE_EMAIL_VERIFICATION = False
    ENABLE_RATE_LIMITING = True
    ENABLE_FRAUD_DETECTION = True


def get_config() -> Config:
    """Get configuration based on environment"""
    env = os.getenv("ENVIRONMENT", "dev").lower()
    
    if env in ("production", "prod"):
        return ProductionConfig()
    else:
        return DevelopmentConfig()


# Global config instance
config = get_config()
