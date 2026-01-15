"""
Database models and schemas
"""

from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional
from decimal import Decimal


@dataclass
class User:
    """User model"""
    user_id: str
    email: Optional[str] = None
    password_hash: Optional[str] = None
    wallet_address: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    email_verified: bool = False
    is_active: bool = True
    last_login_at: Optional[str] = None
    require_email_verification: bool = True  # User preference for email verification
    
    def to_dict(self) -> Dict:
        """Convert to dictionary (excluding sensitive data)"""
        data = asdict(self)
        data.pop("password_hash", None)  # Never expose password hash
        return data
    
    def to_db_item(self) -> Dict:
        """Convert to DynamoDB item"""
        return asdict(self)


@dataclass
class UserWallet:
    """User wallet linkage model"""
    wallet_address: str
    user_id: str
    linked_at: str
    is_primary: bool = False
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class Session:
    """User session model"""
    session_token: str
    user_id: str
    created_at: str
    expires_at: str
    platform: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    is_valid: bool = True
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class PlayerData:
    """Player game data model"""
    user_id: str
    games_played: int = 0
    games_won: int = 0
    total_score: int = 0
    highest_wave: int = 0
    level: int = 1
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    # Legacy fields (kept for backwards compatibility)
    dust_count: int = 0
    high_score: int = 0
    attempt_count: int = 0
    mint_right: int = 3
    token_id: int = -1
    token_level: int = 0
    skill_locations: Optional[List[Dict[str, any]]] = None
    
    def __post_init__(self):
        if self.skill_locations is None:
            self.skill_locations = []
    
    def to_dict(self) -> Dict:
        data = asdict(self)
        # Convert Decimal to int for JSON serialization
        for key in ['dust_count', 'high_score', 'attempt_count', 'mint_right', 'token_id', 'token_level', 
                    'games_played', 'games_won', 'total_score', 'highest_wave', 'level']:
            if isinstance(data.get(key), Decimal):
                data[key] = int(data[key])
        return data


@dataclass
class Achievement:
    """Player achievements model"""
    user_id: str
    achievement_id: str
    unlocked_at: str
    progress: int = 100  # 0-100 percentage
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class LeaderboardEntry:
    """Leaderboard entry model"""
    user_id: str
    score_type: str  # 'kills' or 'dust'
    score_value: int
    rank: Optional[int] = None
    timestamp: Optional[str] = None
    season_id: Optional[str] = None
    
    def to_dict(self) -> Dict:
        data = asdict(self)
        if isinstance(data.get('score_value'), Decimal):
            data['score_value'] = int(data['score_value'])
        return data


@dataclass
class EmailVerification:
    """Email verification token model"""
    email: str
    verification_token: str
    user_id: str
    created_at: str
    expires_at: str
    is_used: bool = False
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class PasswordReset:
    """Password reset token model"""
    email: str
    reset_token: str
    user_id: str
    created_at: str
    expires_at: str
    is_used: bool = False
    
    def to_dict(self) -> Dict:
        return asdict(self)


# Helper functions for datetime handling

def now_iso() -> str:
    """Get current time in ISO format"""
    return datetime.now(timezone.utc).isoformat()


def expires_at(hours: int) -> str:
    """Get expiration time in ISO format"""
    expires = datetime.now(timezone.utc) + timedelta(hours=hours)
    return expires.isoformat()
