"""
Database models and schemas
"""

from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional
from decimal import Decimal


@dataclass
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
    require_email_verification: bool = False
    is_active: bool = True
    last_login_at: Optional[str] = None
    
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


# ==================== GAME SESSION DATA ACCESS ====================

import boto3
import uuid

dynamodb = boto3.resource('dynamodb', region_name='eu-north-1')

def create_game_session(user_id, difficulty='normal', game_mode='survival'):
    """
    Create new game session in hive_sessions table.
    
    Args:
        user_id: User ID from JWT
        difficulty: normal, hard, insane
        game_mode: survival, endless, campaign
    
    Returns:
        dict: Session object with session_id, user_id, started_at, etc.
    """
    table = dynamodb.Table('hive_sessions')
    session_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    
    session = {
        'session_id': session_id,
        'user_id': user_id,
        'difficulty': difficulty,
        'game_mode': game_mode,
        'started_at': now,
        'score': 0,
        'status': 'active',
        'duration_seconds': 0
    }
    
    table.put_item(Item=session)
    return session


def get_game_session(session_id):
    """
    Retrieve game session by ID.
    
    Args:
        session_id: Session UUID
    
    Returns:
        dict or None: Session object if found
    """
    table = dynamodb.Table('hive_sessions')
    response = table.get_item(Key={'session_id': session_id})
    return response.get('Item')


def end_game_session(session_id, score, duration_seconds, reason='user_quit'):
    """
    Mark session as ended and record final score.
    
    Args:
        session_id: Session UUID
        score: Final score
        duration_seconds: Total play time
        reason: game_over, user_quit, disconnected
    
    Returns:
        dict: Updated session object
    """
    table = dynamodb.Table('hive_sessions')
    now = datetime.now(timezone.utc).isoformat()
    
    table.update_item(
        Key={'session_id': session_id},
        UpdateExpression='SET #status = :status, final_score = :score, ended_at = :ended, duration_seconds = :duration, end_reason = :reason',
        ExpressionAttributeNames={'#status': 'status'},
        ExpressionAttributeValues={
            ':status': 'ended',
            ':score': score,
            ':ended': now,
            ':duration': duration_seconds,
            ':reason': reason
        }
    )
    
    # Return updated session
    return get_game_session(session_id)


def get_player_data(user_id):
    """
    Retrieve player progression data.
    
    Args:
        user_id: User UUID
    
    Returns:
        dict: Player data (level, xp, gold, total_score)
    """
    table = dynamodb.Table('hive_player_data')
    response = table.get_item(Key={'user_id': user_id})
    return response.get('Item', {
        'user_id': user_id,
        'level': 1,
        'experience': 0,
        'gold': 0,
        'total_score': 0,
        'games_played': 0
    })


def update_player_progression(user_id, score_earned, xp_earned, gold_earned):
    """
    Update player level, XP, gold after session end.
    
    Args:
        user_id: User UUID
        score_earned: Score from session
        xp_earned: XP from session
        gold_earned: Gold from session
    
    Returns:
        dict: Updated player data with level_up flag
    """
    table = dynamodb.Table('hive_player_data')
    player = get_player_data(user_id)
    
    old_xp = player.get('experience', 0)
    old_level = player.get('level', 1)
    old_gold = player.get('gold', 0)
    old_score = player.get('total_score', 0)
    games_played = player.get('games_played', 0)
    
    new_xp = old_xp + xp_earned
    new_gold = old_gold + gold_earned
    new_score = old_score + score_earned
    new_level = calculate_level_from_xp(new_xp)
    
    table.update_item(
        Key={'user_id': user_id},
        UpdateExpression='SET experience = :xp, #lvl = :level, gold = :gold, total_score = :score, games_played = :games',
        ExpressionAttributeNames={'#lvl': 'level'},
        ExpressionAttributeValues={
            ':xp': new_xp,
            ':level': new_level,
            ':gold': new_gold,
            ':score': new_score,
            ':games': games_played + 1
        }
    )
    
    return {
        'user_id': user_id,
        'old_level': old_level,
        'new_level': new_level,
        'level_up': new_level > old_level,
        'experience': new_xp,
        'xp_earned': xp_earned,
        'gold': new_gold,
        'gold_earned': gold_earned,
        'total_score': new_score
    }


def calculate_level_from_xp(xp):
    """
    Calculate player level from total XP.
    
    XP thresholds:
    Level 1: 0 XP
    Level 2: 1000 XP
    Level 3: 3000 XP
    Level 4: 6000 XP
    Level 5: 10000 XP
    ... (exponential growth)
    
    Args:
        xp: Total experience points
    
    Returns:
        int: Player level (1-100)
    """
    thresholds = [0, 1000, 3000, 6000, 10000, 15000, 21000, 28000, 36000, 45000, 55000]
    
    for level in range(len(thresholds) - 1, -1, -1):
        if xp >= thresholds[level]:
            return level + 1
    
    return 1


def update_leaderboard(user_id, score, board_type='alltime'):
    """
    Update leaderboard entry if score is better than current.
    
    Args:
        user_id: User UUID
        score: Session score
        board_type: daily, weekly, or alltime
    
    Returns:
        bool: True if leaderboard was updated
    """
    table_name = f'hive_leaderboard_{board_type}'
    table = dynamodb.Table(table_name)
    
    # Get current entry
    response = table.get_item(Key={'user_id': user_id})
    current = response.get('Item', {})
    current_score = current.get('score', 0)
    
    # Only update if new score is better
    if score > current_score:
        now = datetime.now(timezone.utc).isoformat()
        table.put_item(Item={
            'user_id': user_id,
            'score': score,
            'timestamp': now
        })
        return True
    
    return False
