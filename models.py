"""
Database models and schemas
"""

from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional
from decimal import Decimal
from logger import logger


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


# ==================== KEY OWNERSHIP MANAGEMENT ====================

def get_key_ownership(user_id):
    """
    Get player's key ownership counts from player_data table.
    
    Args:
        user_id: User UUID
    
    Returns:
        dict: {bronze: int, silver: int, gold: int}
    """
    table = dynamodb.Table('hive_player_data')
    response = table.get_item(Key={'user_id': user_id})
    player_data = response.get('Item', {})
    
    # Get keys_owned map or default to 0 for each
    keys_owned = player_data.get('keys_owned', {})
    return {
        'bronze': int(keys_owned.get('bronze', 0)),
        'silver': int(keys_owned.get('silver', 0)),
        'gold': int(keys_owned.get('gold', 0))
    }


def add_key_to_player(user_id, key_type, purchase_event):
    """
    Add a key to player's inventory and record purchase event with idempotency.
    
    Uses tx_index map to guard against duplicate tx_hash processing.
    
    Args:
        user_id: User UUID
        key_type: "bronze", "silver", or "gold"
        purchase_event: Purchase event dict from contract_adapter
    
    Returns:
        dict: Updated key ownership {bronze: int, silver: int, gold: int}
        
    Raises:
        Exception: If tx_hash already processed (ConditionExpression fails)
    """
    from botocore.exceptions import ClientError
    
    table = dynamodb.Table('hive_player_data')
    tx_hash = purchase_event.get('tx_hash', '')
    
    # Get current ownership and history
    response = table.get_item(Key={'user_id': user_id})
    player_data = response.get('Item', {})
    
    current_keys = {
        'bronze': int(player_data.get('keys_owned', {}).get('bronze', 0)),
        'silver': int(player_data.get('keys_owned', {}).get('silver', 0)),
        'gold': int(player_data.get('keys_owned', {}).get('gold', 0))
    }
    
    # Increment the key count
    current_keys[key_type] += 1
    
    # Get current purchase history (limit to last 100)
    purchase_history = player_data.get('key_purchase_history', [])
    purchase_history.insert(0, purchase_event)  # Most recent first
    purchase_history = purchase_history[:100]  # Keep last 100
    
    # Build tx_index (map of tx_hash -> true for deduplication)
    tx_index = player_data.get('tx_index', {})
    
    # Prepare update expression with idempotency guard
    now = datetime.now(timezone.utc).isoformat()
    
    try:
        table.update_item(
            Key={'user_id': user_id},
            UpdateExpression='SET keys_owned = :keys, key_purchase_history = :history, tx_index.#tx = :true, updated_at = :now',
            ConditionExpression='attribute_not_exists(tx_index.#tx)',
            ExpressionAttributeNames={
                '#tx': tx_hash  # Use attribute name placeholder for tx_hash
            },
            ExpressionAttributeValues={
                ':keys': current_keys,
                ':history': purchase_history,
                ':true': True,
                ':now': now
            }
        )
        
        logger.info(
            f"Key added to player with idempotency guard: {key_type}",
            context={"user_id": user_id, "tx_hash": tx_hash}
        )
        
        return current_keys
        
    except ClientError as e:
        if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
            logger.warning(
                f"Duplicate tx_hash detected: {tx_hash}",
                context={"user_id": user_id}
            )
            raise Exception(f"Transaction {tx_hash} already processed") from e
        else:
            raise


def check_tx_hash_processed(tx_hash):
    """
    Check if a transaction hash has already been processed (idempotency check).
    
    Scans key_purchase_history across all users for the given tx_hash.
    
    Args:
        tx_hash: Transaction hash to check (0x-prefixed)
    
    Returns:
        bool: True if tx_hash found, False otherwise
    """
    try:
        table = dynamodb.Table('hive_player_data')
        
        # Normalize tx_hash for comparison
        tx_hash = tx_hash.lower().strip()
        if not tx_hash.startswith('0x'):
            tx_hash = '0x' + tx_hash
        
        # Scan for any purchase event with this tx_hash
        # Note: In production, consider maintaining a separate transaction index table
        # for better performance than full table scan
        response = table.scan(
            ProjectionExpression='key_purchase_history',
            Limit=100  # Process in batches to avoid timeout
        )
        
        # Check current batch
        for item in response.get('Items', []):
            history = item.get('key_purchase_history', [])
            for event in history:
                if event.get('tx_hash', '').lower() == tx_hash:
                    return True
        
        # Note: For full idempotency across large table, implement pagination
        # For now, first 100 users should cover most cases
        while 'LastEvaluatedKey' in response and len(response.get('Items', [])) < 1000:
            response = table.scan(
                ProjectionExpression='key_purchase_history',
                ExclusiveStartKey=response['LastEvaluatedKey'],
                Limit=100
            )
            for item in response.get('Items', []):
                history = item.get('key_purchase_history', [])
                for event in history:
                    if event.get('tx_hash', '').lower() == tx_hash:
                        return True
        
        return False
        
    except Exception as e:
        from logger import logger
        logger.error(f"Error checking tx_hash: {str(e)}", error=e)
        # Fail open: if we can't check, allow it (better UX than blocking legit transactions)
        return False




def get_key_purchase_history(user_id, limit=20):
    """
    Get player's key purchase history.
    
    Args:
        user_id: User UUID
        limit: Max number of events to return
    
    Returns:
        list: Purchase event objects
    """
    table = dynamodb.Table('hive_player_data')
    response = table.get_item(Key={'user_id': user_id})
    player_data = response.get('Item', {})
    
    history = player_data.get('key_purchase_history', [])
    return history[:limit]


# ==================== GAMEPLAY DATA MANAGEMENT ====================

def get_player_pilots(user_id):
    """
    Get player's owned pilots.
    
    Args:
        user_id: User UUID
    
    Returns:
        list: Pilot objects
    """
    table = dynamodb.Table('hive_player_data')
    response = table.get_item(Key={'user_id': user_id})
    player_data = response.get('Item', {})
    
    pilots = player_data.get('pilots', [])
    return pilots


def unlock_pilot(user_id, pilot_id):
    """
    Unlock a new pilot for the player.
    
    Args:
        user_id: User UUID
        pilot_id: Pilot identifier
    
    Returns:
        dict: Updated pilot list
    """
    table = dynamodb.Table('hive_player_data')
    now = datetime.now(timezone.utc).isoformat()
    
    # Get current pilots
    current_pilots = get_player_pilots(user_id)
    
    # Check if already unlocked
    for pilot in current_pilots:
        if pilot.get('pilot_id') == pilot_id:
            return {'error': 'Pilot already unlocked'}
    
    # Add new pilot
    new_pilot = {
        'pilot_id': pilot_id,
        'pilot_level': 1,
        'acquired_at': now,
        'is_active': len(current_pilots) == 0  # First pilot is active
    }
    current_pilots.append(new_pilot)
    
    # Update DB
    table.update_item(
        Key={'user_id': user_id},
        UpdateExpression='SET pilots = :pilots, updated_at = :now',
        ExpressionAttributeValues={
            ':pilots': current_pilots,
            ':now': now
        }
    )
    
    return {'pilots': current_pilots, 'unlocked': new_pilot}


def get_player_mechs(user_id):
    """
    Get player's owned mechs.
    
    Args:
        user_id: User UUID
    
    Returns:
        list: Mech objects
    """
    table = dynamodb.Table('hive_player_data')
    response = table.get_item(Key={'user_id': user_id})
    player_data = response.get('Item', {})
    
    mechs = player_data.get('mechs', [])
    return mechs


def unlock_mech(user_id, mech_id, variant='standard'):
    """
    Unlock a new mech for the player.
    
    Args:
        user_id: User UUID
        mech_id: Mech identifier
        variant: Mech variant/rarity
    
    Returns:
        dict: Updated mech list
    """
    table = dynamodb.Table('hive_player_data')
    now = datetime.now(timezone.utc).isoformat()
    
    # Get current mechs
    current_mechs = get_player_mechs(user_id)
    
    # Check if already unlocked
    for mech in current_mechs:
        if mech.get('mech_id') == mech_id:
            return {'error': 'Mech already unlocked'}
    
    # Add new mech
    new_mech = {
        'mech_id': mech_id,
        'acquired_at': now,
        'variant': variant,
        'is_active': len(current_mechs) == 0  # First mech is active
    }
    current_mechs.append(new_mech)
    
    # Update DB
    table.update_item(
        Key={'user_id': user_id},
        UpdateExpression='SET mechs = :mechs, updated_at = :now',
        ExpressionAttributeValues={
            ':mechs': current_mechs,
            ':now': now
        }
    )
    
    return {'mechs': current_mechs, 'unlocked': new_mech}


def get_active_boosts(user_id):
    """
    Get player's active boosts.
    
    Args:
        user_id: User UUID
    
    Returns:
        list: Active boost objects
    """
    table = dynamodb.Table('hive_player_data')
    response = table.get_item(Key={'user_id': user_id})
    player_data = response.get('Item', {})
    
    boosts = player_data.get('boosts', [])
    
    # Filter only active (non-expired) boosts
    now = datetime.now(timezone.utc)
    active_boosts = []
    for boost in boosts:
        expires_at = datetime.fromisoformat(boost.get('expires_at'))
        if expires_at > now and boost.get('is_active', True):
            active_boosts.append(boost)
    
    return active_boosts


def activate_boost(user_id, boost_id, boost_name, duration_seconds):
    """
    Activate a boost for the player.
    
    Args:
        user_id: User UUID
        boost_id: Boost identifier
        boost_name: Display name
        duration_seconds: Boost duration
    
    Returns:
        dict: New boost object
    """
    table = dynamodb.Table('hive_player_data')
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    expires_at = (now + timedelta(seconds=duration_seconds)).isoformat()
    
    # Get current boosts
    response = table.get_item(Key={'user_id': user_id})
    player_data = response.get('Item', {})
    boosts = player_data.get('boosts', [])
    
    # Add new boost
    new_boost = {
        'boost_id': boost_id,
        'boost_name': boost_name,
        'acquired_at': now_iso,
        'duration_seconds': duration_seconds,
        'expires_at': expires_at,
        'is_active': True
    }
    boosts.append(new_boost)
    
    # Update DB
    table.update_item(
        Key={'user_id': user_id},
        UpdateExpression='SET boosts = :boosts, updated_at = :now',
        ExpressionAttributeValues={
            ':boosts': boosts,
            ':now': now_iso
        }
    )
    
    return new_boost


def get_player_skills(user_id):
    """
    Get player's skills.
    
    Args:
        user_id: User UUID
    
    Returns:
        list: Skill objects
    """
    table = dynamodb.Table('hive_player_data')
    response = table.get_item(Key={'user_id': user_id})
    player_data = response.get('Item', {})
    
    skills = player_data.get('skills', [])
    return skills


def unlock_skill(user_id, skill_id, slot=None):
    """
    Unlock or upgrade a skill for the player.
    
    Args:
        user_id: User UUID
        skill_id: Skill identifier
        slot: Skill slot (optional)
    
    Returns:
        dict: Updated skill object
    """
    table = dynamodb.Table('hive_player_data')
    now = datetime.now(timezone.utc).isoformat()
    
    # Get current skills
    current_skills = get_player_skills(user_id)
    
    # Check if skill already exists (upgrade level)
    skill_found = False
    for skill in current_skills:
        if skill.get('skill_id') == skill_id:
            skill['skill_level'] = skill.get('skill_level', 1) + 1
            skill_found = True
            updated_skill = skill
            break
    
    # If not found, add new skill
    if not skill_found:
        new_skill = {
            'skill_id': skill_id,
            'skill_level': 1,
            'slot': slot,
            'unlocked_at': now
        }
        current_skills.append(new_skill)
        updated_skill = new_skill
    
    # Update DB
    table.update_item(
        Key={'user_id': user_id},
        UpdateExpression='SET skills = :skills, updated_at = :now',
        ExpressionAttributeValues={
            ':skills': current_skills,
            ':now': now
        }
    )
    
    return {'skills': current_skills, 'updated': updated_skill}


def update_gems(user_id, amount):
    """
    Update player's gem count.
    
    Args:
        user_id: User UUID
        amount: Gems to add (can be negative)
    
    Returns:
        int: New gem count
    """
    table = dynamodb.Table('hive_player_data')
    now = datetime.now(timezone.utc).isoformat()
    
    # Get current gems
    response = table.get_item(Key={'user_id': user_id})
    player_data = response.get('Item', {})
    current_gems = player_data.get('gems', 0)
    
    new_gems = max(0, current_gems + amount)
    
    # Update DB
    table.update_item(
        Key={'user_id': user_id},
        UpdateExpression='SET gems = :gems, updated_at = :now',
        ExpressionAttributeValues={
            ':gems': new_gems,
            ':now': now
        }
    )
    
    return new_gems


def update_dust(user_id, amount):
    """
    Update player's dust count.
    
    Args:
        user_id: User UUID
        amount: Dust to add (can be negative)
    
    Returns:
        int: New dust count
    """
    table = dynamodb.Table('hive_player_data')
    now = datetime.now(timezone.utc).isoformat()
    
    # Get current dust
    response = table.get_item(Key={'user_id': user_id})
    player_data = response.get('Item', {})
    current_dust = player_data.get('dust_count', 0)
    
    new_dust = max(0, current_dust + amount)
    
    # Update DB
    table.update_item(
        Key={'user_id': user_id},
        UpdateExpression='SET dust_count = :dust, updated_at = :now',
        ExpressionAttributeValues={
            ':dust': new_dust,
            ':now': now
        }
    )
    
    return new_dust


def unlock_achievement(user_id, achievement_id):
    """
    Unlock an achievement for the player.
    
    Args:
        user_id: User UUID
        achievement_id: Achievement identifier
    
    Returns:
        dict: New achievement object
    """
    import boto3
    dynamodb = boto3.resource('dynamodb', region_name='eu-north-1')
    achievements_table = dynamodb.Table('hive_achievements')
    
    now = datetime.now(timezone.utc).isoformat()
    
    # Check if already unlocked
    response = achievements_table.query(
        KeyConditionExpression='user_id = :uid',
        FilterExpression='achievement_id = :aid',
        ExpressionAttributeValues={
            ':uid': user_id,
            ':aid': achievement_id
        }
    )
    
    if response.get('Items'):
        return {'error': 'Achievement already unlocked'}
    
    # Create achievement record
    achievement = {
        'user_id': user_id,
        'achievement_id': achievement_id,
        'unlocked_at': now,
        'progress': 100
    }
    
    achievements_table.put_item(Item=achievement)
    
    return achievement
