"""
Main Lambda Handler for Hive Invasion Backend
Unified API for mobile and web platforms
"""

import json
from datetime import datetime, timezone

# Import utilities
from config import config
from responses import APIResponse, get_origin, get_request_id
from validation import validate_request_body, ValidationError
from logger import logger
from decorators import require_auth, optional_auth, rate_limit, log_request

# Import auth services
from email_auth import EmailAuthService
from wallet_auth import WalletAuthService
from jwt_handler import JWTHandler

# Import game services (to be implemented)
# achievements import AchievementsService
# save import SaveService
# leaderboard import LeaderboardService
# profile import ProfileService


def lambda_handler(event, context):
    """
    Main Lambda handler
    Routes requests to appropriate handlers
    """
    try:
        # Validate configuration on cold start
        if hasattr(lambda_handler, '_first_run'):
            errors = config.validate()
            if errors and config.is_production():
                logger.critical("Configuration errors", context={"errors": errors})
                return APIResponse.server_error("Service misconfigured")
            lambda_handler._first_run = False
        
        origin = get_origin(event)
        method = event.get('httpMethod') or event.get('requestContext', {}).get('http', {}).get('method', 'GET')
        path = event.get('path') or event.get('rawPath', '/')
        
        # Normalize path
        path = path.strip('/').lower()
        
        # Handle OPTIONS (CORS preflight)
        if method == 'OPTIONS':
            return APIResponse.options(origin)
        
        # Route to appropriate handler
        if path.startswith('auth/'):
            return handle_auth(event, context, method, path, origin)
        
        elif path.startswith('game/') or path.startswith('player/'):
            return handle_game(event, context, method, path, origin)
        
        elif path.startswith('leaderboard/'):
            return handle_leaderboard(event, context, method, path, origin)
        
        elif path.startswith('analytics/'):
            return handle_analytics(event, context, method, path, origin)
        
        elif path in ('', 'health', 'ping'):
            return handle_health(event, context, origin)
        
        else:
            return APIResponse.error(
                f"Endpoint not found: {method} /{path}",
                status_code=404,
                error_code="NOT_FOUND",
                origin=origin
            )
    
    except ValidationError as e:
        logger.warning(f"Validation error: {e.message}", context={"field": e.field})
        return APIResponse.validation_error(e.field, e.message, get_origin(event))
    
    except Exception as e:
        import traceback
        error_details = {
            "error_type": type(e).__name__,
            "error_message": str(e),
            "traceback": traceback.format_exc(),
            "path": event.get('path'),
            "method": event.get('httpMethod')
        }
        logger.error(f"Unhandled error in lambda_handler", error=e, context=error_details)
        print(f"[DETAILED ERROR] {error_details}")  # Extra stdout logging
        return APIResponse.server_error(origin=get_origin(event))


lambda_handler._first_run = True


# ==================== AUTH HANDLERS ====================

def handle_auth(event, context, method, path, origin):
    """Handle authentication endpoints"""
    
    try:
        body = validate_request_body(event.get('body'))
        
        # POST /auth/register - Email registration
        if path == 'auth/register' and method == 'POST':
            from validation import Validator
            
            email = Validator.required(body, 'email')
            password = Validator.required(body, 'password')
            
            auth_service = EmailAuthService()
            success, data, error = auth_service.register(email, password)
            
            if success:
                return APIResponse.success(data, status_code=201, origin=origin)
            else:
                return APIResponse.error(error, status_code=400, origin=origin)
        
        # POST /auth/login - Email login
        elif path == 'auth/login' and method == 'POST':
            from validation import Validator
            
            email = Validator.required(body, 'email')
            password = Validator.required(body, 'password')
            
            auth_service = EmailAuthService()
            success, data, error = auth_service.login(email, password)
            
            if success:
                return APIResponse.success(data, origin=origin)
            else:
                return APIResponse.error(error, status_code=401, origin=origin)
        
        # POST /auth/wallet/message - Get message to sign
        elif path == 'auth/wallet/message' and method == 'POST':
            from validation import Validator
            
            wallet_address = Validator.required(body, 'wallet_address')
            
            wallet_service = WalletAuthService()
            success, data, error = wallet_service.get_message_to_sign(wallet_address)
            
            if success:
                return APIResponse.success(data, origin=origin)
            else:
                return APIResponse.error(error, origin=origin)
        
        # POST /auth/wallet/verify - Verify wallet signature
        elif path == 'auth/wallet/verify' and method == 'POST':
            from validation import Validator
            
            wallet_address = Validator.required(body, 'wallet_address')
            signature = Validator.required(body, 'signature')
            message = Validator.required(body, 'message')
            
            wallet_service = WalletAuthService()
            success, data, error = wallet_service.authenticate_wallet(wallet_address, signature, message)
            
            if success:
                return APIResponse.success(data, origin=origin)
            else:
                return APIResponse.error(error, status_code=401, origin=origin)
        
        # POST /auth/refresh - Refresh access token
        elif path == 'auth/refresh' and method == 'POST':
            from validation import Validator
            
            refresh_token = Validator.required(body, 'refresh_token')
            
            is_valid, payload, error = JWTHandler.verify_token(refresh_token, "refresh")
            
            if not is_valid:
                return APIResponse.unauthorized(error, origin)
            
            user_id = payload.get('sub')
            tokens = JWTHandler.create_token_pair(user_id)
            
            return APIResponse.success(tokens, origin=origin)
        
        # POST /auth/link-wallet - Link wallet to current user (requires auth)
        elif path == 'auth/link-wallet' and method == 'POST':
            return handle_link_wallet(event, context)
        
        # DELETE /auth/unlink-wallet - Unlink wallet from current user (requires auth)
        elif path == 'auth/unlink-wallet' and method == 'DELETE':
            return handle_unlink_wallet(event, context)
        
        # POST /auth/change-password - Change password (requires auth)
        elif path == 'auth/change-password' and method == 'POST':
            return handle_change_password(event, context)
        
        # POST /auth/password-reset/request - Request password reset
        elif path == 'auth/password-reset/request' and method == 'POST':
            from validation import Validator
            
            email = Validator.required(body, 'email')
            logger.info(f"Password reset request for email: {email}")
            
            auth_service = EmailAuthService()
            success, error = auth_service.request_password_reset(email)
            
            logger.info(f"Password reset result - success: {success}, error: {error}")
            
            # Always return success to prevent email enumeration
            return APIResponse.success(
                {"message": "If the email exists, a reset link has been sent"},
                origin=origin
            )
        
        # POST /auth/password-reset/confirm - Confirm password reset
        elif path == 'auth/password-reset/confirm' and method == 'POST':
            from validation import Validator
            
            reset_token = Validator.required(body, 'reset_token')
            new_password = Validator.required(body, 'new_password')
            
            auth_service = EmailAuthService()
            success, error = auth_service.reset_password(reset_token, new_password)
            
            if success:
                return APIResponse.success({"message": "Password reset successful"}, origin=origin)
            else:
                return APIResponse.error(error, origin=origin)
        
        # GET /auth/verify-email - Verify email with token
        elif path == 'auth/verify-email' and method == 'GET':
            params = event.get('queryStringParameters', {}) or {}
            verification_token = params.get('token')
            
            if not verification_token:
                return APIResponse.error("Verification token is required", status_code=400, origin=origin)
            
            logger.info(f"Email verification attempt with token: {verification_token[:10]}...")
            
            auth_service = EmailAuthService()
            success, error = auth_service.verify_email(verification_token)
            
            if success:
                return APIResponse.success({"message": "Email verified successfully"}, origin=origin)
            else:
                return APIResponse.error(error, status_code=400, origin=origin)
        
        # DELETE /auth/account - Delete account (requires auth)
        elif path == 'auth/account' and method == 'DELETE':
            return handle_delete_account(event, context)
        
        else:
            return APIResponse.not_found("Auth endpoint", origin)
    
    except Exception as e:
        import traceback
        logger.error("Auth handler error", error=e, context={
            "error_type": type(e).__name__,
            "error_message": str(e),
            "traceback": traceback.format_exc()
        })
        return APIResponse.server_error(origin=origin)


@require_auth()
def handle_link_wallet(event, context, user_id):
    """Link wallet to current user"""
    origin = get_origin(event)
    
    try:
        body = validate_request_body(event.get('body'))
        from validation import Validator
        
        wallet_address = Validator.required(body, 'wallet_address')
        signature = Validator.required(body, 'signature')
        message = Validator.required(body, 'message')
        
        wallet_service = WalletAuthService()
        success, error = wallet_service.link_wallet_to_user(user_id, wallet_address, signature, message)
        
        if success:
            return APIResponse.success(
                {"message": "Wallet linked successfully", "wallet_address": wallet_address},
                origin=origin
            )
        else:
            return APIResponse.error(error, origin=origin)
    
    except Exception as e:
        logger.error("Link wallet error", error=e, user_id=user_id)
        return APIResponse.server_error(origin=origin)


@require_auth()
def handle_unlink_wallet(event, context, user_id):
    """Unlink wallet from current user"""
    origin = get_origin(event)
    
    try:
        import boto3
        dynamodb = boto3.resource('dynamodb', region_name=config.AWS_REGION)
        
        # Get user to find wallet address
        users_table = dynamodb.Table(config.TABLE_USERS)
        user_response = users_table.get_item(Key={"user_id": user_id})
        
        if 'Item' not in user_response:
            return APIResponse.error("User not found", status_code=404, origin=origin)
        
        user_data = user_response['Item']
        wallet_address = user_data.get('wallet_address')
        
        if not wallet_address:
            return APIResponse.error(
                "No wallet linked to this account",
                status_code=400,
                origin=origin
            )
        
        # Remove wallet from user_wallets table
        user_wallets_table = dynamodb.Table(config.TABLE_USER_WALLETS)
        user_wallets_table.delete_item(Key={"wallet_address": wallet_address})
        
        # Remove wallet_address from user record
        users_table.update_item(
            Key={"user_id": user_id},
            UpdateExpression="REMOVE wallet_address",
            ConditionExpression="attribute_exists(user_id)"
        )
        
        logger.info(
            "Wallet unlinked",
            context={"user_id": user_id, "wallet_address": wallet_address}
        )
        
        return APIResponse.success(
            {
                "message": "Wallet unlinked successfully",
                "unlinked_wallet": wallet_address
            },
            origin=origin
        )
    
    except Exception as e:
        logger.error("Unlink wallet error", error=e, user_id=user_id)
        return APIResponse.server_error(origin=origin)


@require_auth()
def handle_delete_account(event, context, user_id):
    """Delete user account (GDPR compliance)"""
    origin = get_origin(event)
    
    try:
        import boto3
        from datetime import datetime, timezone
        import json
        
        dynamodb = boto3.resource('dynamodb', region_name=config.AWS_REGION)
        
        # 1. Get complete user data before deletion
        users_table = dynamodb.Table(config.TABLE_USERS)
        user_response = users_table.get_item(Key={"user_id": user_id})
        
        if 'Item' not in user_response:
            return APIResponse.error("User not found", status_code=404, origin=origin)
        
        user_data = user_response['Item']
        email = user_data.get('email', 'unknown')
        
        # 2. Log deletion to deleted_accounts table for audit trail
        deleted_accounts_table = dynamodb.Table(config.TABLE_DELETED_ACCOUNTS)
        deletion_record = {
            "user_id": user_id,
            "email": email,
            "deletion_requested_at": datetime.now(timezone.utc).isoformat(),
            "deletion_scheduled_for": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
            "original_user_data": json.dumps(user_data, default=str),
            "ip_address": event.get('requestContext', {}).get('identity', {}).get('sourceIp', 'unknown'),
            "user_agent": event.get('headers', {}).get('User-Agent', 'unknown'),
            "reason": "user_requested",
            "status": "pending"
        }
        
        deleted_accounts_table.put_item(Item=deletion_record)
        
        logger.info("Account deletion scheduled", context={
            "user_id": user_id,
            "email": email,
            "scheduled_date": deletion_record["deletion_scheduled_for"]
        })
        
        # 3. Mark user as inactive (soft delete)
        users_table.update_item(
            Key={"user_id": user_id},
            UpdateExpression="SET is_active = :inactive, deleted_at = :now",
            ExpressionAttributeValues={
                ":inactive": False,
                ":now": datetime.now(timezone.utc).isoformat()
            }
        )
        
        # 4. Log to CloudWatch for additional audit
        print(json.dumps({
            "event": "ACCOUNT_DELETION_REQUESTED",
            "user_id": user_id,
            "email": email,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ip": deletion_record["ip_address"]
        }))
        
        return APIResponse.success(
            {
                "message": "Account deletion scheduled. Data will be removed within 30 days.",
                "scheduled_deletion_date": deletion_record["deletion_scheduled_for"]
            },
            origin=origin
        )
    
    except Exception as e:
        logger.error("Account deletion error", error=e, user_id=user_id)
        # Log the error attempt as well
        try:
            print(json.dumps({
                "event": "ACCOUNT_DELETION_FAILED",
                "user_id": user_id,
                "error": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }))
        except:
            pass
        return APIResponse.server_error(origin=origin)


@require_auth()
def handle_change_password(event, context, user_id):
    """Change password for authenticated user"""
    origin = get_origin(event)
    
    try:
        body = validate_request_body(event.get('body'))
        from validation import Validator
        
        current_password = Validator.required(body, 'current_password')
        new_password = Validator.required(body, 'new_password')
        
        # Validate new password is different
        if current_password == new_password:
            return APIResponse.error(
                "New password must be different from current password",
                status_code=400,
                origin=origin
            )
        
        import boto3
        from security import PasswordHasher
        
        dynamodb = boto3.resource('dynamodb', region_name=config.AWS_REGION)
        users_table = dynamodb.Table(config.TABLE_USERS)
        
        # Get user
        user_response = users_table.get_item(Key={"user_id": user_id})
        if 'Item' not in user_response:
            return APIResponse.error("User not found", status_code=404, origin=origin)
        
        user_data = user_response['Item']
        
        # Verify current password
        password_hash = user_data.get("password_hash")
        if not password_hash or not PasswordHasher.verify_password(current_password, password_hash):
            logger.warning("Failed password change attempt - wrong current password", context={
                "user_id": user_id
            })
            return APIResponse.error(
                "Current password is incorrect",
                status_code=401,
                origin=origin
            )
        
        # Validate new password strength
        is_strong, password_error = PasswordHasher.validate_password_strength(new_password)
        if not is_strong:
            return APIResponse.error(password_error, status_code=400, origin=origin)
        
        # Hash new password
        new_password_hash = PasswordHasher.hash_password(new_password)
        
        # Update password
        users_table.update_item(
            Key={"user_id": user_id},
            UpdateExpression="SET password_hash = :new_hash, updated_at = :now",
            ExpressionAttributeValues={
                ":new_hash": new_password_hash,
                ":now": datetime.now(timezone.utc).isoformat()
            }
        )
        
        logger.info("Password changed successfully", context={"user_id": user_id})
        
        return APIResponse.success(
            {"message": "Password changed successfully"},
            origin=origin
        )
    
    except ValidationError as e:
        return APIResponse.validation_error(e.field, e.message, origin)
    except Exception as e:
        logger.error("Password change error", error=e, user_id=user_id)
        return APIResponse.server_error(origin=origin)


# ==================== GAME HANDLERS ====================

def handle_game(event, context, method, path, origin):
    """Handle game-related endpoints"""
    try:
        # GET /player/profile - Get player profile
        if path == 'player/profile' and method == 'GET':
            return handle_player_profile(event, context)
        
        # GET /player/achievements - Get player achievements
        elif path == 'player/achievements' and method == 'GET':
            return handle_player_achievements(event, context)
        
        else:
            return APIResponse.success(
                {"message": "Game endpoints - to be implemented"},
                origin=origin
            )
    
    except Exception as e:
        logger.error("Game handler error", error=e)
        return APIResponse.server_error(origin=origin)


@require_auth()
def handle_player_profile(event, context, user_id):
    """Get player profile"""
    origin = get_origin(event)
    
    try:
        import boto3
        dynamodb = boto3.resource('dynamodb', region_name=config.AWS_REGION)
        
        # Get user from users table
        users_table = dynamodb.Table(config.TABLE_USERS)
        user_response = users_table.get_item(Key={"user_id": user_id})
        
        if 'Item' not in user_response:
            return APIResponse.error("User not found", status_code=404, origin=origin)
        
        user = user_response['Item']
        
        # Get player data (or create default)
        player_table = dynamodb.Table(config.TABLE_PLAYER_DATA)
        player_response = player_table.get_item(Key={"user_id": user_id})
        
        if 'Item' in player_response:
            player_data = player_response['Item']
        else:
            # Create default player data
            player_data = {
                'user_id': user_id,
                'level': 1,
                'total_score': 0,
                'games_played': 0,
                'games_won': 0,
                'highest_wave': 0,
                'created_at': datetime.now(timezone.utc).isoformat()
            }
            player_table.put_item(Item=player_data)
        
        # Combine user and player data
        profile = {
            'user_id': user_id,
            'username': user.get('email', '').split('@')[0],
            'email': user.get('email'),
            'wallet_address': user.get('wallet_address'),
            'level': player_data.get('level', 1),
            'total_score': player_data.get('total_score', 0),
            'games_played': player_data.get('games_played', 0),
            'games_won': player_data.get('games_won', 0),
            'highest_wave': player_data.get('highest_wave', 0),
            'dust_count': player_data.get('dust_count', 0),
            'created_at': user.get('created_at'),
            'is_verified': user.get('email_verified', False),
            'last_login_at': user.get('last_login_at')
        }
        
        # Return without 'player' wrapper for easier frontend access
        return APIResponse.success(profile, origin=origin)
    
    except Exception as e:
        logger.error("Player profile error", error=e, user_id=user_id)
        return APIResponse.server_error(origin=origin)


@require_auth()
def handle_player_achievements(event, context, user_id):
    """Get player achievements"""
    origin = get_origin(event)
    
    try:
        import boto3
        dynamodb = boto3.resource('dynamodb', region_name=config.AWS_REGION)
        
        achievements_table = dynamodb.Table(config.TABLE_ACHIEVEMENTS)
        response = achievements_table.query(
            KeyConditionExpression='user_id = :uid',
            ExpressionAttributeValues={':uid': user_id}
        )
        
        achievements = response.get('Items', [])
        
        # Return empty list if no achievements yet
        return APIResponse.success({'achievements': achievements}, origin=origin)
    
    except Exception as e:
        logger.error("Player achievements error", error=e, user_id=user_id)
        return APIResponse.server_error(origin=origin)


# ==================== LEADERBOARD HANDLERS ====================

def handle_leaderboard(event, context, method, path, origin):
    """Handle leaderboard endpoints"""
    try:
        # GET /leaderboard/rank - Get current user's rank
        if path == 'leaderboard/rank' and method == 'GET':
            return handle_player_rank(event, context)
        
        # GET /leaderboard/{period} - Get leaderboard
        elif path.startswith('leaderboard/') and method == 'GET':
            period = path.split('/')[-1]  # daily, weekly, alltime
            # Create wrapper for optional auth
            return _handle_leaderboard_with_period(event, context, period, origin)
        
        else:
            return APIResponse.success(
                {"message": "Leaderboard endpoints - to be implemented"},
                origin=origin
            )
    
    except Exception as e:
        logger.error("Leaderboard handler error", error=e)
        return APIResponse.server_error(origin=origin)


def _handle_leaderboard_with_period(event, context, period, origin):
    """Internal wrapper for leaderboard data with period"""
    try:
        import boto3
        dynamodb = boto3.resource('dynamodb', region_name=config.AWS_REGION)
        
        # Map period to table
        table_map = {
            'daily': config.TABLE_LEADERBOARD_DAILY,
            'weekly': config.TABLE_LEADERBOARD_WEEKLY,
            'alltime': config.TABLE_LEADERBOARD_ALLTIME
        }
        
        table_name = table_map.get(period)
        if not table_name:
            return APIResponse.error("Invalid period", status_code=400, origin=origin)
        
        leaderboard_table = dynamodb.Table(table_name)
        
        # Query leaderboard (limit to top 100)
        response = leaderboard_table.scan(Limit=100)
        entries = response.get('Items', [])
        
        # Sort by score descending
        entries.sort(key=lambda x: x.get('score', 0), reverse=True)
        
        # Get user data for each entry
        users_table = dynamodb.Table(config.TABLE_USERS)
        leaderboard = []
        
        for entry in entries[:100]:  # Top 100
            user_response = users_table.get_item(Key={"user_id": entry['user_id']})
            user = user_response.get('Item', {})
            
            leaderboard.append({
                'username': user.get('email', '').split('@')[0],
                'score': entry.get('score', 0),
                'level': entry.get('level', 1),
                'timestamp': entry.get('updated_at', entry.get('created_at'))
            })
        
        return APIResponse.success({'leaderboard': leaderboard}, origin=origin)
    
    except Exception as e:
        logger.error("Leaderboard data error", error=e, period=period)
        return APIResponse.server_error(origin=origin)


@require_auth()
def handle_player_rank(event, context, user_id):
    """Get player's current rank"""
    origin = get_origin(event)
    
    try:
        # Return default rank for now
        return APIResponse.success({
            'rank': {
                'daily': None,
                'weekly': None,
                'alltime': None
            }
        }, origin=origin)
    
    except Exception as e:
        logger.error("Player rank error", error=e, user_id=user_id)
        return APIResponse.server_error(origin=origin)


# ==================== ANALYTICS HANDLERS ====================

def handle_analytics(event, context, method, path, origin):
    """Handle analytics endpoints"""
    # Placeholder for analytics logic
    return APIResponse.success(
        {"message": "Analytics endpoints - to be implemented"},
        origin=origin
    )


# ==================== HEALTH CHECK ====================

def handle_health(event, context, origin):
    """Health check endpoint"""
    return APIResponse.success({
        "status": "healthy",
        "version": config.API_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "environment": "production" if config.is_production() else "development"
    }, origin=origin)
