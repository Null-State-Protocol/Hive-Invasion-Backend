"""
Main Lambda Handler for Hive Invasion Backend
Unified API for mobile and web platforms
"""

import json
from datetime import datetime, timezone

# Import utilities
from config import config
from responses import APIResponse, get_origin, get_request_id, inject_cors_headers
from validation import validate_request_body, ValidationError
from logger import logger
from decorators import require_auth, optional_auth, rate_limit, log_request
from models import now_iso

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
    
    CRITICAL: All responses are wrapped with inject_cors_headers() to guarantee
    CORS headers are present on every response (success, error, exception).
    """
    origin = get_origin(event)  # Extract origin early, before any routing
    
    try:
        # Validate configuration on cold start
        if hasattr(lambda_handler, '_first_run'):
            errors = config.validate()
            if errors and config.is_production():
                logger.critical("Configuration errors", context={"errors": errors})
                return inject_cors_headers(
                    APIResponse.server_error("Service misconfigured", origin=origin),
                    origin
                )
            lambda_handler._first_run = False
        
        method = event.get('httpMethod') or event.get('requestContext', {}).get('http', {}).get('method', 'GET')
        path = event.get('path') or event.get('rawPath', '/')
        
        # Normalize path
        path = path.strip('/').lower()
        
        # Handle OPTIONS (CORS preflight) - MUST be before auth checks
        if method == 'OPTIONS':
            return inject_cors_headers(APIResponse.options(origin), origin)
        
        # Route to appropriate handler
        if path.startswith('auth/'):
            return inject_cors_headers(handle_auth(event, context, method, path, origin), origin)
        
        elif path.startswith('session/'):
            return inject_cors_headers(handle_session(event, context, method, path, origin), origin)
        
        elif path.startswith('game/') or path.startswith('player/'):
            return inject_cors_headers(handle_game(event, context, method, path, origin), origin)
        
        elif path.startswith('leaderboard/'):
            return inject_cors_headers(handle_leaderboard(event, context, method, path, origin), origin)
        
        elif path.startswith('keys/'):
            return inject_cors_headers(handle_keys(event, context, method, path, origin), origin)
        
        elif path.startswith('analytics/'):
            return inject_cors_headers(handle_analytics(event, context, method, path, origin), origin)
        
        elif path in ('', 'health', 'ping'):
            return inject_cors_headers(handle_health(event, context, origin), origin)
        
        else:
            return inject_cors_headers(
                APIResponse.error(
                    f"Endpoint not found: {method} /{path}",
                    status_code=404,
                    error_code="NOT_FOUND",
                    origin=origin
                ),
                origin
            )
    
    except ValidationError as e:
        logger.warning(f"Validation error: {e.message}", context={"field": e.field})
        return inject_cors_headers(
            APIResponse.validation_error(e.field, e.message, origin),
            origin
        )
    
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
        return inject_cors_headers(
            APIResponse.server_error("Internal server error", origin=origin),
            origin
        )


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
                # Check if error is email verification related
                if error and "verify your email" in error.lower():
                    # Send new verification code for 2-step login
                    try:
                        # Get user_id from email
                        response = auth_service.user_emails_table.get_item(Key={"email": email.lower().strip()})
                        if "Item" in response:
                            user_id = response["Item"]["user_id"]
                            # Send verification email
                            auth_service._send_verification_email(email.lower().strip(), user_id, resend=True)
                            logger.info(f"2-step verification code sent for {email}")
                            return APIResponse.error(
                                "Email verification required. A verification code has been sent to your email.",
                                status_code=403,
                                origin=origin
                            )
                    except Exception as e:
                        logger.error("Failed to send verification code on login", error=e)
                
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
        
        # POST /auth/verify-email - Verify email with 4-digit code
        elif path == 'auth/verify-email' and method == 'POST':
            body = validate_request_body(event.get('body'))
            email = body.get('email', '').strip()
            verification_code = body.get('code', '').strip()
            return_token = body.get('return_token', False)  # For 2-step login flow
            
            if not email or not verification_code:
                return APIResponse.error("Email and verification code are required", status_code=400, origin=origin)
            
            logger.info(f"Email verification attempt for {email} (return_token={return_token})")
            
            auth_service = EmailAuthService()
            success, data, error = auth_service.verify_email(email, verification_code, return_token=return_token)
            
            if success:
                if return_token and data:
                    # 2-step login flow - return user data and tokens
                    return APIResponse.success(data, origin=origin)
                else:
                    # Registration flow - just confirmation
                    return APIResponse.success({"message": "Email verified successfully"}, origin=origin)
            else:
                return APIResponse.error(error, status_code=400, origin=origin)
        
        # POST /auth/resend-code - Resend verification code
        elif path == 'auth/resend-code' and method == 'POST':
            body = validate_request_body(event.get('body'))
            email = body.get('email', '').strip()
            
            if not email:
                return APIResponse.error("Email is required", status_code=400, origin=origin)
            
            logger.info(f"Resend verification code request for {email}")
            
            auth_service = EmailAuthService()
            success, error = auth_service.resend_verification_code(email)
            
            if success:
                return APIResponse.success({"message": "Verification code resent successfully"}, origin=origin)
            else:
                return APIResponse.error(error, status_code=400, origin=origin)
        
        # POST /auth/complete-registration - Complete registration with password
        elif path == 'auth/complete-registration' and method == 'POST':
            body = validate_request_body(event.get('body'))
            email = body.get('email', '').strip()
            password = body.get('password', '').strip()
            
            if not email or not password:
                return APIResponse.error("Email and password are required", status_code=400, origin=origin)
            
            logger.info(f"Complete registration for {email}")
            
            auth_service = EmailAuthService()
            success, auth_data, error = auth_service.complete_registration(email, password)
            
            if success:
                return APIResponse.success(auth_data, origin=origin)
            else:
                return APIResponse.error(error, status_code=400, origin=origin)
        
        # DELETE /auth/account - Delete account (requires auth)
        elif path == 'auth/account' and method == 'DELETE':
            return handle_delete_account(event, context)
        
        # PUT /auth/settings/2step - Update 2-step login setting (requires auth)
        elif path == 'auth/settings/2step' and method == 'PUT':
            return handle_update_2step_setting(event, context)
        
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
    """Delete user account immediately (hard delete)"""
    origin = get_origin(event)
    
    try:
        import boto3
        from datetime import datetime, timezone
        import json
        
        dynamodb = boto3.resource('dynamodb', region_name=config.AWS_REGION)
        
        # 1. Get user data before deletion
        users_table = dynamodb.Table(config.TABLE_USERS)
        user_response = users_table.get_item(Key={"user_id": user_id})
        
        if 'Item' not in user_response:
            return APIResponse.error("User not found", status_code=404, origin=origin)
        
        user_data = user_response['Item']
        email = user_data.get('email', 'unknown')
        
        # 2. Delete from all tables
        try:
            # Delete from users table
            users_table.delete_item(Key={"user_id": user_id})
            
            # Delete from user_emails table
            if email and email != 'unknown':
                user_emails_table = dynamodb.Table(config.TABLE_USER_EMAILS)
                user_emails_table.delete_item(Key={"email": email})
            
            # Delete from email verification table
            if email and email != 'unknown':
                verification_table = dynamodb.Table(config.TABLE_EMAIL_VERIFICATION)
                verification_table.delete_item(Key={"email": email})
            
            logger.info("Account deleted successfully", context={
                "user_id": user_id,
                "email": email
            })
            
            return APIResponse.success(
                {
                    "message": "Account deleted successfully"
                },
                origin=origin
            )
            
        except Exception as delete_error:
            logger.error("Error during account deletion", error=delete_error, user_id=user_id)
            raise delete_error
    
    except Exception as e:
        logger.error("Account deletion error", error=e, user_id=user_id)
        return APIResponse.server_error(origin=origin)


@require_auth()
def handle_update_2step_setting(event, context, user_id):
    """Update 2-step login (email verification) setting"""
    origin = get_origin(event)
    
    try:
        body = validate_request_body(event.get('body'))
        enabled = body.get('enabled', True)
        verification_code = body.get('code')  # Optional verification code
        send_code = body.get('send_code', False)  # Request to send code
        
        import boto3
        dynamodb = boto3.resource('dynamodb', region_name=config.AWS_REGION)
        users_table = dynamodb.Table(config.TABLE_USERS)
        
        # Get user data
        user_response = users_table.get_item(Key={"user_id": user_id})
        if "Item" not in user_response:
            return APIResponse.error("User not found", status_code=404, origin=origin)
        
        user_data = user_response["Item"]
        email = user_data.get("email")
        
        # If email not in user record, try hive_email_verification table
        if not email:
            verification_table = dynamodb.Table(config.TABLE_EMAIL_VERIFICATION)
            # Query by user_id GSI to find their email
            response = verification_table.query(
                IndexName='user_id-index',
                KeyConditionExpression='user_id = :uid',
                ExpressionAttributeValues={':uid': user_id},
                Limit=1
            )
            if response.get('Items'):
                email = response['Items'][0].get('email')
        
        if not email:
            return APIResponse.error("Email not found for user", status_code=404, origin=origin)
        
        # If send_code requested, send verification code and return
        if send_code:
            from email_auth import EmailAuthService
            auth_service = EmailAuthService()
            auth_service._send_verification_email(email, user_id, resend=True)
            logger.info("2-step toggle verification code sent", context={"user_id": user_id, "email": email})
            return APIResponse.success({
                "message": "Verification code sent to your email",
                "code_sent": True
            }, origin=origin)
        
        # If verification code provided, verify it
        if verification_code:
            from email_auth import EmailAuthService
            auth_service = EmailAuthService()
            success, _, error = auth_service.verify_email(email, verification_code, return_token=False)
            if not success:
                return APIResponse.error(error or "Invalid verification code", status_code=400, origin=origin)
        
        # Update user setting
        users_table.update_item(
            Key={"user_id": user_id},
            UpdateExpression="SET require_email_verification = :enabled, updated_at = :now",
            ExpressionAttributeValues={
                ":enabled": enabled,
                ":now": now_iso()
            }
        )
        
        logger.info("2-step setting updated", context={
            "user_id": user_id,
            "enabled": enabled
        })
        
        return APIResponse.success({
            "message": f"2-step login {'enabled' if enabled else 'disabled'}",
            "require_email_verification": enabled
        }, origin=origin)
        
    except Exception as e:
        logger.error("Update 2-step setting error", error=e, user_id=user_id)
        import traceback
        logger.error("Traceback", context={"traceback": traceback.format_exc()})
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
        
        # POST /player/achievements/unlock - Unlock achievement
        elif path == 'player/achievements/unlock' and method == 'POST':
            return handle_unlock_achievement(event, context)
        
        # GET /player/pilots - Get owned pilots
        elif path == 'player/pilots' and method == 'GET':
            return handle_player_pilots(event, context)
        
        # POST /player/pilots - Unlock pilot
        elif path == 'player/pilots' and method == 'POST':
            return handle_unlock_pilot(event, context)
        
        # GET /player/mechs - Get owned mechs
        elif path == 'player/mechs' and method == 'GET':
            return handle_player_mechs(event, context)
        
        # POST /player/mechs - Unlock mech
        elif path == 'player/mechs' and method == 'POST':
            return handle_unlock_mech(event, context)
        
        # GET /player/boosts - Get active boosts
        elif path == 'player/boosts' and method == 'GET':
            return handle_player_boosts(event, context)
        
        # POST /player/boosts - Activate boost
        elif path == 'player/boosts' and method == 'POST':
            return handle_activate_boost(event, context)
        
        # GET /player/skills - Get skills
        elif path == 'player/skills' and method == 'GET':
            return handle_player_skills(event, context)
        
        # POST /player/skills - Unlock/upgrade skill
        elif path == 'player/skills' and method == 'POST':
            return handle_unlock_skill(event, context)
        
        # GET /player/gems - Get gems
        elif path == 'player/gems' and method == 'GET':
            return handle_player_gems(event, context)
        
        # PUT /player/gems - Update gems
        elif path == 'player/gems' and method == 'PUT':
            return handle_update_gems(event, context)
        
        # GET /player/dust - Get dust
        elif path == 'player/dust' and method == 'GET':
            return handle_player_dust(event, context)
        
        # PUT /player/dust - Update dust
        elif path == 'player/dust' and method == 'PUT':
            return handle_update_dust(event, context)
        
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
            'gems': player_data.get('gems', 0),
            'pilots': player_data.get('pilots', []),
            'mechs': player_data.get('mechs', []),
            'boosts': player_data.get('boosts', []),
            'skills': player_data.get('skills', []),
            'created_at': user.get('created_at'),
            'is_verified': user.get('email_verified', False),
            'require_email_verification': user.get('require_email_verification', False),
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


@require_auth()
def handle_unlock_achievement(event, context, user_id):
    """Unlock an achievement"""
    origin = get_origin(event)
    
    try:
        from models import unlock_achievement
        from validation import Validator
        
        body = validate_request_body(event.get('body'))
        achievement_id = Validator.required(body, 'achievement_id')
        
        result = unlock_achievement(user_id, achievement_id)
        
        if 'error' in result:
            return APIResponse.error(result['error'], status_code=400, origin=origin)
        
        return APIResponse.success(result, status_code=201, origin=origin)
    
    except ValidationError as e:
        return APIResponse.validation_error(e.field, e.message, origin)
    except Exception as e:
        logger.error("Unlock achievement error", error=e, user_id=user_id)
        return APIResponse.server_error(origin=origin)


@require_auth()
def handle_player_pilots(event, context, user_id):
    """Get player's pilots"""
    origin = get_origin(event)
    
    try:
        from models import get_player_pilots
        
        pilots = get_player_pilots(user_id)
        return APIResponse.success({'pilots': pilots}, origin=origin)
    
    except Exception as e:
        logger.error("Player pilots error", error=e, user_id=user_id)
        return APIResponse.server_error(origin=origin)


@require_auth()
def handle_unlock_pilot(event, context, user_id):
    """Unlock a pilot"""
    origin = get_origin(event)
    
    try:
        from models import unlock_pilot
        from validation import Validator
        
        body = validate_request_body(event.get('body'))
        pilot_id = Validator.required(body, 'pilot_id')
        
        result = unlock_pilot(user_id, pilot_id)
        
        if 'error' in result:
            return APIResponse.error(result['error'], status_code=400, origin=origin)
        
        return APIResponse.success(result, status_code=201, origin=origin)
    
    except ValidationError as e:
        return APIResponse.validation_error(e.field, e.message, origin)
    except Exception as e:
        logger.error("Unlock pilot error", error=e, user_id=user_id)
        return APIResponse.server_error(origin=origin)


@require_auth()
def handle_player_mechs(event, context, user_id):
    """Get player's mechs"""
    origin = get_origin(event)
    
    try:
        from models import get_player_mechs
        
        mechs = get_player_mechs(user_id)
        return APIResponse.success({'mechs': mechs}, origin=origin)
    
    except Exception as e:
        logger.error("Player mechs error", error=e, user_id=user_id)
        return APIResponse.server_error(origin=origin)


@require_auth()
def handle_unlock_mech(event, context, user_id):
    """Unlock a mech"""
    origin = get_origin(event)
    
    try:
        from models import unlock_mech
        from validation import Validator
        
        body = validate_request_body(event.get('body'))
        mech_id = Validator.required(body, 'mech_id')
        variant = body.get('variant', 'standard')
        
        result = unlock_mech(user_id, mech_id, variant)
        
        if 'error' in result:
            return APIResponse.error(result['error'], status_code=400, origin=origin)
        
        return APIResponse.success(result, status_code=201, origin=origin)
    
    except ValidationError as e:
        return APIResponse.validation_error(e.field, e.message, origin)
    except Exception as e:
        logger.error("Unlock mech error", error=e, user_id=user_id)
        return APIResponse.server_error(origin=origin)


@require_auth()
def handle_player_boosts(event, context, user_id):
    """Get player's active boosts"""
    origin = get_origin(event)
    
    try:
        from models import get_active_boosts
        
        boosts = get_active_boosts(user_id)
        return APIResponse.success({'boosts': boosts}, origin=origin)
    
    except Exception as e:
        logger.error("Player boosts error", error=e, user_id=user_id)
        return APIResponse.server_error(origin=origin)


@require_auth()
def handle_activate_boost(event, context, user_id):
    """Activate a boost"""
    origin = get_origin(event)
    
    try:
        from models import activate_boost
        from validation import Validator
        
        body = validate_request_body(event.get('body'))
        boost_id = Validator.required(body, 'boost_id')
        boost_name = Validator.required(body, 'boost_name')
        duration_seconds = int(body.get('duration_seconds', 3600))
        
        result = activate_boost(user_id, boost_id, boost_name, duration_seconds)
        return APIResponse.success(result, status_code=201, origin=origin)
    
    except ValidationError as e:
        return APIResponse.validation_error(e.field, e.message, origin)
    except Exception as e:
        logger.error("Activate boost error", error=e, user_id=user_id)
        return APIResponse.server_error(origin=origin)


@require_auth()
def handle_player_skills(event, context, user_id):
    """Get player's skills"""
    origin = get_origin(event)
    
    try:
        from models import get_player_skills
        
        skills = get_player_skills(user_id)
        return APIResponse.success({'skills': skills}, origin=origin)
    
    except Exception as e:
        logger.error("Player skills error", error=e, user_id=user_id)
        return APIResponse.server_error(origin=origin)


@require_auth()
def handle_unlock_skill(event, context, user_id):
    """Unlock or upgrade a skill"""
    origin = get_origin(event)
    
    try:
        from models import unlock_skill
        from validation import Validator
        
        body = validate_request_body(event.get('body'))
        skill_id = Validator.required(body, 'skill_id')
        slot = body.get('slot')
        
        result = unlock_skill(user_id, skill_id, slot)
        return APIResponse.success(result, status_code=201, origin=origin)
    
    except ValidationError as e:
        return APIResponse.validation_error(e.field, e.message, origin)
    except Exception as e:
        logger.error("Unlock skill error", error=e, user_id=user_id)
        return APIResponse.server_error(origin=origin)


@require_auth()
def handle_player_gems(event, context, user_id):
    """Get player's gems"""
    origin = get_origin(event)
    
    try:
        import boto3
        dynamodb = boto3.resource('dynamodb', region_name=config.AWS_REGION)
        player_table = dynamodb.Table(config.TABLE_PLAYER_DATA)
        
        response = player_table.get_item(Key={"user_id": user_id})
        player_data = response.get('Item', {})
        gems = player_data.get('gems', 0)
        
        return APIResponse.success({'gems': int(gems)}, origin=origin)
    
    except Exception as e:
        logger.error("Player gems error", error=e, user_id=user_id)
        return APIResponse.server_error(origin=origin)


@require_auth()
def handle_update_gems(event, context, user_id):
    """Update player's gems"""
    origin = get_origin(event)
    
    try:
        from models import update_gems
        from validation import Validator
        
        body = validate_request_body(event.get('body'))
        amount = int(Validator.required(body, 'amount'))
        
        new_gems = update_gems(user_id, amount)
        return APIResponse.success({'gems': new_gems}, origin=origin)
    
    except ValidationError as e:
        return APIResponse.validation_error(e.field, e.message, origin)
    except Exception as e:
        logger.error("Update gems error", error=e, user_id=user_id)
        return APIResponse.server_error(origin=origin)


@require_auth()
def handle_player_dust(event, context, user_id):
    """Get player's dust"""
    origin = get_origin(event)
    
    try:
        import boto3
        dynamodb = boto3.resource('dynamodb', region_name=config.AWS_REGION)
        player_table = dynamodb.Table(config.TABLE_PLAYER_DATA)
        
        response = player_table.get_item(Key={"user_id": user_id})
        player_data = response.get('Item', {})
        dust = player_data.get('dust_count', 0)
        
        return APIResponse.success({'dust': int(dust)}, origin=origin)
    
    except Exception as e:
        logger.error("Player dust error", error=e, user_id=user_id)
        return APIResponse.server_error(origin=origin)


@require_auth()
def handle_update_dust(event, context, user_id):
    """Update player's dust"""
    origin = get_origin(event)
    
    try:
        from models import update_dust
        from validation import Validator
        
        body = validate_request_body(event.get('body'))
        amount = int(Validator.required(body, 'amount'))
        
        new_dust = update_dust(user_id, amount)
        return APIResponse.success({'dust': new_dust}, origin=origin)
    
    except ValidationError as e:
        return APIResponse.validation_error(e.field, e.message, origin)
    except Exception as e:
        logger.error("Update dust error", error=e, user_id=user_id)
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
        import boto3
        from boto3.dynamodb.conditions import Key
        dynamodb = boto3.resource('dynamodb', region_name=config.AWS_REGION)

        def get_rank(table_name, period=None):
            table = dynamodb.Table(table_name)
            if period:
                response = table.query(
                    KeyConditionExpression=Key('period').eq(period)
                )
                items = response.get('Items', [])
            else:
                response = table.scan()
                items = response.get('Items', [])

            if not items:
                return None

            items.sort(key=lambda x: x.get('score', 0), reverse=True)
            for idx, item in enumerate(items, start=1):
                if item.get('user_id') == user_id:
                    return idx
            return None

        daily_rank = get_rank(config.TABLE_LEADERBOARD_DAILY, period='daily')
        weekly_rank = get_rank(config.TABLE_LEADERBOARD_WEEKLY, period='weekly')
        alltime_rank = get_rank(config.TABLE_LEADERBOARD_ALLTIME)

        return APIResponse.success({
            'rank': {
                'daily': daily_rank,
                'weekly': weekly_rank,
                'alltime': alltime_rank
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


# ==================== SESSION HANDLERS ====================

def handle_session(event, context, method, path, origin):
    """
    Handle game session endpoints.
    
    Routes:
    - POST /session/start
    - PUT /session/{session_id}/end
    """
    # Route to appropriate handler
    if path == 'session/start' and method == 'POST':
        return handle_session_start(event, context)
    elif path.startswith('session/') and path.endswith('/end') and method == 'PUT':
        return handle_session_end(event, context, path)
    else:
        return APIResponse.error(
            f"Unsupported session endpoint: {method} {path}",
            status_code=404,
            error_code='NOT_FOUND',
            origin=origin
        )


@require_auth()
def handle_session_start(event, context, user_id):
    """POST /session/start - Create new game session"""
    from models import create_game_session
    
    try:
        origin = get_origin(event)
        body = validate_request_body(event.get('body'))
        
        difficulty = body.get('difficulty', 'normal')
        game_mode = body.get('game_mode', 'survival')
        
        # Validate inputs
        valid_difficulties = ['normal', 'hard', 'insane']
        valid_modes = ['survival', 'endless', 'campaign']
        
        if difficulty not in valid_difficulties:
            return APIResponse.error(
                f"Invalid difficulty. Must be one of: {', '.join(valid_difficulties)}",
                status_code=400,
                error_code='INVALID_DIFFICULTY',
                origin=origin
            )
        
        if game_mode not in valid_modes:
            return APIResponse.error(
                f"Invalid game_mode. Must be one of: {', '.join(valid_modes)}",
                status_code=400,
                error_code='INVALID_GAME_MODE',
                origin=origin
            )
        
        # Create session
        session = create_game_session(user_id, difficulty, game_mode)
        
        logger.info(f"Session started: {session['session_id']} by user {user_id}")
        
        return APIResponse.success(session, status_code=201, origin=origin)
        
    except Exception as e:
        logger.error(f"Error in handle_session_start: {str(e)}")
        return APIResponse.server_error(origin=get_origin(event))


@require_auth()
def handle_session_end(event, context, user_id, path):
    """PUT /session/{session_id}/end - End game session"""
    from models import (
        get_game_session,
        end_game_session,
        update_player_progression,
        update_leaderboard
    )
    
    try:
        origin = get_origin(event)
        body = validate_request_body(event.get('body'))
        
        # Extract session_id from path
        parts = path.split('/')
        if len(parts) != 3:
            return APIResponse.error(
                "Invalid path format",
                status_code=400,
                error_code='INVALID_PATH',
                origin=origin
            )
        
        session_id = parts[1]
        
        # Get session
        session = get_game_session(session_id)
        if not session:
            return APIResponse.error(
                "Session not found",
                status_code=404,
                error_code='SESSION_NOT_FOUND',
                origin=origin
            )
        
        # Verify ownership
        if session['user_id'] != user_id:
            return APIResponse.error(
                "Forbidden",
                status_code=403,
                error_code='FORBIDDEN',
                origin=origin
            )
        
        # Check if already ended
        if session.get('status') == 'ended':
            return APIResponse.error(
                "Session already ended",
                status_code=400,
                error_code='SESSION_ALREADY_ENDED',
                origin=origin
            )
        
        # Get score/duration from request
        score = body.get('score', 0)
        duration_seconds = body.get('duration', 0)
        end_reason = body.get('reason', 'completed')
        
        # End the session
        end_game_session(session_id, score, duration_seconds, end_reason)
        
        # Calculate rewards
        xp_earned = int(score * 0.1)
        gold_earned = int(score * 0.5)
        dust_earned = int(score * 0.2)  # New: dust reward
        
        # Update player progression
        progression = update_player_progression(user_id, score, xp_earned, gold_earned)
        
        # Update dust
        from models import update_dust
        new_dust = update_dust(user_id, dust_earned)
        
        # Update leaderboards
        try:
            update_leaderboard(user_id, score, 'alltime')
        except Exception as e:
            logger.warning(f"Leaderboard update failed: {str(e)}")
        
        logger.info(f"Session ended: {session_id} - Score: {score}")
        
        return APIResponse.success({
            'session_id': session_id,
            'score': score,
            'duration': duration_seconds,
            'rewards': {
                'xp_earned': xp_earned,
                'gold_earned': gold_earned,
                'dust_earned': dust_earned,
                'new_dust': new_dust,
                'level_up': progression.get('level_up', False),
                'new_level': progression.get('new_level')
            }
        }, origin=origin)
        
    except Exception as e:
        logger.error(f"Error in handle_session_end: {str(e)}")
        return APIResponse.server_error(origin=get_origin(event))


# ==================== KEY STORE HANDLERS ====================

def handle_keys(event, context, method, path, origin):
    """
    Handle key purchase/ownership endpoints.
    
    Routes:
    - POST /keys/purchase
    - GET /keys/owned
    - GET /keys/history
    """
    try:
        # POST /keys/purchase - Purchase a key (mock contract)
        if path == 'keys/purchase' and method == 'POST':
            return handle_key_purchase(event, context)
        
        # GET /keys/owned - Get owned keys
        elif path == 'keys/owned' and method == 'GET':
            return handle_keys_owned(event, context)
        
        # GET /keys/history - Get purchase history
        elif path == 'keys/history' and method == 'GET':
            return handle_keys_history(event, context)
        
        else:
            return APIResponse.error(
                f"Unsupported keys endpoint: {method} {path}",
                status_code=404,
                error_code='NOT_FOUND',
                origin=origin
            )
    
    except Exception as e:
        logger.error("Keys handler error", error=e)
        return APIResponse.server_error(origin=origin)


@require_auth()
def handle_key_purchase(event, context, user_id):
    """POST /keys/purchase - Purchase a key with SOMI payment on Somnia network"""
    from contract_adapter import ContractAdapter
    from models import add_key_to_player
    from validation import Validator
    from datetime import datetime, timezone
    import uuid
    import re
    import json
    from security import SecurityHeaders
    
    try:
        origin = get_origin(event)
        request_id = getattr(context, "aws_request_id", None) or get_request_id(event)
        body = validate_request_body(event.get('body'))
        
        def build_message_response(message, status_code=400, request_id_override=None):
            headers = SecurityHeaders.get_headers(origin)
            headers["Content-Type"] = "application/json"
            body = {"message": message}
            request_id_value = request_id_override or request_id
            if request_id_value:
                body["request_id"] = request_id_value
            return {
                "statusCode": status_code,
                "headers": headers,
                "body": json.dumps(body)
            }

        def log_rejected(reason):
            print("[Keys] purchase rejected:", {
                "tx": tx_hash[:12] if 'tx_hash' in locals() else None,
                "key_type": key_type if 'key_type' in locals() else None,
                "reason": reason
            })

        # Validate inputs
        key_type = Validator.required(body, 'key_type')
        tx_hash = Validator.required(body, 'tx_hash')
        
        # Normalize key_type
        key_type = key_type.lower()
        if key_type not in {"bronze", "silver", "gold"}:
            reason = f"Invalid key type: {key_type}"
            log_rejected(reason)
            return build_message_response(reason, status_code=400)
        
        # Normalize and validate tx_hash
        tx_hash = tx_hash.strip()
        if not tx_hash.startswith("0x"):
            tx_hash = "0x" + tx_hash
        if not re.fullmatch(r"0x[a-fA-F0-9]{64}", tx_hash):
            reason = "Invalid tx_hash format"
            log_rejected(reason)
            return build_message_response(reason, status_code=400)
        
        # Verify user has a linked wallet
        import boto3
        dynamodb = boto3.resource('dynamodb', region_name=config.AWS_REGION)
        users_table = dynamodb.Table(config.TABLE_USERS)
        user_response = users_table.get_item(Key={"user_id": user_id})
        
        if 'Item' not in user_response:
            return APIResponse.error("User not found", status_code=404, origin=origin)
        
        user_data = user_response['Item']
        wallet_address = user_data.get('wallet_address', '').lower()
        
        # Ensure wallet is linked
        if not wallet_address:
            reason = "No wallet linked. Please connect your wallet first."
            log_rejected(reason)
            return build_message_response(reason, status_code=400)
        if not re.fullmatch(r"0x[a-fA-F0-9]{40}", wallet_address):
            reason = "Invalid wallet address"
            log_rejected(reason)
            return build_message_response(reason, status_code=400)
        
        tx_hash_short = f"{tx_hash[:10]}...{tx_hash[-6:]}" if tx_hash else ""
        wallet_short = f"{wallet_address[:10]}...{wallet_address[-6:]}" if wallet_address else ""
        logger.info(
            f"Starting SOMI payment verification: {key_type}",
            context={"tx_hash": tx_hash_short, "wallet": wallet_short, "user_id": user_id}
        )
        
        # Verify transaction on Somnia mainnet
        try:
            verification = ContractAdapter.verify_transaction_on_somnia(tx_hash, key_type, wallet_address)
        except (ValueError, KeyError, AssertionError) as e:
            reason = str(e)
            print("[Keys] verify failed:", {"key_type": key_type, "tx": tx_hash[:12], "reason": reason})
            logger.warning(
                f"Transaction verification failed: {tx_hash_short}",
                context={"reason": reason, "user_id": user_id}
            )
            log_rejected(reason)
            return build_message_response(reason, status_code=400)
        
        if not verification.get("verified"):
            status = verification.get("status")
            reason = verification.get("reason", "Unknown error")
            
            if status == "pending":
                logger.info(
                    f"Transaction pending on-chain: {tx_hash}",
                    context={"reason": reason}
                )
                return APIResponse.success({
                    "ok": False,
                    "pending": True,
                    "message": "Transaction not yet confirmed on-chain. Please try again in a moment.",
                    "tx_hash": tx_hash,
                    "retry_after_seconds": 10
                }, status_code=202, origin=origin)
            
            # Failed verification (wrong amount, wrong recipient, etc)
            logger.warning(
                f"Transaction verification failed: {tx_hash}",
                context={"reason": reason, "status": status}
            )
            log_rejected(reason)
            return build_message_response(reason, status_code=400)
        
        tx_data = verification.get("tx_data", {})
        if tx_data:
            print("[Keys] verify ok:", {
                "key_type": key_type,
                "tx": tx_hash[:12],
                "from": (tx_data.get("from") or "")[:10],
                "to": (tx_data.get("to") or "")[:10]
            })
            logger.info(
                "SOMI verification data",
                context={
                    "tx_hash": tx_hash_short,
                    "to": tx_data.get("to"),
                    "from": tx_data.get("from"),
                    "value": tx_data.get("value"),
                    "status": tx_data.get("status")
                }
            )
        
        # Transaction verified! Create purchase event
        timestamp = datetime.now(timezone.utc).isoformat()
        
        purchase_event = {
            "event_id": tx_hash,  # Use tx_hash as event_id for unique identification
            "tx_hash": tx_hash,
            "key_type": key_type,
            "timestamp": timestamp,
            "from_wallet": wallet_address,
            "to_wallet": ContractAdapter.TREASURY_WALLET.lower(),
            "amount_wei": str(ContractAdapter.get_expected_price(key_type)),
            "status": "confirmed"
        }
        
        # Update player's key ownership with idempotency guard
        try:
            new_balances = add_key_to_player(user_id, key_type, purchase_event)
        except Exception as e:
            if "already processed" in str(e):
                logger.warning(
                    f"Duplicate transaction attempt: {tx_hash}",
                    context={"user_id": user_id}
                )
                return APIResponse.error(
                    "This transaction has already been processed. Duplicate purchase rejected.",
                    status_code=409,
                    error_code="DUPLICATE_TRANSACTION",
                    origin=origin
                )
            else:
                raise
        
        logger.info(
            f"Key purchased successfully: {key_type}",
            context={
                "tx_hash": tx_hash,
                "wallet": wallet_address,
                "user_id": user_id,
                "new_balances": new_balances
            }
        )
        
        return APIResponse.success({
            "ok": True,
            "key_type": key_type,
            "new_balances": new_balances,
            "tx_hash": tx_hash,
            "message": "Key purchased successfully with verified SOMI payment on Somnia mainnet"
        }, status_code=201, origin=origin)
        
    except ValidationError as e:
        reason = e.message
        log_rejected(reason)
        return build_message_response(reason, status_code=400)
    except (ValueError, KeyError, AssertionError) as e:
        reason = str(e)
        log_rejected(reason)
        return build_message_response(reason, status_code=400)
    except Exception as e:
        print("[Keys] purchase crash:", {
            "request_id": request_id,
            "error": repr(e)
        })
        logger.error(
            f"Key purchase error: {str(e)}",
            error=e,
            user_id=user_id,
            context={"tx_hash": tx_hash if 'tx_hash' in locals() else None}
        )
        return build_message_response("Internal error", status_code=500, request_id_override=request_id)


@require_auth()
def handle_keys_owned(event, context, user_id):
    """GET /keys/owned - Get player's owned keys"""
    from contract_adapter import ContractAdapter
    from models import get_key_ownership
    
    try:
        origin = get_origin(event)
        
        # Get user's wallet address
        import boto3
        dynamodb = boto3.resource('dynamodb', region_name=config.AWS_REGION)
        users_table = dynamodb.Table(config.TABLE_USERS)
        user_response = users_table.get_item(Key={"user_id": user_id})
        
        if 'Item' not in user_response:
            return APIResponse.error("User not found", status_code=404, origin=origin)
        
        user_data = user_response['Item']
        wallet_address = user_data.get('wallet_address', '')
        
        # Get ownership from DB (mock contract check)
        keys_owned_data = get_key_ownership(user_id)
        ownership = ContractAdapter.get_owned_keys_mock(user_id, wallet_address, keys_owned_data)
        
        return APIResponse.success({
            "wallet_address": wallet_address,
            "owned": {
                "bronze": ownership["bronze"],
                "silver": ownership["silver"],
                "gold": ownership["gold"]
            },
            "source": ownership["source"]
        }, origin=origin)
        
    except Exception as e:
        logger.error(f"Keys owned error: {str(e)}", error=e, user_id=user_id)
        return APIResponse.server_error(origin=get_origin(event))


@require_auth()
def handle_keys_history(event, context, user_id):
    """GET /keys/history - Get key purchase history"""
    from models import get_key_purchase_history
    
    try:
        origin = get_origin(event)
        
        # Get query param for limit
        query_params = event.get('queryStringParameters', {}) or {}
        limit = int(query_params.get('limit', 20))
        limit = min(limit, 100)  # Max 100
        
        # Get purchase history
        history = get_key_purchase_history(user_id, limit)
        
        return APIResponse.success({
            "history": history,
            "count": len(history)
        }, origin=origin)
        
    except Exception as e:
        logger.error(f"Keys history error: {str(e)}", error=e, user_id=user_id)
        return APIResponse.server_error(origin=get_origin(event))
