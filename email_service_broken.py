"""
Email service using AWS SES
For password reset and notifications
"""

import boto3
from botocore.exceptions import ClientError
from config import config
from logger import logger
from datetime import datetime


class EmailService:
    """Email service using AWS SES"""
    
    def __init__(self):
        self.ses = boto3.client('ses', region_name=config.AWS_REGION)
        self.sender_email = config.SENDER_EMAIL or "noreply@hiveinvasion.games"
    
    def send_password_reset_email(self, to_email: str, reset_token: str, user_name: str = None) -> bool:
        """Send password reset email"""
        try:
            # Create reset link
            reset_link = f"{config.FRONTEND_URL}/reset-password?token={reset_token}"
            
            display_name = user_name or to_email.split('@')[0]
            
            # HTML email body
            html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #f0f4f8 0%, #e2e8f0 100%);
            line-height: 1.6;
            color: #1a202c;
            padding: 40px 20px;
        }}
        .email-wrapper {{
            max-width: 650px;
            margin: 0 auto;
            background: #ffffff;
            border-radius: 24px;
            overflow: hidden;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.15);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 50%, #f093fb 100%);
            padding: 60px 40px;
            text-align: center;
            position: relative;
            overflow: hidden;
        }}
        .header::before {{
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(255,255,255,0.1) 1px, transparent 1px);
            background-size: 30px 30px;
            animation: moveGrid 20s linear infinite;
        }}
        @keyframes moveGrid {{
            0% {{ transform: translate(0, 0); }}
            100% {{ transform: translate(30px, 30px); }}
        }}
        .bee-container {{
            position: relative;
            display: inline-block;
            margin-bottom: 20px;
        }}
        .bee-icon {{
            font-size: 80px;
            filter: drop-shadow(0 10px 20px rgba(0,0,0,0.3));
            animation: float 3s ease-in-out infinite;
            display: inline-block;
            position: relative;
            z-index: 2;
        }}
        @keyframes float {{
            0%, 100% {{ transform: translateY(0px) rotate(-5deg); }}
            50% {{ transform: translateY(-15px) rotate(5deg); }}
        }}
        .bee-glow {{
            position: absolute;
            width: 100px;
            height: 100px;
            background: radial-gradient(circle, rgba(255, 193, 7, 0.4) 0%, transparent 70%);
            border-radius: 50%;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            animation: pulse 2s ease-in-out infinite;
            z-index: 1;
        }}
        @keyframes pulse {{
            0%, 100% {{ transform: translate(-50%, -50%) scale(1); opacity: 0.5; }}
            50% {{ transform: translate(-50%, -50%) scale(1.2); opacity: 0.8; }}
        }}
        .header h1 {{
            color: white;
            font-size: 42px;
            font-weight: 900;
            margin: 0;
            text-shadow: 0 4px 15px rgba(0,0,0,0.3);
            letter-spacing: 2px;
            position: relative;
            z-index: 2;
            background: linear-gradient(180deg, #ffffff 0%, #e0e7ff 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}
        .header-subtitle {{
            color: rgba(255,255,255,0.95);
            font-size: 18px;
            margin-top: 15px;
            font-weight: 600;
            position: relative;
            z-index: 2;
            text-shadow: 0 2px 8px rgba(0,0,0,0.2);
        }}
        .content {{
            padding: 55px 45px;
            background: white;
        }}
        .greeting {{
            font-size: 24px;
            color: #2d3748;
            margin-bottom: 25px;
            font-weight: 700;
        }}
        .greeting-emoji {{
            font-size: 28px;
            margin-right: 8px;
        }}
        .message {{
            font-size: 17px;
            color: #4a5568;
            margin-bottom: 35px;
            line-height: 1.9;
        }}
        .button-container {{
            text-align: center;
            margin: 45px 0;
        }}
        .button {{
            display: inline-block;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white !important;
            padding: 20px 60px;
            text-decoration: none;
            border-radius: 50px;
            font-weight: 800;
            font-size: 18px;
            box-shadow: 0 15px 35px rgba(102, 126, 234, 0.4);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            letter-spacing: 1px;
            text-transform: uppercase;
            position: relative;
            overflow: hidden;
        }}
        .button::before {{
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent);
            transition: left 0.5s;
        }}
        .button:hover::before {{
            left: 100%;
        }}
        .info-card {{
            background: linear-gradient(135deg, #ebf4ff 0%, #e0e7ff 100%);
            border: 2px solid #c3dafe;
            border-radius: 16px;
            padding: 25px;
            margin: 35px 0;
            position: relative;
        }}
        .info-card::before {{
            content: '🔗';
            position: absolute;
            top: -15px;
            left: 25px;
            font-size: 24px;
            background: white;
            padding: 5px 10px;
            border-radius: 12px;
            box-shadow: 0 4px 10px rgba(0,0,0,0.1);
        }}
        .info-card-title {{
            color: #4c51bf;
            font-size: 15px;
            font-weight: 700;
            margin-bottom: 15px;
            margin-top: 10px;
        }}
        .link-code {{
            background: white;
            border: 2px solid #a3bffa;
            padding: 15px 18px;
            border-radius: 12px;
            word-break: break-all;
            font-family: 'SF Mono', 'Monaco', 'Courier New', monospace;
            font-size: 13px;
            color: #5a67d8;
            display: block;
            font-weight: 600;
            line-height: 1.6;
        }}
        .security-box {{
            background: linear-gradient(135deg, #fff5e1 0%, #ffe4b5 100%);
            border: 3px solid #fbbf24;
            border-radius: 16px;
            padding: 30px;
            margin: 35px 0;
            position: relative;
        }}
        .security-header {{
            display: flex;
            align-items: center;
            font-size: 18px;
            color: #92400e;
            margin-bottom: 18px;
            font-weight: 800;
        }}
        .security-icon {{
            font-size: 28px;
            margin-right: 12px;
            animation: shake 3s ease-in-out infinite;
        }}
        @keyframes shake {{
            0%, 100% {{ transform: rotate(0deg); }}
            10%, 30%, 50%, 70%, 90% {{ transform: rotate(-5deg); }}
            20%, 40%, 60%, 80% {{ transform: rotate(5deg); }}
        }}
        .security-item {{
            display: flex;
            align-items: flex-start;
            color: #78350f;
            font-size: 15px;
            line-height: 1.7;
            margin: 12px 0;
            font-weight: 500;
        }}
        .security-item-icon {{
            font-size: 18px;
            margin-right: 12px;
            margin-top: 2px;
            flex-shrink: 0;
        }}
        .divider {{
            height: 2px;
            background: linear-gradient(90deg, transparent, #e2e8f0, transparent);
            margin: 35px 0;
        }}
        .help-section {{
            background: #f7fafc;
            border-radius: 12px;
            padding: 20px;
            text-align: center;
            margin: 30px 0;
        }}
        .help-section p {{
            color: #718096;
            font-size: 14px;
            margin: 0;
        }}
        .help-section strong {{
            color: #4a5568;
            font-weight: 700;
        }}
        .footer {{
            background: linear-gradient(135deg, #1a202c 0%, #2d3748 100%);
            padding: 40px 45px;
            text-align: center;
            position: relative;
        }}
        .footer-logo {{
            color: white;
            font-size: 20px;
            font-weight: 900;
            margin-bottom: 10px;
            letter-spacing: 2px;
        }}
        .footer-tagline {{
            color: #a0aec0;
            font-size: 15px;
            margin-bottom: 25px;
            font-weight: 600;
        }}
        .footer-divider {{
            height: 1px;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.1), transparent);
            margin: 25px 0;
        }}
        .footer p {{
            color: #718096;
            font-size: 13px;
            margin: 10px 0;
        }}
        .footer-copyright {{
            color: #4a5568;
            font-size: 12px;
            margin-top: 20px;
        }}
        @media only screen and (max-width: 600px) {{
            body {{ padding: 20px 10px; }}
            .content {{ padding: 35px 25px; }}
            .header {{ padding: 45px 25px; }}
            .footer {{ padding: 30px 25px; }}
            .button {{ padding: 18px 45px; font-size: 16px; }}
            .header h1 {{ font-size: 32px; }}
            .bee-icon {{ font-size: 60px; }}
        }}
    </style>
</head>
<body>
    <div class="email-wrapper">
        <div class="header">
            <div class="bee-container">
                <div class="bee-glow"></div>
                <div class="bee-icon">🐝</div>
            </div>
            <h1>HIVE INVASION</h1>
            <p class="header-subtitle">🔐 Password Reset Request</p>
        </div>
        
        <div class="content">
            <p class="greeting">
                <span class="greeting-emoji">👋</span>
                Hi <strong>{display_name}</strong>,
            </p>
            
            <p class="message">
                We received a request to reset your password for your <strong>Hive Invasion</strong> account. 
                Click the button below to create a new password and regain access to defend your kingdom!
            </p>
            
            <div class="button-container">
                <a href="{reset_link}" class="button">🔒 Reset Password</a>
            </div>
            
            <div class="info-card">
                <p class="info-card-title">Or copy and paste this link into your browser:</p>
                <code class="link-code">{reset_link}</code>
            </div>
            
            <div class="security-box">
                <div class="security-header">
                    <span class="security-icon">⚠️</span>
                    Security Notice
                </div>
                <div class="security-item">
                    <span class="security-item-icon">⏰</span>
                    <div>This reset link will <strong>expire in 1 hour</strong> for your account security.</div>
                </div>
                <div class="security-item">
                    <span class="security-item-icon">🔒</span>
                    <div>If you didn't request this password reset, you can safely <strong>ignore this email</strong>.</div>
                </div>
                <div class="security-item">
                    <span class="security-item-icon">✅</span>
                    <div>Your password won't change until you click the link above and create a new one.</div>
                </div>
            </div>
            
            <div class="divider"></div>
            
            <div class="help-section">
                <p><strong>💬 Need Help?</strong></p>
                <p>Contact our support team anytime - we're here to help!</p>
            </div>
        </div>
        
        <div class="footer">
            <p class="footer-logo">🐝 HIVE INVASION</p>
            <p class="footer-tagline">⚔️ Defend • 🏰 Raid • 👑 Conquer</p>
            <div class="footer-divider"></div>
            <p>This is an automated message. Please do not reply to this email.</p>
            <p class="footer-copyright">© {datetime.now().year} Pixcape Games. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
            """
        .divider {{
            height: 1px;
            background: linear-gradient(90deg, transparent, #e5e7eb, transparent);
            margin: 30px 0;
        }}
        @media only screen and (max-width: 600px) {{
            .content {{ padding: 30px 20px; }}
            .header {{ padding: 40px 20px; }}
            .footer {{ padding: 25px 20px; }}
            .button {{ padding: 15px 40px; font-size: 15px; }}
        }}
    </style>
</head>
<body>
    <div class="email-wrapper">
        <div class="header">
            <div class="bee-icon">🐝</div>
            <h1>HIVE INVASION</h1>
            <p>Password Reset Request</p>
        </div>
        
        <div class="content">
            <p class="greeting">Hi <strong>{display_name}</strong>,</p>
            
            <p class="message">
                We received a request to reset your password for your Hive Invasion account. 
                Click the button below to create a new password and regain access to your kingdom.
            </p>
            
            <div class="button-container">
                <a href="{reset_link}" class="button">Reset Your Password</a>
            </div>
            
            <div class="link-section">
                <p>Or copy and paste this link into your browser:</p>
                <code class="link-code">{reset_link}</code>
            </div>
            
            <div class="warning-box">
                <strong>
                    <span class="warning-icon">⚠️</span>
                    Security Note
                </strong>
                <p>🕐 This link will expire in <strong>1 hour</strong> for your security.</p>
                <p>🔒 If you didn't request this password reset, please ignore this email.</p>
                <p>💡 Your password will not change until you create a new one using the link above.</p>
            </div>
            
            <div class="divider"></div>
            
            <p style="color: #9ca3af; font-size: 13px; text-align: center;">
                Need help? Contact our support team anytime.
            </p>
        </div>
        
        <div class="footer">
            <p style="font-weight: 600; color: #6b7280;">🐝 HIVE INVASION</p>
            <p>Defend, Raid, Conquer!</p>
            <div class="divider" style="margin: 20px 0;"></div>
            <p>This is an automated message. Please do not reply to this email.</p>
            <p>© {datetime.now().year} Pixcape Games. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
            """
            
            # Text fallback
            text_body = f"""
HIVE INVASION - Password Reset Request

Hi {display_name},

We received a request to reset your password for your Hive Invasion account.

Click the link below to reset your password:
{reset_link}

This link will expire in 1 hour for your security.

If you didn't request this, please ignore this email.

---
Hive Invasion Team
© {datetime.now().year} Pixcape Games
            """
            
            # Send email
            response = self.ses.send_email(
                Source=self.sender_email,
                Destination={'ToAddresses': [to_email]},
                Message={
                    'Subject': {
                        'Data': '🔐 Hive Invasion - Reset Your Password',
                        'Charset': 'UTF-8'
                    },
                    'Body': {
                        'Text': {
                            'Data': text_body,
                            'Charset': 'UTF-8'
                        },
                        'Html': {
                            'Data': html_body,
                            'Charset': 'UTF-8'
                        }
                    }
                }
            )
            
            logger.info(f"Password reset email sent to {to_email}", context={
                "message_id": response.get('MessageId')
            })
            return True
            
        except ClientError as e:
            logger.error(f"Failed to send password reset email", error=e, context={
                "to_email": to_email,
                "error_code": e.response['Error']['Code']
            })
            return False
        except Exception as e:
            logger.error(f"Unexpected error sending email", error=e)
            return False
    
    def send_welcome_email(self, to_email: str, user_name: str = None) -> bool:
        """Send welcome email to new users"""
        try:
            display_name = user_name or to_email.split('@')[0]
            
            html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #1e5f99, #7c4dff); color: white; padding: 30px; border-radius: 10px; text-align: center; }}
        .content {{ background: #f9f9f9; padding: 30px; margin: 20px 0; border-radius: 10px; }}
        .button {{ display: inline-block; background: linear-gradient(135deg, #1e5f99, #7c4dff); color: white; padding: 15px 40px; text-decoration: none; border-radius: 50px; font-weight: bold; margin: 20px 0; }}
        .feature {{ background: white; padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 4px solid #7c4dff; }}
        .footer {{ color: #666; font-size: 12px; text-align: center; margin-top: 30px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🐝 Welcome to HIVE INVASION!</h1>
        </div>
        
        <div class="content">
            <p>Hi <strong>{display_name}</strong>,</p>
            
            <p>Welcome to Hive Invasion! Your account has been successfully created.</p>
            
            <h3>🎮 What's Next?</h3>
            
            <div class="feature">
                <strong>💎 Collect Diamonds</strong><br>
                Battle through waves and collect diamonds to upgrade your defenses
            </div>
            
            <div class="feature">
                <strong>🏆 Climb the Leaderboard</strong><br>
                Compete with players worldwide and claim your spot at the top
            </div>
            
            <div class="feature">
                <strong>🎯 Unlock Achievements</strong><br>
                Complete challenges and earn exclusive rewards
            </div>
            
            <p style="text-align: center;">
                <a href="{config.FRONTEND_URL}" class="button">Start Playing Now</a>
            </p>
        </div>
        
        <div class="footer">
            <p>Need help? Contact us at support@pixcape.games</p>
            <p>© {datetime.now().year} Pixcape Games. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
            """
            
            response = self.ses.send_email(
                Source=self.sender_email,
                Destination={'ToAddresses': [to_email]},
                Message={
                    'Subject': {
                        'Data': '🐝 Welcome to Hive Invasion!',
                        'Charset': 'UTF-8'
                    },
                    'Body': {
                        'Html': {
                            'Data': html_body,
                            'Charset': 'UTF-8'
                        }
                    }
                }
            )
            
            logger.info(f"Welcome email sent to {to_email}", context={
                "message_id": response.get('MessageId')
            })
            return True
            
        except Exception as e:
            logger.error(f"Failed to send welcome email", error=e)
            return False
