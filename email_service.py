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
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 60px 40px;
            text-align: center;
        }}
        .bee-icon {{
            font-size: 80px;
            margin-bottom: 20px;
        }}
        .header h1 {{
            color: white;
            font-size: 42px;
            font-weight: 900;
            margin: 0;
            letter-spacing: 2px;
        }}
        .header-subtitle {{
            color: rgba(255,255,255,0.95);
            font-size: 18px;
            margin-top: 15px;
            font-weight: 600;
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
            letter-spacing: 1px;
        }}
        .info-card {{
            background: linear-gradient(135deg, #ebf4ff 0%, #e0e7ff 100%);
            border: 2px solid #c3dafe;
            border-radius: 16px;
            padding: 25px;
            margin: 35px 0;
        }}
        .info-card-title {{
            color: #4c51bf;
            font-size: 15px;
            font-weight: 700;
            margin-bottom: 15px;
        }}
        .link-code {{
            background: white;
            border: 2px solid #a3bffa;
            padding: 15px 18px;
            border-radius: 12px;
            word-break: break-all;
            font-family: monospace;
            font-size: 13px;
            color: #5a67d8;
            display: block;
            font-weight: 600;
        }}
        .security-box {{
            background: linear-gradient(135deg, #fff5e1 0%, #ffe4b5 100%);
            border: 3px solid #fbbf24;
            border-radius: 16px;
            padding: 30px;
            margin: 35px 0;
        }}
        .security-header {{
            font-size: 18px;
            color: #92400e;
            margin-bottom: 18px;
            font-weight: 800;
        }}
        .security-item {{
            color: #78350f;
            font-size: 15px;
            line-height: 1.7;
            margin: 12px 0;
        }}
        .footer {{
            background: linear-gradient(135deg, #1a202c 0%, #2d3748 100%);
            padding: 40px 45px;
            text-align: center;
        }}
        .footer-logo {{
            color: white;
            font-size: 20px;
            font-weight: 900;
            margin-bottom: 10px;
        }}
        .footer-tagline {{
            color: #a0aec0;
            font-size: 15px;
            margin-bottom: 25px;
        }}
        .footer p {{
            color: #718096;
            font-size: 13px;
            margin: 10px 0;
        }}
    </style>
</head>
<body>
    <div class="email-wrapper">
        <div class="header">
            <div class="bee-icon">🐝</div>
            <h1>HIVE INVASION</h1>
            <p class="header-subtitle">🔐 Password Reset Request</p>
        </div>
        
        <div class="content">
            <p class="greeting">👋 Hi <strong>{display_name}</strong>,</p>
            
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
                <div class="security-header">⚠️ Security Notice</div>
                <div class="security-item">⏰ This reset link will <strong>expire in 1 hour</strong> for your account security.</div>
                <div class="security-item">🔒 If you didn't request this password reset, you can safely <strong>ignore this email</strong>.</div>
                <div class="security-item">✅ Your password won't change until you click the link above and create a new one.</div>
            </div>
        </div>
        
        <div class="footer">
            <p class="footer-logo">🐝 HIVE INVASION</p>
            <p class="footer-tagline">⚔️ Defend • 🏰 Raid • 👑 Conquer</p>
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
    
    def send_password_reset_code_email(self, to_email: str, reset_code: str, user_name: str = None) -> bool:
        """Send password reset email with 4-digit code"""
        try:
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
            background-color: #f5f5f5;
            line-height: 1.6;
            color: #333;
            padding: 20px;
        }}
        .email-wrapper {{
            max-width: 600px;
            margin: 0 auto;
            background: #ffffff;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
        }}
        .header {{
            background: #000;
            padding: 40px 30px;
            text-align: center;
        }}
        .logo {{
            width: 120px;
            height: auto;
            margin-bottom: 15px;
        }}
        .header h1 {{
            color: #FFEB3B;
            font-size: 28px;
            font-weight: 700;
            margin: 0;
        }}
        .header-subtitle {{
            color: #fff;
            font-size: 14px;
            margin-top: 8px;
        }}
        .content {{
            padding: 40px 30px;
        }}
        .greeting {{
            font-size: 18px;
            color: #333;
            margin-bottom: 20px;
        }}
        .message {{
            font-size: 15px;
            color: #666;
            margin-bottom: 30px;
            line-height: 1.6;
        }}
        .code-container {{
            text-align: center;
            margin: 35px 0;
            background: #f8f9fa;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            padding: 30px;
        }}
        .code-label {{
            color: #666;
            font-size: 13px;
            font-weight: 600;
            margin-bottom: 15px;
            text-transform: uppercase;
        }}
        .reset-code {{
            font-size: 48px;
            font-weight: 700;
            color: #000;
            letter-spacing: 12px;
            font-family: 'Courier New', monospace;
        }}
        .info-box {{
            background: #fff9e6;
            border-left: 3px solid #FFEB3B;
            padding: 15px 20px;
            margin: 25px 0;
            font-size: 14px;
            color: #666;
        }}
        .footer {{
            background: #f8f9fa;
            padding: 25px 30px;
            text-align: center;
            border-top: 1px solid #e0e0e0;
        }}
        .footer-logo {{
            color: #333;
            font-size: 16px;
            font-weight: 700;
            margin-bottom: 8px;
        }}
        .footer p {{
            color: #999;
            font-size: 12px;
            margin: 5px 0;
        }}
    </style>
</head>
<body>
    <div class="email-wrapper">
        <div class="header">
            <img src="https://hive-invasion-website.kagan-fa3.workers.dev/assets/raw.png" alt="Hive Invasion" class="logo">
            <h1>HIVE INVASION</h1>
            <p class="header-subtitle">Password Reset</p>
        </div>
        
        <div class="content">
            <p class="greeting">Hi, <strong>{display_name}</strong></p>
            
            <p class="message">
                We received a request to reset your password. Enter the code below on the password reset page to create a new password.
            </p>
            
            <div class="code-container">
                <div class="code-label">Reset Code</div>
                <div class="reset-code">{reset_code}</div>
            </div>
            
            <div class="info-box">
                This code expires in 1 hour. If you did not request a password reset, please ignore this email and your password will remain unchanged.
            </div>
        </div>
        
        <div class="footer">
            <p class="footer-logo">HIVE INVASION</p>
            <p>This is an automated message. Please do not reply.</p>
            <p>© {datetime.now().year} Pixcape Games. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
            """
            
            # Text fallback
            text_body = f"""
HIVE INVASION - Password Reset

Hi {display_name}

Your password reset code is: {reset_code}

Enter this code on the password reset page to create a new password.

This code expires in 1 hour.

If you did not request this, please ignore this email.

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
                        'Data': f'Hive Invasion - Reset Code: {reset_code}',
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
            
            logger.info(f"Password reset code email sent to {to_email}", context={
                "message_id": response.get('MessageId'),
                "code_length": len(reset_code)
            })
            return True
            
        except ClientError as e:
            logger.error(f"Failed to send password reset code email", error=e, context={
                "to_email": to_email,
                "error_code": e.response['Error']['Code']
            })
            return False
        except Exception as e:
            logger.error(f"Unexpected error sending password reset code email", error=e)
            return False
    
    def send_verification_email(self, to_email: str, verification_token: str, user_name: str = None) -> bool:
        """Send email verification email"""
        try:
            # Create verification link
            verify_link = f"{config.FRONTEND_URL}/verify-email?token={verification_token}"
            
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
        }}
        .header {{
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
            padding: 60px 40px;
            text-align: center;
        }}
        .bee-icon {{
            font-size: 80px;
            margin-bottom: 20px;
        }}
        .header h1 {{
            color: white;
            font-size: 42px;
            font-weight: 900;
            margin: 0;
            letter-spacing: 2px;
        }}
        .header-subtitle {{
            color: rgba(255,255,255,0.95);
            font-size: 18px;
            margin-top: 15px;
            font-weight: 600;
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
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
            color: white !important;
            padding: 20px 60px;
            text-decoration: none;
            border-radius: 50px;
            font-weight: 800;
            font-size: 18px;
            letter-spacing: 1px;
        }}
        .info-card {{
            background: linear-gradient(135deg, #d1fae5 0%, #a7f3d0 100%);
            border: 2px solid #6ee7b7;
            border-radius: 16px;
            padding: 25px;
            margin: 35px 0;
        }}
        .info-card-title {{
            color: #065f46;
            font-size: 15px;
            font-weight: 700;
            margin-bottom: 15px;
        }}
        .link-code {{
            background: white;
            border: 2px solid #6ee7b7;
            padding: 15px 18px;
            border-radius: 12px;
            word-break: break-all;
            font-family: monospace;
            font-size: 13px;
            color: #047857;
            display: block;
            font-weight: 600;
        }}
        .welcome-box {{
            background: linear-gradient(135deg, #fef3c7 0%, #fde68a 100%);
            border: 3px solid #fbbf24;
            border-radius: 16px;
            padding: 30px;
            margin: 35px 0;
        }}
        .welcome-header {{
            font-size: 18px;
            color: #92400e;
            margin-bottom: 18px;
            font-weight: 800;
        }}
        .welcome-item {{
            color: #78350f;
            font-size: 15px;
            line-height: 1.7;
            margin: 12px 0;
        }}
        .footer {{
            background: linear-gradient(135deg, #1a202c 0%, #2d3748 100%);
            padding: 40px 45px;
            text-align: center;
        }}
        .footer-logo {{
            color: white;
            font-size: 20px;
            font-weight: 900;
            margin-bottom: 10px;
        }}
        .footer-tagline {{
            color: #a0aec0;
            font-size: 15px;
            margin-bottom: 25px;
        }}
        .footer p {{
            color: #718096;
            font-size: 13px;
            margin: 10px 0;
        }}
    </style>
</head>
<body>
    <div class="email-wrapper">
        <div class="header">
            <div class="bee-icon">🐝</div>
            <h1>HIVE INVASION</h1>
            <p class="header-subtitle">✅ Verify Your Email</p>
        </div>
        
        <div class="content">
            <p class="greeting">👋 Welcome <strong>{display_name}</strong>!</p>
            
            <p class="message">
                Thank you for joining <strong>Hive Invasion</strong>! 
                We're excited to have you defend your kingdom. Click the button below to verify your email address and complete your registration.
            </p>
            
            <div class="button-container">
                <a href="{verify_link}" class="button">✅ Verify Email</a>
            </div>
            
            <div class="info-card">
                <p class="info-card-title">Or copy and paste this link into your browser:</p>
                <code class="link-code">{verify_link}</code>
            </div>
            
            <div class="welcome-box">
                <div class="welcome-header">🎮 What's Next?</div>
                <div class="welcome-item">🏰 Build and defend your kingdom</div>
                <div class="welcome-item">⚔️ Raid enemy bases for resources</div>
                <div class="welcome-item">💎 Earn Dust rewards and climb the leaderboard</div>
                <div class="welcome-item">🎯 Complete quests from partner networks</div>
            </div>
        </div>
        
        <div class="footer">
            <p class="footer-logo">🐝 HIVE INVASION</p>
            <p class="footer-tagline">⚔️ Defend • 🏰 Raid • 👑 Conquer</p>
            <p>This is an automated message. Please do not reply to this email.</p>
            <p>© {datetime.now().year} Pixcape Games. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
            """
            
            # Text fallback
            text_body = f"""
HIVE INVASION - Verify Your Email

Welcome {display_name}!

Thank you for joining Hive Invasion! Click the link below to verify your email address:
{verify_link}

What's Next?
- Build and defend your kingdom
- Raid enemy bases for resources
- Earn Dust rewards and climb the leaderboard
- Complete quests from partner networks

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
                        'Data': '✅ Hive Invasion - Verify Your Email',
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
            
            logger.info(f"Verification email sent to {to_email}", context={
                "message_id": response.get('MessageId')
            })
            return True
            
        except ClientError as e:
            logger.error(f"Failed to send verification email", error=e, context={
                "to_email": to_email,
                "error_code": e.response['Error']['Code']
            })
            return False
        except Exception as e:
            logger.error(f"Unexpected error sending verification email", error=e)
            return False    
    def send_verification_code_email(self, to_email: str, verification_code: str, user_name: str = None) -> bool:
        """Send verification email with 4-digit code"""
        try:
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
            background-color: #f5f5f5;
            line-height: 1.6;
            color: #333;
            padding: 20px;
        }}
        .email-wrapper {{
            max-width: 600px;
            margin: 0 auto;
            background: #ffffff;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
        }}
        .header {{
            background: #000;
            padding: 40px 30px;
            text-align: center;
        }}
        .logo {{
            width: 120px;
            height: auto;
            margin-bottom: 15px;
        }}
        .header h1 {{
            color: #FFEB3B;
            font-size: 28px;
            font-weight: 700;
            margin: 0;
        }}
        .header-subtitle {{
            color: #fff;
            font-size: 14px;
            margin-top: 8px;
        }}
        .content {{
            padding: 40px 30px;
        }}
        .greeting {{
            font-size: 18px;
            color: #333;
            margin-bottom: 20px;
        }}
        .message {{
            font-size: 15px;
            color: #666;
            margin-bottom: 30px;
            line-height: 1.6;
        }}
        .code-container {{
            text-align: center;
            margin: 35px 0;
            background: #f8f9fa;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            padding: 30px;
        }}
        .code-label {{
            color: #666;
            font-size: 13px;
            font-weight: 600;
            margin-bottom: 15px;
            text-transform: uppercase;
        }}
        .verification-code {{
            font-size: 48px;
            font-weight: 700;
            color: #000;
            letter-spacing: 12px;
            font-family: 'Courier New', monospace;
        }}
        .info-box {{
            background: #fff9e6;
            border-left: 3px solid #FFEB3B;
            padding: 15px 20px;
            margin: 25px 0;
            font-size: 14px;
            color: #666;
        }}
        .footer {{
            background: #f8f9fa;
            padding: 25px 30px;
            text-align: center;
            border-top: 1px solid #e0e0e0;
        }}
        .footer-logo {{
            color: #333;
            font-size: 16px;
            font-weight: 700;
            margin-bottom: 8px;
        }}
        .footer p {{
            color: #999;
            font-size: 12px;
            margin: 5px 0;
        }}
    </style>
</head>
<body>
    <div class="email-wrapper">
        <div class="header">
            <img src="https://hive-invasion-website.kagan-fa3.workers.dev/assets/raw.png" alt="Hive Invasion" class="logo">
            <h1>HIVE INVASION</h1>
            <p class="header-subtitle">Email Verification</p>
        </div>
        
        <div class="content">
            <p class="greeting">Welcome, <strong>{display_name}</strong></p>
            
            <p class="message">
                Thank you for joining Hive Invasion. Please enter the verification code below to complete your registration.
            </p>
            
            <div class="code-container">
                <div class="code-label">Verification Code</div>
                <div class="verification-code">{verification_code}</div>
            </div>
            
            <div class="info-box">
                This code expires in 24 hours. If you did not request this verification, please ignore this email.
            </div>
        </div>
        
        <div class="footer">
            <p class="footer-logo">HIVE INVASION</p>
            <p>This is an automated message. Please do not reply.</p>
            <p>© {datetime.now().year} Pixcape Games. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
            """
            
            # Text fallback
            text_body = f"""
HIVE INVASION - Email Verification

Welcome {display_name}

Your verification code is: {verification_code}

Enter this code on the registration page to complete your account setup.

This code expires in 24 hours.

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
                        'Data': f'Hive Invasion - Verification Code: {verification_code}',
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
            
            logger.info(f"Verification code email sent to {to_email}", context={
                "message_id": response.get('MessageId'),
                "code_length": len(verification_code)
            })
            return True
            
        except ClientError as e:
            logger.error(f"Failed to send verification code email", error=e, context={
                "to_email": to_email,
                "error_code": e.response['Error']['Code']
            })
            return False
        except Exception as e:
            logger.error(f"Unexpected error sending verification code email", error=e)
            return False