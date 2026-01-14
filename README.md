# 🐝 Hive Invasion Backend

**AWS Lambda backend for Hive Invasion game - Authentication, email verification, and player data management**

[![GitHub](https://img.shields.io/badge/GitHub-Null--State--Protocol-181717?logo=github)](https://github.com/Null-State-Protocol/Hive-Invasion-Backend)
[![Python](https://img.shields.io/badge/Python-3.13-blue?logo=python)](https://www.python.org/)
[![AWS](https://img.shields.io/badge/AWS-Lambda-FF9900?logo=amazonaws)](https://aws.amazon.com/lambda/)
[![License](https://img.shields.io/badge/License-Proprietary-red)](LICENSE)

## 🎯 Features

### Authentication System ✅
- **Email/Password Authentication**
  - Secure registration with bcrypt password hashing
  - Email verification via AWS SES (6-digit tokens)
  - Login enforcement (blocks unverified users)
  - Password reset flow with secure tokens
  
- **MetaMask Wallet Integration**
  - Signature-based authentication
  - Wallet linking/unlinking to existing accounts
  - Cross-platform identity management
  
- **JWT Token Management**
  - Access tokens (60 min expiry)
  - Refresh tokens (30 days expiry)
  - Secure token rotation

### Security 🔒
- bcrypt password hashing (12 rounds)
- JWT HS256 token signing
- Input validation and sanitization
- CORS security headers
- GDPR-compliant account deletion
- Session management with token verification

### Email Services 📧
- AWS SES integration
- Email verification templates
- Password reset notifications
- Custom sender domain (info@pixcape.games)

### Player Data Management 🎮
- User profile storage
- Game progress tracking (demo data)
- Dust balance system
- Account linking (email + wallet)

## 📁 Project Structure

```
Hive-Invasion-Backend-Lambda/
├── lambda_function.py          # Main Lambda handler (routes all /auth endpoints)
├── email_auth.py               # Email/password authentication logic
├── wallet_auth.py              # MetaMask wallet authentication
├── email_service.py            # AWS SES email sending
├── jwt_handler.py              # JWT token creation/verification
├── models.py                   # DynamoDB models and queries
├── config.py                   # Environment configuration
├── decorators.py               # Auth decorators (@require_auth)
├── validation.py               # Request validation
├── responses.py                # Standardized API responses
├── logger.py                   # Logging utilities
├── security.py                 # Password hashing, token generation
├── analytics.py                # Game analytics (demo)
├── requirements.txt            # Python dependencies
├── create-tables.sh            # DynamoDB table creation script
├── deploy-lambda.sh            # Lambda deployment script
└── README.md
```

## 🗄️ DynamoDB Tables

### Authentication Tables
1. **hive_users** - Main user accounts
   - PK: `user_id` (UUID)
   - Attributes: email, password_hash, email_verified, wallet_address, dust_balance, created_at

2. **hive_user_emails** - Email → user_id mapping (GSI for fast lookups)
   - PK: `email`
   - Attributes: user_id, created_at

3. **hive_user_wallets** - Wallet → user_id mapping
   - PK: `wallet_address`
   - Attributes: user_id, linked_at

4. **hive_email_verification** - Email verification tokens (24hr expiry)
   - PK: `token` (6-digit code)
   - Attributes: email, user_id, expires_at, created_at

5. **hive_password_reset** - Password reset tokens (1hr expiry)
   - PK: `token` (6-digit code)
   - Attributes: email, user_id, expires_at, created_at

6. **hive_sessions** - Active user sessions
   - PK: `session_id` (UUID)
   - Attributes: user_id, refresh_token, created_at, expires_at

7. **hive_deleted_accounts** - Soft-deleted accounts (GDPR compliance)
   - PK: `user_id`
   - Attributes: deletion_timestamp, email, wallet_address

### Game Tables
8. **hive_player_data** - Player game progress
   - PK: `user_id`
   - Attributes: level, score, games_played, rank, achievements (JSON)

9. **hive_achievements** - Achievement tracking
   - PK: `user_id`
   - SK: `achievement_id`
   - Attributes: unlocked_at, progress

10. **hive_leaderboard_kills** - Kill leaderboard
    - PK: `user_id`
    - Attributes: kills, rank, updated_at

11. **hive_leaderboard_dust** - Dust leaderboard
    - PK: `user_id`
    - Attributes: dust_balance, rank, updated_at

### Analytics Tables
12. **hive_analytics** - Game events and analytics
    - PK: `event_id` (UUID)
    - SK: `timestamp`
    - GSI: `user_id` + `timestamp` (UserEventsIndex)
    - Attributes: event_type, session_id, metadata (JSON)

13. **hive_logs** - Application logs
    - PK: `log_id` (UUID)
    - Attributes: level, message, user_id, request_id, timestamp

14. **hive_nft_claims** - NFT claim tracking
    - PK: `user_id`
    - SK: `nft_id`
    - Attributes: claimed_at, tx_hash

## 🔌 API Endpoints

### Base URL
```
Production: https://bb5nb3l00b.execute-api.eu-north-1.amazonaws.com/prod
```

### Authentication Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/auth/register` | Register with email/password | ❌ |
| POST | `/auth/login` | Login with email/password | ❌ |
| GET | `/auth/verify-email?token=XXX` | Verify email address | ❌ |
| POST | `/auth/password-reset/request` | Request password reset email | ❌ |
| POST | `/auth/password-reset/confirm` | Confirm password reset with token | ❌ |
| POST | `/auth/refresh` | Refresh access token | ❌ |
| POST | `/auth/wallet/message` | Get message to sign for MetaMask | ❌ |
| POST | `/auth/wallet/verify` | Verify MetaMask signature | ❌ |
| POST | `/auth/link-wallet` | Link MetaMask to account | ✅ |
| DELETE | `/auth/unlink-wallet` | Unlink MetaMask from account | ✅ |
| POST | `/auth/change-password` | Change account password | ✅ |
| DELETE | `/auth/account` | Delete account (GDPR) | ✅ |

### Player Endpoints (Future)

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/player/profile` | Get player profile | ✅ |
| POST | `/player/save` | Update game progress | ✅ |
| GET | `/player/achievements` | Get achievements | ✅ |
| POST | `/player/achievements` | Unlock achievement | ✅ |

### Leaderboard Endpoints (Future)

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/leaderboard/top?type=kills\|dust` | Get top 100 players | ❌ |
| GET | `/leaderboard/me` | Get my rank | ✅ |
| POST | `/leaderboard/score` | Submit score | ✅ |

## 🚀 Deployment Guide

### Prerequisites
- AWS CLI installed and configured
- IAM role with Lambda, DynamoDB, SES permissions
- Python 3.13 runtime
- DynamoDB tables created (see `create-tables.sh`)

### 1. Create DynamoDB Tables

```bash
# Run table creation script
chmod +x create-tables.sh
./create-tables.sh
```

This creates all 14 tables in `eu-north-1` region.

### 2. Deploy Lambda Function

#### Option A: Using deployment script (recommended)

```bash
chmod +x deploy-lambda.sh
./deploy-lambda.sh
```

#### Option B: Manual deployment

```bash
# Create deployment package (code only, no dependencies)
rm -f function.zip
zip -r function.zip *.py config.py -x "*__pycache__*" -x "*.pyc"

# Deploy to Lambda
aws lambda update-function-code \
  --function-name hive-invasion-backend \
  --zip-file fileb://function.zip \
  --region eu-north-1

# Verify deployment
aws lambda get-function \
  --function-name hive-invasion-backend \
  --region eu-north-1
```

### 3. Configure Environment Variables

Lambda environment variables (set via AWS Console or CLI):

```bash
JWT_SECRET=7DaWobDIlVj2CODvEEnDUrBF_3T22XRLMFgECfo7Dm0
ALLOWED_ORIGINS=https://hive-invasion-website.kagan-fa3.workers.dev
ENVIRONMENT=production
ENABLE_EMAIL_VERIFICATION=true
SENDER_EMAIL=info@pixcape.games
AWS_REGION=eu-north-1
```

### 4. Setup API Gateway

1. Create REST API in API Gateway
2. Create resource: `/auth`
3. Create method: `ANY` → Proxy to Lambda
4. Enable CORS
5. Deploy to stage: `prod`
6. Note the endpoint URL: `https://bb5nb3l00b.execute-api.eu-north-1.amazonaws.com/prod`

### 5. Verify AWS SES

```bash
# Verify sender email
aws ses verify-email-identity \
  --email-address info@pixcape.games \
  --region eu-north-1

# Check verification status
aws ses get-identity-verification-attributes \
  --identities info@pixcape.games \
  --region eu-north-1
```

### 6. Test Deployment

```bash
# Health check
curl https://bb5nb3l00b.execute-api.eu-north-1.amazonaws.com/prod/auth/health

# Register test user
curl -X POST https://bb5nb3l00b.execute-api.eu-north-1.amazonaws.com/prod/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"Test1234!"}'
```

## ⚙️ Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `JWT_SECRET` | Required | Min 32-char secret for JWT signing |
| `ALLOWED_ORIGINS` | Required | Comma-separated CORS origins |
| `ENVIRONMENT` | `production` | `dev` or `production` |
| `ENABLE_EMAIL_VERIFICATION` | `true` | Enforce email verification on login |
| `SENDER_EMAIL` | Required | AWS SES verified sender email |
| `AWS_REGION` | `eu-north-1` | AWS region for DynamoDB/SES |
| `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` | `60` | Access token expiry |
| `JWT_REFRESH_TOKEN_EXPIRE_DAYS` | `30` | Refresh token expiry |
| `BCRYPT_ROUNDS` | `12` | Password hashing rounds |

### Security Configuration

```python
# config.py
BCRYPT_ROUNDS = 12  # Production: 14 for higher security
ENABLE_EMAIL_VERIFICATION = True
PASSWORD_MIN_LENGTH = 8
PASSWORD_REQUIRE_UPPERCASE = True
PASSWORD_REQUIRE_LOWERCASE = True
PASSWORD_REQUIRE_DIGIT = True
PASSWORD_REQUIRE_SPECIAL = True
```

## 🔐 Security Best Practices

1. **JWT Secret**: Use minimum 32 random characters in production
2. **CORS**: Only allow trusted frontend origins
3. **HTTPS**: Always use HTTPS in production (API Gateway enforces this)
4. **Email Verification**: Keep enabled to prevent spam accounts
5. **Password Policy**: Enforce strong passwords (8+ chars, mixed case, digits, special)
6. **Token Expiry**: Access tokens expire in 60 minutes, refresh in 30 days
7. **bcrypt Rounds**: Use 12-14 rounds for password hashing (higher = more secure but slower)
8. **AWS SES**: Keep in sandbox mode until production-ready (verify recipient emails)

## 🧪 Testing

### Manual Testing

```bash
# Register
curl -X POST $API_URL/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@test.com","password":"Pass123!"}'

# Login
curl -X POST $API_URL/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@test.com","password":"Pass123!"}'

# Get profile (requires token)
curl -X GET $API_URL/player/profile \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### Database Cleanup (Testing)

```bash
# Delete all users
aws dynamodb scan --table-name hive_users --region eu-north-1 | \
  jq -r '.Items[].user_id.S' | \
  while read id; do
    aws dynamodb delete-item \
      --table-name hive_users \
      --key "{\"user_id\":{\"S\":\"$id\"}}" \
      --region eu-north-1
  done

# Same for other tables: hive_user_emails, hive_email_verification, etc.
```

## � Architecture

### Request Flow

```
User → Cloudflare Pages → API Gateway → Lambda → DynamoDB
                                              ↓
                                           AWS SES (emails)
```

### Lambda Handler Flow

```python
lambda_function.py
    ↓
handle_auth() / handle_game()
    ↓
email_auth.py / wallet_auth.py
    ↓
models.py (DynamoDB operations)
    ↓
responses.py (standardized JSON)
```

### Authentication Flow

#### Email Registration
1. User submits email + password
2. Backend validates input, hashes password (bcrypt)
3. Creates user in `hive_users` table
4. Generates 6-digit verification token
5. Stores token in `hive_email_verification` table (24hr TTL)
6. Sends verification email via AWS SES
7. User clicks link → GET `/auth/verify-email?token=XXX`
8. Backend marks `email_verified=true`
9. User can now login

#### Email Login
1. User submits email + password
2. Backend checks if email verified (if enabled)
3. Verifies password with bcrypt
4. Generates JWT access token (60min) + refresh token (30 days)
5. Stores refresh token in `hive_sessions` table
6. Returns both tokens to client

#### MetaMask Wallet Auth
1. User requests message to sign
2. Backend generates random nonce
3. User signs message with MetaMask
4. Backend verifies signature with web3
5. If valid, generates JWT tokens
6. User can link wallet to existing email account

## 📝 Development Notes

### Current Status (v2.9.0)
- ✅ Email/password authentication working
- ✅ Email verification system operational
- ✅ Password reset flow complete
- ✅ MetaMask wallet linking functional
- ✅ JWT token management implemented
- ✅ All 14 DynamoDB tables created
- ✅ CORS configured for Cloudflare Pages
- ✅ Production deployment to AWS Lambda
- ⏳ Game endpoints (achievements, save, leaderboard) - demo data only
- ⏳ Analytics and logging - basic implementation

### Future Roadmap
- [ ] Complete game endpoints implementation
- [ ] Real-time leaderboard updates
- [ ] Achievement unlock notifications
- [ ] NFT minting integration
- [ ] Admin dashboard and tools
- [ ] Rate limiting and DDoS protection
- [ ] CloudWatch monitoring integration
- [ ] Unit test coverage
- [ ] CI/CD pipeline (GitHub Actions)
- [ ] Terraform infrastructure as code

### Known Issues
- AWS SES in sandbox mode (requires manual recipient verification)
- No rate limiting on auth endpoints yet
- Demo data used for player achievements/quests
- No automated backup system for DynamoDB

## 🤝 Contributing

This is a private project for Hive Invasion game. For internal development:

1. Clone the repository
2. Make changes to `.py` files
3. Test locally with AWS credentials
4. Run `./deploy-lambda.sh` to deploy
5. Verify endpoints with curl/Postman
6. Commit changes to `main` branch

## 📄 License

© 2026 Pixcape - All rights reserved. Proprietary software for Hive Invasion game.

## 📞 Support

- **Organization:** [Null State Protocol](https://github.com/Null-State-Protocol)
- **Frontend Repo:** [hive-invasion-website](https://github.com/Null-State-Protocol/hive-invasion-website)
- **Backend Repo:** [Hive-Invasion-Backend](https://github.com/Null-State-Protocol/Hive-Invasion-Backend)
- **Live Site:** [https://hive-invasion-website.kagan-fa3.workers.dev](https://hive-invasion-website.kagan-fa3.workers.dev)
- **API Endpoint:** `https://bb5nb3l00b.execute-api.eu-north-1.amazonaws.com/prod`

---

**Version:** 2.9.0  
**Last Updated:** January 14, 2026  
**Status:** Production-ready authentication system, game features in development
