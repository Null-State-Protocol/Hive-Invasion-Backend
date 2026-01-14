# Hive Invasion Backend - Unified API

**Profesyonel, güvenli ve ölçeklenebilir backend sistemi**

## 🎯 Özellikler

### Kimlik Doğrulama
- ✅ **Email/Password Authentication**
  - Güvenli kayıt ve giriş
  - Şifre gücü doğrulama (bcrypt)
  - Email doğrulama (opsiyonel)
  - Şifre sıfırlama
  
- ✅ **Wallet Authentication**
  - MetaMask entegrasyonu
  - Signature verification
  - Wallet-based login
  
- ✅ **Account Linking**
  - Email ↔ Wallet bağlama
  - Çoklu kimlik doğrulama yöntemleri
  - Cross-platform hesap senkronizasyonu

### Güvenlik
- 🔒 JWT token authentication (access + refresh)
- 🔒 bcrypt password hashing (12-14 rounds)
- 🔒 Rate limiting (DDoS koruması)
- 🔒 Input validation ve sanitization
- 🔒 CORS security headers
- 🔒 SQL injection prevention (DynamoDB)
- 🔒 GDPR compliant account deletion

### Logging & Analytics
- 📊 **Custom Logging System** (DynamoDB tabanlı, CloudWatch alternatifi)
  - Structured logging
  - Query by user, request, level
  - Auto-expiration (TTL)
  - Error tracking
  
- 📊 **Game Analytics**
  - Session tracking
  - Event tracking (achievements, kills, etc.)
  - User behavior analytics
  - Aggregated statistics

### Oyun Özellikleri
- 🎮 Achievement sistemi
- 🎮 Save/Load oyun durumu
- 🎮 Leaderboard (kills + dust)
- 🎮 Skill system
- 🎮 NFT mint entegrasyonu
- 🎮 Cross-platform sync

## 📁 Proje Yapısı

```
new-backend/
├── lambda_function.py          # Ana Lambda handler
├── requirements.txt            # Python dependencies
├── README.md
│
├── src/
│   ├── config.py              # Konfigürasyon yönetimi
│   │
│   ├── auth/                  # Kimlik doğrulama
│   │   ├── email_auth.py      # Email/password auth
│   │   ├── wallet_auth.py     # Wallet auth
│   │   └── jwt_handler.py     # JWT token management
│   │
│   ├── game/                  # Oyun servisleri
│   │   ├── achievements.py    # Achievement sistemi
│   │   ├── save.py            # Save/load
│   │   ├── leaderboard.py     # Leaderboard
│   │   └── profile.py         # Oyuncu profili
│   │
│   ├── logging/               # Logging ve analytics
│   │   ├── logger.py          # Custom logger
│   │   └── analytics.py       # Game analytics
│   │
│   ├── database/              # Database katmanı
│   │   ├── models.py          # Data modelleri
│   │   └── repositories.py    # Database işlemleri
│   │
│   └── utils/                 # Yardımcı modüller
│       ├── security.py        # Güvenlik utilities
│       ├── validation.py      # Input validation
│       ├── responses.py       # HTTP response builders
│       └── decorators.py      # Auth decorators
│
├── tests/                     # Unit testler
│   ├── test_auth.py
│   ├── test_game.py
│   └── test_security.py
│
└── deployment/                # Deployment scriptleri
    ├── terraform/             # Infrastructure as Code
    └── scripts/               # Deployment helpers
```

## 🗄️ DynamoDB Tabloları

### Kimlik Doğrulama Tabloları
1. **hive_users** - Ana kullanıcı tablosu
   - PK: `user_id` (UUID)
   - Attributes: email, password_hash, email_verified, created_at, etc.

2. **hive_user_emails** - Email → user_id mapping
   - PK: `email`
   - GSI: `user_id`

3. **hive_user_wallets** - Wallet → user_id mapping
   - PK: `wallet_address`
   - GSI: `user_id` (UserWalletsIndex)

4. **hive_sessions** - Aktif oturumlar
   - PK: `session_token`
   - GSI: `user_id`

5. **hive_email_verification** - Email doğrulama
   - PK: `email`
   - GSI: `verification_token` (VerificationTokenIndex)

6. **hive_password_reset** - Şifre sıfırlama
   - PK: `email`
   - GSI: `reset_token` (ResetTokenIndex)

### Oyun Tabloları
7. **hive_player_data** - Oyun kayıt verileri
   - PK: `user_id`

8. **hive_achievements** - Başarılar
   - PK: `user_id`
   - SK: `achievement_id`

9. **hive_leaderboard_kills** - Kill leaderboard
   - PK: `user_id`
   - SK: `timestamp`
   - GSI: `score` (ScoreIndex)

10. **hive_leaderboard_dust** - Dust leaderboard
    - PK: `user_id`
    - SK: `timestamp`
    - GSI: `score` (ScoreIndex)

### Logging Tabloları
11. **hive_logs** - System logs
    - PK: `log_id`
    - SK: `timestamp`
    - GSI: `user_id` (UserLogsIndex)
    - GSI: `request_id` (RequestLogsIndex)
    - GSI: `level` + `timestamp` (LevelLogsIndex)
    - TTL: Auto-expire after 90 days

12. **hive_analytics** - Game analytics
    - PK: `event_id`
    - SK: `timestamp`
    - GSI: `user_id` + `timestamp` (UserEventsIndex)
    - GSI: `event_type` + `timestamp` (EventTypeIndex)
    - GSI: `session_id` + `timestamp` (SessionEventsIndex)
    - TTL: Auto-expire after 90 days

## 🔌 API Endpoints

### Authentication

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| POST | `/auth/register` | Email ile kayıt | ❌ |
| POST | `/auth/login` | Email ile giriş | ❌ |
| POST | `/auth/wallet/message` | Wallet imza mesajı al | ❌ |
| POST | `/auth/wallet/verify` | Wallet imzasını doğrula | ❌ |
| POST | `/auth/refresh` | Token yenile | ❌ |
| POST | `/auth/link-wallet` | Hesaba wallet bağla | ✅ |
| POST | `/auth/link-email` | Hesaba email bağla | ✅ |
| POST | `/auth/password-reset/request` | Şifre sıfırlama talebi | ❌ |
| POST | `/auth/password-reset/confirm` | Şifre sıfırla | ❌ |
| DELETE | `/auth/account` | Hesap sil (GDPR) | ✅ |

### Player/Game

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/player/profile` | Oyuncu profili | ✅ |
| GET | `/player/save` | Oyun kaydı getir | ✅ |
| POST | `/player/save` | Oyun kaydı güncelle | ✅ |
| GET | `/player/achievements` | Başarılar listesi | ✅ |
| POST | `/player/achievements` | Başarı kaydet | ✅ |

### Leaderboard

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/leaderboard/top?type=kills\|dust` | Top 100 listesi | ❌ |
| GET | `/leaderboard/me` | Kendi sıralaman | ✅ |
| POST | `/leaderboard/score` | Skor gönder | ✅ |

### Analytics

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| POST | `/analytics/event` | Event kaydet | ✅ |
| GET | `/analytics/stats` | Kullanıcı istatistikleri | ✅ |

### Utility

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/health` | Health check | ❌ |
| GET | `/ping` | Ping | ❌ |

## 🚀 Kurulum ve Deployment

### Local Development

```bash
# 1. Dependencies kur
pip install -r requirements.txt

# 2. Environment variables ayarla
export AWS_REGION=eu-north-1
export JWT_SECRET=<your-secret-key>
export ENVIRONMENT=dev

# 3. DynamoDB Local çalıştır (opsiyonel)
docker run -p 8000:8000 amazon/dynamodb-local

# 4. Lambda'yı local test et
python lambda_function.py
```

### AWS Deployment

```bash
# 1. Deployment package oluştur
zip -r function.zip lambda_function.py src/ -x "*.pyc" -x "__pycache__/*"

# 2. Dependencies ekle
pip install -r requirements.txt -t package/
cd package && zip -r ../function.zip . && cd ..

# 3. Lambda'yı güncelle
aws lambda update-function-code \
  --function-name hive-invasion-backend \
  --zip-file fileb://function.zip \
  --region eu-north-1

# 4. Environment variables ayarla
aws lambda update-function-configuration \
  --function-name hive-invasion-backend \
  --environment Variables="{JWT_SECRET=xxx,ENVIRONMENT=production}" \
  --region eu-north-1
```

## ⚙️ Konfigürasyon

Environment variables:

```bash
# AWS
AWS_REGION=eu-north-1

# JWT
JWT_SECRET=<min-32-char-secret>
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=60
JWT_REFRESH_TOKEN_EXPIRE_DAYS=30

# Security
BCRYPT_ROUNDS=12                      # production: 14
ENABLE_EMAIL_VERIFICATION=true
ENABLE_RATE_LIMITING=true

# Features
ENABLE_ANALYTICS=true
ENABLE_FRAUD_DETECTION=true

# CORS
ALLOWED_ORIGINS=https://hiveinvasion.com,https://app.hiveinvasion.com

# Logging
LOG_LEVEL=INFO                        # DEBUG, INFO, WARNING, ERROR
LOG_RETENTION_DAYS=90

# Environment
ENVIRONMENT=production                # dev, production
```

## 🔐 Güvenlik Best Practices

1. **JWT Secret**: Production'da minimum 32 karakter, rastgele string kullanın
2. **Password Policy**: Güçlü şifre gereksinimleri aktif
3. **Rate Limiting**: Auth endpoint'leri için 5 req/min limit
4. **CORS**: Sadece belirlediğiniz origin'lere izin verin
5. **HTTPS**: API Gateway'de SSL/TLS zorunlu
6. **Input Validation**: Tüm user input'lar validate ediliyor
7. **SQL Injection**: DynamoDB kullanıldığı için risk yok
8. **XSS Protection**: Response header'lar ile korumalı

## 📊 Monitoring

### Custom Logging
```python
from src.logging.logger import logger

logger.info("User action", context={"user_id": user_id})
logger.error("Operation failed", error=exception)
```

### Analytics
```python
from src.logging.analytics import track_achievement

track_achievement(user_id="123", achievement_id="first_win")
```

## 🧪 Testing

```bash
# Unit testleri çalıştır
pytest tests/

# Coverage raporu
pytest --cov=src tests/

# Specific test
pytest tests/test_auth.py::test_register
```

## 📝 TODO

- [ ] Game endpoints implementasyonu (achievements, save, leaderboard)
- [ ] Email gönderme (SES veya SendGrid entegrasyonu)
- [ ] Fraud detection sistemi
- [ ] Sezon sistemi (leaderboard)
- [ ] Admin endpoints
- [ ] Backup ve restore sistemi
- [ ] Terraform deployment scriptleri
- [ ] CI/CD pipeline
- [ ] Performance monitoring
- [ ] API documentation (Swagger/OpenAPI)

## 📄 Lisans

© 2026 Pixcape - All rights reserved

## 👥 İletişim

- **Proje**: Hive Invasion Backend
- **Version**: 1.0.0
- **Güncellenme**: 7 Ocak 2026
