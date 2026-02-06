# GenAI Sentinel - Secure Authentication Backend

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.10+-green)
![FastAPI](https://img.shields.io/badge/FastAPI-0.109.0-teal)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-14+-blue)

Production-ready authentication backend for the GenAI Sentinel cyberpunk-themed AI Security Dashboard with PostgreSQL database, JWT authentication, bcrypt password hashing, and comprehensive audit logging.

## 🔐 Security Features

- **🔒 Password Security**: bcrypt hashing with configurable rounds
- **🎫 JWT Authentication**: Access and refresh tokens with expiration
- **📊 Complete Audit Logging**: All login attempts tracked with metadata
- **🛡️ Zero-Trust Principles**: Role-based access control (RBAC)
- **🚨 Threat Detection**: Security event monitoring for suspicious activity
- **🔍 Brute Force Protection**: Failed attempt tracking and alerting
- **🌐 CORS Protection**: Configurable origin whitelisting
- **🛑 Security Headers**: HSTS, X-Frame-Options, XSS Protection

## 📋 Requirements

- Python 3.10+
- PostgreSQL 14+
- pip or poetry for dependency management

## 🚀 Quick Start

### 1. Clone and Setup

```bash
cd backend
python -m venv venv

# Windows
venv\Scripts\activate

# Unix/MacOS
source venv/bin/activate

pip install -r requirements.txt
```

### 2. Database Setup

Create PostgreSQL database:

```bash
createdb genai_sentinel

# Or using psql
psql -U postgres
CREATE DATABASE genai_sentinel;
\q
```

Run the schema:

```bash
psql -U postgres -d genai_sentinel -f database/schema.sql
```

### 3. Environment Configuration

Copy the example environment file:

```bash
copy .env.example .env
```

Edit `.env` and update:

```env
DATABASE_URL=postgresql://your_user:your_password@localhost:5432/genai_sentinel
JWT_SECRET_KEY=your-super-secret-key-generate-with-openssl-rand-hex-32
CORS_ORIGINS=http://localhost:3000,http://localhost:5173
```

**⚠️ IMPORTANT**: Generate a secure JWT secret:

```bash
# Linux/Mac
openssl rand -hex 32

# Windows (PowerShell)
[System.Convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Minimum 0 -Maximum 256 }))
```

### 4. Run the Application

```bash
cd app
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Or use the built-in runner:

```bash
python app/main.py
```

Server will start at: `http://localhost:8000`

API documentation: `http://localhost:8000/api/docs`

## 📚 API Endpoints

### Authentication

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/auth/login` | User login | ❌ |
| POST | `/auth/refresh` | Refresh access token | ❌ |
| GET | `/auth/me` | Get current user | ✅ |
| POST | `/auth/logout` | Logout (audit only) | ✅ |

### System

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/` | API root | ❌ |
| GET | `/health` | Health check | ❌ |

## 🔑 Usage Examples

### Login

```bash
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "Admin@123"
  }'
```

Response:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 1800
}
```

### Get Current User

```bash
curl -X GET http://localhost:8000/auth/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### Refresh Token

```bash
curl -X POST http://localhost:8000/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "YOUR_REFRESH_TOKEN"
  }'
```

## 🗄️ Database Schema

### Tables

- **users**: User accounts with RBAC
- **login_audit_logs**: Complete login attempt history
- **security_events**: Security incidents and threats

### Default Users

| Username | Password | Role |
|----------|----------|------|
| admin | Admin@123 | admin |
| analyst | Analyst@123 | analyst |

**⚠️ Change default passwords in production!**

## 🔒 Security Best Practices

### Production Checklist

- [ ] Change JWT_SECRET_KEY to a strong random value
- [ ] Update default user passwords
- [ ] Set DEBUG=False in production
- [ ] Use environment variables for sensitive config
- [ ] Enable HTTPS/TLS in production
- [ ] Implement rate limiting (use slowapi)
- [ ] Set up database backups
- [ ] Monitor security_events table
- [ ] Implement token blacklist for logout (Redis)
- [ ] Use strong DATABASE_URL credentials
- [ ] Restrict CORS_ORIGINS to your frontend domain
- [ ] Set up proper logging with rotation
- [ ] Enable database connection pooling
- [ ] Implement account lockout after failed attempts

### Zero-Trust Implementation

1. **Never Trust, Always Verify**: Every request requires valid JWT
2. **Least Privilege**: Role-based access control enforced
3. **Audit Everything**: All authentication events logged
4. **Defense in Depth**: Multiple security layers (bcrypt + JWT + CORS)
5. **Fail Securely**: Generic error messages prevent information leakage

## 🧪 Testing

Run the health check:

```bash
curl http://localhost:8000/health
```

Expected response:
```json
{
  "status": "healthy",
  "database": "connected",
  "version": "1.0.0"
}
```

## 📁 Project Structure

```
backend/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI application
│   ├── config.py            # Configuration management
│   ├── database.py          # Database connection
│   ├── models.py            # SQLAlchemy models
│   ├── schemas.py           # Pydantic schemas
│   ├── security.py          # Auth utilities
│   └── routers/
│       ├── __init__.py
│       └── auth.py          # Authentication routes
├── database/
│   └── schema.sql           # PostgreSQL schema
├── requirements.txt         # Python dependencies
├── .env.example            # Environment template
└── README.md               # This file
```

## 🛠️ Technology Stack

- **FastAPI**: Modern async web framework
- **SQLAlchemy**: ORM for database operations
- **PostgreSQL**: Relational database
- **python-jose**: JWT implementation
- **passlib**: Password hashing with bcrypt
- **Pydantic**: Data validation
- **Uvicorn**: ASGI server

## 📝 License

MIT License - Feel free to use this in your projects.

## 🤝 Contributing

This is a production-ready template. Feel free to customize for your needs.

## 📞 Support

For issues or questions, please check the API documentation at `/api/docs`.

---

**Built with 🔐 by a Senior Backend Security Engineer**
