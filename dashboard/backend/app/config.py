"""
GenAI Sentinel - Configuration Management
Loads environment variables and provides application settings
"""
from pydantic_settings import BaseSettings
from typing import List
import os


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""
    
    # Database
    DATABASE_URL: str = "postgresql://postgres:postgres@localhost:5432/genai_sentinel"
    DB_ECHO: bool = False
    
    # JWT Configuration
    JWT_SECRET_KEY: str = "dev-secret-key-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # CORS
    CORS_ORIGINS: str = "http://localhost:3000,http://localhost:5173,http://127.0.0.1:5500"
    
    # Application
    APP_NAME: str = "GenAI Sentinel"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    
    # Security
    BCRYPT_ROUNDS: int = 12
    MAX_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_DURATION_MINUTES: int = 15
    
    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = 60
    
    @property
    def cors_origins_list(self) -> List[str]:
        """Parse CORS origins from comma-separated string"""
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",")]
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


# Singleton instance
settings = Settings()

# Validate critical settings on startup
if settings.JWT_SECRET_KEY == "dev-secret-key-change-in-production" and not settings.DEBUG:
    raise ValueError("⚠️  SECURITY WARNING: Change JWT_SECRET_KEY in production!")

if settings.DATABASE_URL.startswith("postgresql://postgres:postgres") and not settings.DEBUG:
    print("⚠️  WARNING: Using default database credentials. Change in production!")
