"""
GenAI Sentinel - Pydantic Schemas
Request/response validation models
"""
from pydantic import BaseModel, Field, EmailStr
from typing import Optional
from datetime import datetime


class UserLogin(BaseModel):
    """Login request schema"""
    username: str = Field(..., min_length=3, max_length=50, description="Username")
    password: str = Field(..., min_length=6, max_length=100, description="Password")
    
    class Config:
        json_schema_extra = {
            "example": {
                "username": "admin",
                "password": "Admin@123"
            }
        }


class Token(BaseModel):
    """JWT token response"""
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Token expiration in seconds")
    
    class Config:
        json_schema_extra = {
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "bearer",
                "expires_in": 1800
            }
        }


class TokenRefresh(BaseModel):
    """Token refresh request"""
    refresh_token: str = Field(..., description="Valid refresh token")


class UserResponse(BaseModel):
    """User data response (no password)"""
    id: int
    username: str
    role: str
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime] = None
    email: Optional[str] = None
    full_name: Optional[str] = None
    
    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "id": 1,
                "username": "admin",
                "role": "admin",
                "is_active": True,
                "created_at": "2024-01-01T00:00:00Z",
                "last_login": "2024-01-15T10:30:00Z",
                "email": "admin@genai-sentinel.local",
                "full_name": "System Administrator"
            }
        }


class LoginAuditLogResponse(BaseModel):
    """Login audit log response"""
    id: int
    username: str
    login_time: datetime
    ip_address: str
    user_agent: Optional[str]
    success: bool
    failure_reason: Optional[str] = None
    
    class Config:
        from_attributes = True


class SecurityEventResponse(BaseModel):
    """Security event response"""
    id: int
    event_type: str
    severity: str
    description: str
    timestamp: datetime
    ip_address: Optional[str] = None
    
    class Config:
        from_attributes = True


class MessageResponse(BaseModel):
    """Generic message response"""
    message: str
    detail: Optional[str] = None
    
    class Config:
        json_schema_extra = {
            "example": {
                "message": "Operation successful",
                "detail": "Additional information"
            }
        }
