"""
GenAI Sentinel - Authentication Routes
Login, logout, token refresh, and user management endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from datetime import datetime
from typing import Optional

from app.database import get_db
from app.models import User, LoginAuditLog, SecurityEvent
from app.schemas import UserLogin, Token, UserResponse, MessageResponse, TokenRefresh
from app.security import (
    verify_password,
    create_token_pair,
    get_current_user,
    decode_token,
    create_access_token
)
from app.config import settings

router = APIRouter(prefix="/auth", tags=["Authentication"])


def get_client_info(request: Request) -> dict:
    """Extract client IP and user agent from request"""
    # Try to get real IP from X-Forwarded-For header (if behind proxy)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        ip_address = forwarded_for.split(",")[0].strip()
    else:
        ip_address = request.client.host if request.client else "unknown"
    
    user_agent = request.headers.get("User-Agent", "unknown")
    
    return {
        "ip_address": ip_address,
        "user_agent": user_agent
    }


def log_login_attempt(
    db: Session,
    username: str,
    success: bool,
    ip_address: str,
    user_agent: str,
    user_id: Optional[int] = None,
    failure_reason: Optional[str] = None
):
    """
    Log a login attempt to the audit table
    
    Args:
        db: Database session
        username: Username attempted
        success: Whether login succeeded
        ip_address: Client IP address
        user_agent: Client user agent
        user_id: User ID if login succeeded
        failure_reason: Reason for failure if applicable
    """
    audit_log = LoginAuditLog(
        user_id=user_id,
        username=username,
        success=success,
        ip_address=ip_address,
        user_agent=user_agent,
        failure_reason=failure_reason
    )
    db.add(audit_log)
    db.commit()


def create_security_event(
    db: Session,
    event_type: str,
    severity: str,
    description: str,
    ip_address: str,
    user_agent: str,
    triggered_by: Optional[int] = None,
    metadata: Optional[dict] = None
):
    """
    Create a security event record
    
    Args:
        db: Database session
        event_type: Type of security event
        severity: low, medium, high, or critical
        description: Event description
        ip_address: Client IP
        user_agent: Client user agent
        triggered_by: User ID if applicable
        metadata: Additional context as JSON
    """
    event = SecurityEvent(
        event_type=event_type,
        severity=severity,
        description=description,
        triggered_by=triggered_by,
        ip_address=ip_address,
        user_agent=user_agent,
        metadata=metadata
    )
    db.add(event)
    db.commit()


@router.post("/login", response_model=Token, status_code=status.HTTP_200_OK)
async def login(
    credentials: UserLogin,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    User login endpoint
    
    - Validates username and password
    - Generates JWT access and refresh tokens
    - Logs all login attempts (success and failure)
    - Updates last_login timestamp on success
    - Creates security events for suspicious activity
    
    Returns JWT tokens on successful authentication
    """
    client_info = get_client_info(request)
    ip_address = client_info["ip_address"]
    user_agent = client_info["user_agent"]
    
    # Query user from database
    user = db.query(User).filter(User.username == credentials.username).first()
    
    # Check if user exists
    if not user:
        # Log failed attempt with non-existent user
        log_login_attempt(
            db, credentials.username, False, ip_address, user_agent,
            failure_reason="User not found"
        )
        
        # Create security event for potential reconnaissance
        create_security_event(
            db,
            event_type="suspicious_login",
            severity="low",
            description=f"Login attempt for non-existent user: {credentials.username}",
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        # Generic error message to avoid user enumeration
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Check if account is active
    if not user.is_active:
        log_login_attempt(
            db, credentials.username, False, ip_address, user_agent,
            user_id=user.id, failure_reason="Account inactive"
        )
        
        create_security_event(
            db,
            event_type="suspicious_login",
            severity="medium",
            description=f"Login attempt for inactive account: {credentials.username}",
            ip_address=ip_address,
            user_agent=user_agent,
            triggered_by=user.id
        )
        
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive"
        )
    
    # Verify password
    if not verify_password(credentials.password, user.password_hash):
        log_login_attempt(
            db, credentials.username, False, ip_address, user_agent,
            user_id=user.id, failure_reason="Invalid password"
        )
        
        # Check for multiple failed attempts (brute force detection)
        recent_failures = db.query(LoginAuditLog).filter(
            LoginAuditLog.username == credentials.username,
            LoginAuditLog.success == False,
            LoginAuditLog.login_time >= datetime.utcnow().replace(hour=0, minute=0, second=0)
        ).count()
        
        if recent_failures >= settings.MAX_LOGIN_ATTEMPTS:
            create_security_event(
                db,
                event_type="brute_force_attempt",
                severity="high",
                description=f"Multiple failed login attempts detected for user: {credentials.username}",
                ip_address=ip_address,
                user_agent=user_agent,
                triggered_by=user.id,
                metadata={"failed_attempts": recent_failures + 1}
            )
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Successful login - create tokens
    tokens = create_token_pair(user.username, user.id, user.role)
    
    # Update last login time
    user.last_login = datetime.utcnow()
    db.commit()
    
    # Log successful login
    log_login_attempt(
        db, credentials.username, True, ip_address, user_agent,
        user_id=user.id
    )
    
    # Return tokens
    return Token(
        access_token=tokens["access_token"],
        refresh_token=tokens["refresh_token"],
        token_type="bearer",
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )


@router.post("/refresh", response_model=Token)
async def refresh_token(
    token_data: TokenRefresh,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Refresh access token using a valid refresh token
    
    Returns new access and refresh tokens
    """
    client_info = get_client_info(request)
    
    try:
        # Decode refresh token
        payload = decode_token(token_data.refresh_token)
        
        # Verify it's a refresh token
        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type"
            )
        
        username = payload.get("sub")
        user_id = payload.get("user_id")
        role = payload.get("role")
        
        # Verify user still exists and is active
        user = db.query(User).filter(User.id == user_id).first()
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive"
            )
        
        # Create new token pair
        tokens = create_token_pair(username, user_id, role)
        
        return Token(
            access_token=tokens["access_token"],
            refresh_token=tokens["refresh_token"],
            token_type="bearer",
            expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )
        
    except HTTPException:
        # Log invalid token attempt
        create_security_event(
            db,
            event_type="invalid_token",
            severity="medium",
            description="Invalid refresh token used",
            ip_address=client_info["ip_address"],
            user_agent=client_info["user_agent"]
        )
        raise


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: User = Depends(get_current_user)
):
    """
    Get current authenticated user information
    
    Requires valid JWT token in Authorization header
    """
    return current_user


@router.post("/logout", response_model=MessageResponse)
async def logout(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Logout endpoint
    
    Note: JWT tokens are stateless, so we can't invalidate them server-side
    without a token blacklist. For production, implement token blacklist in Redis.
    
    This endpoint logs the logout event for audit purposes.
    """
    client_info = get_client_info(request)
    
    # Log logout event as a security event
    create_security_event(
        db,
        event_type="unusual_activity",
        severity="low",
        description=f"User logged out: {current_user.username}",
        ip_address=client_info["ip_address"],
        user_agent=client_info["user_agent"],
        triggered_by=current_user.id
    )
    
    return MessageResponse(
        message="Logged out successfully",
        detail="Clear the token from client storage"
    )
