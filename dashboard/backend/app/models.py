"""
GenAI Sentinel - SQLAlchemy ORM Models
Database models for users, audit logs, and security events
"""
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base


class User(Base):
    """User account model with RBAC support"""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default="user")
    is_active = Column(Boolean, nullable=False, default=True, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_login = Column(DateTime(timezone=True), nullable=True)
    email = Column(String(255), unique=True, nullable=True)
    full_name = Column(String(100), nullable=True)
    
    # Relationships
    audit_logs = relationship("LoginAuditLog", back_populates="user", cascade="all, delete-orphan")
    security_events = relationship("SecurityEvent", back_populates="user", foreign_keys="SecurityEvent.triggered_by")
    
    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}', role='{self.role}')>"
    
    def to_dict(self):
        """Convert to dictionary (excludes password_hash)"""
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "email": self.email,
            "full_name": self.full_name
        }


class LoginAuditLog(Base):
    """Login attempt audit trail"""
    __tablename__ = "login_audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    username = Column(String(50), nullable=False)
    login_time = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    ip_address = Column(String(45), nullable=False, index=True)
    user_agent = Column(Text, nullable=True)
    success = Column(Boolean, nullable=False, index=True)
    failure_reason = Column(String(100), nullable=True)
    session_id = Column(String(255), nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="audit_logs")
    
    def __repr__(self):
        status = "SUCCESS" if self.success else "FAILED"
        return f"<LoginAuditLog(username='{self.username}', status={status}, ip='{self.ip_address}')>"
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "username": self.username,
            "login_time": self.login_time.isoformat() if self.login_time else None,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "success": self.success,
            "failure_reason": self.failure_reason,
            "session_id": self.session_id
        }


class SecurityEvent(Base):
    """Security incident and threat detection events"""
    __tablename__ = "security_events"
    
    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String(50), nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True)
    description = Column(Text, nullable=False)
    triggered_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    metadata = Column(JSON, nullable=True)  # Flexible JSONB field
    
    # Relationships
    user = relationship("User", back_populates="security_events", foreign_keys=[triggered_by])
    
    def __repr__(self):
        return f"<SecurityEvent(type='{self.event_type}', severity='{self.severity}')>"
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            "id": self.id,
            "event_type": self.event_type,
            "severity": self.severity,
            "description": self.description,
            "triggered_by": self.triggered_by,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "metadata": self.metadata
        }
