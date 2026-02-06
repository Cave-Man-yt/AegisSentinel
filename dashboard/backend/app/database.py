"""
GenAI Sentinel - Database Connection Management
SQLAlchemy setup with connection pooling and session management
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from typing import Generator
from app.config import settings

# Create SQLAlchemy engine with connection pooling
engine = create_engine(
    settings.DATABASE_URL,
    echo=settings.DB_ECHO,
    pool_pre_ping=True,  # Verify connections before using
    pool_size=10,  # Number of connections to keep open
    max_overflow=20,  # Additional connections when pool is exhausted
)

# Session factory
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

# Base class for ORM models
Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """
    Database session dependency for FastAPI
    
    Usage in routes:
        @app.get("/endpoint")
        def my_endpoint(db: Session = Depends(get_db)):
            ...
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """
    Initialize database tables
    Call this on application startup if needed
    """
    Base.metadata.create_all(bind=engine)


def check_db_connection() -> bool:
    """
    Check if database connection is alive
    Returns True if connected, False otherwise
    """
    try:
        db = SessionLocal()
        db.execute("SELECT 1")
        db.close()
        return True
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        return False
