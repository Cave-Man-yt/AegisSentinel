"""
GenAI Sentinel - Simple Login System + Metrics
FastAPI backend with SQLite, bcrypt, and latency tracking
"""
import sqlite3
import bcrypt
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pathlib import Path

# Initialize FastAPI
app = FastAPI(title="GenAI Sentinel")

# CORS Configuration (allow frontend access)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database path
DB_PATH = Path(__file__).parent / "users.db"


# Pydantic models
class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    success: bool
    message: str = ""


# Database initialization
def init_db():
    """Initialize SQLite database and create users table"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    
    # Check if default users exist
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        # Add default users
        # admin / Admin@123
        admin_hash = bcrypt.hashpw("Admin@123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            ("admin", admin_hash)
        )
        
        # welcome@123 / helloworld@123
        user_hash = bcrypt.hashpw("helloworld@123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            ("welcome@123", user_hash)
        )
        
        conn.commit()
        print("✅ Default users created: admin, welcome@123")
    
    conn.close()


# Password verification
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against bcrypt hash"""
    try:
        return bcrypt.checkpw(
            plain_password.encode('utf-8'),
            hashed_password.encode('utf-8')
        )
    except Exception:
        return False


# Get user from database
def get_user(username: str):
    """Fetch user from SQLite database"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT id, username, password_hash FROM users WHERE username = ?",
        (username,)
    )
    
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return {
            "id": result[0],
            "username": result[1],
            "password_hash": result[2]
        }
    return None


# ============ API ENDPOINTS ============

@app.on_event("startup")
async def startup_event():
    """Initialize database on startup"""
    init_db()
    
    # Initialize latency tracker with some sample data
    from latency_tracker import get_latency_tracker
    tracker = get_latency_tracker()
    
    print("🚀 GenAI Sentinel System Started")
    print(f"📁 Database: {DB_PATH}")
    print(f"📊 Latency Tracker: Initialized (window={tracker.window_size})")


@app.get("/")
async def root():
    """API root endpoint"""
    return {
        "message": "GenAI Sentinel API",
        "status": "online",
        "endpoints": {
            "login": "/login",
            "metrics": "/metrics/latency",
            "scan": "/metrics/scan"
        }
    }


@app.post("/login", response_model=LoginResponse)
async def login(credentials: LoginRequest):
    """
    Simple login endpoint
    
    Returns:
        - success: false with error message if credentials invalid
        - success: true if login successful
    """
    # Fetch user from database
    user = get_user(credentials.username)
    
    # Check if user exists
    if not user:
        return LoginResponse(
            success=False,
            message="Invalid username or password"
        )
    
    # Verify password
    if not verify_password(credentials.password, user["password_hash"]):
        return LoginResponse(
            success=False,
            message="Invalid username or password"
        )
    
    # Login successful
    return LoginResponse(
        success=True,
        message="Login successful"
    )


# Include metrics routes
from metrics_routes import router as metrics_router
app.include_router(metrics_router)

# Include security metrics routes
from security_metrics_routes import router as security_router
app.include_router(security_router)


# Run with: uvicorn main:app --reload --port 8000
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
