"""
GenAI Sentinel - Add User Script
Utility to add a new user with bcrypt-hashed password
"""
import sys
import os

# Add parent directory to path to import app modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.security import hash_password

def generate_user_hash(password: str):
    """Generate bcrypt hash for a password"""
    hashed = hash_password(password)
    print(f"Bcrypt hash for password: {hashed}")
    return hashed

def create_user_sql(username: str, password: str, role: str = 'user', email: str = None, full_name: str = None):
    """Generate SQL INSERT statement for a new user"""
    password_hash = hash_password(password)
    
    email = email or f"{username}@genai-sentinel.local"
    full_name = full_name or username.capitalize()
    
    sql = f"""
-- Insert user: {username} (password: {password})
INSERT INTO users (username, password_hash, role, email, full_name) 
VALUES (
    '{username}',
    '{password_hash}',
    '{role}',
    '{email}',
    '{full_name}'
);
"""
    print(sql)
    return sql

if __name__ == "__main__":
    # Generate hash for the custom user
    print("=" * 60)
    print("GenAI Sentinel - User Creation Utility")
    print("=" * 60)
    
    # Example: Add user welcome@123 with password helloworld@123
    username = "welcome@123"
    password = "helloworld@123"
    
    print(f"\nGenerating SQL for user: {username}")
    print(f"Password: {password}")
    print("-" * 60)
    
    create_user_sql(
        username=username,
        password=password,
        role='user',
        email='welcome@genai-sentinel.local',
        full_name='Welcome User'
    )
    
    print("\n" + "=" * 60)
    print("Copy the SQL above and run it in your PostgreSQL database")
    print("=" * 60)
