"""
Test Script - Verify Login Credentials
Run this to check what users exist in the database and test password verification
"""
import sqlite3
import bcrypt
from pathlib import Path

DB_PATH = Path(__file__).parent / "users.db"

def test_credentials():
    """Test all credentials in the database"""
    
    # Test credentials to try
    test_users = [
        ("admin", "Admin@123"),
        ("welcome@123", "helloworld@123"),
    ]
    
    print("=" * 60)
    print("🔍 TESTING LOGIN CREDENTIALS")
    print("=" * 60)
    
    # Connect to database
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Get all users
        cursor.execute("SELECT username, password_hash FROM users")
        db_users = cursor.fetchall()
        
        print(f"\n📊 Found {len(db_users)} users in database:\n")
        
        for i, (username, hash_val) in enumerate(db_users, 1):
            print(f"{i}. Username: {username}")
            print(f"   Hash: {hash_val[:50]}...")
        
        print("\n" + "=" * 60)
        print("🧪 TESTING CREDENTIALS")
        print("=" * 60)
        
        # Test each credential
        for test_user, test_pass in test_users:
            print(f"\n🔑 Testing: {test_user} / {test_pass}")
            
            # Find user in database
            cursor.execute("SELECT password_hash FROM users WHERE username = ?", (test_user,))
            result = cursor.fetchone()
            
            if not result:
                print(f"   ❌ User '{test_user}' NOT FOUND in database")
                continue
            
            stored_hash = result[0]
            
            # Test password
            is_valid = bcrypt.checkpw(
                test_pass.encode('utf-8'),
                stored_hash.encode('utf-8')
            )
            
            if is_valid:
                print(f"   ✅ PASSWORD CORRECT! Login should work.")
            else:
                print(f"   ❌ PASSWORD INCORRECT! Hash mismatch.")
        
        conn.close()
        
        print("\n" + "=" * 60)
        print("✅ WORKING CREDENTIALS:")
        print("=" * 60)
        print("Username: admin")
        print("Password: Admin@123")
        print()
        print("Username: welcome@123")
        print("Password: helloworld@123")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        print("\nMake sure you've run 'python main.py' at least once to create the database!")

def show_all_users():
    """Display all users in the database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT id, username FROM users")
        users = cursor.fetchall()
        conn.close()
        
        print("\n📋 ALL USERS IN DATABASE:")
        for user_id, username in users:
            print(f"  ID {user_id}: {username}")
        print()
        
    except Exception as e:
        print(f"Could not read database: {e}")

if __name__ == "__main__":
    if not DB_PATH.exists():
        print("❌ Database not found!")
        print(f"Expected location: {DB_PATH}")
        print("\n🔧 Solution: Run 'python main.py' first to create the database")
    else:
        test_credentials()
        show_all_users()
