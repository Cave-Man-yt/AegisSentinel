"""
Simple credential tester - Create a working user from scratch
"""
import bcrypt

def create_password_hash(password):
    """Generate bcrypt hash for a password"""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(password, hash_str):
    """Verify a password against its hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hash_str.encode('utf-8'))

# Test credentials
print("=" * 60)
print("CREATING FRESH PASSWORD HASHES")
print("=" * 60)

credentials = [
    ("admin", "Admin@123"),
    ("welcome@123", "helloworld@123"),
]

for username, password in credentials:
    # Generate new hash
    new_hash = create_password_hash(password)
    
    print(f"\nUsername: {username}")
    print(f"Password: {password}")
    print(f"Hash: {new_hash}")
    
    # Verify it works
    if verify_password(password, new_hash):
        print("✅ Hash verification: SUCCESS")
    else:
        print("❌ Hash verification: FAILED")

print("\n" + "=" * 60)
print("SQL INSERT STATEMENTS")
print("=" * 60)

for username, password in credentials:
    hash_val = create_password_hash(password)
    print(f"\nINSERT INTO users (username, password_hash) VALUES ('{username}', '{hash_val}');")

print("\n" + "=" * 60)
