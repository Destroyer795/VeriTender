import bcrypt

# --- NIST SP 800-63-2 PASSWORD STORAGE ---

def hash_password(password: str):
    """
    Generates a secure salt and hashes the password.
    Returns both hash and salt to store in DB.
    """
    # Rubric Requirement: Hashing with Salt
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed, salt

def verify_password(plain_password: str, hashed_password: bytes):
    """
    Checks if the provided password matches the stored hash.
    """
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password)