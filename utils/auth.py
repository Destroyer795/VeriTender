import bcrypt

# NIST SP 800-63-2 Password Storage
# Using bcrypt for adaptive hashing with salt (resists brute-force attacks)

def hash_password(password: str):
    """
    Generates secure salt and hashes password with bcrypt (default: 12 rounds).
    Salt prevents rainbow table attacks - identical passwords produce different hashes.
    """
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed, salt

def verify_password(plain_password: str, hashed_password: bytes):
    """
    Verifies password against stored hash.
    bcrypt.checkpw provides constant-time comparison (timing-attack resistance).
    """
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password)