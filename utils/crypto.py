from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
import base64
import hashlib
import os

# PERSISTENT KEY MANAGEMENT
KEY_DIR = "keys"
PRIVATE_KEY_FILE = os.path.join(KEY_DIR, "private.pem")
PUBLIC_KEY_FILE = os.path.join(KEY_DIR, "public.pem")

def load_or_generate_keys():
    """
    Loads RSA keys from files. If they don't exist, generates new ones and saves them.
    This ensures encryption works across server restarts.
    """
    if not os.path.exists(KEY_DIR):
        os.makedirs(KEY_DIR)

    if os.path.exists(PRIVATE_KEY_FILE) and os.path.exists(PUBLIC_KEY_FILE):
        # Load existing keys
        with open(PRIVATE_KEY_FILE, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(PUBLIC_KEY_FILE, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
        print("✅ Loaded existing RSA Keys from disk.")
    else:
        # Generate new keys
        print("⚠️ No keys found. Generating new RSA Keys...")
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        # Save Private Key
        with open(PRIVATE_KEY_FILE, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # Save Public Key
        with open(PUBLIC_KEY_FILE, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
    
    return private_key, public_key

# Initialize Keys ONCE when module loads
SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY = load_or_generate_keys()

# ENCRYPTION LOGIC

def encrypt_bid_data(amount: str):
    """
    Hybrid Encryption:
    1. Generate a random AES Key (Fernet).
    2. Encrypt the Bid Amount using AES.
    3. Encrypt the AES Key using Server's RSA Public Key.
    """
    # 1. AES Encryption (Symmetric)
    aes_key = Fernet.generate_key()
    cipher_suite = Fernet(aes_key)
    encrypted_data = cipher_suite.encrypt(amount.encode())

    # 2. RSA Encryption of the AES Key (Asymmetric)
    encrypted_key = SERVER_PUBLIC_KEY.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return {
        "enc_data": encrypted_data,      # Store as BLOB or Bytes
        "enc_key": encrypted_key         # Store as BLOB or Bytes
    }

def decrypt_bid_data(enc_data: bytes, enc_key: bytes):
    """
    Decryption:
    1. Decrypt AES Key using Server's RSA Private Key.
    2. Decrypt Bid Data using the decrypted AES Key.
    """
    try:
        # 1. Recover AES Key
        aes_key = SERVER_PRIVATE_KEY.decrypt(
            enc_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # 2. Decrypt Data
        cipher_suite = Fernet(aes_key)
        decrypted_amount = cipher_suite.decrypt(enc_data).decode()
        return decrypted_amount

    except Exception as e:
        print(f"Decryption Error: {e}")
        return "[ERROR: Decryption Failed - Integrity Compromised]"

def sign_bid(data: str):
    """
    Creates a Digital Signature of the data (SHA-256 hash signed with Private Key).
    Note: In a real world, User signs with THEIR private key. 
    Here, we simulate signing to prove integrity.
    """
    signature = SERVER_PRIVATE_KEY.sign(
        data.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode() # Return as String for easy DB storage