from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
import base64
import os

# Persistent RSA Key Management
# Keys are stored on disk to survive server restarts (production: use HSM or Azure Key Vault)
KEY_DIR = "keys"
PRIVATE_KEY_FILE = os.path.join(KEY_DIR, "private.pem")
PUBLIC_KEY_FILE = os.path.join(KEY_DIR, "public.pem")

def load_or_generate_keys():
    """
    Loads RSA keys from files. If they don't exist, generates new ones and saves them.
    Persistent keys are required so bids encrypted with one key can be decrypted later.
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
        # Generate new 2048-bit RSA keys (government standard)
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

# Initialize RSA Key Pair ONCE when module loads
# SERVER_PRIVATE_KEY: RSA private key (used for decryption and signing)
# SERVER_PUBLIC_KEY: RSA public key (used for encrypting AES keys)
SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY = load_or_generate_keys()

# Encryption and Decryption Functions

def encrypt_bid_data(amount: str):
    """
    Hybrid Encryption for optimal security and performance:
    1. Generate random AES symmetric key
    2. Encrypt bid amount with AES key (fast symmetric encryption)
    3. Encrypt AES key with RSA public key (secure key exchange)
    """
    # Step 1 & 2: AES Symmetric Encryption
    # Generate one-time AES key and encrypt the bid amount
    aes_key = Fernet.generate_key()  # Random 256-bit AES key
    cipher_suite = Fernet(aes_key)
    encrypted_data = cipher_suite.encrypt(amount.encode())  # Bid encrypted with AES

    # Step 3: RSA Asymmetric Encryption
    # Encrypt the AES key using SERVER's RSA PUBLIC KEY
    # Only the matching RSA PRIVATE KEY can decrypt this
    encrypted_key = SERVER_PUBLIC_KEY.encrypt(
        aes_key,  # The AES key itself becomes the data to encrypt
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return {
        "enc_data": encrypted_data,  # Bid amount encrypted with AES key
        "enc_key": encrypted_key     # AES key encrypted with RSA public key
    }

def decrypt_bid_data(enc_data: bytes, enc_key: bytes):
    """
    Hybrid Decryption (reverse of encryption):
    1. Decrypt AES key using RSA PRIVATE key (only officials have access)
    2. Decrypt bid amount using recovered AES key
    """
    try:
        # Step 1: RSA Asymmetric Decryption
        # Decrypt the wrapped AES key using SERVER's RSA PRIVATE KEY
        aes_key = SERVER_PRIVATE_KEY.decrypt(
            enc_key,  # The encrypted AES key
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Step 2: AES Symmetric Decryption
        # Use the recovered AES key to decrypt the actual bid amount
        cipher_suite = Fernet(aes_key)
        decrypted_amount = cipher_suite.decrypt(enc_data).decode()
        return decrypted_amount

    except Exception as e:
        print(f"Decryption Error: {e}")
        return "[ERROR: Decryption Failed - Integrity Compromised]"

def sign_bid(data: str):
    """
    Creates digital signature using RSA PRIVATE KEY for non-repudiation.
    Signs the bid data - can be verified later using RSA PUBLIC KEY.
    """
    signature = SERVER_PRIVATE_KEY.sign(  # Sign with RSA private key
        data.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH  # Max randomness for PSS
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()  # Convert to text for DB storage