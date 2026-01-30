import sqlite3
from datetime import datetime

# SQLite database for development (production would use PostgreSQL with connection pooling)
DB_NAME = "veritender.db"

def get_db_connection():
    """
    Creates a connection to the SQLite database.
    row_factory allows accessing columns by name (e.g., row['username']).
    """
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """
    Initializes the database tables.
    Uses constraints at database level for defense in depth.
    """
    conn = get_db_connection()
    c = conn.cursor()
    
    # TABLE 1: USERS
    # Stores credentials and roles with salt for secure hashing
    # CHECK constraint enforces valid role values at database level
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash BLOB NOT NULL,
            salt BLOB NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('contractor', 'official', 'auditor'))
        )
    ''')
    
    # TABLE 2: BIDS (The Vault)
    # Schema separates enc_data and enc_key for hybrid encryption
    # Officials can see bids exist without decrypting until authorized
    c.execute('''
        CREATE TABLE IF NOT EXISTS bids (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            enc_data TEXT NOT NULL,       -- AES Encrypted Bid Amount
            enc_key TEXT NOT NULL,        -- RSA Encrypted AES Key
            signature TEXT NOT NULL,      -- Digital Signature (PSS)
            status TEXT DEFAULT 'SEALED', -- SEALED / OPENED
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    # TABLE 3: AUDIT LOGS
    # Implements RBAC - Auditors have read-only access to this table
    # No foreign key to preserve logs even if user accounts are deleted (compliance)
    c.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event TEXT NOT NULL,
            username TEXT NOT NULL,  -- Denormalized for persistence
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()
    print(f"Database '{DB_NAME}' initialized successfully.")

if __name__ == "__main__":
    init_db()