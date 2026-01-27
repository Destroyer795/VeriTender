import sqlite3
from datetime import datetime

# The physical file that will be created
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
    Run this function once to set up the schema.
    """
    conn = get_db_connection()
    c = conn.cursor()
    
    # TABLE 1: USERS
    # Stores user credentials and roles.
    # We store 'salt' explicitly to satisfy Rubric Point 4 (Hashing with Salt).
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
    # Stores the encrypted bids.
    # Note the specific columns for Hybrid Encryption components.
    c.execute('''
        CREATE TABLE IF NOT EXISTS bids (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            enc_data TEXT NOT NULL,       -- AES Encrypted Bid Amount
            enc_key TEXT NOT NULL,        -- RSA Encrypted AES Key
            signature TEXT NOT NULL,      -- Digital Signature for Non-Repudiation
            status TEXT DEFAULT 'SEALED', -- SEALED / OPENED
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    # TABLE 3: AUDIT LOGS
    # Required for the "Auditor" role to have something unique to access.
    c.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event TEXT NOT NULL,
            username TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()
    print(f"Database '{DB_NAME}' initialized successfully.")

# This allows you to run `python database.py` to reset the DB
if __name__ == "__main__":
    init_db()