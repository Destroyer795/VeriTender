VeriTender | Secure Government Tender Portal
============================================

VeriTender is a secure web application designed to manage government tender submissions with high standards of confidentiality, integrity, and non-repudiation. It implements core cybersecurity concepts including Hybrid Encryption, Digital Signatures, and Role-Based Access Control (RBAC) to ensure a tamper-proof bidding process.

Key Features
------------

*   **Multi-Factor Authentication (MFA):** Secure login using Password + Email OTP (One Time Password).
    
*   **Role-Based Access Control (RBAC):** Strict separation of duties between Contractors, Officials, and Auditors.
    
*   **Hybrid Encryption:** Bids are encrypted using AES-256 (for data) and RSA-2048 (for key exchange), ensuring only authorized officials can reveal bid amounts.
    
*   **Digital Signatures & Receipts:** Every submission generates a SHA-256 signature and a Base64 receipt to prove data integrity and non-repudiation.
    
*   **Immutable Audit Logs:** All critical actions (login, submission, decryption) are recorded in a read-only log for compliance.
    
*   **Session Security:** Implements anti-caching headers, signed session cookies, and automatic timeouts.
    

Technology Stack
----------------

*   **Backend:** Python 3.10+, FastAPI
    
*   **Database:** SQLite (with normalized schema)
    
*   **Frontend:** HTML5, Jinja2 Templates, Bootstrap 5
    
*   **Cryptography:** cryptography library (Fernet, RSA, SHA-256)
    
*   **Email:** SMTP (Gmail TLS)
    

Installation and Setup
----------------------

### 1\. Clone the Repository

```Bash
git clone https://github.com/yourusername/VeriTender.git
cd veritender
```

### 2\. Create a Virtual Environment

```Bash
# Windows
python -m venv venv
venv\Scripts\activate

# Mac/Linux
python3 -m venv venv
source venv/bin/activate
```

### 3\. Install Dependencies

```Bash
pip install -r requirements.txt
```

### 4\. Configure Environment Variables

Create a .env file in the root directory and add your email credentials for MFA.

```Ini, TOML
EMAIL_USER=your_email@gmail.com
EMAIL_PASS=your_app_password
SECRET_KEY=your_random_secret_string
```

### 5\. Initialize the Database

Run the seed script to create the database and populate it with initial users.

```Bash
python seed.py
```

**Note:** If you need to reset the database (clear all data and start fresh), use:

```Bash
python reset_db.py
```

This will delete the existing database and reinitialize it with default users.

### 6\. Run the Application

```Bash
python main.py
```

Access the application at: `http://127.0.0.1:8000`

User Roles and Workflow
-----------------------

### 1\. Contractor

*   **Responsibilities:** View active tenders and submit sealed bids.
    
*   **Security:** Bids are encrypted client-side before storage. The contractor receives a Base64 digital receipt as proof of submission.
    

### 2\. Government Official

*   **Responsibilities:** Open sealed tenders after the deadline.
    
*   **Security:** Possesses the RSA Private Key required to decrypt the AES keys of the submitted bids. Verifies the digital signature upon decryption.
    

### 3\. System Auditor

*   **Responsibilities:** Monitor system activity for suspicious behavior.
    
*   **Security:** Read-only access to the Audit Logs. Cannot view bid details or submit tenders.
    

Security Architecture
---------------------

1.  **Submission Phase:**
    
    *   Contractor inputs Bid Amount ($X).
        
    *   System generates a random AES Key and encrypts $X.
        
    *   System encrypts the AES Key using the Server's RSA Public Key.
        
    *   System hashes $X (SHA-256) and signs it to create a Digital Signature.
        
    *   Encrypted Data + Encrypted Key + Signature are stored in veritender.db.
        
2.  **Verification Phase:**
    
    *   Official initiates decryption.
        
    *   System uses Server's RSA Private Key to decrypt the AES Key.
        
    *   System uses AES Key to reveal $X.
        
    *   System calculates a fresh hash of $X and compares it with the stored signature.
        
    *   **Result:** Integrity Confirmed (Match) or Warning (Mismatch).
        

Project Structure
-----------------

```Plaintext
VeriTender/
├── keys/                   # RSA Keys (Auto-generated, do not commit)
├── static/                 # Static assets (if any)
├── templates/              # HTML Jinja2 Templates
│   ├── base.html           # Main layout
│   ├── dashboard.html      # Role-based landing page
│   ├── login.html          # Auth pages
│   └── ...
├── utils/
│   ├── auth.py             # Password hashing logic
│   ├── crypto.py           # Encryption & Signing logic
│   ├── email_service.py    # SMTP logic
│   └── logger.py           # Auditing logic
├── database.py             # SQLite connection
├── main.py                 # FastAPI application entry point
├── seed.py                 # Database initialization script
├── reset_db.py             # Database reset utility
└── requirements.txt        # Python dependencies
```
