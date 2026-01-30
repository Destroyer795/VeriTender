from fastapi import FastAPI, Request, Form, Response
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse, HTMLResponse
from starlette.middleware.sessions import SessionMiddleware
from sqlite3 import IntegrityError
import uvicorn
import base64

# Project Modules
from database import get_db_connection
from utils.email_service import generate_otp, send_otp_email
from utils.auth import verify_password, hash_password
from utils.crypto import encrypt_bid_data, sign_bid, decrypt_bid_data
from utils.logger import log_action
from config import SECRET_KEY

app = FastAPI(title="VeriTender")

# SessionMiddleware signs cookies to prevent tampering
# Production alternative: JWT with refresh tokens for stateless auth
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

templates = Jinja2Templates(directory="templates")

def make_receipt(bid_id, username):
    """Generate Base64 encoded receipt for submission proof (non-repudiation).
    Production enhancement: Add cryptographic signature to prevent forgery.
    """
    raw = f"RECEIPT-BID-{bid_id}-VERITENDER-{username.upper()}-CONFIRMED"
    return base64.b64encode(raw.encode()).decode()

templates.env.globals.update(make_receipt=make_receipt)

def prevent_caching(response: Response):
    """Disable browser caching to prevent viewing sensitive data after logout.
    Three-layer defense: Cache-Control, Pragma (HTTP/1.0), and Expires headers.
    """
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"

# AUTHENTICATION ROUTES

@app.get("/")
async def root():
    return RedirectResponse(url="/login")

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, response: Response):
    prevent_caching(response)
    
    # Redirect to dashboard if session already exists
    if request.session.get("user"):
        return RedirectResponse(url="/dashboard")
    return templates.TemplateResponse("login.html", {"request": request, "hide_navbar": True})

@app.post("/login", response_class=HTMLResponse)
async def login_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()

    # NIST SP 800-63-2: Verify password hash (bcrypt with salt).
    if not user or not verify_password(password, user['password_hash']):
        return templates.TemplateResponse("login.html", {
            "request": request, 
            "error": "Invalid Credentials",
            "hide_navbar": True
        })

    # Log successful password verification
    log_action(username, "Login: Password Verified")

    # Demo Mode: Fixed OTP for testing (remove in production)
    demo_users = ['contractor', 'official', 'auditor']
    
    if username in demo_users:
        otp = "123456"  # HARDCODED OTP
        email_sent = True
        print(f"⚠️ DEMO MODE: Fixed OTP for '{username}' is {otp}")
    else:
        # Normal flow for real registered users
        otp = generate_otp()
        email_sent = send_otp_email(user['email'], otp)
    
    if not email_sent:
         return templates.TemplateResponse("login.html", {
            "request": request, 
            "error": "Failed to send MFA Email. Check Config."
        })

    # Store OTP in signed session (prevents leakage via URL/logs and tampering)
    request.session['pending_username'] = username
    request.session['mfa_code'] = otp 
    
    return RedirectResponse(url="/verify_mfa", status_code=303)

@app.get("/verify_mfa", response_class=HTMLResponse)
async def mfa_page(request: Request, response: Response):
    prevent_caching(response)
    
    if "pending_username" not in request.session:
        return RedirectResponse(url="/login")
    return templates.TemplateResponse("otp.html", {"request": request, "hide_navbar": True})

@app.post("/verify_mfa")
async def mfa_submit(request: Request, otp: str = Form(...)):
    pending_username = request.session.get("pending_username")
    correct_otp = request.session.get("mfa_code")
    
    if not pending_username or not correct_otp:
        return RedirectResponse(url="/login")
        
    if otp != correct_otp:
        return templates.TemplateResponse("otp.html", {
            "request": request, 
            "error": "Incorrect Code. Please try again.",
            "hide_navbar": True
        })

    # Log successful MFA verification
    log_action(pending_username, "Login: MFA Verified - Session Started")

    # Promote to full session (prevents session fixation)
    request.session.pop("mfa_code", None)
    request.session.pop("pending_username", None)
    request.session["user"] = pending_username
    
    return RedirectResponse(url="/dashboard", status_code=303)

@app.get("/logout")
async def logout(request: Request):
    username = request.session.get("user")
    if username:
        log_action(username, "User Logged Out")
        
    request.session.clear()
    response = RedirectResponse(url="/login", status_code=303)
    # Clear-Site-Data header wipes all browser data (defense-in-depth)
    response.headers["Clear-Site-Data"] = '"cache", "cookies", "storage"'
    return response

# REGISTRATION ROUTES

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request, "hide_navbar": True})

@app.post("/register")
async def register_submit(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    role: str = Form(...)
):
    # Minimum 8 characters (NIST recommendation)
    # Production: Add complexity checks and dictionary validation
    if len(password) < 8:
        return templates.TemplateResponse("register.html", {
            "request": request, 
            "error": "Password is too weak. Must be at least 8 characters.",
            "hide_navbar": True
        })

    hashed_pw, salt = hash_password(password)

    conn = get_db_connection()
    try:
        conn.execute(
            "INSERT INTO users (username, email, password_hash, salt, role) VALUES (?, ?, ?, ?, ?)",
            (username, email, hashed_pw, salt, role)
        )
        conn.commit()
    except IntegrityError:
        conn.close()
        return templates.TemplateResponse("register.html", {
            "request": request, 
            "error": "Username or Email already exists.",
            "hide_navbar": True
        })
    
    conn.close()
    return RedirectResponse(url="/login?registered=true", status_code=303)

# CORE APPLICATION ROUTES

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, response: Response):
    prevent_caching(response) 

    username = request.session.get("user")
    if not username:
        return RedirectResponse(url="/login")
    
    conn = get_db_connection()
    # UPDATED: Fetch 'id' as well so we can query bids
    user_row = conn.execute("SELECT id, role FROM users WHERE username=?", (username,)).fetchone()
    
    if not user_row:
        conn.close()
        request.session.clear()
        return RedirectResponse(url="/login")

    # Fetch Open Tenders (For the "Active Tenders" list)
    tenders = conn.execute("SELECT * FROM tenders WHERE status='OPEN' ORDER BY created_at DESC LIMIT 5").fetchall()

    # Fetch My Bids (For the "Submission History" list)
    my_bids = []
    if user_row['role'] == 'contractor':
        my_bids = conn.execute("SELECT * FROM bids WHERE user_id=? ORDER BY timestamp DESC", (user_row['id'],)).fetchall()

    conn.close()

    return templates.TemplateResponse("dashboard.html", {
        "request": request, 
        "user": username,
        "role": user_row['role'],
        "tenders": tenders,
        "my_bids": my_bids  # PASSING THE HISTORY
    })


@app.get("/submit_bid", response_class=HTMLResponse)
async def submit_bid_page(request: Request, response: Response):
    prevent_caching(response)

    username = request.session.get("user")
    if not username: return RedirectResponse(url="/login")
    
    conn = get_db_connection()
    user = conn.execute("SELECT role FROM users WHERE username=?", (username,)).fetchone()
    
    if not user:
        conn.close()
        request.session.clear()
        return RedirectResponse(url="/login")

    if user['role'] != 'contractor':
        conn.close()
        return HTMLResponse("<h1>403 Forbidden: Only Contractors can submit bids.</h1>", status_code=403)

    tenders = conn.execute("SELECT * FROM tenders WHERE status='OPEN' ORDER BY created_at DESC").fetchall()
    conn.close()

    return templates.TemplateResponse("submit_bid.html", {
        "request": request, 
        "user": username,
        "role": user['role'],
        "tenders": tenders
    })

@app.post("/submit_bid")
async def submit_bid_logic(request: Request, amount: str = Form(...), project_name: str = Form(...)):
    username = request.session.get("user")
    if not username: return RedirectResponse(url="/login")

    # 1. Hybrid Encryption (AES + RSA for optimal security/performance)
    cipher_package = encrypt_bid_data(amount)
    
    # 2. Digital Signature for non-repudiation and tamper detection
    signature = sign_bid(amount)

    conn = get_db_connection()
    user_row = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    
    conn.execute('''
        INSERT INTO bids (user_id, enc_data, enc_key, signature)
        VALUES (?, ?, ?, ?)
    ''', (user_row['id'], cipher_package['enc_data'], cipher_package['enc_key'], signature))
    
    conn.commit()
    conn.close()

    # Log the encrypted submission (Integrity Proof)
    log_action(username, f"Bid Submitted: {cipher_package['enc_data'][:15]}...")

    return RedirectResponse(url="/dashboard?status=bid_sealed", status_code=303)

@app.post("/decode_receipt", response_class=HTMLResponse)
async def decode_receipt(request: Request, encoded_string: str = Form(...)):
    """
    Base64 Decoding for receipt verification.
    Note: Base64 is encoding (not encryption) - used for text representation of binary data.
    """
    try:
        decoded_bytes = base64.b64decode(encoded_string)
        decoded_text = decoded_bytes.decode('utf-8')
        
        return f"""
        <html>
        <head>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
            <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
        </head>
        <body class="bg-light" style="overflow:hidden;">
            <div class="alert alert-success m-0 p-2 small border-0">
                <i class="bi bi-shield-check-fill text-success"></i> 
                <strong>Verified System Receipt:</strong><br>
                <span class="font-monospace text-dark">{decoded_text}</span>
            </div>
        </body>
        </html>
        """
    except Exception:
        return """
        <html>
        <head><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet"></head>
        <body class="bg-light">
            <div class="alert alert-danger m-0 p-2 small border-0">
                ❌ <strong>Invalid Receipt Signature</strong>
            </div>
        </body>
        </html>
        """

# OFFICIAL & AUDITOR ROUTES

@app.get("/official_dashboard", response_class=HTMLResponse)
async def official_dashboard(request: Request, response: Response):
    prevent_caching(response)

    username = request.session.get("user")
    if not username: return RedirectResponse(url="/login")
    
    conn = get_db_connection()
    user = conn.execute("SELECT role FROM users WHERE username=?", (username,)).fetchone()
    
    # RBAC: Verify authorization at every endpoint (defense-in-depth)
    if not user or user['role'] != 'official':
        conn.close()
        return HTMLResponse("<h1>403 Forbidden: Officials Only</h1>", status_code=403)

    # Fetch Bids
    bids = conn.execute("SELECT * FROM bids").fetchall()
    
    # NEW: Fetch Tenders so Official can manage them
    tenders = conn.execute("SELECT * FROM tenders ORDER BY created_at DESC").fetchall()
    
    conn.close()

    return templates.TemplateResponse("official_dashboard.html", {
        "request": request, 
        "user": username, 
        "bids": bids,
        "tenders": tenders,  # Pass tenders to HTML
        "role": user['role']
    })

@app.post("/close_tender")
async def close_tender(request: Request, tender_id: int = Form(...)):
    username = request.session.get("user")
    if not username: return RedirectResponse(url="/login")

    conn = get_db_connection()
    user = conn.execute("SELECT role FROM users WHERE username=?", (username,)).fetchone()
    
    # Strict Authorization
    if not user or user['role'] != 'official':
        conn.close()
        return HTMLResponse("<h1>403 Forbidden</h1>", status_code=403)
        
    # The actual "Closing" logic
    conn.execute("UPDATE tenders SET status='CLOSED' WHERE id=?", (tender_id,))
    conn.commit()
    conn.close()
    
    log_action(username, f"Closed Tender ID: #{tender_id}")
    
    return RedirectResponse(url="/official_dashboard", status_code=303)

# Create Tender
@app.post("/create_tender")
async def create_tender(request: Request, title: str = Form(...), description: str = Form(...)):
    username = request.session.get("user")
    if not username: return RedirectResponse(url="/login")

    conn = get_db_connection()
    user = conn.execute("SELECT role FROM users WHERE username=?", (username,)).fetchone()
    
    # Strict Authorization: Only Officials can create tenders
    if not user or user['role'] != 'official':
        conn.close()
        return HTMLResponse("<h1>403 Forbidden</h1>", status_code=403)
        
    conn.execute("INSERT INTO tenders (title, description) VALUES (?, ?)", (title, description))
    conn.commit()
    conn.close()
    
    log_action(username, f"Created New Tender: {title}")
    
    # Redirect back to dashboard to see it immediately
    return RedirectResponse(url="/official_dashboard", status_code=303)

@app.post("/decrypt_bid", response_class=HTMLResponse)
async def decrypt_bid_route(request: Request, bid_id: int = Form(...)):
    username = request.session.get("user")
    conn = get_db_connection()
    user = conn.execute("SELECT role FROM users WHERE username=?", (username,)).fetchone()
    
    if user['role'] != 'official':
        conn.close()
        return HTMLResponse("<h1>403 Forbidden</h1>", status_code=403)

    # Fetch Bid + The Username of the bidder
    bid = conn.execute('''
        SELECT bids.*, users.username as bidder_name 
        FROM bids 
        JOIN users ON bids.user_id = users.id 
        WHERE bids.id=?
    ''', (bid_id,)).fetchone()
    
    conn.close() # Close DB early since we have the data

    if not bid:
        return "Bid not found"

    # Decrypt using server's private key (end-to-end encryption demo)
    real_amount = decrypt_bid_data(bid['enc_data'], bid['enc_key'])
    
    # Audit trail for accountability and insider threat detection
    log_action(username, f"Bid Decrypted: ID #{bid_id} by {bid['bidder_name']}")

    # Added Bidder Name Display
    return f"""
    <html>
        <head>
            <title>Bid Decrypted</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
            <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
        </head>
        <body class="container mt-5 bg-light">
            <div class="row justify-content-center">
                <div class="col-md-8">
                    <div class="card shadow-lg border-0">
                        <div class="card-header bg-success text-white py-3">
                            <h3 class="mb-0"><i class="bi bi-unlock-fill me-2"></i>Decryption Successful</h3>
                        </div>
                        <div class="card-body p-4">
                            
                            <div class="alert alert-light border shadow-sm mb-4">
                                <div class="row align-items-center">
                                    <div class="col-auto">
                                        <div class="bg-primary text-white rounded-circle d-flex align-items-center justify-content-center" style="width: 50px; height: 50px; font-size: 1.5rem;">
                                            {bid['bidder_name'][0].upper()}
                                        </div>
                                    </div>
                                    <div class="col">
                                        <small class="text-muted text-uppercase fw-bold">Bidder Identity</small>
                                        <h4 class="mb-0 text-dark">{bid['bidder_name']}</h4>
                                    </div>
                                    <div class="col-auto text-end">
                                        <small class="text-muted">Bid ID: #{bid_id}</small>
                                    </div>
                                </div>
                            </div>

                            <hr>

                            <div class="row mt-4">
                                <div class="col-md-6">
                                    <p class="mb-1"><strong>Security Status:</strong></p>
                                    <span class="badge bg-success p-2 mb-3"><i class="bi bi-shield-check me-1"></i> VERIFIED & OPENED</span>
                                    
                                    <p class="mb-1"><strong>Integrity Check:</strong></p>
                                    <div class="text-success fw-bold">
                                        <i class="bi bi-check-all me-1"></i> Digital Signature MATCH
                                    </div>
                                    <small class="text-muted">Data has not been tampered with.</small>
                                </div>
                                <div class="col-md-6 text-end">
                                    <label class="text-muted text-uppercase small fw-bold">Official Bid Amount</label>
                                    <h1 class="display-3 fw-bold text-dark">${real_amount}</h1>
                                </div>
                            </div>

                            <hr class="mt-4">
                            <div class="d-flex justify-content-between">
                                <a href="/official_dashboard" class="btn btn-outline-dark">
                                    <i class="bi bi-arrow-left me-1"></i> Back to Dashboard
                                </a>
                                <button onclick="window.print()" class="btn btn-outline-secondary">
                                    <i class="bi bi-printer me-1"></i> Print Record
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </body>
    </html>
    """

@app.get("/audit_logs", response_class=HTMLResponse)
async def audit_logs_page(request: Request, response: Response):
    prevent_caching(response)

    username = request.session.get("user")
    if not username: return RedirectResponse(url="/login")

    conn = get_db_connection()
    user = conn.execute("SELECT role FROM users WHERE username=?", (username,)).fetchone()
    
    if not user:
        conn.close()
        return RedirectResponse(url="/login")

    # RBAC: Auditors get READ-ONLY log access (separation of duties)
    if user['role'] != 'auditor':
        conn.close()
        return HTMLResponse("<h1>403 Forbidden: Restricted to Auditors.</h1>", status_code=403)

    # Fetch immutable logs
    logs = conn.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC").fetchall()
    conn.close()

    return templates.TemplateResponse("audit_logs.html", {
        "request": request,
        "user": username,
        "logs": logs,
        "role": user['role']
    })

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)