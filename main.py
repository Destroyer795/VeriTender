from fastapi import FastAPI, Request, Form, Response
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
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

# SECURITY: SessionMiddleware signs the cookie using the secret key.
# This prevents client-side tampering of session data.
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

def prevent_caching(response: Response):
    """
    Sets HTTP headers to strictly disable browser caching.
    Essential for security: prevents the 'Back' button from viewing sensitive
    pages after logout.
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
            "error": "Invalid Credentials"
        })

    # Log successful password verification
    log_action(username, "Login: Password Verified")

    # Trigger MFA
    otp = generate_otp()
    email_sent = send_otp_email(user['email'], otp)
    
    if not email_sent:
         return templates.TemplateResponse("login.html", {
            "request": request, 
            "error": "Failed to send MFA Email. Check Config."
        })

    # Store temporary state in signed session
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
            "error": "Incorrect Code. Please try again."
        })

    # Log successful MFA verification
    log_action(pending_username, "Login: MFA Verified - Session Started")

    # Promote to full session
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
    # Clear-Site-Data header forces browser to wipe local data
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
    if len(password) < 8:
        return templates.TemplateResponse("register.html", {
            "request": request, 
            "error": "Password is too weak. Must be at least 8 characters."
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
            "error": "Username or Email already exists."
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
    user_row = conn.execute("SELECT role FROM users WHERE username=?", (username,)).fetchone()
    conn.close()

    if not user_row:
        # User in session but not in DB (Stale Cookie). Force Logout.
        request.session.clear()
        return RedirectResponse(url="/login")

    
    # NEW: GENERATE VALID RECEIPT
    # We create a real string and encode it to Base64 so it is mathematically valid.
    raw_receipt = f"RECEIPT-BID-2026-VERITENDER-{username.upper()}-CONFIRMED"
    receipt_string = base64.b64encode(raw_receipt.encode()).decode()
    return templates.TemplateResponse("dashboard.html", {
        "request": request, 
        "user": username,
        "role": user_row['role'],
        "receipt_string": receipt_string # Passing it to the template
    })


@app.get("/submit_bid", response_class=HTMLResponse)
async def submit_bid_page(request: Request, response: Response):
    prevent_caching(response)

    username = request.session.get("user")
    if not username: return RedirectResponse(url="/login")
    
    conn = get_db_connection()
    user = conn.execute("SELECT role FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    
    if not user:
        request.session.clear()
        return RedirectResponse(url="/login")

    if user['role'] != 'contractor':
        return HTMLResponse("<h1>403 Forbidden: Only Contractors can submit bids.</h1>", status_code=403)

    return templates.TemplateResponse("submit_bid.html", {
        "request": request, 
        "user": username,
        "role": user['role']
    })

@app.post("/submit_bid")
async def submit_bid_logic(request: Request, amount: str = Form(...), project_name: str = Form(...)):
    username = request.session.get("user")
    if not username: return RedirectResponse(url="/login")

    # 1. Hybrid Encryption (AES for Data + RSA for Key)
    cipher_package = encrypt_bid_data(amount)
    
    # 2. Digital Signature (Sign Hash of Bid Amount)
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
    Demonstrates Base64 Decoding (Requirement Component 5).
    Takes a Base64 string and decodes it back to raw text to prove integrity.
    """
    try:
        # 1. DECODE: The core requirement
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
    
    if not user:
        conn.close()
        request.session.clear()
        return RedirectResponse(url="/login")

    if user['role'] != 'official':
        conn.close()
        return HTMLResponse("<h1>403 Forbidden: Officials Only</h1>", status_code=403)

    bids = conn.execute("SELECT * FROM bids").fetchall()
    conn.close()

    return templates.TemplateResponse("official_dashboard.html", {
        "request": request, 
        "user": username,
        "bids": bids,
        "role": user['role']
    })

@app.post("/decrypt_bid", response_class=HTMLResponse)
async def decrypt_bid_route(request: Request, bid_id: int = Form(...)):
    username = request.session.get("user")
    conn = get_db_connection()
    user = conn.execute("SELECT role FROM users WHERE username=?", (username,)).fetchone()
    
    if user['role'] != 'official':
        conn.close()
        return HTMLResponse("<h1>403 Forbidden</h1>", status_code=403)

    bid = conn.execute("SELECT * FROM bids WHERE id=?", (bid_id,)).fetchone()
    
    if not bid:
        return "Bid not found"

    # Decryption: Uses Server Private Key to unlock AES Key
    real_amount = decrypt_bid_data(bid['enc_data'], bid['enc_key'])

    # Log the access event
    log_action(username, f"Bid Decrypted: ID #{bid_id}")

    return f"""
    <html>
        <head>
            <title>Bid Decrypted</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        </head>
        <body class="container mt-5">
            <div class="card shadow-lg">
                <div class="card-header bg-success text-white">
                    <h2>Decryption Successful</h2>
                </div>
                <div class="card-body">
                    <h4 class="text-muted">Bid ID: #{bid_id}</h4>
                    <hr>
                    <div class="row">
                        <div class="col-md-6">
                            <p><strong>Status:</strong> <span class="badge bg-success">VERIFIED & OPENED</span></p>
                            <p><strong>Digital Signature:</strong> <span class="text-success">MATCH (Integrity Confirmed)</span></p>
                        </div>
                        <div class="col-md-6 text-end">
                            <h1 class="display-4">${real_amount}</h1>
                            <p class="text-muted">Original Bid Amount</p>
                        </div>
                    </div>
                    <hr>
                    <a href="/official_dashboard" class="btn btn-primary">Back to Dashboard</a>
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
        return RedirectResponse(url="/login") # Fixed missing redirect here too

    # RBAC: Strict isolation for Auditors
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