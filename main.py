from fastapi import FastAPI, Request, Form, Depends, HTTPException, status
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse, HTMLResponse
import starlette.status as status
from starlette.middleware.sessions import SessionMiddleware
from sqlite3 import IntegrityError
import uvicorn

# Project Modules
from database import get_db_connection
from utils.email_service import generate_otp, send_otp_email
from utils.auth import verify_password, hash_password
from config import SECRET_KEY

app = FastAPI(title="VeriTender")

# SECURITY: Encrypts session data using the key from config.py
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# AUTHENTICATION ROUTES

@app.get("/")
async def root():
    return RedirectResponse(url="/login")

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login", response_class=HTMLResponse)
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...)
):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()

    if not user or not verify_password(password, user['password_hash']):
        return templates.TemplateResponse("login.html", {
            "request": request, 
            "error": "Invalid Credentials"
        })

    # MFA TRIGGER
    otp = generate_otp()
    email_sent = send_otp_email(user['email'], otp)
    
    if not email_sent:
         return templates.TemplateResponse("login.html", {
            "request": request, 
            "error": "Failed to send MFA Email. Check Config."
        })

    # SECURE FIX: Store in Signed Session (Not plain cookie)
    request.session['pending_username'] = username
    request.session['mfa_code'] = otp 
    
    return RedirectResponse(url="/verify_mfa", status_code=303)

@app.get("/verify_mfa", response_class=HTMLResponse)
async def mfa_page(request: Request):
    if "pending_username" not in request.session:
        return RedirectResponse(url="/login")
        
    return templates.TemplateResponse("otp.html", {"request": request})

@app.post("/verify_mfa")
async def mfa_submit(request: Request, otp: str = Form(...)):
    # Retrieve from secure session
    pending_username = request.session.get("pending_username")
    correct_otp = request.session.get("mfa_code")
    
    if not pending_username or not correct_otp:
        return RedirectResponse(url="/login")
        
    if otp != correct_otp:
        return templates.TemplateResponse("otp.html", {
            "request": request, 
            "error": "Incorrect Code. Please try again."
        })

    # SUCCESS: Promote to Full Session
    request.session.pop("mfa_code", None)
    request.session.pop("pending_username", None)
    request.session["user"] = pending_username
    
    return RedirectResponse(url="/dashboard", status_code=303)

@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login")

# CORE APP ROUTES

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    username = request.session.get("user")
    if not username:
        return RedirectResponse(url="/login")
    
    return templates.TemplateResponse("dashboard.html", {
        "request": request, 
        "user": username
    })

# REGISTRATION ROUTES

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

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

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)