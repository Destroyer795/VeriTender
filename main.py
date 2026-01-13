from fastapi import FastAPI, Request, Form, Depends, HTTPException, status
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse, HTMLResponse
import starlette.status as status

# Import your database and security modules
from database import get_db_connection
from utils.auth import verify_password

app = FastAPI(title="VeriTender")

# Setup Templates and Static files
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# --- ROUTES ---

@app.get("/")
async def root():
    return RedirectResponse(url="/login")

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Renders the login form."""
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login", response_class=HTMLResponse)
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...)
):
    """
    1. Checks if user exists in SQLite.
    2. Verifies password hash using bcrypt.
    3. If valid, redirects to MFA page (Phase 2).
    """
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()

    # --- SECURITY CHECK ---
    # NIST Requirement: Don't reveal if it was the username or password that failed.
    if not user or not verify_password(password, user['password_hash']):
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid Credentials"
        })

    # If password is correct, we will eventually send the Email OTP here.
    # For now, let's just confirm it works.
    return f"Password Accepted for user: {user['role']}. Next Step: Send Email MFA."

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)