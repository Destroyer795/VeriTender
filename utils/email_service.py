import smtplib
from email.message import EmailMessage
import random
from config import EMAIL_ADDRESS, EMAIL_PASSWORD

# Email-based OTP for Multi-Factor Authentication
# Production alternative: TOTP (e.g., Google Authenticator) or push notifications

def generate_otp():
    """Generates a 6-digit numeric OTP (1 million combinations)."""
    return str(random.randint(100000, 999999))

def send_otp_email(to_email: str, otp: str):
    """
    Sends OTP via Gmail SMTP with TLS encryption.
    Uses SMTP_SSL (port 465) for implicit TLS from connection start.
    """
    msg = EmailMessage()
    msg.set_content(f"""
    Subject: VeriTender Security Code
    
    Your Multi-Factor Authentication (MFA) code is:
    
    {otp}
    
    This code expires in 5 minutes.
    Do not share this with anyone.
    """)
    
    msg['Subject'] = "VeriTender Access Code"
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = to_email

    try:
        # Gmail SMTP with SSL/TLS (port 465)
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)
        return True
    except Exception as e:
        print(f"FAILED to send email: {e}")
        return False