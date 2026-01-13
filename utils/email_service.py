import smtplib
from email.message import EmailMessage
import random
from config import EMAIL_ADDRESS, EMAIL_PASSWORD

def generate_otp():
    """Generates a 6-digit numeric OTP."""
    return str(random.randint(100000, 999999))

def send_otp_email(to_email: str, otp: str):
    """
    Sends the OTP to the user's email using Gmail SMTP.
    Returns True if successful, False otherwise.
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
        # Standard Gmail SMTP Configuration
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)
        return True
    except Exception as e:
        print(f"FAILED to send email: {e}")
        return False