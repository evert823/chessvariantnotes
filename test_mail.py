import os
import smtplib
from email.message import EmailMessage
from dotenv import load_dotenv

load_dotenv()  # loads .env from project root

HOST = os.getenv("SMTP_HOST")
PORT = int(os.getenv("SMTP_PORT", "587"))
USER = os.getenv("SMTP_USER")
PASS = os.getenv("SMTP_PASS")
TO = "ejkarman@ijfinity.nl"
USE_TLS = os.getenv("SMTP_TLS", "true").lower() in ("1", "true", "yes")

if not all([HOST, PORT, USER, PASS]):
    raise SystemExit("SMTP settings missing in environment (.env)")

msg = EmailMessage()
msg["Subject"] = "Test823"
msg["From"] = os.getenv("SMTP_FROM", USER)
msg["To"] = TO
msg.set_content("SMTP test")

try:
    if USE_TLS:
        with smtplib.SMTP(HOST, PORT, timeout=10) as s:
            s.ehlo()
            s.starttls()
            s.ehlo()
            s.login(USER, PASS)
            s.send_message(msg)
    else:
        with smtplib.SMTP_SSL(HOST, PORT, timeout=10) as s:
            s.login(USER, PASS)
            s.send_message(msg)
    print("sent")
except Exception as e:
    print("send failed:", e)
