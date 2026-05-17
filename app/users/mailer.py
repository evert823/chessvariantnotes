import os
import smtplib
from email.message import EmailMessage
from typing import Tuple
from dotenv import load_dotenv

# load .env values
load_dotenv()

def _send_smtp(msg: EmailMessage) -> Tuple[bool, str]:
    smtp_host = os.getenv("SMTP_HOST")
    if not smtp_host:
        return False, "no-smtp-configured"

    try:
        smtp_port = int(os.getenv("SMTP_PORT", "587"))
        use_tls = os.getenv("SMTP_TLS", "false").lower() in ("1", "true", "yes")

        if use_tls and smtp_port == 465:
            server = smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=10)
            if os.getenv("SMTP_USER") and os.getenv("SMTP_PASS"):
                server.login(os.getenv("SMTP_USER"), os.getenv("SMTP_PASS"))
        else:
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
            server.ehlo()
            if use_tls:
                server.starttls()
                server.ehlo()
            if os.getenv("SMTP_USER") and os.getenv("SMTP_PASS"):
                server.login(os.getenv("SMTP_USER"), os.getenv("SMTP_PASS"))

        server.send_message(msg)
        server.quit()
        return True, ""
    except Exception as e:
        return False, str(e)

def send_confirmation_email(to_email: str, confirm_url: str, expires_at: str) -> Tuple[bool, str]:
    msg = EmailMessage()
    msg["Subject"] = os.getenv("SMTP_SUBJECT", "Confirm your registration")
    msg["From"] = os.getenv("SMTP_FROM", os.getenv("SMTP_USER", "no-reply@example.com"))
    msg["To"] = to_email
    msg.set_content(
        f"Please confirm your registration by visiting the following link:\n\n{confirm_url}\n\nThis link expires at {expires_at} UTC."
    )
    return _send_smtp(msg)

def send_simple_email(to_email: str, subject: str, body: str) -> Tuple[bool, str]:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = os.getenv("SMTP_FROM", os.getenv("SMTP_USER", "no-reply@example.com"))
    msg["To"] = to_email
    msg.set_content(body)
    return _send_smtp(msg)
