from dotenv import load_dotenv
import os
import secrets
from datetime import datetime, timedelta
import jwt
import uuid
from typing import Optional

load_dotenv()

# Secret used to sign JWTs. In production set JWT_SECRET_KEY in your environment.
SECRET_KEY = os.getenv("JWT_SECRET_KEY") or secrets.token_urlsafe(48)

# Signing algorithm for JWTs (HMAC SHA-256 by default)
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

def create_access_token(userid: str, expires_delta: timedelta):
    now = datetime.utcnow()
    exp = now + expires_delta
    payload = {
        "sub": userid,
        "iat": now,
        "exp": exp,
        "jti": uuid.uuid4().hex,
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    # PyJWT may return bytes in older versions; ensure a str is returned.
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token

# add this helper to return full payload (used for session jti validation)
def decode_token_payload(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None
    return payload
