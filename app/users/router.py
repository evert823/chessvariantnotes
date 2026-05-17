from typing import List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy import select, or_
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta
import secrets
import os
import asyncio
from dotenv import load_dotenv
from app.users.security import hash_password

# load .env values
load_dotenv()

from app.users.db import get_async_session
from app.users.models import User, Token
from app.users.schemas import UserRead, RegisterRequest
from app.users.mailer import send_confirmation_email

router = APIRouter()

@router.get("/users", response_model=List[UserRead])
async def list_users(session: AsyncSession = Depends(get_async_session)):
    """
    Return all users (no hashed_password returned because schema omits it).
    Mounted at /auth/users (main.py already includes the users router with prefix "/auth").
    """
    result = await session.execute(select(User))
    users = result.scalars().all()
    return users

@router.get("/me", response_model=UserRead)
async def get_current_user(
    request: Request,
    x_user_id: Optional[str] = Header(None, convert_underscores=False),
    session: AsyncSession = Depends(get_async_session),
):
    """
    PoC auth check:
    - prefer cookie 'user_id' or 'session_user_id'
    - fall back to X-User-Id header (useful for manual testing / localStorage)
    Replace with real JWT/cookie auth later.
    """
    user_id = request.cookies.get("user_id") or request.cookies.get("session_user_id") or x_user_id
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")
    result = await session.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user

@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(
    body: RegisterRequest,
    session: AsyncSession = Depends(get_async_session),
):
    # uniqueness check
    q = await session.execute(
        select(User).where(or_(User.email == body.email, User.username == body.username))
    )
    exists = q.scalar_one_or_none()
    if exists:
        raise HTTPException(status_code=400, detail="email or username already in use")

    # create user (not yet verified)
    user = User(
        email=body.email,
        username=body.username,
        # re-hash client-side hash with a slow, salted algorithm before storing
        hashed_password=hash_password(body.password),
        is_active=True,
        is_verified=False,
    )
    session.add(user)
    await session.flush()  # populate user.id

    # create verification token
    token_str = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(hours=int(os.getenv("REG_TOKEN_HOURS", "24")))
    token = Token(
        user_id=user.id,
        token=token_str,
        token_type="verification",
        expires_at=expires_at,
        used=False,
        revoked=False,
    )
    session.add(token)
    await session.commit()

    # build confirmation URL using SITE_URL from .env
    site_base = os.getenv("SITE_URL", "https://vps1.mcs2web.com")
    confirm_url = f"{site_base}/auth/confirm?token={token_str}"

    # send email in background thread to avoid blocking event loop
    loop = asyncio.get_running_loop()
    sent, err = await loop.run_in_executor(None, send_confirmation_email, body.email, confirm_url, expires_at.isoformat())

    # If SMTP not configured or failed, log/return dev link for testing
    if not sent:
        # for dev: print link to console
        print(f"[DEV] registration confirm link for {body.email}: {confirm_url} (send_error={err})")

    return {
        "status": "created",
        "email_sent": sent,
        "confirm_url_for_dev": None if sent else confirm_url
    }
