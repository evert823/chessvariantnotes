from typing import List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status, Response
from sqlalchemy import select, or_
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta
import secrets
import os
import asyncio
from dotenv import load_dotenv
from app.users.security import hash_password, verify_password

# load .env values
load_dotenv()

from app.users.db import get_async_session
from app.users.models import User, Token
from app.users.schemas import UserRead, RegisterRequest, LoginRequest
from app.users.mailer import send_confirmation_email, send_simple_email

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

@router.get("/me", response_model=Optional[UserRead])
async def get_current_user(
    request: Request,
    session: AsyncSession = Depends(get_async_session),
):
    print(f"{request.cookies.get("user_id")}")
    user_id = request.cookies.get("user_id")
    if not user_id:
        return None
    result = await session.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        return None
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

@router.get("/confirm")
async def confirm_registration(
    token: str,
    session: AsyncSession = Depends(get_async_session),
):
    """
    Confirm registration:
    - validate token (exists, type=verification, not used, not revoked, not expired)
    - ensure target user exists and is not already verified
    - mark token.used = True and user.is_verified = True, commit
    - send completion email
    """
    if not token:
        raise HTTPException(status_code=400, detail="token required")

    result = await session.execute(
        select(Token).where(Token.token == token, Token.token_type == "verification")
    )
    tkn = result.scalar_one_or_none()
    if not tkn:
        raise HTTPException(status_code=404, detail="invalid token")

    # check token state
    if tkn.revoked:
        raise HTTPException(status_code=400, detail="token revoked")
    if tkn.used:
        # idempotent: if already used, respond OK
        return {"status": "already_used"}
    if tkn.expires_at and datetime.utcnow() > tkn.expires_at:
        raise HTTPException(status_code=400, detail="token expired")

    # fetch user
    result = await session.execute(select(User).where(User.id == tkn.user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="user not found")

    if user.is_verified:
        # mark token used anyway to avoid reuse
        tkn.used = True
        session.add(tkn)
        await session.commit()
        return {"status": "already_verified"}

    # perform state changes
    tkn.used = True
    user.is_verified = True
    session.add_all([tkn, user])
    await session.commit()

    # send completion email (background)
    site_base = os.getenv("SITE_URL", "https://vps1.mcs2web.com")
    subject = "Registration confirmed"
    body = f"Your account on {site_base} has been successfully confirmed. You can now login."

    loop = asyncio.get_running_loop()
    sent, err = await loop.run_in_executor(None, send_simple_email, user.email, subject, body)
    if not sent:
        # log dev link or error
        print(f"[DEV] confirmation email send failed for {user.email}: {err}")

    return {"status": "confirmed", "email_sent": sent}

@router.post("/login", response_model=UserRead)
async def login(
    body: LoginRequest,
    response: Response,
    session: AsyncSession = Depends(get_async_session),
):
    """
    Login with username or email + client-side hashed password.
    On success sets a HttpOnly cookie 'user_id' for the session.
    """
    if not body.password:
        # password not provided -> remain logged out
        raise HTTPException(status_code=400, detail="password required")

    result = await session.execute(
        select(User).where(or_(User.email == body.username_or_email, User.username == body.username_or_email))
    )
    user = result.scalar_one_or_none()
    if not user or not user.is_active or not user.is_verified:
        raise HTTPException(status_code=401, detail="invalid credentials")

    # verify: body.password is the client-side hash; server stored a slow hash
    if not verify_password(body.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="invalid credentials")

    # set session cookie (for PoC). In production use secure session tokens / JWTs.
    response.set_cookie(
        key="user_id",
        value=user.id,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
        max_age=3600,  # adjust as needed
    )
    return user

@router.post("/logout")
async def logout(response: Response):
    """
    Clear session cookie.
    """
    response.delete_cookie("user_id", path="/")
    return {"status": "logged_out"}
