from typing import List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status, Response
from sqlalchemy import select, or_, func, update
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta
import secrets
import os
import asyncio
from dotenv import load_dotenv
from app.users.security import hash_password, verify_password
from urllib.parse import quote_plus
from app.users.auth import create_access_token, decode_access_token

# load .env values
load_dotenv()

from app.users.db import get_async_session
from app.users.models import User, Token
from app.users.schemas import UserRead, RegisterRequest, LoginRequest
from app.users.schemas import ResetPasswordRequest1, ResetPasswordRequest2, ChangeUsernameRequest
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
    token = request.cookies.get("access_token")
    if not token:
        return None
    user_id = decode_access_token(token)
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
    username_clean = (body.username or "").strip()
    if not username_clean:
        raise HTTPException(status_code=400, detail="username required")

    # uniqueness check
    q = await session.execute(
        select(User).where(or_(User.email == body.email, func.lower(User.username) == func.lower(username_clean)))
    )
    exists = q.scalar_one_or_none()
    if exists:
        raise HTTPException(status_code=400, detail="email or username already in use")

    # create user (not yet verified)
    user = User(
        email=body.email,
        username=username_clean,
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
        select(User).where(
            or_(
                User.email == body.username_or_email,
                func.lower(User.username) == func.lower(body.username_or_email)
            )
        )
    )
    user = result.scalar_one_or_none()
    if not user or not user.is_active or not user.is_verified:
        raise HTTPException(status_code=401, detail="invalid credentials")

    # verify: body.password is the client-side hash; server stored a slow hash
    if not verify_password(body.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="invalid credentials")

    # record last login time
    user.last_login_at = datetime.utcnow()
    session.add(user)
    await session.commit()

    # create JWT access token and set session cookie (HttpOnly)
    expires_seconds = 3600
    token = create_access_token(userid=user.id, expires_delta=timedelta(seconds=expires_seconds))
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
        max_age=expires_seconds,
    )
    return user

@router.post("/logout")
async def logout(response: Response):
    """
    Clear session cookie.
    """
    response.delete_cookie("access_token", path="/")
    return {"status": "logged_out"}


@router.post("/requestresetpassword")
async def request_reset_password(
    body: ResetPasswordRequest1,
    session: AsyncSession = Depends(get_async_session),
):
    """
    Request password reset:
    - accepts email (ResetPasswordRequest1)
    - ensure email exists
    - create a verification token for password reset
    - set user.is_verified = False (unregistered)
    - send email with reset link containing token + username and mention username in body

    To avoid account enumeration timing differences we always attempt to send an email
    to the provided address. If the email exists we send a reset link; otherwise we
    send a generic notice. The response is identical either way.
    """
    if not body.email:
        raise HTTPException(status_code=400, detail="email required")

    result = await session.execute(select(User).where(User.email == body.email))
    user = result.scalar_one_or_none()

    # If user exists and active -> create token, mark unverified, revoke old tokens
    if user and user.is_active:
        # mark user unregistered (so /resetpassword will accept the flow)
        user.is_verified = False

        # revoke any previous unused password-reset tokens for this user
        await session.execute(
            update(Token)
            .where(Token.user_id == user.id, Token.token_type == "passwordreset", Token.used == False, Token.revoked == False)
            .values(revoked=True)
        )

        # create token (passwordreset type)
        token_str = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(hours=int(os.getenv("REG_TOKEN_HOURS", "24")))
        token = Token(
            user_id=user.id,
            token=token_str,
            token_type="passwordreset",
            expires_at=expires_at,
            used=False,
            revoked=False,
        )
        session.add_all([user, token])
        await session.commit()

        # build reset URL (include token + username)
        site_base = os.getenv("SITE_URL", "https://vps1.mcs2web.com")
        reset_url = f"{site_base}/chessvariantnotes/resetpassword.html?token={quote_plus(token_str)}&username={quote_plus(user.username)}"

        subject = "Password reset request"
        mail_body = (
            f"Hello {user.username},\n\n"
            f"A password reset was requested for your account. Use the link below to reset your password:\n\n"
            f"{reset_url}\n\n"
            f"Username: {user.username}\n\n"
            f"If you did not request this, please ignore this email."
        )

        # send email in background thread
        loop = asyncio.get_running_loop()
        sent, err = await loop.run_in_executor(None, send_simple_email, user.email, subject, mail_body)
        if not sent:
            # dev fallback
            print(f"[DEV] password reset link for {user.email}: {reset_url} (send_error={err})")

        return {"status": "reset_requested", "email_sent": sent}

    # For non-existing or inactive addresses: send a generic notice email to avoid timing-based enumeration
    subject = "Password reset requested"
    generic_body = (
        "Hello,\n\n"
        "A request was received to reset the password for this email address. If you initiated this request, follow the instructions you received. "
        "If you did not request a reset, no action is required.\n\n"
        "If you have an account with us you will receive a reset link. If not, you can ignore this message."
    )

    loop = asyncio.get_running_loop()
    sent, err = await loop.run_in_executor(None, send_simple_email, body.email, subject, generic_body)
    if not sent:
        # dev fallback logging
        print(f"[DEV] generic password reset notice send failed for {body.email}: {err}")

    return {"status": "reset_requested", "email_sent": sent}


@router.post("/resetpassword")
async def reset_password(
    body: ResetPasswordRequest2,
    session: AsyncSession = Depends(get_async_session),
):
    """
    Reset password + confirm account:
    - requires token, username, password (client-side hash)
    - ensure user is unregistered (is_verified == False)
    - validate token (type=verification, not used/revoked/expired, belongs to user)
    - perform additional server-side hash of provided password and store
    - set user.is_verified = True and token.used = True
    """
    if not (body.token and body.username and body.password):
        raise HTTPException(status_code=400, detail="token, username and password required")

    # find user by username to ensure both belong to the same account
    q = await session.execute(
        select(User).where(User.username == body.username)
    )
    user = q.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="user not found")

    # user should be unregistered (not verified) per requirement
    if user.is_verified:
        raise HTTPException(status_code=400, detail="user already verified")

    # load token and validate (ensure it belongs to the user in the DB query)
    result = await session.execute(
        select(Token).where(
            Token.token == body.token,
            Token.token_type == "passwordreset",
            Token.user_id == user.id
        )
    )
    tkn = result.scalar_one_or_none()
    if not tkn:
        raise HTTPException(status_code=404, detail="invalid token")
    # removed explicit tkn.user_id check because query already scoped it
    if tkn.revoked:
        raise HTTPException(status_code=400, detail="token revoked")
    if tkn.used:
        return {"status": "already_used"}
    if tkn.expires_at and datetime.utcnow() > tkn.expires_at:
        raise HTTPException(status_code=400, detail="token expired")
    
    # perform additional server-side hash of the client-side hashed password
    new_hashed = hash_password(body.password)

    # apply changes
    user.hashed_password = new_hashed
    user.is_verified = True
    tkn.used = True
    session.add_all([user, tkn])
    await session.commit()

    # notify user (background)
    site_base = os.getenv("SITE_URL", "https://vps1.mcs2web.com")
    subject = "Account confirmed and password set"
    mail_body = f"Your account on {site_base} has been confirmed and your password updated."

    loop = asyncio.get_running_loop()
    sent, err = await loop.run_in_executor(None, send_simple_email, user.email, subject, mail_body)
    if not sent:
        print(f"[DEV] password reset confirmation email send failed for {user.email}: {err}")

    return {"status": "password_reset", "email_sent": sent}

@router.post("/changeusername")
async def change_username(
    body: ChangeUsernameRequest,
    current_user = Depends(get_current_user),
    session: AsyncSession = Depends(get_async_session),
):
    """
    Change current user's username after verifying current password.
    Mounted at /auth/changeusername.
    """
    if not current_user:
        raise HTTPException(status_code=401, detail="not authenticated")

    # verify provided (client-side hashed) password against stored slow hash
    if not verify_password(body.password, current_user.hashed_password):
        raise HTTPException(status_code=401, detail="invalid credentials")

    new_username_clean = (body.new_username or "").strip()
    if not new_username_clean:
        raise HTTPException(status_code=400, detail="new_username required")

    # check username uniqueness
    q = await session.execute(
        select(User).where(func.lower(User.username) == func.lower(new_username_clean))
    )
    exists = q.scalar_one_or_none()
    if exists and exists.id != current_user.id:
        raise HTTPException(status_code=400, detail="username already in use")

    # apply change
    old_username = current_user.username
    current_user.username = new_username_clean
    session.add(current_user)
    await session.commit()

    # notify user by email (background)
    subject = "Username changed"
    mail_body = (
        f"Hello,\n\n"
        f"Your username has been changed from {old_username} to {new_username_clean}.\n\n"
        f"If you did not request this change, please contact support."
    )
    loop = asyncio.get_running_loop()
    sent, err = await loop.run_in_executor(None, send_simple_email, current_user.email, subject, mail_body)
    if not sent:
        print(f"[DEV] username change email send failed for {current_user.email}: {err}")

    return {"status": "username_changed", "email_sent": sent}
