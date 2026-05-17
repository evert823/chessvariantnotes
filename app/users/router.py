from typing import List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.users.db import get_async_session
from app.users.models import User
from app.users.schemas import UserRead

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
