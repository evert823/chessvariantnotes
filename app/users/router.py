from typing import List

from fastapi import APIRouter, Depends
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
