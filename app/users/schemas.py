from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime

class UserRead(BaseModel):
    id: str
    email: EmailStr
    username: str
    is_active: bool = True
    is_superuser: bool = False
    is_verified: bool = False
    created_at: Optional[datetime]
    last_login_at: Optional[datetime]

    class Config:
        orm_mode = True

class RegisterRequest(BaseModel):
    email: EmailStr
    username: str
    password: str  # client-sent hashed password (as you specified)

class LoginRequest(BaseModel):
    username_or_email: str
    password: str  # client-side hashed password
