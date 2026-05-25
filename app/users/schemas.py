from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime

class UserRead(BaseModel):
    id: str
    email: EmailStr
    username: str
    is_active: bool = True
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

class ChangeUsernameRequest(BaseModel):
    new_username: str
    password: str  # client-side hashed password

class ResetPasswordRequest1(BaseModel):
    email: EmailStr

class ResetPasswordRequest2(BaseModel):
    token: str
    username: str
    password: str  # client-sent hashed password (as you specified)

class DeleteAccountRequest(BaseModel):
    email: EmailStr
    token: str

