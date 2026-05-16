"""
Auth configuration for app.users:
- define secrets, token lifetimes
- create authentication backends (JWT / cookie / oauth)
- instantiate FastAPIUsers and expose dependencies like current_active_user
- provide get_user_db / get_user_manager glue if needed
"""

import os

SECRET_KEY = os.getenv("SECRET_KEY", "please_change_me")
ACCESS_TOKEN_EXPIRE_SECONDS = int(os.getenv("ACCESS_TOKEN_EXPIRE_SECONDS", "3600"))

# TODO: import and configure fastapi-users here, e.g.:
# from fastapi_users.authentication import JWTStrategy, AuthenticationBackend, CookieTransport
# from fastapi_users import FastAPIUsers
# from app.users.db import get_async_session
# from app.users.models import User
# from app.users.schemas import UserDB, UserCreate, UserRead
#
# def get_jwt_strategy() -> JWTStrategy:
#     return JWTStrategy(secret=SECRET_KEY, lifetime_seconds=ACCESS_TOKEN_EXPIRE_SECONDS)
#
# auth_backend = AuthenticationBackend(name="jwt", transport=..., get_strategy=get_jwt_strategy)
# fastapi_users = FastAPIUsers(user_db, [auth_backend], UserDB, UserCreate, UserRead)
#
# # exports used by main / routers:
# current_active_user = fastapi_users.current_user(active=True)
# get_auth_router = fastapi_users.get_auth_router
