from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api import router as api_router
from app.users import router as users_router
from app.users import models as users_models
from app.users.db import init_db

app = FastAPI()

@app.on_event("startup")
async def on_startup():
    await init_db()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/chessvariantnotes/api")
app.include_router(users_router, prefix="/auth")
