import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import (
    create_token,
    create_user,
    get_user_by_email,
    verify_password,
)
from app.compile import CompileError, compile_python
from app.config import settings
from app.database import SessionLocal, get_db
from app.schemas import CompileRequest, CompileResponse, Token, UserLogin, UserRegister

logger = logging.getLogger(__name__)


async def seed_dev_account() -> None:
    """Create a default dev account if it does not already exist.

    Password is read from settings.DEV_SEED_PASSWORD (env: DEV_SEED_PASSWORD).
    This account must NEVER be seeded in a production environment.
    """
    logger.warning(
        "DEBUG mode is ON — seeding dev account dev@example.com. "
        "Ensure DEBUG=False and this account does not exist in production."
    )
    async with SessionLocal() as db:
        existing = await get_user_by_email(db, "dev@example.com")
        if existing is None:
            await create_user(db, "dev@example.com", settings.DEV_SEED_PASSWORD)
            logger.info("Debug mode: created dev account dev@example.com")
        else:
            logger.info("Debug mode: dev account dev@example.com already exists, skipping")


@asynccontextmanager
async def lifespan(app: FastAPI):  # noqa: ARG001
    """Application lifespan: run startup logic, then yield, then shutdown."""
    if settings.DEBUG:
        await seed_dev_account()
    yield


app = FastAPI(title="Assembly Tutorial API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/auth/register", response_model=Token, status_code=status.HTTP_201_CREATED)
async def register(body: UserRegister, db: AsyncSession = Depends(get_db)):
    existing = await get_user_by_email(db, body.email)
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")
    user = await create_user(db, body.email, body.password)
    return Token(access_token=create_token(str(user.id)))


@app.post("/auth/login", response_model=Token)
async def login(body: UserLogin, db: AsyncSession = Depends(get_db)):
    user = await get_user_by_email(db, body.email)
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return Token(access_token=create_token(str(user.id)))


@app.post("/compile", response_model=CompileResponse)
async def compile_code(body: CompileRequest):
    try:
        result = await compile_python(body.code)
    except CompileError as e:
        logger.warning("Compile error: %s", e)
        raise HTTPException(status_code=422, detail=str(e))
    return result
