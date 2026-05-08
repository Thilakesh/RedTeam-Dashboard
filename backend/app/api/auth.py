from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.security import create_access_token, hash_password, verify_password
from app.models import Organization, Project, User
from app.schemas.auth import LoginRequest, SignupRequest, TokenResponse

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/signup", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def signup(req: SignupRequest, db: AsyncSession = Depends(get_db)) -> TokenResponse:
    existing = await db.scalar(select(User).where(User.email == req.email))
    if existing is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "email already registered")

    org = Organization(name=req.org_name)
    db.add(org)
    await db.flush()

    # every org gets a default project at signup so users can scan immediately
    project = Project(org_id=org.id, name="default")
    db.add(project)

    user = User(
        org_id=org.id,
        email=req.email,
        password_hash=hash_password(req.password),
        role="owner",
    )
    db.add(user)
    await db.commit()

    return TokenResponse(access_token=create_access_token(user.id, user.org_id))


@router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest, db: AsyncSession = Depends(get_db)) -> TokenResponse:
    user = await db.scalar(select(User).where(User.email == req.email))
    if user is None or not verify_password(req.password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
    return TokenResponse(access_token=create_access_token(user.id, user.org_id))
