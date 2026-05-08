from uuid import UUID

from fastapi import Depends, HTTPException, Query, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.security import decode_token
from app.models import User

bearer_scheme = HTTPBearer(auto_error=False)


class CurrentUser:
    def __init__(self, user: User):
        self.id: UUID = user.id
        self.org_id: UUID = user.org_id
        self.email: str = user.email


async def _user_from_token(token: str, db: AsyncSession) -> CurrentUser:
    try:
        payload = decode_token(token)
    except ValueError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token") from None
    user = await db.get(User, UUID(payload["sub"]))
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user not found")
    return CurrentUser(user)


async def get_current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> CurrentUser:
    if creds is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing token")
    return await _user_from_token(creds.credentials, db)


async def get_current_user_sse(
    token: str = Query(..., description="JWT — query-param auth for EventSource"),
    db: AsyncSession = Depends(get_db),
) -> CurrentUser:
    return await _user_from_token(token, db)
