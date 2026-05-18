"""JWT (RS256) + opaque refresh token primitives.

Access tokens are short-lived (10 min default) JWTs signed RS256.
Refresh tokens are 32-byte random URL-safe strings. They are opaque to the
client; only the SHA-256 hex is stored server-side in `refresh_sessions`.
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from jose import JWTError, jwt

from app.core.config import get_settings
from app.core.keys import get_private_key, get_public_key

_ALGO = "RS256"


def create_access_token(*, user_id: UUID, role: str, session_id: UUID) -> tuple[str, UUID, datetime]:
    """Issue an access token. Returns (token, jti, expires_at)."""
    settings = get_settings()
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=settings.jwt_access_expire_minutes)
    jti = uuid4()
    payload = {
        "sub": str(user_id),
        "role": role,
        "jti": str(jti),
        "sid": str(session_id),
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
    }
    token = jwt.encode(payload, get_private_key(), algorithm=_ALGO)
    return token, jti, expires_at


def decode_access_token(token: str) -> dict:
    settings = get_settings()
    try:
        return jwt.decode(
            token,
            get_public_key(),
            algorithms=[_ALGO],
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
        )
    except JWTError as e:
        raise ValueError(f"invalid access token: {e}") from e


def generate_refresh_token() -> str:
    """Opaque 256-bit URL-safe random string. Never decoded."""
    return secrets.token_urlsafe(32)


def hash_refresh_token(token: str) -> str:
    """SHA-256 hex of refresh token; what we store + index on."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_invite_token() -> str:
    """Same shape as refresh — opaque random URL-safe, hashed at rest."""
    return secrets.token_urlsafe(32)


def hash_invite_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_csrf_token() -> str:
    """Random token echoed by frontend in X-CSRF-Token; cookie+header double-submit."""
    return secrets.token_urlsafe(24)
