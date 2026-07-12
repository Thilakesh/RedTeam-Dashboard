"""Password hashing (bcrypt).

JWT issuance/verification lives in app/core/tokens.py (RS256, kept separate
from password hashing so each module has a single responsibility).
"""
from __future__ import annotations

from functools import lru_cache

import bcrypt

# bcrypt has a hard 72-byte input limit; truncate explicitly so long passwords
# don't 500. Acceptable for a recon dashboard — entropy at 72 bytes is plenty.
_BCRYPT_MAX_BYTES = 72


def _truncate(password: str) -> bytes:
    return password.encode("utf-8")[:_BCRYPT_MAX_BYTES]


def hash_password(password: str) -> str:
    return bcrypt.hashpw(_truncate(password), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(_truncate(password), hashed.encode("utf-8"))


@lru_cache
def dummy_hash() -> str:
    """A real bcrypt hash of a fixed placeholder, computed once and cached.

    Login uses this so bcrypt always runs — even when the user doesn't exist
    or has no password set — so a missing-user response takes the same time
    as a wrong-password one instead of leaking user existence via timing.
    """
    return hash_password("not-a-real-password-used-for-timing-only")
