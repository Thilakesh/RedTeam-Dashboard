from uuid import UUID

from pydantic import BaseModel, EmailStr, Field

from app.schemas.base import StrictRequest


class LoginRequest(StrictRequest):
    email: EmailStr
    password: str


class InviteAcceptRequest(StrictRequest):
    token: str = Field(min_length=10, max_length=200)
    password: str = Field(min_length=8, max_length=128)


class MeResponse(BaseModel):
    id: UUID
    email: EmailStr
    role: str
    org_id: UUID
    features: list[str]


class LoginResponse(BaseModel):
    """Returned on /auth/login + /auth/refresh + /auth/invite/accept.
    Cookies carry the real auth; this body surfaces the CSRF token to JS
    so it can echo it in the X-CSRF-Token header."""

    csrf_token: str
    user: MeResponse
