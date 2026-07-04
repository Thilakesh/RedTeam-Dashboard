from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: EmailStr
    first_name: str | None = None
    last_name: str | None = None
    role: str
    is_active: bool
    is_super_admin: bool = False
    created_by: UUID | None
    created_at: datetime
    has_pending_invite: bool = False


class UserCreateRequest(BaseModel):
    email: EmailStr
    first_name: str | None = Field(default=None, max_length=80)
    last_name: str | None = Field(default=None, max_length=80)
    role: str = Field(pattern="^(admin|analyst)$", default="analyst")


class UserCreateResponse(BaseModel):
    user: UserOut
    invite_token: str
    invite_url: str


class UserPatchRequest(BaseModel):
    first_name: str | None = Field(default=None, max_length=80)
    last_name: str | None = Field(default=None, max_length=80)
    role: str | None = Field(default=None, pattern="^(admin|analyst)$")
    is_active: bool | None = None


class FeatureRow(BaseModel):
    feature_name: str
    enabled: bool


class FeatureSetRequest(BaseModel):
    enabled: bool


class SessionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    user_id: UUID
    user_email: EmailStr | None = None
    device_label: str | None
    ip_address: str | None
    user_agent: str | None
    expires_at: datetime
    revoked: bool
    revoked_reason: str | None
    last_used_at: datetime | None
    created_at: datetime


class AuditOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    actor_user_id: UUID | None
    actor_ip: str | None
    action: str
    target_type: str | None
    target_id: UUID | None
    meta: dict
    created_at: datetime


class ProfileUpdateRequest(BaseModel):
    email: EmailStr | None = None
    first_name: str | None = Field(default=None, max_length=80)
    last_name: str | None = Field(default=None, max_length=80)
    new_password: str | None = Field(default=None, min_length=8, max_length=128)
    current_password: str | None = None


class SystemSettingsOut(BaseModel):
    bbot_timeout: int
    jwt_access_expire_minutes: int
    jwt_refresh_expire_days: int


class SystemSettingsPatchRequest(BaseModel):
    """Only mutable knobs surfaced for now; everything else is env-controlled."""

    bbot_timeout: int | None = Field(default=None, ge=60, le=14400)


class OpenRouterSettingsOut(BaseModel):
    """Never includes the raw API key — only whether one is set + a last-4 hint."""

    api_key_set: bool
    api_key_hint: str | None = None
    default_model: str


class OpenRouterSettingsUpdateRequest(BaseModel):
    api_key: str | None = Field(default=None, max_length=300)
    default_model: str | None = Field(default=None, max_length=120)


class OpenRouterTestRequest(BaseModel):
    api_key: str | None = Field(default=None, max_length=300)
    default_model: str | None = Field(default=None, max_length=120)


class OpenRouterTestResponse(BaseModel):
    status: Literal["connected", "invalid_key", "connection_failed"]
    detail: str | None = None
