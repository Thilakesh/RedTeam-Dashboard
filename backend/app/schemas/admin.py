from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: EmailStr
    role: str
    is_active: bool
    created_by: UUID | None
    created_at: datetime
    has_pending_invite: bool = False


class UserCreateRequest(BaseModel):
    email: EmailStr
    role: str = Field(pattern="^(admin|analyst)$", default="analyst")


class UserCreateResponse(BaseModel):
    user: UserOut
    invite_token: str
    invite_url: str


class UserPatchRequest(BaseModel):
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
    new_password: str | None = Field(default=None, min_length=8, max_length=128)
    current_password: str | None = None


class SystemSettingsOut(BaseModel):
    bbot_timeout: int
    jwt_access_expire_minutes: int
    jwt_refresh_expire_days: int
    rl_login_per_15min: int
    rl_refresh_per_min: int


class SystemSettingsPatchRequest(BaseModel):
    """Only mutable knobs surfaced for now; everything else is env-controlled."""

    bbot_timeout: int | None = Field(default=None, ge=60, le=14400)
    rl_login_per_15min: int | None = Field(default=None, ge=1, le=1000)
    rl_refresh_per_min: int | None = Field(default=None, ge=1, le=1000)
