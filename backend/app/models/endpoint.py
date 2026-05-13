"""Endpoint — first-class HTTP route discovered by katana / ffuf / swagger spec.

Endpoints are tenant-scoped via target_id (mirrors the asset graph pattern).
A single Endpoint is dedup'd by (target_id, url, method) so re-discovery
across scans updates last_seen and observes status_code drift via
EndpointObservation rows.

Boundary rule: vuln stages WRITE to this table (katana, ffuf, swagger_discoverer);
recon stages NEVER do. A URL is not part of the recon "map" — it's the result of
walking the surface, which is offensive analysis.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class Endpoint(Base):
    __tablename__ = "endpoints"
    __table_args__ = (
        UniqueConstraint("target_id", "url", "method", name="uq_endpoint_identity"),
    )

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True, default=uuid4)
    target_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    service_id: Mapped[UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("services.id", ondelete="SET NULL"), nullable=True
    )
    url: Mapped[str] = mapped_column(String(2000), nullable=False)
    path: Mapped[str] = mapped_column(String(2000), nullable=False, index=True)
    method: Mapped[str] = mapped_column(String(10), nullable=False, server_default="GET")
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    content_type: Mapped[str | None] = mapped_column(String(200), nullable=True)
    content_length: Mapped[int | None] = mapped_column(Integer, nullable=True)
    title: Mapped[str | None] = mapped_column(String(500), nullable=True)
    is_login: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    is_signup: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    is_upload: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    is_api: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    is_admin: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    source_tool: Mapped[str] = mapped_column(String(50), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
