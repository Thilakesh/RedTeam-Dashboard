"""EndpointObservation — append-only per-scan observation of an endpoint.

Mirrors AssetObservation: each scan that touches an endpoint adds a fresh row
capturing transient state (status_code, response_size, content_type, headers).
This is what powers the Diff tab's endpoint regressions ("returned 200 last
scan, 404 this scan").
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import DateTime, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class EndpointObservation(Base):
    __tablename__ = "endpoint_observations"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True, default=uuid4)
    endpoint_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("endpoints.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scan_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    stage_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scan_stages.id", ondelete="CASCADE"), nullable=False
    )
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    response_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    content_type: Mapped[str | None] = mapped_column(String(200), nullable=True)
    response_headers: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
