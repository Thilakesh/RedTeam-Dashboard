from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import DateTime, ForeignKey, Integer, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class Asset(Base):
    """A deduplicated asset observed under a target.

    `canonical_key` identifies the asset within (target_id, type) — e.g. the FQDN for a
    subdomain or the dotted-quad for an IP. Per-tool details live in `attributes` and grow
    over time as more sources observe the asset.
    """

    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("target_id", "type", "canonical_key", name="uq_asset_identity"),
    )

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True, default=uuid4)
    target_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"), index=True
    )
    type: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    canonical_key: Mapped[str] = mapped_column(String(500), nullable=False)
    attributes: Mapped[dict] = mapped_column(JSONB, default=dict)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AssetObservation(Base):
    __tablename__ = "asset_observations"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True, default=uuid4)
    asset_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), index=True
    )
    scan_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    stage_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scan_stages.id", ondelete="CASCADE")
    )
    source_tool: Mapped[str] = mapped_column(String(80), nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, default=80)
    payload: Mapped[dict] = mapped_column(JSONB, default=dict)
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
