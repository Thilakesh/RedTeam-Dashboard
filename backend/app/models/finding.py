from __future__ import annotations

import enum
from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import DateTime, Enum, Float, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class FindingSeverity(str, enum.Enum):
    HIGH = "HIGH"
    MED = "MED"
    LOW = "LOW"
    INFO = "INFO"


class Finding(Base):
    """One risk-prioritization row per (scan, asset). Written by RiskPrioritizerStage.

    This is NOT an Asset — it lives in findings, not assets/asset_observations.
    The ENUM type 'finding_severity' is created explicitly in the migration
    (see CLAUDE.md ENUM gotcha — do not use sa.Enum with create_type=False in columns).
    """

    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("scan_id", "asset_id", name="uq_finding_scan_asset"),
        UniqueConstraint("scan_id", "priority_rank", name="uq_finding_scan_rank"),
    )

    # Tenant scoping: findings are scoped through scan_id → scans.org_id.
    # The API layer uses _ensure_scan_visible() which checks Scan.org_id == user.org_id
    # before any findings query. org_id is intentionally not denormalized here — findings
    # are never queried without a known scan_id, so the join cost is negligible.

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True, default=uuid4)
    scan_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=True
    )
    # MIGRATION REQUIRED PATTERN — do NOT let alembic autogenerate handle this ENUM.
    # The migration must manually create the type before the table:
    #   finding_severity = postgresql.ENUM("HIGH","MED","LOW","INFO",
    #       name="finding_severity", create_type=False)
    #   finding_severity.create(op.get_bind(), checkfirst=True)
    # See migrations/versions/0001_initial.py and CLAUDE.md for the working pattern.
    severity: Mapped[FindingSeverity] = mapped_column(
        Enum(FindingSeverity, name="finding_severity", create_type=False), nullable=False
    )
    priority_rank: Mapped[int] = mapped_column(Integer, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    signals: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    recommended_action: Mapped[str] = mapped_column(Text, nullable=False)
    # Intended values: "llm" (written by RiskPrioritizerStage via OpenRouter),
    # "fallback" (future: rule-based scorer if LLM unavailable).
    source: Mapped[str] = mapped_column(String(20), nullable=False, default="llm")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
