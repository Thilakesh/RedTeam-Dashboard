from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class VulnEvidence(Base):
    """Append-only evidence row for a Vulnerability.

    Every scan that re-detects the same vuln adds a new row here. This gives:
    - Reproducibility: copy the request/response from the latest evidence row
    - Confidence trending: 5 detections across 5 scans = real; 1 = likely FP
    """

    __tablename__ = "vuln_evidence"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True, default=uuid4)
    vulnerability_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scan_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    stage_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scan_stages.id", ondelete="CASCADE"), nullable=False
    )
    source_tool: Mapped[str] = mapped_column(String(80), nullable=False)
    request: Mapped[str | None] = mapped_column(Text, nullable=True)
    response_excerpt: Mapped[str | None] = mapped_column(Text, nullable=True)
    matcher_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    extracted: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    confidence: Mapped[int] = mapped_column(Integer, nullable=False, server_default="80")
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
