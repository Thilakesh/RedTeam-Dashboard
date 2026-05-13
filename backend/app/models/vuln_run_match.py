from __future__ import annotations

from uuid import UUID

from sqlalchemy import ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class VulnRunMatch(Base):
    """Per-scan join table for vuln diff view.

    state values:
    - "new"              first time this vuln was detected in any scan
    - "seen"             detected again, was already open
    - "fixed_in_this_run" was open but not detected in this scan → auto-transition to fixed
    """

    __tablename__ = "vuln_run_matches"

    scan_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), primary_key=True
    )
    vulnerability_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        primary_key=True,
        index=True,
    )
    state: Mapped[str] = mapped_column(String(30), nullable=False)
