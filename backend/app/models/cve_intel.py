"""CveIntel — daily-refreshed EPSS / KEV cache.

Vuln stages MUST NOT call out to live feeds (CI gate enforced). They read from
this table. workers/feeds_refresher.py (M-Vuln-7) is the only writer.

Indexed by cve_id (PK). Joined on Vulnerability.cve_ids[] in the correlator
to enrich risk_score / kev / epss columns.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class CveIntel(Base):
    __tablename__ = "cve_intel"

    cve_id: Mapped[str] = mapped_column(String(30), primary_key=True)
    epss: Mapped[float | None] = mapped_column(Float, nullable=True)
    kev: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    kev_added_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ransomware_use: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    refreshed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
