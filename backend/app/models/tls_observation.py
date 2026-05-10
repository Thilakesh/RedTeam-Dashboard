"""TlsObservation — first-class TLS posture row for a service.

Each httpx/nmap/testssl probe of a TLS-bearing service appends a row.
Drives the TLS UI tab (cert expiry, weak ciphers, deprecated protocols, grade).

Distinct from Vulnerability: TLS *observation* is recon-tier (we observe what's
there); TLS *vulnerability* (Heartbleed/POODLE/etc.) is vuln-tier (testssl
scoring → Vulnerability rows). They reference the same service from different
angles.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class TlsObservation(Base):
    __tablename__ = "tls_observations"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True, default=uuid4)
    service_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("services.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scan_id: Mapped[UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True
    )
    cert_subject: Mapped[str | None] = mapped_column(String(500), nullable=True)
    cert_issuer: Mapped[str | None] = mapped_column(String(500), nullable=True)
    cert_not_before: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cert_not_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cert_san: Mapped[list[str]] = mapped_column(
        ARRAY(sa.Text), nullable=False, server_default="{}"
    )
    protocols: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    weak_ciphers: Mapped[list[str]] = mapped_column(
        ARRAY(sa.Text), nullable=False, server_default="{}"
    )
    grade: Mapped[str | None] = mapped_column(String(5), nullable=True)
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
