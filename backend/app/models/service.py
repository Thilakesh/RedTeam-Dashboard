from __future__ import annotations

import enum
from datetime import datetime
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class ServiceClassification(str, enum.Enum):
    """Coarse-grained service taxonomy used for conditional vuln-stage routing.

    Computed at recon write-time from service_name + product + port heuristics
    in `services/classify_service.py`. Vuln stages can declare e.g.
    `required_signals=["service.classification:database"]` to fire only on DBs.
    """
    web = "web"
    database = "database"
    messaging = "messaging"
    control_plane = "control_plane"
    file_share = "file_share"
    mail = "mail"
    directory = "directory"
    crypto = "crypto"
    rpc = "rpc"
    monitoring = "monitoring"
    iot = "iot"
    cache = "cache"
    unknown = "unknown"


class Service(Base):
    """First-class service row promoted from Asset(type='service').

    Canonical key: "{host}:{port}/{proto}" — matches Asset.canonical_key for the
    dual-write transition period. Once scan_view.build_port_rows reads from this
    table exclusively, the Asset(type='service') rows can be dropped (migration 0008).
    """

    __tablename__ = "services"
    __table_args__ = (
        UniqueConstraint("target_id", "canonical_key", name="uq_service_identity"),
    )

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True, default=uuid4)
    target_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    proto: Mapped[str] = mapped_column(String(10), nullable=False)
    canonical_key: Mapped[str] = mapped_column(String(300), nullable=False)
    state: Mapped[str] = mapped_column(String(20), nullable=False, server_default="open")
    service_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    product: Mapped[str | None] = mapped_column(String(200), nullable=True)
    version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    banner: Mapped[str | None] = mapped_column(String(500), nullable=True)
    cpes: Mapped[list[str]] = mapped_column(
        ARRAY(sa.Text), nullable=False, server_default="{}"
    )
    tls: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    classification: Mapped[ServiceClassification] = mapped_column(
        Enum(ServiceClassification, name="service_classification", create_type=False),
        nullable=False,
        server_default="unknown",
    )
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
