"""HvtSignal — high-value target evidence, decoupled from Vulnerability.

A Joomla admin panel and a Heartbleed CVE used to live in the same table with
the same lifecycle (mistake). This row captures the *judgement* that an asset
is high-value attack territory: panels, login forms, swagger docs, dev portals,
known platforms (jenkins, gitlab, k8s_dashboard).

Composite hvt_score per asset is computed in services/hvt_score.py.
Conditional vuln stages can require `hvt_signal:{type}:score>={n}`.
"""

from __future__ import annotations

import enum
from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import DateTime, Enum, Float, ForeignKey, Integer, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class HvtSignalType(str, enum.Enum):
    admin_panel = "admin_panel"
    login_form = "login_form"
    signup_form = "signup_form"
    upload_form = "upload_form"
    api_doc = "api_doc"            # swagger / openapi / api-docs
    dev_portal = "dev_portal"
    jenkins = "jenkins"
    wordpress = "wordpress"
    gitlab = "gitlab"
    k8s_dashboard = "k8s_dashboard"
    exposed_index = "exposed_index"
    swagger = "swagger"
    graphql = "graphql"
    git_repo = "git_repo"          # exposed .git/
    env_file = "env_file"          # exposed .env
    other = "other"


class HvtSignal(Base):
    __tablename__ = "hvt_signals"
    __table_args__ = (
        UniqueConstraint(
            "target_id", "asset_id", "endpoint_id", "signal_type",
            name="uq_hvt_identity",
        ),
    )

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True, default=uuid4)
    target_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    endpoint_id: Mapped[UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("endpoints.id", ondelete="SET NULL"), nullable=True
    )
    service_id: Mapped[UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("services.id", ondelete="SET NULL"), nullable=True
    )
    signal_type: Mapped[HvtSignalType] = mapped_column(
        Enum(HvtSignalType, name="hvt_signal_type", create_type=False), nullable=False
    )
    score: Mapped[float] = mapped_column(Float, nullable=False, server_default="0.5")
    confidence: Mapped[int] = mapped_column(Integer, nullable=False, server_default="80")
    evidence: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    source_tool: Mapped[str] = mapped_column(String(50), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
