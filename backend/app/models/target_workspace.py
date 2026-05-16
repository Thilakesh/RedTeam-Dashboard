import enum
from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import DateTime, Enum, ForeignKey, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class WorkspaceStatus(str, enum.Enum):
    active = "active"
    archived = "archived"


class TargetWorkspace(Base):
    __tablename__ = "target_workspaces"
    __table_args__ = (
        UniqueConstraint("target_id", "parent_scan_id", name="uq_workspace_target_parent"),
    )

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), index=True, nullable=False)
    target_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("targets.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    parent_scan_id: Mapped[UUID | None] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="SET NULL"),
        nullable=True,
    )
    label: Mapped[str] = mapped_column(String(120), nullable=False)
    status: Mapped[WorkspaceStatus] = mapped_column(
        Enum(WorkspaceStatus, name="workspace_status", create_type=False),
        nullable=False,
        server_default="active",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
