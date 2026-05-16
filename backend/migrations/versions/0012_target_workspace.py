"""target workspaces + investigation tasks + investigation findings

Revision ID: 0012
Revises: 0011
Create Date: 2026-05-16

Adds the Target Workspace feature: an analyst-driven, per-asset investigation
environment that sits alongside Scan/VulnScan but is NOT a scan kind.

Tables:
- target_workspaces: long-lived analyst container per (target, parent_recon_scan).
  Unique on (target_id, parent_scan_id) — re-clicking "Target Investigation"
  on the same recon scan returns the existing workspace.
- investigation_tasks: per-click record (one tool on one asset).
- investigation_findings: tool-specific normalized signals (admin_panel,
  weak_cipher, etc) — lighter-weight than Vulnerability rows.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0012"
down_revision: Union[str, None] = "0011"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    workspace_status = postgresql.ENUM(
        "active", "archived",
        name="workspace_status",
        create_type=False,
    )
    workspace_status.create(op.get_bind(), checkfirst=True)

    task_status = postgresql.ENUM(
        "queued", "running", "completed", "failed", "cancelled",
        name="investigation_task_status",
        create_type=False,
    )
    task_status.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "target_workspaces",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "target_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("targets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "parent_scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("label", sa.String(120), nullable=False),
        sa.Column("status", workspace_status, nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("target_id", "parent_scan_id", name="uq_workspace_target_parent"),
    )
    op.create_index("ix_target_workspaces_org_id", "target_workspaces", ["org_id"])
    op.create_index("ix_target_workspaces_target_id", "target_workspaces", ["target_id"])

    op.create_table(
        "investigation_tasks",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "workspace_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("target_workspaces.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "asset_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("tool", sa.String(40), nullable=False),
        sa.Column("status", task_status, nullable=False, server_default="queued"),
        sa.Column("progress_pct", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("params", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("raw_output", sa.Text(), nullable=True),
        sa.Column("error", sa.String(2000), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_investigation_tasks_workspace_status",
        "investigation_tasks",
        ["workspace_id", "status"],
    )
    op.create_index("ix_investigation_tasks_asset_id", "investigation_tasks", ["asset_id"])

    op.create_table(
        "investigation_findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "task_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("investigation_tasks.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "asset_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.String(60), nullable=False),
        sa.Column("severity", sa.String(10), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("evidence", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_investigation_findings_task_id", "investigation_findings", ["task_id"])
    op.create_index(
        "ix_investigation_findings_asset_kind",
        "investigation_findings",
        ["asset_id", "kind"],
    )


def downgrade() -> None:
    op.drop_table("investigation_findings")
    op.drop_table("investigation_tasks")
    op.drop_table("target_workspaces")
    op.execute("DROP TYPE IF EXISTS investigation_task_status")
    op.execute("DROP TYPE IF EXISTS workspace_status")
