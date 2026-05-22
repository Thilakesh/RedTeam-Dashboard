"""operations console — standalone manual operations

Revision ID: 0018
Revises: 0017
Create Date: 2026-05-21

Adds the standalone Operations Console: analyst-driven manual scans against a
hand-typed domain/IP, with NO recon-asset/workspace linkage. Fully isolated from
the investigation_tasks / Assets feature.

Tables:
- operations: one manually-launched scan (one tool, one typed target). Owned by
  org_id (tenant) + created_by (user). Status is a plain VARCHAR(16) — no Postgres
  ENUM (avoids the create_type gotcha).
- operation_findings: per-operation normalized signals (same shape as
  investigation_findings) so the existing per-tool result components render them.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0018"
down_revision: Union[str, None] = "0017"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "operations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target", sa.String(255), nullable=False),
        sa.Column("target_type", sa.String(16), nullable=False),
        sa.Column("tool", sa.String(40), nullable=False),
        sa.Column("profile", sa.String(50), nullable=True),
        sa.Column("protocol", sa.String(8), nullable=True),
        sa.Column("custom_args", sa.Text(), nullable=True),
        sa.Column("generated_command", sa.Text(), nullable=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="queued"),
        sa.Column("progress_pct", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("raw_output", sa.Text(), nullable=True),
        sa.Column("error", sa.String(2000), nullable=True),
        sa.Column(
            "created_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_operations_org_id", "operations", ["org_id"])

    op.create_table(
        "operation_findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "operation_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("operations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.String(60), nullable=False),
        sa.Column("severity", sa.String(10), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("evidence", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index(
        "ix_operation_findings_operation_id", "operation_findings", ["operation_id"]
    )


def downgrade() -> None:
    op.drop_table("operation_findings")
    op.drop_table("operations")
