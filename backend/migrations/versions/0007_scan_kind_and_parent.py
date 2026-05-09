"""add scan kind, parent_scan_id, intrusive; add CRITICAL to finding_severity

Revision ID: 0007
Revises: 0006
Create Date: 2026-05-09

Changes:
  - scans.kind: ENUM scan_kind ('recon' | 'vuln_analysis'), backfill existing rows as 'recon'
  - scans.parent_scan_id: self-referential FK (vuln scans point to their parent recon scan)
  - scans.intrusive: boolean opt-in for aggressive vuln stages
  - finding_severity ENUM: add 'CRITICAL' value
  - Partial unique index: prevents two concurrent vuln scans per target
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0007"
down_revision: Union[str, None] = "0006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── scan_kind ENUM ────────────────────────────────────────────────────────
    scan_kind = postgresql.ENUM(
        "recon", "vuln_analysis",
        name="scan_kind",
        create_type=False,
    )
    scan_kind.create(op.get_bind(), checkfirst=True)

    # ── add columns to scans ──────────────────────────────────────────────────
    op.add_column(
        "scans",
        sa.Column("kind", scan_kind, nullable=False, server_default="recon"),
    )
    op.add_column(
        "scans",
        sa.Column(
            "parent_scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.add_column(
        "scans",
        sa.Column("intrusive", sa.Boolean(), nullable=False, server_default="false"),
    )

    # Backfill: all existing scans are recon scans.
    op.execute("UPDATE scans SET kind = 'recon' WHERE kind IS NULL")

    # Partial unique index: only one queued/running vuln_analysis scan per target.
    op.execute(
        """
        CREATE UNIQUE INDEX uq_vuln_scan_active_per_target
        ON scans (target_id)
        WHERE kind = 'vuln_analysis' AND status IN ('queued', 'running')
        """
    )

    # ── CRITICAL to finding_severity ──────────────────────────────────────────
    # ALTER TYPE ADD VALUE must run outside a transaction in PostgreSQL.
    with op.get_context().autocommit_block():
        op.execute(
            "ALTER TYPE finding_severity ADD VALUE IF NOT EXISTS 'CRITICAL' BEFORE 'HIGH'"
        )


def downgrade() -> None:
    # Cannot remove ENUM values in PostgreSQL — manual intervention required for CRITICAL.
    op.execute("DROP INDEX IF EXISTS uq_vuln_scan_active_per_target")
    op.drop_column("scans", "intrusive")
    op.drop_column("scans", "parent_scan_id")
    op.drop_column("scans", "kind")
    op.execute("DROP TYPE IF EXISTS scan_kind")
