"""add findings and ai_usage tables

Revision ID: c358f6fe0d08
Revises: 0002
Create Date: 2026-05-07 04:55:30.215210

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = 'c358f6fe0d08'
down_revision: Union[str, None] = '0002'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # CLAUDE.md ENUM pattern: single postgresql.ENUM instance, create_type=False,
    # explicit .create() call, same instance referenced from the column.
    finding_severity = postgresql.ENUM(
        "HIGH", "MED", "LOW", "INFO",
        name="finding_severity",
        create_type=False,
    )
    finding_severity.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=True),
        sa.Column("severity", finding_severity, nullable=False),
        sa.Column("priority_rank", sa.Integer(), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("signals", postgresql.JSONB(), nullable=False,
                  server_default=sa.text("'[]'::jsonb")),
        sa.Column("recommended_action", sa.Text(), nullable=False),
        sa.Column("source", sa.String(20), nullable=False, server_default="llm"),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()")),
        sa.UniqueConstraint("scan_id", "asset_id", name="uq_finding_scan_asset"),
        sa.UniqueConstraint("scan_id", "priority_rank", name="uq_finding_scan_rank"),
    )
    op.create_index("ix_findings_scan_rank", "findings", ["scan_id", "priority_rank"])
    op.create_index("ix_findings_scan_severity", "findings", ["scan_id", "severity"])

    op.create_table(
        "ai_usage",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("model", sa.String(100), nullable=False),
        sa.Column("prompt_tokens", sa.Integer(), nullable=True),
        sa.Column("completion_tokens", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()")),
    )
    op.create_index("ix_ai_usage_scan_id", "ai_usage", ["scan_id"])


def downgrade() -> None:
    op.drop_table("ai_usage")
    op.drop_index("ix_findings_scan_severity", table_name="findings")
    op.drop_index("ix_findings_scan_rank", table_name="findings")
    op.drop_table("findings")
    postgresql.ENUM(name="finding_severity", create_type=False).drop(
        op.get_bind(), checkfirst=True
    )
