"""add vulnerability analysis tables

Revision ID: 0006
Revises: 0005
Create Date: 2026-05-09

Adds:
  - vulnerabilities: per-target deduped weakness rows with CVE/CVSS/EPSS/KEV and status lifecycle
  - vuln_evidence: append-only evidence per detection (request/response/matcher)
  - vuln_run_matches: per-scan diff table (new/seen/fixed_in_this_run)

ENUM types vuln_severity and vuln_status are created explicitly (CLAUDE.md pattern).
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0006"
down_revision: Union[str, None] = "0005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── ENUMs (must be created before tables that reference them) ─────────────
    vuln_severity = postgresql.ENUM(
        "CRITICAL", "HIGH", "MED", "LOW", "INFO",
        name="vuln_severity",
        create_type=False,
    )
    vuln_severity.create(op.get_bind(), checkfirst=True)

    vuln_status = postgresql.ENUM(
        "open", "triaged", "false_positive", "fixed", "wont_fix", "reopened",
        name="vuln_status",
        create_type=False,
    )
    vuln_status.create(op.get_bind(), checkfirst=True)

    # ── vulnerabilities ───────────────────────────────────────────────────────
    op.create_table(
        "vulnerabilities",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "target_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("targets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "asset_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "service_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("services.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "technology_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("technologies.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("canonical_key", sa.String(500), nullable=False),
        sa.Column("template_id", sa.String(300), nullable=True),
        sa.Column("cve_ids", postgresql.ARRAY(sa.Text()), nullable=False, server_default="{}"),
        sa.Column("cwe_ids", postgresql.ARRAY(sa.Text()), nullable=False, server_default="{}"),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("severity", vuln_severity, nullable=False),
        sa.Column("cvss_v3", sa.Float(), nullable=True),
        sa.Column("cvss_vector", sa.String(200), nullable=True),
        sa.Column("epss", sa.Float(), nullable=True),
        sa.Column("kev", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column("status", vuln_status, nullable=False, server_default="open"),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_verified_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("target_id", "canonical_key", name="uq_vuln_identity"),
    )
    op.create_index("ix_vulnerabilities_target_id", "vulnerabilities", ["target_id"])

    # ── vuln_evidence ─────────────────────────────────────────────────────────
    op.create_table(
        "vuln_evidence",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "vulnerability_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "stage_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scan_stages.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("source_tool", sa.String(80), nullable=False),
        sa.Column("request", sa.Text(), nullable=True),
        sa.Column("response_excerpt", sa.Text(), nullable=True),
        sa.Column("matcher_name", sa.String(200), nullable=True),
        sa.Column("extracted", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("confidence", sa.Integer(), nullable=False, server_default="80"),
        sa.Column("observed_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_vuln_evidence_vulnerability_id", "vuln_evidence", ["vulnerability_id"])
    op.create_index("ix_vuln_evidence_scan_id", "vuln_evidence", ["scan_id"])

    # ── vuln_run_matches ──────────────────────────────────────────────────────
    op.create_table(
        "vuln_run_matches",
        sa.Column(
            "scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "vulnerability_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("state", sa.String(30), nullable=False),
    )
    op.create_index("ix_vuln_run_matches_vulnerability_id", "vuln_run_matches", ["vulnerability_id"])


def downgrade() -> None:
    op.drop_table("vuln_run_matches")
    op.drop_table("vuln_evidence")
    op.drop_table("vulnerabilities")
    op.execute("DROP TYPE IF EXISTS vuln_status")
    op.execute("DROP TYPE IF EXISTS vuln_severity")
