"""endpoints + endpoint_observations + hvt_signals + tls_observations + cve_intel

Revision ID: 0008
Revises: 0007
Create Date: 2026-05-11

M-Vuln-5 schema. New tables:
  - endpoints: first-class HTTP routes (replaces JSONB-trapped katana output)
  - endpoint_observations: append-only per-scan endpoint state
  - hvt_signals: high-value target classification, decoupled from Vulnerability
  - tls_observations: TLS posture rows for services
  - cve_intel: daily-refreshed EPSS / KEV cache

Backfill: parse existing vuln_evidence.extracted->'endpoints' JSONB into the
endpoints table. Idempotent (re-runnable).

ENUM types created explicitly (CLAUDE.md pattern). Each new table is target_id
CASCADE for tenant safety.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0008"
down_revision: Union[str, None] = "0007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── ENUM: hvt_signal_type ─────────────────────────────────────────────────
    hvt_signal_type = postgresql.ENUM(
        "admin_panel", "login_form", "signup_form", "upload_form",
        "api_doc", "dev_portal", "jenkins", "wordpress", "gitlab",
        "k8s_dashboard", "exposed_index", "swagger", "graphql",
        "git_repo", "env_file", "other",
        name="hvt_signal_type",
        create_type=False,
    )
    hvt_signal_type.create(op.get_bind(), checkfirst=True)

    # ── endpoints ─────────────────────────────────────────────────────────────
    op.create_table(
        "endpoints",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "target_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column(
            "asset_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column(
            "service_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("services.id", ondelete="SET NULL"), nullable=True,
        ),
        sa.Column("url", sa.String(2000), nullable=False),
        sa.Column("path", sa.String(2000), nullable=False),
        sa.Column("method", sa.String(10), nullable=False, server_default="GET"),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("content_type", sa.String(200), nullable=True),
        sa.Column("content_length", sa.Integer(), nullable=True),
        sa.Column("title", sa.String(500), nullable=True),
        sa.Column("is_login", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("is_signup", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("is_upload", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("is_api", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("is_admin", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("source_tool", sa.String(50), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("target_id", "url", "method", name="uq_endpoint_identity"),
    )
    op.create_index("ix_endpoints_target_id", "endpoints", ["target_id"])
    op.create_index("ix_endpoints_path", "endpoints", ["path"])

    # ── endpoint_observations ─────────────────────────────────────────────────
    op.create_table(
        "endpoint_observations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "endpoint_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column(
            "scan_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column(
            "stage_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scan_stages.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("response_size", sa.Integer(), nullable=True),
        sa.Column("content_type", sa.String(200), nullable=True),
        sa.Column("response_headers", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("observed_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_endpoint_obs_endpoint_id", "endpoint_observations", ["endpoint_id"])
    op.create_index("ix_endpoint_obs_scan_id", "endpoint_observations", ["scan_id"])

    # ── hvt_signals ───────────────────────────────────────────────────────────
    op.create_table(
        "hvt_signals",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "target_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column(
            "asset_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column(
            "endpoint_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("endpoints.id", ondelete="SET NULL"), nullable=True,
        ),
        sa.Column(
            "service_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("services.id", ondelete="SET NULL"), nullable=True,
        ),
        sa.Column("signal_type", hvt_signal_type, nullable=False),
        sa.Column("score", sa.Float(), nullable=False, server_default="0.5"),
        sa.Column("confidence", sa.Integer(), nullable=False, server_default="80"),
        sa.Column("evidence", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("source_tool", sa.String(50), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint(
            "target_id", "asset_id", "endpoint_id", "signal_type",
            name="uq_hvt_identity",
        ),
    )
    op.create_index("ix_hvt_signals_target_id", "hvt_signals", ["target_id"])

    # ── tls_observations ──────────────────────────────────────────────────────
    op.create_table(
        "tls_observations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "service_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("services.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column(
            "target_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column(
            "scan_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="SET NULL"), nullable=True,
        ),
        sa.Column("cert_subject", sa.String(500), nullable=True),
        sa.Column("cert_issuer", sa.String(500), nullable=True),
        sa.Column("cert_not_before", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cert_not_after", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "cert_san", postgresql.ARRAY(sa.Text()),
            nullable=False, server_default="{}",
        ),
        sa.Column("protocols", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column(
            "weak_ciphers", postgresql.ARRAY(sa.Text()),
            nullable=False, server_default="{}",
        ),
        sa.Column("grade", sa.String(5), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_tls_obs_service_id", "tls_observations", ["service_id"])
    op.create_index("ix_tls_obs_target_id", "tls_observations", ["target_id"])

    # ── cve_intel ─────────────────────────────────────────────────────────────
    op.create_table(
        "cve_intel",
        sa.Column("cve_id", sa.String(30), primary_key=True),
        sa.Column("epss", sa.Float(), nullable=True),
        sa.Column("kev", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("kev_added_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ransomware_use", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("refreshed_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── Backfill: parse vuln_evidence.extracted->'endpoints' JSONB into endpoints
    # M-Vuln-3 katana wrote a single VulnRecord per asset with endpoints in
    # evidence.extracted. We move those into first-class rows. Idempotent via
    # ON CONFLICT against uq_endpoint_identity.
    op.execute(
        r"""
        INSERT INTO endpoints (
            id, target_id, asset_id, service_id, url, path, method,
            source_tool, first_seen, last_seen
        )
        SELECT
            gen_random_uuid(),
            v.target_id,
            v.asset_id,
            NULL,
            ep_url,
            COALESCE(
                NULLIF(regexp_replace(ep_url, '^https?://[^/]+', ''), ''),
                '/'
            ),
            'GET',
            'katana',
            v.first_seen,
            v.last_seen
        FROM vulnerabilities v
        JOIN vuln_evidence ve ON ve.vulnerability_id = v.id
        CROSS JOIN LATERAL jsonb_array_elements_text(
            COALESCE(ve.extracted->'endpoints', '[]'::jsonb)
        ) AS ep_url
        WHERE v.canonical_key LIKE 'endpoints:%'
        ON CONFLICT (target_id, url, method) DO NOTHING
        """
    )


def downgrade() -> None:
    op.drop_table("cve_intel")
    op.drop_table("tls_observations")
    op.drop_table("hvt_signals")
    op.drop_table("endpoint_observations")
    op.drop_table("endpoints")
    op.execute("DROP TYPE IF EXISTS hvt_signal_type")
