"""promote services and technologies to first-class tables

Revision ID: 0005
Revises: ba7455c89b4b
Create Date: 2026-05-09

Adds:
  - services: one row per (target, host:port/proto), unique on (target_id, canonical_key)
  - technologies: one row per (target, asset, tech_name), unique on (target_id, asset_id, name)

Backfills:
  - services from Asset(type='service') rows
  - technologies from asset_observations WHERE source_tool='httpx' AND payload->'tech' IS NOT NULL

Asset(type='service') rows are kept during this transition window.
Drop them in a follow-up migration once scan_view reads exclusively from `services`.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005"
down_revision: Union[str, None] = "ba7455c89b4b"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── services ──────────────────────────────────────────────────────────────
    op.create_table(
        "services",
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
            sa.ForeignKey("assets.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("host", sa.String(255), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("proto", sa.String(10), nullable=False),
        sa.Column("canonical_key", sa.String(300), nullable=False),
        sa.Column("state", sa.String(20), nullable=False, server_default="open"),
        sa.Column("service_name", sa.String(100), nullable=True),
        sa.Column("product", sa.String(200), nullable=True),
        sa.Column("version", sa.String(100), nullable=True),
        sa.Column("banner", sa.String(500), nullable=True),
        sa.Column(
            "cpes",
            postgresql.ARRAY(sa.Text()),
            nullable=False,
            server_default="{}",
        ),
        sa.Column("tls", postgresql.JSONB(), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("target_id", "canonical_key", name="uq_service_identity"),
    )
    op.create_index("ix_services_target_id", "services", ["target_id"])

    # ── technologies ──────────────────────────────────────────────────────────
    op.create_table(
        "technologies",
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
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("version", sa.String(100), nullable=True),
        sa.Column("cpe", sa.String(300), nullable=True),
        sa.Column("category", sa.String(100), nullable=True),
        sa.Column("confidence", sa.Integer(), nullable=False, server_default="80"),
        sa.Column("source_tool", sa.String(80), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("target_id", "asset_id", "name", name="uq_tech_identity"),
    )
    op.create_index("ix_technologies_target_id", "technologies", ["target_id"])
    op.create_index("ix_technologies_asset_id", "technologies", ["asset_id"])

    # ── backfill: services from Asset(type='service') ─────────────────────────
    # naabu/nmap payload always carries host, port, proto, state, service_name,
    # product, version. We take the most-recent observation per asset via LATERAL.
    op.execute(
        """
        INSERT INTO services (
            id, target_id, asset_id, host, port, proto, canonical_key,
            state, service_name, product, version, cpes, first_seen, last_seen
        )
        SELECT
            gen_random_uuid(),
            a.target_id,
            a.id,
            COALESCE(latest.payload->>'host', SPLIT_PART(a.canonical_key, ':', 1)),
            COALESCE((latest.payload->>'port')::integer, 0),
            COALESCE(latest.payload->>'proto', 'tcp'),
            a.canonical_key,
            COALESCE(latest.payload->>'state', 'open'),
            latest.payload->>'service_name',
            latest.payload->>'product',
            latest.payload->>'version',
            '{}',
            a.first_seen,
            a.last_seen
        FROM assets a
        LEFT JOIN LATERAL (
            SELECT payload
            FROM asset_observations
            WHERE asset_id = a.id
            ORDER BY observed_at DESC
            LIMIT 1
        ) latest ON true
        WHERE a.type = 'service'
        ON CONFLICT ON CONSTRAINT uq_service_identity DO NOTHING
        """
    )

    # ── backfill: technologies from httpx observations ────────────────────────
    # httpx observations land on http_service assets; payload.tech is a JSON array
    # of strings like ["WordPress 5.8", "nginx", "jQuery 3.6.0"].
    # Technology.asset_id points to the http_service asset directly.
    op.execute(
        """
        INSERT INTO technologies (
            id, target_id, asset_id, name, version, source_tool, first_seen, last_seen
        )
        SELECT DISTINCT ON (a.target_id, a.id, te.name)
            gen_random_uuid(),
            a.target_id,
            a.id,
            te.name,
            te.version,
            'httpx',
            a.first_seen,
            a.last_seen
        FROM assets a
        JOIN asset_observations ao ON ao.asset_id = a.id AND ao.source_tool = 'httpx'
        JOIN LATERAL (
            SELECT
                TRIM(REGEXP_REPLACE(t.value, ' [0-9].*$', '')) AS name,
                CASE WHEN t.value ~ ' [0-9]'
                     THEN REGEXP_REPLACE(t.value, '^.* ', '')
                     ELSE NULL
                END AS version
            FROM jsonb_array_elements_text(ao.payload->'tech') AS t(value)
            WHERE t.value IS NOT NULL AND t.value <> ''
        ) te ON true
        WHERE a.type = 'http_service'
          AND ao.payload ? 'tech'
          AND jsonb_array_length(ao.payload->'tech') > 0
        ON CONFLICT ON CONSTRAINT uq_tech_identity DO NOTHING
        """
    )


def downgrade() -> None:
    op.drop_table("technologies")
    op.drop_table("services")
