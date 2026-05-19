"""verified targets: is_verified / verified_by / verified_at on targets

Revision ID: 0014
Revises: 0013
Create Date: 2026-05-18

Admin-asserted trust flag (orthogonal to authorization_verified_at, which
proves DNS/HTTP ownership). When is_verified=true, aggressive scan profiles
(deep recon, intrusive vuln, ffuf/dirsearch/naabu/nmap_deep) are allowed
against the target. When false, only passive scans are allowed.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0014"
down_revision: Union[str, None] = "0013"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "targets",
        sa.Column("is_verified", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "targets",
        sa.Column(
            "verified_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.add_column(
        "targets",
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_targets_is_verified", "targets", ["is_verified"])


def downgrade() -> None:
    op.drop_index("ix_targets_is_verified", table_name="targets")
    op.drop_column("targets", "verified_at")
    op.drop_column("targets", "verified_by")
    op.drop_column("targets", "is_verified")
