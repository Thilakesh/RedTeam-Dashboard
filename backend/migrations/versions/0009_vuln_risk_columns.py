"""vulnerabilities: add endpoint_id + risk/exposure/exploitability/blast columns

Revision ID: 0009
Revises: 0008
Create Date: 2026-05-11

Additive only. risk/exposure/exploitability/blast are computed by the M-Vuln-7
correlator; nullable until then. endpoint_id lets a Vulnerability scope to a
specific HTTP route (e.g. nuclei matching a CVE on /admin/login.php).
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0009"
down_revision: Union[str, None] = "0008"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "vulnerabilities",
        sa.Column(
            "endpoint_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("endpoints.id", ondelete="SET NULL"), nullable=True,
        ),
    )
    op.add_column("vulnerabilities", sa.Column("risk_score", sa.Float(), nullable=True))
    op.add_column("vulnerabilities", sa.Column("exposure_score", sa.Float(), nullable=True))
    op.add_column("vulnerabilities", sa.Column("exploitability_score", sa.Float(), nullable=True))
    op.add_column("vulnerabilities", sa.Column("blast_radius_score", sa.Float(), nullable=True))


def downgrade() -> None:
    op.drop_column("vulnerabilities", "blast_radius_score")
    op.drop_column("vulnerabilities", "exploitability_score")
    op.drop_column("vulnerabilities", "exposure_score")
    op.drop_column("vulnerabilities", "risk_score")
    op.drop_column("vulnerabilities", "endpoint_id")
