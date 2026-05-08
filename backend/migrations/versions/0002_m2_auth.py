"""M2: add authorization fields to targets

Revision ID: 0002
Revises: 0001
Create Date: 2026-05-06

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("targets", sa.Column("authorization_token", sa.String(64), nullable=True))
    op.add_column("targets", sa.Column("authorization_verified_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("targets", sa.Column("authorization_proof", sa.String(20), nullable=True))


def downgrade() -> None:
    op.drop_column("targets", "authorization_proof")
    op.drop_column("targets", "authorization_verified_at")
    op.drop_column("targets", "authorization_token")
