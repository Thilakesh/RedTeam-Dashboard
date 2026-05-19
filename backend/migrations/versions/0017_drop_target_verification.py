"""drop all target verification columns

Revision ID: 0017
Revises: 0015
Create Date: 2026-05-19

Removes both verification subsystems entirely:
- PR #6 follow-up: is_verified / verified_by / verified_at + ix_targets_is_verified
- M2 legacy DNS/HTTP ownership proof: authorization_token /
  authorization_verified_at / authorization_proof

Per the new architecture, scan authorization is gated only by RBAC role
and per-user feature flags. No technical target-level gating remains.
Forward-only — verification data is UX state, not customer data.
"""
from typing import Sequence, Union

from alembic import op

revision: str = "0017"
down_revision: Union[str, None] = "0015"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_index("ix_targets_is_verified", table_name="targets")
    op.drop_column("targets", "verified_at")
    op.drop_column("targets", "verified_by")
    op.drop_column("targets", "is_verified")
    op.drop_column("targets", "authorization_proof")
    op.drop_column("targets", "authorization_verified_at")
    op.drop_column("targets", "authorization_token")


def downgrade() -> None:
    pass  # irreversible cleanup
