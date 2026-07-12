"""target_workspaces.created_by — per-analyst isolation

Revision ID: 0021
Revises: 0020
Create Date: 2026-07-11

Security fix: workspaces (and their investigation tasks/findings) were only
scoped by org_id, so any analyst in the org could read/act on any other
analyst's workspace — inconsistent with scans, which already scope by
created_by. Adds a nullable created_by FK and backfills existing rows from
their parent scan's created_by (falls back to NULL, which the admin-only
scan_filter() bypass still surfaces to admins; analysts simply won't see
pre-existing workspaces with no resolvable owner).
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0021"
down_revision: Union[str, None] = "0020"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "target_workspaces",
        sa.Column(
            "created_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index(
        "ix_target_workspaces_created_by", "target_workspaces", ["created_by"]
    )
    op.execute(
        """
        UPDATE target_workspaces AS w
        SET created_by = s.created_by
        FROM scans AS s
        WHERE w.parent_scan_id = s.id
        """
    )


def downgrade() -> None:
    op.drop_index("ix_target_workspaces_created_by", table_name="target_workspaces")
    op.drop_column("target_workspaces", "created_by")
