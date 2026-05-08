"""add_queued_stopped_scan_status

Revision ID: ba7455c89b4b
Revises: c358f6fe0d08
Create Date: 2026-05-07 12:24:41.664792

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = 'ba7455c89b4b'
down_revision: Union[str, None] = 'c358f6fe0d08'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ALTER TYPE ADD VALUE must run outside a transaction block in PostgreSQL < 12.
    # Using autocommit_block ensures compatibility across all supported versions.
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE scan_status ADD VALUE IF NOT EXISTS 'queued' BEFORE 'created'")
        op.execute("ALTER TYPE scan_status ADD VALUE IF NOT EXISTS 'stopped' AFTER 'failed'")


def downgrade() -> None:
    # PostgreSQL does not support removing enum values — manual intervention needed
    pass
