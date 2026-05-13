"""Delete legacy panel_detector Vulnerability rows.

Revision ID: 0011
Revises: 0010
Create Date: 2026-05-10

panel_detector used to emit Vulnerability rows (a category error — a Joomla
admin panel is not a CVE). M-Vuln-6 rewrites it to emit HvtSignal rows. This
migration deletes the stale rows so they don't pollute the Vulnerabilities tab.

Safe to re-run: WHERE clause is specific; no rows with canonical_key like
'panel:%' should exist after M-Vuln-6 ships.
"""
from typing import Sequence, Union

from alembic import op

revision: str = "0011"
down_revision: Union[str, None] = "0010"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Delete vulnerabilities produced by the old panel_detector implementation.
    # canonical_key for those rows was: panel:{name_slug}:{asset_id}
    op.execute(
        "DELETE FROM vulnerabilities WHERE canonical_key LIKE 'panel:%'"
    )


def downgrade() -> None:
    # Cannot restore deleted rows; downgrade is a no-op.
    pass
