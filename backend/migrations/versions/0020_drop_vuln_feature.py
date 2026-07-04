"""drop vulnerability scans feature

Revision ID: 0020
Revises: 0019
Create Date: 2026-05-23

Forward-only removal of the Vulnerability Scans feature. Drops all vuln-exclusive
tables, Scan.kind/parent_scan_id/intrusive columns, and the four vuln-related
ENUM types. Shared tables (endpoints, endpoint_observations, tls_observations,
services, technologies, ai_usage) stay — they're still written by the recon and
investigation pipelines.
"""
from typing import Sequence, Union

from alembic import op

revision: str = "0020"
down_revision: Union[str, None] = "0019"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 0. Remove vuln-analysis Scan rows so the column drops don't leave orphans.
    op.execute("DELETE FROM scans WHERE kind = 'vuln_analysis'")

    # 1. Drop vuln-exclusive tables (children first).
    op.drop_table("vuln_run_matches")
    op.drop_table("vuln_evidence")
    op.drop_table("vulnerabilities")
    op.drop_table("cve_intel")
    op.drop_table("hvt_signals")

    # 2. Drop Scan vuln-linkage columns and the vuln-scoped partial unique index.
    op.execute("DROP INDEX IF EXISTS uq_vuln_scan_active_per_target")
    op.drop_column("scans", "intrusive")
    op.drop_column("scans", "parent_scan_id")
    op.drop_column("scans", "kind")

    # 3. Drop now-unused ENUM types (Postgres does not drop them automatically).
    op.execute("DROP TYPE IF EXISTS vuln_severity")
    op.execute("DROP TYPE IF EXISTS vuln_status")
    op.execute("DROP TYPE IF EXISTS scan_kind")
    op.execute("DROP TYPE IF EXISTS hvt_signal_type")


def downgrade() -> None:
    """Forward-only. Restoring the vuln feature would require re-running
    migrations 0006-0011 from scratch, plus data recovery."""
    pass
