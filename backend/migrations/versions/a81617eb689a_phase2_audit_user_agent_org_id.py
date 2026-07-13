"""phase2 audit user_agent org_id + append-only enforcement

Revision ID: a81617eb689a
Revises: 2ad5daee83cd
Create Date: 2026-07-13 10:39:39.600607

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = 'a81617eb689a'
down_revision: Union[str, None] = '2ad5daee83cd'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('audit_logs', sa.Column('user_agent', sa.String(length=255), nullable=True))
    op.add_column('audit_logs', sa.Column('org_id', postgresql.UUID(as_uuid=True), nullable=True))
    op.create_index(op.f('ix_audit_logs_org_id'), 'audit_logs', ['org_id'], unique=False)

    # Append-only enforcement via triggers, NOT grants. The app's DB role
    # (recon) owns this table (it created it via migrations), and Postgres
    # table owners always bypass GRANT/REVOKE ACL checks — so REVOKE alone is
    # a no-op here. Triggers fire regardless of ownership, so they're the
    # only mechanism that actually blocks the owning role. The REVOKEs are
    # kept anyway as defense-in-depth for if the app ever connects as a
    # separate non-owner role.
    op.execute("REVOKE UPDATE, TRUNCATE ON audit_logs FROM recon")

    # DELETE: blocked unless the transaction sets app.allow_audit_purge, which
    # only the retention cron does (services/audit.py::purge_expired).
    op.execute(
        """
        CREATE OR REPLACE FUNCTION audit_logs_guard_delete() RETURNS trigger AS $$
        BEGIN
            IF current_setting('app.allow_audit_purge', true) IS DISTINCT FROM 'true' THEN
                RAISE EXCEPTION 'audit_logs is append-only; deletes only allowed via the retention purge job';
            END IF;
            RETURN OLD;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_logs_no_delete
        BEFORE DELETE ON audit_logs
        FOR EACH ROW EXECUTE FUNCTION audit_logs_guard_delete();
        """
    )

    # UPDATE: always blocked, no exceptions — a written row can never be edited.
    op.execute(
        """
        CREATE OR REPLACE FUNCTION audit_logs_guard_update() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'audit_logs rows are immutable and cannot be updated';
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_logs_no_update
        BEFORE UPDATE ON audit_logs
        FOR EACH ROW EXECUTE FUNCTION audit_logs_guard_update();
        """
    )

    # TRUNCATE: always blocked. No row-level trigger fires for TRUNCATE, so
    # this needs its own statement-level trigger.
    op.execute(
        """
        CREATE OR REPLACE FUNCTION audit_logs_guard_truncate() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'audit_logs cannot be truncated; use the retention purge job';
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_logs_no_truncate
        BEFORE TRUNCATE ON audit_logs
        FOR EACH STATEMENT EXECUTE FUNCTION audit_logs_guard_truncate();
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_logs_no_truncate ON audit_logs")
    op.execute("DROP FUNCTION IF EXISTS audit_logs_guard_truncate()")
    op.execute("DROP TRIGGER IF EXISTS audit_logs_no_update ON audit_logs")
    op.execute("DROP FUNCTION IF EXISTS audit_logs_guard_update()")
    op.execute("DROP TRIGGER IF EXISTS audit_logs_no_delete ON audit_logs")
    op.execute("DROP FUNCTION IF EXISTS audit_logs_guard_delete()")
    op.execute("GRANT UPDATE, TRUNCATE ON audit_logs TO recon")

    op.drop_index(op.f('ix_audit_logs_org_id'), table_name='audit_logs')
    op.drop_column('audit_logs', 'org_id')
    op.drop_column('audit_logs', 'user_agent')
