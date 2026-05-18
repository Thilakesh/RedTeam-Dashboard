"""auth overhaul: user_role enum, refresh_sessions, blacklisted_jti, user_features, audit_logs, scans.created_by

Revision ID: 0013
Revises: 0012
Create Date: 2026-05-18

Schema migration for the auth/session/RBAC redesign:

- Converts users.role from String(50) (default 'owner') to a PG ENUM
  user_role ('admin','analyst'). Existing rows are migrated to 'analyst' per
  the agreed cutover plan; an admin is seeded at backend startup from env.
- Adds users.is_active, users.created_by, users.password_changed_at,
  users.invite_token_hash, users.invite_expires_at. Makes password_hash
  nullable so invite-created users can exist before accepting.
- Adds scans.created_by (FK users.id, nullable; null for legacy rows).
- Creates refresh_sessions, blacklisted_jti, user_features, audit_logs.

ENUM pattern follows CLAUDE.md guidance: build one postgresql.ENUM instance
with create_type=False, call .create(checkfirst=True), then reference it on
the column.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0013"
down_revision: Union[str, None] = "0012"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()

    # 1. user_role enum.
    user_role = postgresql.ENUM(
        "admin", "analyst",
        name="user_role",
        create_type=False,
    )
    user_role.create(bind, checkfirst=True)

    # 2. users column changes.
    #    a. password_hash → nullable (invite flow).
    op.alter_column("users", "password_hash", existing_type=sa.String(255), nullable=True)

    #    b. Coerce any legacy role value into the new enum domain before the type swap.
    op.execute("UPDATE users SET role = 'analyst' WHERE role NOT IN ('admin','analyst')")
    op.execute("ALTER TABLE users ALTER COLUMN role DROP DEFAULT")
    op.execute("ALTER TABLE users ALTER COLUMN role TYPE user_role USING role::user_role")
    op.execute("ALTER TABLE users ALTER COLUMN role SET DEFAULT 'analyst'")
    op.execute("ALTER TABLE users ALTER COLUMN role SET NOT NULL")

    #    c. Add new columns.
    op.add_column("users", sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()))
    op.add_column(
        "users",
        sa.Column(
            "created_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.add_column("users", sa.Column("password_changed_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("users", sa.Column("invite_token_hash", sa.String(64), nullable=True))
    op.add_column("users", sa.Column("invite_expires_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_users_invite_token_hash", "users", ["invite_token_hash"])

    # 3. scans.created_by (nullable; null for legacy pre-rbac rows — admin still sees them).
    op.add_column(
        "scans",
        sa.Column(
            "created_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index("ix_scans_created_by", "scans", ["created_by"])

    # 4. refresh_sessions.
    op.create_table(
        "refresh_sessions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("refresh_token_hash", sa.String(64), nullable=False),
        sa.Column("device_label", sa.String(120), nullable=True),
        sa.Column("ip_address", postgresql.INET(), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("revoked_reason", sa.String(40), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "parent_session_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("refresh_sessions.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("refresh_token_hash", name="uq_refresh_sessions_token_hash"),
    )
    op.create_index("ix_refresh_sessions_user_id", "refresh_sessions", ["user_id"])
    op.create_index(
        "ix_refresh_sessions_user_revoked",
        "refresh_sessions",
        ["user_id", "revoked"],
    )

    # 5. blacklisted_jti.
    op.create_table(
        "blacklisted_jti",
        sa.Column("jti", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("reason", sa.String(40), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_blacklisted_jti_user_id", "blacklisted_jti", ["user_id"])
    op.create_index("ix_blacklisted_jti_expires_at", "blacklisted_jti", ["expires_at"])

    # 6. user_features (default-enabled; only rows with enabled=false matter).
    op.create_table(
        "user_features",
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("feature_name", sa.String(60), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column(
            "updated_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.PrimaryKeyConstraint("user_id", "feature_name", name="pk_user_features"),
    )

    # 7. audit_logs (append-only).
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column(
            "actor_user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("actor_ip", postgresql.INET(), nullable=True),
        sa.Column("action", sa.String(80), nullable=False),
        sa.Column("target_type", sa.String(40), nullable=True),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("meta", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_audit_logs_actor_user_id", "audit_logs", ["actor_user_id"])
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"])
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])


def downgrade() -> None:
    op.drop_table("audit_logs")
    op.drop_table("user_features")
    op.drop_table("blacklisted_jti")
    op.drop_table("refresh_sessions")

    op.drop_index("ix_scans_created_by", table_name="scans")
    op.drop_column("scans", "created_by")

    op.drop_index("ix_users_invite_token_hash", table_name="users")
    op.drop_column("users", "invite_expires_at")
    op.drop_column("users", "invite_token_hash")
    op.drop_column("users", "password_changed_at")
    op.drop_column("users", "created_by")
    op.drop_column("users", "is_active")

    # Reverse role: enum → varchar default 'owner'.
    op.execute("ALTER TABLE users ALTER COLUMN role DROP DEFAULT")
    op.execute("ALTER TABLE users ALTER COLUMN role TYPE varchar(50) USING role::text")
    op.execute("ALTER TABLE users ALTER COLUMN role SET DEFAULT 'owner'")
    op.execute("DROP TYPE IF EXISTS user_role")

    op.alter_column("users", "password_hash", existing_type=sa.String(255), nullable=False)
