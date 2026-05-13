"""services.classification ENUM + heuristic backfill

Revision ID: 0010
Revises: 0009
Create Date: 2026-05-11

Adds service_classification ENUM and the column on services. Backfill walks
existing services and applies a port/product heuristic — same logic as the
runtime classifier in services/classify_service.py. Anything ambiguous lands
on 'unknown' (the server_default).
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0010"
down_revision: Union[str, None] = "0009"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    classification = postgresql.ENUM(
        "web", "database", "messaging", "control_plane", "file_share",
        "mail", "directory", "crypto", "rpc", "monitoring",
        "iot", "cache", "unknown",
        name="service_classification",
        create_type=False,
    )
    classification.create(op.get_bind(), checkfirst=True)

    op.add_column(
        "services",
        sa.Column(
            "classification", classification,
            nullable=False, server_default="unknown",
        ),
    )

    # ── Heuristic backfill: port-driven classification.
    # Anything not matched stays 'unknown' (server_default).
    op.execute(
        """
        UPDATE services SET classification = 'web'
        WHERE port IN (80, 443, 8080, 8443, 8000, 8888) OR service_name ILIKE 'http%'
        """
    )
    op.execute(
        """
        UPDATE services SET classification = 'database'
        WHERE port IN (3306, 5432, 1433, 1521, 27017, 6379, 9042, 5984, 7474)
           OR service_name IN ('mysql', 'postgresql', 'mssql', 'oracle', 'mongodb',
                                'redis', 'cassandra', 'couchdb', 'neo4j')
        """
    )
    op.execute(
        """
        UPDATE services SET classification = 'cache'
        WHERE port IN (11211)
           OR service_name IN ('memcached')
        """
    )
    op.execute(
        """
        UPDATE services SET classification = 'messaging'
        WHERE port IN (5672, 15672, 9092, 1883, 61616)
           OR service_name IN ('amqp', 'kafka', 'mqtt', 'activemq')
        """
    )
    op.execute(
        """
        UPDATE services SET classification = 'control_plane'
        WHERE port IN (22, 23, 3389, 5985, 5986, 2375, 2376, 6443, 10250)
           OR service_name IN ('ssh', 'telnet', 'rdp', 'docker', 'kubelet')
        """
    )
    op.execute(
        """
        UPDATE services SET classification = 'file_share'
        WHERE port IN (21, 445, 139, 2049)
           OR service_name IN ('ftp', 'smb', 'nfs', 'netbios-ssn', 'microsoft-ds')
        """
    )
    op.execute(
        """
        UPDATE services SET classification = 'mail'
        WHERE port IN (25, 110, 143, 465, 587, 993, 995)
           OR service_name IN ('smtp', 'pop3', 'imap', 'submission', 'imaps', 'pop3s')
        """
    )
    op.execute(
        """
        UPDATE services SET classification = 'directory'
        WHERE port IN (389, 636, 88, 464)
           OR service_name IN ('ldap', 'ldaps', 'kerberos')
        """
    )
    op.execute(
        """
        UPDATE services SET classification = 'crypto'
        WHERE service_name IN ('https', 'ssl/http')
           AND classification = 'unknown'
        """
    )
    op.execute(
        """
        UPDATE services SET classification = 'rpc'
        WHERE port IN (135, 111)
           OR service_name IN ('msrpc', 'rpcbind', 'sunrpc')
        """
    )
    op.execute(
        """
        UPDATE services SET classification = 'monitoring'
        WHERE port IN (9090, 3000, 5601)
           OR service_name IN ('prometheus', 'grafana', 'kibana')
        """
    )


def downgrade() -> None:
    op.drop_column("services", "classification")
    op.execute("DROP TYPE IF EXISTS service_classification")
