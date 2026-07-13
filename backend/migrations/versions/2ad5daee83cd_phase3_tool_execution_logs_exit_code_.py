"""phase3 tool execution logs exit_code stderr

Revision ID: 2ad5daee83cd
Revises: 0021
Create Date: 2026-07-13 10:17:17.667237

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = '2ad5daee83cd'
down_revision: Union[str, None] = '0021'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('investigation_tasks', sa.Column('exit_code', sa.Integer(), nullable=True))
    op.add_column('investigation_tasks', sa.Column('stderr', sa.Text(), nullable=True))
    op.add_column('investigation_tasks', sa.Column('stdout_object_key', sa.String(length=255), nullable=True))
    op.add_column('investigation_tasks', sa.Column('stderr_object_key', sa.String(length=255), nullable=True))

    op.add_column('operations', sa.Column('exit_code', sa.Integer(), nullable=True))
    op.add_column('operations', sa.Column('stderr', sa.Text(), nullable=True))
    op.add_column('operations', sa.Column('stdout_object_key', sa.String(length=255), nullable=True))
    op.add_column('operations', sa.Column('stderr_object_key', sa.String(length=255), nullable=True))

    op.add_column('scan_stages', sa.Column('exit_code', sa.Integer(), nullable=True))
    op.add_column('scan_stages', sa.Column('stderr', sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column('scan_stages', 'stderr')
    op.drop_column('scan_stages', 'exit_code')

    op.drop_column('operations', 'stderr_object_key')
    op.drop_column('operations', 'stdout_object_key')
    op.drop_column('operations', 'stderr')
    op.drop_column('operations', 'exit_code')

    op.drop_column('investigation_tasks', 'stderr_object_key')
    op.drop_column('investigation_tasks', 'stdout_object_key')
    op.drop_column('investigation_tasks', 'stderr')
    op.drop_column('investigation_tasks', 'exit_code')
