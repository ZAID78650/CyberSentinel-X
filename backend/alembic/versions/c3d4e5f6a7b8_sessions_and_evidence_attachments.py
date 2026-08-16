"""sessions: device revocation + evidence attachment metadata

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-08-16 19:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c3d4e5f6a7b8'
down_revision: Union[str, None] = 'b2c3d4e5f6a7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('devices') as batch_op:
        batch_op.add_column(sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True))
    with op.batch_alter_table('evidence_records') as batch_op:
        batch_op.add_column(sa.Column('attachment_name', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('attachment_path', sa.String(length=512), nullable=True))
        batch_op.add_column(sa.Column('attachment_hash', sa.String(length=64), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('evidence_records') as batch_op:
        batch_op.drop_column('attachment_hash')
        batch_op.drop_column('attachment_path')
        batch_op.drop_column('attachment_name')
    with op.batch_alter_table('devices') as batch_op:
        batch_op.drop_column('revoked_at')
