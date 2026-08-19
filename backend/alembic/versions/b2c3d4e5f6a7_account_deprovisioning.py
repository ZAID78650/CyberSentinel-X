"""account deprovisioning: token versioning + SSO blocking

Revision ID: b2c3d4e5f6a7
Revises: abcd1234ef56
Create Date: 2026-08-16 18:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b2c3d4e5f6a7'
down_revision: Union[str, None] = 'abcd1234ef56'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _col_exists(table: str, col: str) -> bool:
    cols = [c['name'] for c in sa.inspect(op.get_bind()).get_columns(table)]
    return col in cols


def upgrade() -> None:
    with op.batch_alter_table('users') as batch_op:
        if not _col_exists('users', 'token_version'):
            batch_op.add_column(sa.Column('token_version', sa.Integer(), server_default='0', nullable=False))
        if not _col_exists('users', 'sso_blocked'):
            batch_op.add_column(sa.Column('sso_blocked', sa.Boolean(), server_default=sa.false(), nullable=False))


def downgrade() -> None:
    with op.batch_alter_table('users') as batch_op:
        batch_op.drop_column('sso_blocked')
        batch_op.drop_column('token_version')
