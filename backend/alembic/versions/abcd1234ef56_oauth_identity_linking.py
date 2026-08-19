"""oauth identity linking for users

Revision ID: abcd1234ef56
Revises: f6a7b8c9d0e1
Create Date: 2026-08-16 14:10:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'abcd1234ef56'
down_revision: Union[str, None] = 'f6a7b8c9d0e1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _col_exists(table: str, col: str) -> bool:
    cols = [c['name'] for c in sa.inspect(op.get_bind()).get_columns(table)]
    return col in cols


def upgrade() -> None:
    with op.batch_alter_table('users') as batch_op:
        if not _col_exists('users', 'oauth_provider'):
            batch_op.add_column(sa.Column('oauth_provider', sa.String(length=32), nullable=True))
        if not _col_exists('users', 'oauth_provider_id'):
            batch_op.add_column(sa.Column('oauth_provider_id', sa.String(length=255), nullable=True))
    # Idempotent index/constraint creation
    insp = sa.inspect(op.get_bind())
    existing_idx = {i['name'] for i in insp.get_indexes('users')}
    existing_uq = {c['name'] for c in insp.get_unique_constraints('users')}
    with op.batch_alter_table('users') as batch_op:
        if 'ix_users_oauth_provider' not in existing_idx:
            batch_op.create_index('ix_users_oauth_provider', ['oauth_provider'])
        if 'uq_users_oauth_identity' not in existing_uq:
            batch_op.create_unique_constraint('uq_users_oauth_identity', ['oauth_provider', 'oauth_provider_id'])


def downgrade() -> None:
    with op.batch_alter_table('users') as batch_op:
        batch_op.drop_constraint('uq_users_oauth_identity', type_='unique')
        batch_op.drop_index('ix_users_oauth_provider')
        batch_op.drop_column('oauth_provider_id')
        batch_op.drop_column('oauth_provider')
