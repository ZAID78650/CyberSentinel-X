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


def upgrade() -> None:
    with op.batch_alter_table('users') as batch_op:
        batch_op.add_column(sa.Column('oauth_provider', sa.String(length=32), nullable=True))
        batch_op.add_column(sa.Column('oauth_provider_id', sa.String(length=255), nullable=True))
        batch_op.create_index('ix_users_oauth_provider', ['oauth_provider'])
        batch_op.create_unique_constraint('uq_users_oauth_identity', ['oauth_provider', 'oauth_provider_id'])


def downgrade() -> None:
    with op.batch_alter_table('users') as batch_op:
        batch_op.drop_constraint('uq_users_oauth_identity', type_='unique')
        batch_op.drop_index('ix_users_oauth_provider')
        batch_op.drop_column('oauth_provider_id')
        batch_op.drop_column('oauth_provider')
