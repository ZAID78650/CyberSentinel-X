"""add merkle_root to ledger_blocks

Revision ID: d8e9f0a1b2c3
Revises: a1b2c3d4e5f6
Create Date: 2026-08-16 02:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd8e9f0a1b2c3'
down_revision: Union[str, None] = 'a1b2c3d4e5f6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('ledger_blocks', sa.Column('merkle_root', sa.String(length=64), nullable=True))


def downgrade() -> None:
    op.drop_column('ledger_blocks', 'merkle_root')
