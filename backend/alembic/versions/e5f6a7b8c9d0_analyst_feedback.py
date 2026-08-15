"""analyst feedback table

Revision ID: e5f6a7b8c9d0
Revises: d8e9f0a1b2c3
Create Date: 2026-08-16 02:45:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e5f6a7b8c9d0'
down_revision: Union[str, None] = 'd8e9f0a1b2c3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'analyst_feedback',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('alert_id', sa.Uuid(), nullable=False),
        sa.Column('label', sa.String(length=32), nullable=False),
        sa.Column('note', sa.Text(), nullable=True),
        sa.Column('analyst', sa.String(length=128), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['alert_id'], ['alerts.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_feedback_alert', 'analyst_feedback', ['alert_id'])
    op.create_index('ix_feedback_analyst', 'analyst_feedback', ['analyst'])
    op.create_index('ix_feedback_label', 'analyst_feedback', ['label'])


def downgrade() -> None:
    op.drop_index('ix_feedback_label', table_name='analyst_feedback')
    op.drop_index('ix_feedback_analyst', table_name='analyst_feedback')
    op.drop_index('ix_feedback_alert', table_name='analyst_feedback')
    op.drop_table('analyst_feedback')
