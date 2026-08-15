"""forensic ledger, attack dna, predictions

Revision ID: a1b2c3d4e5f6
Revises: 5938fab8c7d1
Create Date: 2026-08-15 17:40:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, None] = '5938fab8c7d1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('evidence_records',
        sa.Column('incident_id', sa.Uuid(), nullable=True),
        sa.Column('evidence_id', sa.String(length=32), nullable=False),
        sa.Column('evidence_type', sa.String(length=32), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('chain_index', sa.Integer(), nullable=False),
        sa.Column('prev_hash', sa.String(length=64), nullable=False),
        sa.Column('content_hash', sa.String(length=64), nullable=False),
        sa.Column('record_hash', sa.String(length=64), nullable=False),
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('data_source', sa.String(length=24), nullable=False),
        sa.Column('created_by', sa.String(length=128), nullable=False),
        sa.Column('verified_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('meta', sa.JSON(), nullable=True),
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('chain_index'),
        sa.UniqueConstraint('record_hash'),
        sa.UniqueConstraint('evidence_id'),
    )
    op.create_index('ix_evidence_incident', 'evidence_records', ['incident_id'], unique=False)
    op.create_index('ix_evidence_chain_index', 'evidence_records', ['chain_index'], unique=False)

    op.create_table('ledger_blocks',
        sa.Column('block_index', sa.Integer(), nullable=False),
        sa.Column('prev_block_hash', sa.String(length=64), nullable=False),
        sa.Column('records_digest', sa.String(length=64), nullable=False),
        sa.Column('nonce', sa.Integer(), nullable=False),
        sa.Column('block_hash', sa.String(length=64), nullable=False),
        sa.Column('record_count', sa.Integer(), nullable=False),
        sa.Column('mined_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('meta', sa.JSON(), nullable=True),
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('block_hash'),
        sa.UniqueConstraint('block_index'),
    )

    op.create_table('attack_dna',
        sa.Column('incident_id', sa.Uuid(), nullable=False),
        sa.Column('dna_id', sa.String(length=32), nullable=False),
        sa.Column('fingerprint', sa.String(length=64), nullable=False),
        sa.Column('family', sa.String(length=64), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('severity', sa.String(length=16), nullable=False),
        sa.Column('risk_score', sa.Float(), nullable=True),
        sa.Column('techniques', sa.JSON(), nullable=False),
        sa.Column('behaviors', sa.JSON(), nullable=False),
        sa.Column('features', sa.JSON(), nullable=False),
        sa.Column('historical_similarity', sa.Float(), nullable=True),
        sa.Column('similar_to', sa.String(length=32), nullable=True),
        sa.Column('meta', sa.JSON(), nullable=True),
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('dna_id'),
        sa.UniqueConstraint('incident_id'),
    )
    op.create_index('ix_attack_dna_incident', 'attack_dna', ['incident_id'], unique=False)

    op.create_table('attack_predictions',
        sa.Column('incident_id', sa.Uuid(), nullable=False),
        sa.Column('current_stage', sa.String(length=48), nullable=False),
        sa.Column('predicted_stage', sa.String(length=48), nullable=False),
        sa.Column('probability', sa.Float(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('recommended_control', sa.String(length=255), nullable=True),
        sa.Column('rationale', sa.Text(), nullable=True),
        sa.Column('model_version', sa.String(length=32), nullable=False),
        sa.Column('is_prediction', sa.Boolean(), nullable=False),
        sa.Column('meta', sa.JSON(), nullable=True),
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_predictions_incident', 'attack_predictions', ['incident_id'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_predictions_incident', table_name='attack_predictions')
    op.drop_table('attack_predictions')
    op.drop_index('ix_attack_dna_incident', table_name='attack_dna')
    op.drop_table('attack_dna')
    op.drop_table('ledger_blocks')
    op.drop_index('ix_evidence_chain_index', table_name='evidence_records')
    op.drop_index('ix_evidence_incident', table_name='evidence_records')
    op.drop_table('evidence_records')
