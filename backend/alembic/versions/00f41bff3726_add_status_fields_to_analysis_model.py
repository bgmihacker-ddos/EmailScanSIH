"""Add status fields to analysis model

Revision ID: 00f41bff3726
Revises: d15b09c60f7d
Create Date: 2026-09-08 19:28:39.400821

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '00f41bff3726'
down_revision: Union[str, Sequence[str], None] = 'd15b09c60f7d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('analysis_results', sa.Column('status', sa.String(length=32), nullable=False, server_default='completed'))
    op.add_column('analysis_results', sa.Column('current_stage', sa.String(length=255), nullable=True))
    op.add_column('analysis_results', sa.Column('progress_percent', sa.Integer(), nullable=False, server_default='100'))
    op.add_column('analysis_results', sa.Column('error_message', sa.String(length=1000), nullable=True))
    op.add_column('analysis_results', sa.Column('started_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()))
    op.add_column('analysis_results', sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('analysis_results', sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()))
    op.alter_column('analysis_results', 'verdict',
               existing_type=sa.VARCHAR(length=32),
               nullable=True)
    op.alter_column('analysis_results', 'risk_score',
               existing_type=sa.INTEGER(),
               nullable=True)
    op.alter_column('analysis_results', 'severity',
               existing_type=sa.VARCHAR(length=32),
               nullable=True)
    op.alter_column('analysis_results', 'confidence',
               existing_type=sa.INTEGER(),
               nullable=True)
    op.alter_column('analysis_results', 'summary',
               existing_type=sa.VARCHAR(length=1000),
               nullable=True)
    op.alter_column('analysis_results', 'result',
               existing_type=postgresql.JSON(astext_type=sa.Text()),
               nullable=True)
    op.create_index(op.f('ix_analysis_results_status'), 'analysis_results', ['status'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_analysis_results_status'), table_name='analysis_results')
    op.alter_column('analysis_results', 'result',
               existing_type=postgresql.JSON(astext_type=sa.Text()),
               nullable=False)
    op.alter_column('analysis_results', 'summary',
               existing_type=sa.VARCHAR(length=1000),
               nullable=False)
    op.alter_column('analysis_results', 'confidence',
               existing_type=sa.INTEGER(),
               nullable=False)
    op.alter_column('analysis_results', 'severity',
               existing_type=sa.VARCHAR(length=32),
               nullable=False)
    op.alter_column('analysis_results', 'risk_score',
               existing_type=sa.INTEGER(),
               nullable=False)
    op.alter_column('analysis_results', 'verdict',
               existing_type=sa.VARCHAR(length=32),
               nullable=False)
    op.drop_column('analysis_results', 'updated_at')
    op.drop_column('analysis_results', 'completed_at')
    op.drop_column('analysis_results', 'started_at')
    op.drop_column('analysis_results', 'error_message')
    op.drop_column('analysis_results', 'progress_percent')
    op.drop_column('analysis_results', 'current_stage')
    op.drop_column('analysis_results', 'status')
