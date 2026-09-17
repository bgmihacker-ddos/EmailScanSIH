"""Add forensic integrity columns to analysis results."""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "202609130001"
down_revision: Union[str, Sequence[str], None] = "202609120001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("analysis_results", sa.Column("evidence_hash", sa.String(length=128), nullable=True))
    op.add_column("analysis_results", sa.Column("chain_of_custody_id", sa.String(length=128), nullable=True))
    op.add_column("analysis_results", sa.Column("hash_manifest", sa.JSON(), nullable=True))
    op.create_index("ix_analysis_results_evidence_hash", "analysis_results", ["evidence_hash"], unique=False)
    op.create_index("ix_analysis_results_chain_of_custody_id", "analysis_results", ["chain_of_custody_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_analysis_results_chain_of_custody_id", table_name="analysis_results")
    op.drop_index("ix_analysis_results_evidence_hash", table_name="analysis_results")
    op.drop_column("analysis_results", "hash_manifest")
    op.drop_column("analysis_results", "chain_of_custody_id")
    op.drop_column("analysis_results", "evidence_hash")