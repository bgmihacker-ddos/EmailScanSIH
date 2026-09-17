"""Add durable batch analysis tracking."""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "202609130002"
down_revision: Union[str, Sequence[str], None] = "202609130001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "analysis_batches",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="queued"),
        sa.Column("total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("completed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_analysis_batches_status", "analysis_batches", ["status"], unique=False)
    op.add_column("analysis_results", sa.Column("batch_id", sa.String(length=36), nullable=True))
    op.create_index("ix_analysis_results_batch_id", "analysis_results", ["batch_id"], unique=False)
    op.add_column("analysis_jobs", sa.Column("batch_id", sa.String(length=36), nullable=True))
    op.create_index("ix_analysis_jobs_batch_id", "analysis_jobs", ["batch_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_analysis_jobs_batch_id", table_name="analysis_jobs")
    op.drop_column("analysis_jobs", "batch_id")
    op.drop_index("ix_analysis_results_batch_id", table_name="analysis_results")
    op.drop_column("analysis_results", "batch_id")
    op.drop_index("ix_analysis_batches_status", table_name="analysis_batches")
    op.drop_table("analysis_batches")