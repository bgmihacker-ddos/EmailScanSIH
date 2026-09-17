"""Add durable analysis jobs and indexed indicators.

Revision ID: 202609120001
Revises: 00f41bff3726
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "202609120001"
down_revision: Union[str, Sequence[str], None] = "00f41bff3726"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "analysis_jobs",
        sa.Column("analysis_id", sa.String(length=36), nullable=False),
        sa.Column("payload", sa.LargeBinary(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("locked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("analysis_id"),
    )
    op.create_index("ix_analysis_jobs_created_at", "analysis_jobs", ["created_at"], unique=False)

    op.create_table(
        "analysis_indicators",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("analysis_id", sa.String(length=36), nullable=False),
        sa.Column("indicator_type", sa.String(length=32), nullable=False),
        sa.Column("normalized_value", sa.String(length=2048), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False, server_default="ioc_extractor"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_analysis_indicators_analysis_id", "analysis_indicators", ["analysis_id"], unique=False)
    op.create_index("ix_analysis_indicators_indicator_type", "analysis_indicators", ["indicator_type"], unique=False)
    op.create_index("ix_analysis_indicators_normalized_value", "analysis_indicators", ["normalized_value"], unique=False)
    op.create_index("ix_analysis_indicators_created_at", "analysis_indicators", ["created_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_analysis_indicators_created_at", table_name="analysis_indicators")
    op.drop_index("ix_analysis_indicators_normalized_value", table_name="analysis_indicators")
    op.drop_index("ix_analysis_indicators_indicator_type", table_name="analysis_indicators")
    op.drop_index("ix_analysis_indicators_analysis_id", table_name="analysis_indicators")
    op.drop_table("analysis_indicators")
    op.drop_index("ix_analysis_jobs_created_at", table_name="analysis_jobs")
    op.drop_table("analysis_jobs")