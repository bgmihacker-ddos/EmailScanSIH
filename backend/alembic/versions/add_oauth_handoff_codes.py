"""add oauth_handoff_codes table

Revision ID: add_oauth_handoff_codes
Revises: cb6ac85dbb29
Create Date: 2026-09-06
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = 'add_oauth_handoff_codes'
down_revision: Union[str, Sequence[str], None] = 'cb6ac85dbb29'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    bind = op.get_bind()
    if "oauth_handoff_codes" in sa.inspect(bind).get_table_names():
        return

    op.create_table(
        "oauth_handoff_codes",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("code_hash", sa.String(length=255), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
    )

def downgrade() -> None:
    bind = op.get_bind()
    if "oauth_handoff_codes" in sa.inspect(bind).get_table_names():
        op.drop_table("oauth_handoff_codes")
