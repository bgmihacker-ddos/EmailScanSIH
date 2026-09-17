"""Add encrypted mailbox token storage."""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "202609130003"
down_revision: Union[str, Sequence[str], None] = "202609130002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("auth_accounts", sa.Column("access_token_encrypted", sa.String(length=4096), nullable=True))
    op.add_column("auth_accounts", sa.Column("refresh_token_encrypted", sa.String(length=4096), nullable=True))
    op.add_column("auth_accounts", sa.Column("token_expires_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("auth_accounts", sa.Column("token_scope", sa.String(length=2048), nullable=True))


def downgrade() -> None:
    op.drop_column("auth_accounts", "token_scope")
    op.drop_column("auth_accounts", "token_expires_at")
    op.drop_column("auth_accounts", "refresh_token_encrypted")
    op.drop_column("auth_accounts", "access_token_encrypted")