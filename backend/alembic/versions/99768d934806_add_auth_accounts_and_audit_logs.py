"""add auth_accounts and audit_logs

Revision ID: 99768d934806
Revises: 40c425498992
Create Date: 2026-09-06 12:33:57.775024

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '99768d934806'
down_revision: Union[str, Sequence[str], None] = '40c425498992'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema - empty as tables already exist."""
    pass

def downgrade() -> None:
    """Downgrade schema - empty as tables exist."""
    pass
