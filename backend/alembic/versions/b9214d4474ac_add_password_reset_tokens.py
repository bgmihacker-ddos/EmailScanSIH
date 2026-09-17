"""add password_reset_tokens

Revision ID: b9214d4474ac
Revises: 99768d934806
Create Date: 2026-09-06 12:46:02.113663

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b9214d4474ac'
down_revision: Union[str, Sequence[str], None] = '99768d934806'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema - empty as tables already exist."""
    pass

def downgrade() -> None:
    """Downgrade schema."""
    pass
