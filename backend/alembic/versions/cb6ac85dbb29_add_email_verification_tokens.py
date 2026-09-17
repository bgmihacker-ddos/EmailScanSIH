"""add email_verification_tokens

Revision ID: cb6ac85dbb29
Revises: b9214d4474ac
Create Date: 2026-09-06 12:53:34.147213

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'cb6ac85dbb29'
down_revision: Union[str, Sequence[str], None] = 'b9214d4474ac'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema - empty as tables already exist."""
    pass

def downgrade() -> None:
    """Downgrade schema."""
    pass
