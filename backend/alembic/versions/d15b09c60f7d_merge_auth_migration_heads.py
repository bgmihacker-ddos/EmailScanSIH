"""merge authentication migration heads

Revision ID: d15b09c60f7d
Revises: 3ae94cd2dd14, add_oauth_handoff_codes
Create Date: 2026-09-07

"""
from typing import Sequence, Union


revision: str = "d15b09c60f7d"
down_revision: Union[str, Sequence[str], None] = (
    "3ae94cd2dd14",
    "add_oauth_handoff_codes",
)
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Merge independent authentication schema branches."""


def downgrade() -> None:
    """Restore the two independent migration heads."""
