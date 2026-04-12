"""incident owner and analyst note

Revision ID: 20260328_incident_owner_note
Revises: 
Create Date: 2026-03-28
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "20260328_incident_owner_note"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("incidents", sa.Column("owner", sa.String(), nullable=True))
    op.add_column("incidents", sa.Column("analyst_note", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("incidents", "analyst_note")
    op.drop_column("incidents", "owner")