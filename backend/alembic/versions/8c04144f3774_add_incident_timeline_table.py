"""add incident timeline table

Revision ID: 8c04144f3774
Revises: 20260328_incident_owner_note
Create Date: 2026-03-28 10:27:40.401612
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "8c04144f3774"
down_revision: Union[str, Sequence[str], None] = "20260328_incident_owner_note"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "incident_timeline",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("incident_id", sa.String(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=True),
        sa.Column("event_type", sa.String(), nullable=False),
        sa.Column("actor", sa.String(), nullable=True),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("details", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_incident_timeline_incident_id"), "incident_timeline", ["incident_id"], unique=False)
    op.create_index(op.f("ix_incident_timeline_tenant_id"), "incident_timeline", ["tenant_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_incident_timeline_tenant_id"), table_name="incident_timeline")
    op.drop_index(op.f("ix_incident_timeline_incident_id"), table_name="incident_timeline")
    op.drop_table("incident_timeline")