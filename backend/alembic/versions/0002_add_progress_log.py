"""add progress_log column to scans

Revision ID: 0002_add_progress_log
Revises: 0001_initial
Create Date: 2026-07-22
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "0002_add_progress_log"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("progress_log", sa.Text(), nullable=False, server_default=""),
    )


def downgrade() -> None:
    op.drop_column("scans", "progress_log")
