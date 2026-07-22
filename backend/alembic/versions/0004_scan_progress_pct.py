"""add progress_pct column to scans

Revision ID: 0004_scan_progress_pct
Revises: 0003_scan_device_count
Create Date: 2026-07-22
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "0004_scan_progress_pct"
down_revision = "0003_scan_device_count"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("progress_pct", sa.Float(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_column("scans", "progress_pct")
