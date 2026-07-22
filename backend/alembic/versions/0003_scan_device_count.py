"""add device_count column to scans

Revision ID: 0003_scan_device_count
Revises: 0002_add_progress_log
Create Date: 2026-07-22
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "0003_scan_device_count"
down_revision = "0002_add_progress_log"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("device_count", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_column("scans", "device_count")
