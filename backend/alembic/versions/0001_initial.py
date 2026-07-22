"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-07-21
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scans",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("target_cidr", sa.String(255), nullable=False, index=True),
        sa.Column("scan_type", sa.String(32), nullable=False),
        sa.Column("port_range", sa.String(64), nullable=True),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("error", sa.Text, nullable=True),
        sa.Column("nmap_xml_path", sa.String(512), nullable=True),
        sa.Column("nmap_stdout", sa.Text, nullable=True),
    )

    op.create_table(
        "devices",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("scan_id", sa.Integer, sa.ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True),
        sa.Column("ip", sa.String(64), nullable=False, index=True),
        sa.Column("mac", sa.String(64), nullable=True, index=True),
        sa.Column("hostname", sa.String(255), nullable=True),
        sa.Column("vendor", sa.String(255), nullable=True),
        sa.Column("os_guess", sa.String(255), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("mac", "ip", name="uq_device_mac_ip"),
    )

    op.create_table(
        "ports",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("device_id", sa.Integer, sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("scan_id", sa.Integer, sa.ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True),
        sa.Column("port", sa.Integer, nullable=False, index=True),
        sa.Column("protocol", sa.String(16), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("service", sa.String(128), nullable=True),
        sa.Column("version", sa.String(255), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("device_id", "port", "protocol", "scan_id", name="uq_port_per_scan"),
    )

    op.create_table(
        "alerts",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("scan_id", sa.Integer, sa.ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True),
        sa.Column("device_id", sa.Integer, sa.ForeignKey("devices.id", ondelete="SET NULL"), nullable=True, index=True),
        sa.Column("kind", sa.String(32), nullable=False, index=True),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("detail_json", sa.Text, nullable=False),
        sa.Column("acknowledged", sa.Boolean, nullable=False, default=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "settings",
        sa.Column("key", sa.String(64), primary_key=True),
        sa.Column("value", sa.Text, nullable=False),
    )


def downgrade() -> None:
    op.drop_table("settings")
    op.drop_table("alerts")
    op.drop_table("ports")
    op.drop_table("devices")
    op.drop_table("scans")
