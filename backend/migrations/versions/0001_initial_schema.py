"""Initial schema — hosts, events, alerts, evidence

Revision ID: 0001
Revises:
Create Date: 2026-06-08

NOTE FOR EXISTING DEPLOYMENTS
------------------------------
If the database was already created by SQLAlchemy's create_all (pre-Alembic),
stamp it so Alembic skips this migration:

    set -a && source .env && set +a
    PYTHONPATH=. alembic stamp 0001

New deployments apply this migration automatically on first startup.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# PostgreSQL ENUM type objects — created once, shared across tables
eventtype_enum = sa.Enum(
    "CANARY_TOUCHED",
    "ENTROPY_SPIKE",
    "PROCESS_ANOMALY",
    "COMBINED_ALERT",
    "CONTAINMENT_TRIGGERED",
    "CONTAINMENT_COMPLETE",
    "HEARTBEAT",
    name="eventtype",
)

severity_enum = sa.Enum(
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
    name="severity",
)


def upgrade() -> None:
    # Create PostgreSQL ENUM types
    eventtype_enum.create(op.get_bind(), checkfirst=True)
    severity_enum.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "hosts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("host_id", sa.String(255), nullable=False, unique=True, index=True),
        sa.Column("hostname", sa.String(255), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_contained", sa.Boolean(), nullable=True, default=False),
        sa.Column("risk_score", sa.Float(), nullable=True, default=0.0),
    )

    op.create_table(
        "events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "host_id",
            sa.String(255),
            sa.ForeignKey("hosts.host_id"),
            nullable=False,
            index=True,
        ),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("event_type", eventtype_enum, nullable=False),
        sa.Column("severity", severity_enum, nullable=False),
        sa.Column("pid", sa.Integer(), nullable=True),
        sa.Column("process_name", sa.String(255), nullable=True),
        sa.Column("file_path", sa.Text(), nullable=True),
        sa.Column("lineage_score", sa.Float(), nullable=True, default=0.0),
        sa.Column("entropy_delta", sa.Float(), nullable=True, default=0.0),
        sa.Column("canary_hit", sa.Boolean(), nullable=True, default=False),
        sa.Column("details", postgresql.JSON(astext_type=sa.Text()), nullable=True),
    )

    op.create_table(
        "alerts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "event_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("events.id"),
            nullable=False,
            unique=True,
        ),
        sa.Column(
            "host_id",
            sa.String(255),
            sa.ForeignKey("hosts.host_id"),
            nullable=False,
            index=True,
        ),
        sa.Column("severity", severity_enum, nullable=False),
        sa.Column("acknowledged", sa.Boolean(), nullable=True, default=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_table(
        "evidence",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "alert_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("alerts.id"),
            nullable=False,
            index=True,
        ),
        sa.Column("pid", sa.Integer(), nullable=True),
        sa.Column("evidence_dir", sa.Text(), nullable=True),
        sa.Column("files", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("iptables_rule", sa.Text(), nullable=True),
        sa.Column("raw_data", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("evidence")
    op.drop_table("alerts")
    op.drop_table("events")
    op.drop_table("hosts")
    severity_enum.drop(op.get_bind(), checkfirst=True)
    eventtype_enum.drop(op.get_bind(), checkfirst=True)
