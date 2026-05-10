"""baseline — full schema as of v3.5.4

Captures every table that was previously created by db.create_all() plus the
ad-hoc ALTER TABLE migrations that lived in create_app().  This revision is
the starting point for all future Alembic-managed schema evolution.

Existing deployments (any v3.5.x or earlier) should stamp at this revision
BEFORE upgrading to v3.5.4:

    python -m marlinspike.db stamp head

Fresh deployments: upgrade() is run automatically by create_app() on first
boot and creates the complete schema from scratch.

Revision ID: 0001
Revises:     (none — initial baseline)
Create Date: 2026-05-10

"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0001"
down_revision: str | None = None
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    # ------------------------------------------------------------------
    # users
    # ------------------------------------------------------------------
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(length=80), nullable=False),
        sa.Column("password_hash", sa.String(length=256), nullable=False),
        sa.Column("role", sa.String(length=20), nullable=True),
        sa.Column("email", sa.String(length=256), nullable=True),
        sa.Column("session_version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        # Profile fields (added via ALTER TABLE between v2.x and v3.4)
        sa.Column("full_name", sa.String(length=120), nullable=True),
        sa.Column("company", sa.String(length=120), nullable=True),
        sa.Column("phone", sa.String(length=30), nullable=True),
        sa.Column("birthday", sa.Date(), nullable=True),
        sa.Column("address", sa.Text(), nullable=True),
        sa.Column("upload_limit_mb", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("username"),
        sa.UniqueConstraint("email"),
    )

    # ------------------------------------------------------------------
    # projects
    # ------------------------------------------------------------------
    op.create_table(
        "projects",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        # v3.5.4: per-project capture policy (nullable JSON-encoded TEXT).
        # Shape documented in marlinspike/models.py:Project.capture_policy.
        sa.Column("capture_policy", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "name", name="uq_project_user_name"),
    )

    # ------------------------------------------------------------------
    # scan_history  (includes all v3.4 recovery columns)
    # ------------------------------------------------------------------
    op.create_table(
        "scan_history",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("run_id", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=True),
        sa.Column("command", sa.String(length=20), nullable=False),
        sa.Column("scan_profile", sa.String(length=12), nullable=False),
        sa.Column("pcap_source", sa.Text(), nullable=True),
        sa.Column("pcap_hash", sa.String(length=64), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("report_path", sa.Text(), nullable=True),
        sa.Column("node_count", sa.Integer(), nullable=True),
        sa.Column("edge_count", sa.Integer(), nullable=True),
        sa.Column("error_tail", sa.Text(), nullable=True),
        # v3.4.0 recovery columns
        sa.Column("pcap_path", sa.Text(), nullable=True),
        sa.Column("engine_pid", sa.Integer(), nullable=True),
        sa.Column("engine_argv", sa.Text(), nullable=True),
        sa.Column("timeout_at", sa.DateTime(), nullable=True),
        sa.Column("recovery_state", sa.String(length=20), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("run_id"),
    )

    # ------------------------------------------------------------------
    # password_reset_tokens
    # ------------------------------------------------------------------
    op.create_table(
        "password_reset_tokens",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("used_at", sa.DateTime(), nullable=True),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )

    # ------------------------------------------------------------------
    # asset_tags
    # ------------------------------------------------------------------
    op.create_table(
        "asset_tags",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("asset_key", sa.String(length=64), nullable=False),
        sa.Column("owner", sa.String(length=120), nullable=True),
        sa.Column("criticality", sa.String(length=20), nullable=True),
        sa.Column("zone", sa.String(length=80), nullable=True),
        sa.Column("business_function", sa.String(length=120), nullable=True),
        sa.Column("free_text", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.Column("updated_by", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"]),
        sa.ForeignKeyConstraint(["updated_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id", "asset_key", name="uq_asset_tag"),
    )
    op.create_index(op.f("ix_asset_tags_asset_key"), "asset_tags", ["asset_key"])
    op.create_index(op.f("ix_asset_tags_project_id"), "asset_tags", ["project_id"])

    # ------------------------------------------------------------------
    # finding_notes
    # ------------------------------------------------------------------
    op.create_table(
        "finding_notes",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("report_filename", sa.String(length=255), nullable=False),
        sa.Column("finding_signature", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("body", sa.Text(), nullable=True),
        sa.Column("author_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["author_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_finding_notes_finding_signature"), "finding_notes", ["finding_signature"]
    )
    op.create_index(
        op.f("ix_finding_notes_project_id"), "finding_notes", ["project_id"]
    )
    op.create_index(
        op.f("ix_finding_notes_report_filename"), "finding_notes", ["report_filename"]
    )

    # ------------------------------------------------------------------
    # audit_log
    # ------------------------------------------------------------------
    op.create_table(
        "audit_log",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(length=100), nullable=False),
        sa.Column("category", sa.String(length=50), nullable=False),
        sa.Column("actor_user_id", sa.Integer(), nullable=True),
        sa.Column("actor_username", sa.String(length=80), nullable=True),
        sa.Column("actor_role", sa.String(length=20), nullable=True),
        sa.Column("target_type", sa.String(length=50), nullable=True),
        sa.Column("target_id", sa.String(length=200), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )

    # ------------------------------------------------------------------
    # ioc_lists
    # ------------------------------------------------------------------
    op.create_table(
        "ioc_lists",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("source", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.Column("created_by", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id", "name", name="uq_ioc_list_name"),
    )
    op.create_index(op.f("ix_ioc_lists_project_id"), "ioc_lists", ["project_id"])

    # ------------------------------------------------------------------
    # ioc_entries
    # ------------------------------------------------------------------
    op.create_table(
        "ioc_entries",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("list_id", sa.Integer(), nullable=False),
        sa.Column("ioc_type", sa.String(length=16), nullable=False),
        sa.Column("value", sa.String(length=255), nullable=False),
        sa.Column("label", sa.String(length=120), nullable=True),
        sa.Column("severity", sa.String(length=20), nullable=True),
        sa.ForeignKeyConstraint(["list_id"], ["ioc_lists.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("list_id", "ioc_type", "value", name="uq_ioc_entry"),
    )
    op.create_index(op.f("ix_ioc_entries_ioc_type"), "ioc_entries", ["ioc_type"])
    op.create_index(op.f("ix_ioc_entries_list_id"), "ioc_entries", ["list_id"])
    op.create_index(op.f("ix_ioc_entries_value"), "ioc_entries", ["value"])

    # ------------------------------------------------------------------
    # capture_sessions
    # ------------------------------------------------------------------
    op.create_table(
        "capture_sessions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("session_uuid", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=True),
        sa.Column("interface", sa.String(length=64), nullable=False),
        sa.Column("bpf_filter", sa.Text(), nullable=False),
        sa.Column("ring_filesize_kb", sa.Integer(), nullable=False),
        sa.Column("ring_files", sa.Integer(), nullable=False),
        sa.Column("max_duration_s", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("stopped_at", sa.DateTime(), nullable=True),
        sa.Column("capture_dir", sa.Text(), nullable=True),
        sa.Column("bytes_captured", sa.BigInteger(), nullable=False),
        sa.Column("packets_captured", sa.BigInteger(), nullable=False),
        sa.Column("drop_count", sa.BigInteger(), nullable=False),
        sa.Column("rotation_count", sa.Integer(), nullable=False),
        sa.Column("error_tail", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("session_uuid"),
    )
    op.create_index(
        op.f("ix_capture_sessions_interface"), "capture_sessions", ["interface"]
    )
    op.create_index(
        op.f("ix_capture_sessions_project_id"), "capture_sessions", ["project_id"]
    )
    op.create_index(
        op.f("ix_capture_sessions_session_uuid"), "capture_sessions", ["session_uuid"]
    )
    op.create_index(
        op.f("ix_capture_sessions_status"), "capture_sessions", ["status"]
    )
    op.create_index(
        op.f("ix_capture_sessions_user_id"), "capture_sessions", ["user_id"]
    )

    # ------------------------------------------------------------------
    # saved_filters
    # ------------------------------------------------------------------
    op.create_table(
        "saved_filters",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("name", sa.String(length=80), nullable=False),
        sa.Column("expression", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id", "name", name="uq_saved_filter_project_name"),
    )
    op.create_index(
        op.f("ix_saved_filters_project_id"), "saved_filters", ["project_id"]
    )


def downgrade() -> None:
    # Drop in reverse FK order.
    op.drop_index(op.f("ix_saved_filters_project_id"), table_name="saved_filters")
    op.drop_table("saved_filters")

    op.drop_index(op.f("ix_capture_sessions_user_id"), table_name="capture_sessions")
    op.drop_index(op.f("ix_capture_sessions_status"), table_name="capture_sessions")
    op.drop_index(op.f("ix_capture_sessions_session_uuid"), table_name="capture_sessions")
    op.drop_index(op.f("ix_capture_sessions_project_id"), table_name="capture_sessions")
    op.drop_index(op.f("ix_capture_sessions_interface"), table_name="capture_sessions")
    op.drop_table("capture_sessions")

    op.drop_index(op.f("ix_ioc_entries_value"), table_name="ioc_entries")
    op.drop_index(op.f("ix_ioc_entries_list_id"), table_name="ioc_entries")
    op.drop_index(op.f("ix_ioc_entries_ioc_type"), table_name="ioc_entries")
    op.drop_table("ioc_entries")

    op.drop_index(op.f("ix_ioc_lists_project_id"), table_name="ioc_lists")
    op.drop_table("ioc_lists")

    op.drop_table("audit_log")

    op.drop_index(op.f("ix_finding_notes_report_filename"), table_name="finding_notes")
    op.drop_index(op.f("ix_finding_notes_project_id"), table_name="finding_notes")
    op.drop_index(op.f("ix_finding_notes_finding_signature"), table_name="finding_notes")
    op.drop_table("finding_notes")

    op.drop_index(op.f("ix_asset_tags_project_id"), table_name="asset_tags")
    op.drop_index(op.f("ix_asset_tags_asset_key"), table_name="asset_tags")
    op.drop_table("asset_tags")

    op.drop_table("password_reset_tokens")
    op.drop_table("scan_history")
    op.drop_table("projects")
    op.drop_table("users")
