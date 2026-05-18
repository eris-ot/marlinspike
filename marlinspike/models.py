"""MarlinSpike standalone — SQLAlchemy models."""

from datetime import date, datetime, timezone

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default="user")  # 'admin' or 'user'
    email = db.Column(db.String(256), unique=True, nullable=True)
    session_version = db.Column(db.Integer, nullable=False, default=1)
    created_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc)
    )

    # Profile fields
    full_name = db.Column(db.String(120), nullable=True)
    company = db.Column(db.String(120), nullable=True)
    phone = db.Column(db.String(30), nullable=True)
    birthday = db.Column(db.Date, nullable=True)
    address = db.Column(db.Text, nullable=True)
    upload_limit_mb = db.Column(db.Integer, nullable=False, default=200)

    scans = db.relationship("ScanHistory", backref="user", cascade="all, delete-orphan")
    projects = db.relationship("Project", backref="user", cascade="all, delete-orphan")


class Project(db.Model):
    __tablename__ = "projects"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    name = db.Column(db.String(200), nullable=False)
    created_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc)
    )
    # JSON-encoded per-project capture policy. NULL = use system defaults.
    # Shape: {"enabled": bool, "allowed_interfaces": [str, ...],
    #         "max_session_duration_s": int|null,
    #         "max_total_bytes": int|null,  # retained ring-buffer bytes on disk
    #         "operator_warning": str|null}
    capture_policy = db.Column(db.Text, nullable=True)

    __table_args__ = (
        db.UniqueConstraint("user_id", "name", name="uq_project_user_name"),
    )


class ProjectMember(db.Model):
    """Additional members of a project beyond the creator.

    The project creator (projects.user_id) is implicitly owner and is not
    stored here.  This table only holds invited members.
    """

    __tablename__ = "project_members"

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(
        db.Integer, db.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role = db.Column(db.String(20), nullable=False, default="viewer")  # viewer | editor | owner
    invited_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        db.UniqueConstraint("project_id", "user_id", name="uq_project_member"),
    )


class ScanHistory(db.Model):
    __tablename__ = "scan_history"

    id = db.Column(db.Integer, primary_key=True)
    run_id = db.Column(db.String(64), unique=True, nullable=False)
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    project_id = db.Column(
        db.Integer, db.ForeignKey("projects.id", ondelete="SET NULL"), nullable=True
    )
    command = db.Column(db.String(20), nullable=False)
    scan_profile = db.Column(db.String(12), nullable=False, default="full")
    pcap_source = db.Column(db.Text)
    pcap_hash = db.Column(db.String(64))
    status = db.Column(db.String(20), nullable=False)  # running/completed/failed/stopped
    started_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc)
    )
    completed_at = db.Column(db.DateTime)
    report_path = db.Column(db.Text)
    node_count = db.Column(db.Integer, default=0)
    edge_count = db.Column(db.Integer, default=0)
    error_tail = db.Column(db.Text)  # last ~10 output lines on failure

    # Recovery essentials — populated at scan launch, consulted by
    # marlinspike.recovery on every boot to reconcile in-flight scans
    # whose Flask parent died.
    pcap_path = db.Column(db.Text)               # absolute path (re-launch on retry)
    engine_pid = db.Column(db.Integer)           # subprocess PID; cleared on terminal
    engine_argv = db.Column(db.Text)             # JSON-encoded argv (PID-reuse defense)
    timeout_at = db.Column(db.DateTime)          # hard deadline for abandonment reaping
    recovery_state = db.Column(db.String(20))   # NULL / reattached / reaped_*

    project = db.relationship("Project", backref="scans")


class PasswordResetToken(db.Model):
    __tablename__ = "password_reset_tokens"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    token_hash = db.Column(db.String(64), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at = db.Column(db.DateTime, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    created_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc)
    )


class AssetTag(db.Model):
    __tablename__ = "asset_tags"

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id"), nullable=False, index=True)
    asset_key = db.Column(db.String(64), nullable=False, index=True)  # MAC first, IP fallback
    owner = db.Column(db.String(120))
    criticality = db.Column(db.String(20))   # 'low'|'medium'|'high'|'critical'|None
    zone = db.Column(db.String(80))
    business_function = db.Column(db.String(120))
    free_text = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = db.Column(db.Integer, db.ForeignKey("users.id"))

    __table_args__ = (db.UniqueConstraint("project_id", "asset_key", name="uq_asset_tag"),)


class FindingNote(db.Model):
    __tablename__ = "finding_notes"

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id"), nullable=False, index=True)
    report_filename = db.Column(db.String(255), nullable=False, index=True)
    finding_signature = db.Column(db.String(64), nullable=False, index=True)
    status = db.Column(db.String(20), default="open", nullable=False)
    body = db.Column(db.Text)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class AuditLog(db.Model):
    __tablename__ = "audit_log"

    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    actor_user_id = db.Column(db.Integer, nullable=True)
    actor_username = db.Column(db.String(80), nullable=True)
    actor_role = db.Column(db.String(20), nullable=True)
    target_type = db.Column(db.String(50), nullable=True)
    target_id = db.Column(db.String(200), nullable=True)
    status = db.Column(db.String(20), nullable=False, default="success")
    ip_address = db.Column(db.String(45), nullable=True)
    detail = db.Column(db.Text, nullable=True)
    created_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc)
    )


# ── IOC Threat Hunting ──────────────────────────────────────────

class IocList(db.Model):
    __tablename__ = "ioc_lists"

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id"), nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text)
    source = db.Column(db.String(64))  # 'manual' | 'csv' | 'misp' | 'stix'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"))

    entries = db.relationship("IocEntry", backref="ioc_list", cascade="all, delete-orphan")

    __table_args__ = (db.UniqueConstraint("project_id", "name", name="uq_ioc_list_name"),)


class IocEntry(db.Model):
    __tablename__ = "ioc_entries"

    id = db.Column(db.Integer, primary_key=True)
    list_id = db.Column(db.Integer, db.ForeignKey("ioc_lists.id"), nullable=False, index=True)
    ioc_type = db.Column(db.String(16), nullable=False, index=True)  # 'ip'|'mac'|'oui'|'domain'|'sha256'|'md5'
    value = db.Column(db.String(255), nullable=False, index=True)
    label = db.Column(db.String(120))
    severity = db.Column(db.String(20))

    __table_args__ = (db.UniqueConstraint("list_id", "ioc_type", "value", name="uq_ioc_entry"),)


# ── Live Capture (capd-driven) ──────────────────────────────────

class CaptureSession(db.Model):
    __tablename__ = "capture_sessions"

    id = db.Column(db.Integer, primary_key=True)
    session_uuid = db.Column(db.String(64), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id", ondelete="SET NULL"), nullable=True, index=True)

    interface = db.Column(db.String(64), nullable=False, index=True)
    bpf_filter = db.Column(db.Text, default="", nullable=False)
    ring_filesize_kb = db.Column(db.Integer, default=200_000, nullable=False)
    ring_files = db.Column(db.Integer, default=10, nullable=False)
    max_duration_s = db.Column(db.Integer, default=0, nullable=False)

    # 'pending' | 'running' | 'stopping' | 'stopped' | 'failed'
    status = db.Column(db.String(20), default="pending", nullable=False, index=True)
    started_at = db.Column(db.DateTime)
    stopped_at = db.Column(db.DateTime)

    capture_dir = db.Column(db.Text)
    bytes_captured = db.Column(db.BigInteger, default=0, nullable=False)
    packets_captured = db.Column(db.BigInteger, default=0, nullable=False)
    drop_count = db.Column(db.BigInteger, default=0, nullable=False)
    rotation_count = db.Column(db.Integer, default=0, nullable=False)
    error_tail = db.Column(db.Text)

    user = db.relationship("User", backref="capture_sessions")
    project = db.relationship("Project", backref="capture_sessions")


class SavedFilter(db.Model):
    """Per-project named BPF filter library."""

    __tablename__ = "saved_filters"

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id", ondelete="CASCADE"),
                           nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    name = db.Column(db.String(80), nullable=False)
    expression = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        db.UniqueConstraint("project_id", "name", name="uq_saved_filter_project_name"),
    )
