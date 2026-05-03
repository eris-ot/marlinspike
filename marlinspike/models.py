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

    __table_args__ = (
        db.UniqueConstraint("user_id", "name", name="uq_project_user_name"),
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
