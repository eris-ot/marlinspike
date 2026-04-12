"""MarlinSpike standalone — authentication helpers."""

import hashlib
import logging
import secrets
import string
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import redirect, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from _models import PasswordResetToken, User, db

log = logging.getLogger("marlinspike.auth")

# Lazy import to avoid circular dependency at module load time
_audit_fn = None


def _get_audit():
    global _audit_fn
    if _audit_fn is None:
        from _audit import audit as _a
        _audit_fn = _a
    return _audit_fn


# ── Decorators ──


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login_page"))
        # Session invalidation: reject if session_version doesn't match DB
        if "session_version" in session and "user_id" in session:
            user = User.query.get(session["user_id"])
            if user and getattr(user, "session_version", 1) != session["session_version"]:
                session.clear()
                return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login_page"))
        if session.get("role") != "admin":
            return "Forbidden", 403
        return f(*args, **kwargs)
    return decorated


# ── User CRUD ──


def create_user(username, password, role="user", upload_limit_mb=200):
    user = User(
        username=username,
        password_hash=generate_password_hash(password),
        role=role,
        upload_limit_mb=upload_limit_mb,
    )
    db.session.add(user)
    db.session.commit()
    return user


def verify_user(username, password):
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password_hash, password):
        return user
    return None


def change_password(user, new_password):
    user.password_hash = generate_password_hash(new_password)
    user.session_version = (user.session_version or 1) + 1
    db.session.commit()


def generate_random_password(length=16):
    alphabet = string.ascii_letters + string.digits + "!@#$%&*"
    return "".join(secrets.choice(alphabet) for _ in range(length))


# ── Password Reset ──

RESET_TOKEN_TTL_MINUTES = 30


def _hash_token(token: str) -> str:
    """SHA-256 hash a reset token for storage. Never store raw tokens."""
    return hashlib.sha256(token.encode()).hexdigest()


def create_reset_token(user, ip_address=None):
    """Generate a single-use password reset token. Returns the raw token."""
    PasswordResetToken.query.filter_by(user_id=user.id, used_at=None).delete()

    raw_token = secrets.token_urlsafe(32)
    token = PasswordResetToken(
        user_id=user.id,
        token_hash=_hash_token(raw_token),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=RESET_TOKEN_TTL_MINUTES),
        ip_address=ip_address,
    )
    db.session.add(token)
    db.session.commit()

    log.info("Reset token issued for user=%s ip=%s", user.username, ip_address or "?")
    _get_audit()("auth.reset_token_issued",
                  target_type="user", target_id=user.username,
                  actor_user_id=user.id, actor_username=user.username,
                  ip_address=ip_address)
    return raw_token


def validate_reset_token(raw_token):
    """Validate a reset token. Returns the token row if valid, None otherwise."""
    token_hash = _hash_token(raw_token)
    token = PasswordResetToken.query.filter_by(token_hash=token_hash).first()

    if not token:
        _get_audit()("auth.reset_token_rejected", status="failure",
                      detail={"reason": "not_found"})
        return None
    if token.used_at is not None:
        _get_audit()("auth.reset_token_rejected", status="failure",
                      target_type="user", target_id=str(token.user_id),
                      detail={"reason": "already_used"})
        return None
    if datetime.now(timezone.utc) > token.expires_at:
        _get_audit()("auth.reset_token_rejected", status="failure",
                      target_type="user", target_id=str(token.user_id),
                      detail={"reason": "expired"})
        return None

    return token


def use_reset_token(token, new_password):
    """Consume a reset token and change the user's password. Returns the user."""
    user = User.query.get(token.user_id)
    user.password_hash = generate_password_hash(new_password)
    user.session_version = (user.session_version or 1) + 1
    token.used_at = datetime.now(timezone.utc)
    db.session.commit()

    log.info("Reset token used for user=%s", user.username)
    _get_audit()("auth.reset_token_used",
                  target_type="user", target_id=user.username,
                  actor_user_id=user.id, actor_username=user.username)
    return user


def cleanup_expired_tokens():
    """Delete expired or used tokens older than 24h."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    deleted = PasswordResetToken.query.filter(
        (PasswordResetToken.expires_at < cutoff)
        | (PasswordResetToken.used_at.isnot(None) & (PasswordResetToken.used_at < cutoff))
    ).delete(synchronize_session=False)
    db.session.commit()
    return deleted


# ── Bootstrap ──


def bootstrap_admin(app):
    """Create admin user on first run if users table is empty."""
    from _config import ADMIN_PASSWORD

    with app.app_context():
        if User.query.count() > 0:
            return

        password = ADMIN_PASSWORD or generate_random_password()
        create_user("admin", password, role="admin")

        if not ADMIN_PASSWORD:
            print("=" * 60)
            print("  FIRST RUN — admin account created")
            print(f"  Username: admin")
            print(f"  Password: {password}")
            print("  (change this immediately)")
            print("=" * 60)
