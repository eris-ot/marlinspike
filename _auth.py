"""MarlinSpike standalone — authentication helpers."""

import secrets
import string
from functools import wraps

from flask import redirect, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from _models import User, db


# ── Decorators ──


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
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
    db.session.commit()


def generate_random_password(length=16):
    alphabet = string.ascii_letters + string.digits + "!@#$%&*"
    return "".join(secrets.choice(alphabet) for _ in range(length))


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
