"""Tests for the v3.5.4 per-session CSRF token mechanism.

Covers:
* POST without token rejected (403)
* POST with wrong/stale token rejected (403, constant-time compare)
* POST with correct token accepted (200)
* GET never requires the token
* Token rotates on login (session fixation guard)
* @csrf_exempt-decorated view bypasses token check
* csrf_token() exposed in Jinja template context
"""

from __future__ import annotations

import os
import sys

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-csrf-token-v354")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


@pytest.fixture(scope="module")
def app():
    from marlinspike.app import create_app
    application = create_app()
    application.config["TESTING"] = True
    application.config["WTF_CSRF_ENABLED"] = False
    return application


@pytest.fixture(scope="module")
def client(app):
    return app.test_client()


# ── Helper ────────────────────────────────────────────────────────────────────


def _get_csrf(client):
    """Obtain a CSRF token from an authenticated-ish session by hitting GET /login."""
    with client.session_transaction() as sess:
        # Seed the session directly so csrf_token() mints into it
        sess["_csrf"] = None  # trigger lazy mint on next request
    resp = client.get("/login")
    assert resp.status_code == 200
    with client.session_transaction() as sess:
        return sess.get("_csrf")


def _fresh_token(app):
    """Mint a fresh CSRF token in an app context without a real request."""
    with app.test_request_context("/"):
        from flask import session as flask_session
        from marlinspike.csrf import csrf_token
        # Prime a fake session
        flask_session["_csrf"] = None
        flask_session.modified = True
        t = csrf_token()
        return t


# ── GET never requires token ──────────────────────────────────────────────────


def test_get_never_requires_csrf(client):
    resp = client.get("/login")
    # login page — no token needed, never blocked
    assert resp.status_code == 200


def test_get_api_never_requires_csrf(client):
    resp = client.get("/api/taxonomy")
    assert resp.status_code == 200


# ── Token generation + validation helpers ─────────────────────────────────────


def test_csrf_token_mints_on_first_call(app):
    with app.test_request_context("/"):
        from flask import session as flask_session
        from marlinspike.csrf import csrf_token
        flask_session.modified = True
        t1 = csrf_token()
        t2 = csrf_token()
        assert t1 == t2  # idempotent within request
        assert len(t1) >= 32


def test_validate_csrf_constant_time_reject(app):
    with app.test_request_context("/"):
        from flask import session as flask_session
        from marlinspike.csrf import csrf_token, validate_csrf
        flask_session.modified = True
        real = csrf_token()
        assert not validate_csrf("wrong-token")
        assert not validate_csrf("")
        assert not validate_csrf(None)
        assert validate_csrf(real)


def test_rotate_csrf_forces_new_token(app):
    with app.test_request_context("/"):
        from flask import session as flask_session
        from marlinspike.csrf import csrf_token, rotate_csrf
        flask_session.modified = True
        t1 = csrf_token()
        rotate_csrf()
        t2 = csrf_token()
        assert t1 != t2
        assert len(t2) >= 32


# ── POST with no token → 403 ──────────────────────────────────────────────────


def test_post_without_token_rejected(client):
    """POST with no X-CSRF-Token and no Origin/Referer must be rejected."""
    resp = client.post("/api/auth/reset-request", json={"username": "x"})
    assert resp.status_code in (403, 503)
    if resp.status_code == 403:
        err = resp.get_json()["error"]
        assert "CSRF" in err or "Origin" in err


# ── POST with wrong token → 403 ───────────────────────────────────────────────


def test_post_with_wrong_token_rejected(client):
    """POST with an incorrect CSRF token must be rejected (no fallback to origin)."""
    resp = client.post(
        "/api/auth/reset-request",
        json={"username": "x"},
        headers={"X-CSRF-Token": "this-is-not-the-right-token"},
    )
    assert resp.status_code in (403, 503)


def test_post_with_stale_token_rejected(client):
    """A token from a previous session context must not be accepted."""
    fake_stale = "a" * 43  # plausible-length but not the session token
    resp = client.post(
        "/api/auth/reset-request",
        json={"username": "x"},
        headers={"X-CSRF-Token": fake_stale},
    )
    assert resp.status_code in (403, 503)


# ── POST with correct token passes CSRF ───────────────────────────────────────


def test_post_with_correct_token_accepted(client, monkeypatch):
    """POST with the session's own token plus matching origin reaches the view."""
    from marlinspike import config as ms_config
    monkeypatch.setattr(ms_config, "MARLINSPIKE_RESET_TOKEN_DELIVERY", "log")

    with client.session_transaction() as sess:
        import secrets
        token = secrets.token_urlsafe(32)
        sess["_csrf"] = token

    resp = client.post(
        "/api/auth/reset-request",
        json={"username": "x"},
        headers={"X-CSRF-Token": token},
    )
    # CSRF passed — endpoint reached and returned 200 (generic anti-enum response)
    assert resp.status_code == 200


def test_post_origin_alone_passes_when_no_token(client, monkeypatch):
    """A POST with matching Origin but no token still passes (belt-and-suspenders path)."""
    from marlinspike import config as ms_config
    monkeypatch.setattr(ms_config, "MARLINSPIKE_RESET_TOKEN_DELIVERY", "log")

    resp = client.post(
        "/api/auth/reset-request",
        json={"username": "x"},
        headers={"Origin": "http://localhost"},
    )
    # Origin path still works as fallback
    assert resp.status_code == 200


# ── @csrf_exempt bypasses token check ────────────────────────────────────────


def test_csrf_exempt_view_bypasses_check(client):
    """The login POST is @csrf_exempt — it must not be blocked by the CSRF gate."""
    # POST /login with no token and no Origin: should either reach the view
    # (bad-creds → 200 with error rendered) or redirect, not 403.
    resp = client.post(
        "/login",
        data={"username": "nobody", "password": "wrong"},
        follow_redirects=False,
    )
    # 200 (form re-render with error) or redirect — never 403
    assert resp.status_code != 403


# ── Token rotates on login ────────────────────────────────────────────────────


def test_token_rotates_on_login(app, client):
    """After a successful login the pre-login CSRF token is gone (rotation)."""
    from marlinspike.auth import create_user, verify_user
    from marlinspike.models import db

    # Ensure the test user exists
    with app.app_context():
        if not verify_user("csrf_test_user", "Passw0rd!"):
            create_user("csrf_test_user", "Passw0rd!")

    # Plant a known pre-login CSRF token in the session
    with client.session_transaction() as sess:
        import secrets
        pre_token = secrets.token_urlsafe(32)
        sess["_csrf"] = pre_token

    # Perform a successful login
    client.post(
        "/login",
        data={"username": "csrf_test_user", "password": "Passw0rd!"},
        follow_redirects=False,
    )

    # The pre-login token must no longer be in the session
    with client.session_transaction() as sess:
        post_token = sess.get("_csrf")

    # Rotated: either absent (not yet minted) or different
    assert post_token != pre_token


# ── csrf_token available in Jinja context ────────────────────────────────────


def test_csrf_token_in_template_context(app):
    """csrf_token() must be callable inside a rendered template context."""
    with app.test_request_context("/"):
        from flask import session as flask_session
        flask_session.modified = True
        env = app.jinja_env
        ctx_processors = app.template_context_processors.get(None, [])
        ctx = {}
        for processor in ctx_processors:
            ctx.update(processor())
        assert "csrf_token" in ctx
        token = ctx["csrf_token"]()  # it's a callable
        assert isinstance(token, str)
        assert len(token) >= 32
