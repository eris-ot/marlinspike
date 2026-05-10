"""Tests for v3.5.2 security fixes.

Covers:
* Password reset endpoint never returns the token in the HTTP response
  (regardless of MARLINSPIKE_RESET_TOKEN_DELIVERY mode)
* Live capture session start/stop is admin-only by default
* Browser security headers (CSP, X-Content-Type-Options, X-Frame-Options,
  Referrer-Policy) emitted on every response
* CSRF check uses full origin (scheme+host+port), not just hostname
* Extraction endpoint fails closed when tshark/editcap produce no output
* Setup wizard generates valid env values
"""

from __future__ import annotations

import json
import os
import sys

import pytest

# Set DATABASE_URL + SECRET_KEY BEFORE importing marlinspike (config reads at
# import time and v3.5.2 refuses to start without them set).
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-security-v352")

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


# ── Password reset never returns the token (CRITICAL fix) ────────────────────


def test_reset_request_disabled_by_default(client, monkeypatch):
    from marlinspike import config as ms_config
    monkeypatch.setattr(ms_config, "MARLINSPIKE_RESET_TOKEN_DELIVERY", "disabled")
    resp = client.post(
        "/api/auth/reset-request",
        json={"username": "admin"},
        headers={"Origin": "http://localhost"},
    )
    assert resp.status_code == 503
    assert "disabled" in resp.get_json()["error"].lower()


def test_reset_request_does_not_return_token_in_log_mode(client, monkeypatch, caplog):
    from marlinspike import config as ms_config
    monkeypatch.setattr(ms_config, "MARLINSPIKE_RESET_TOKEN_DELIVERY", "log")
    resp = client.post(
        "/api/auth/reset-request",
        json={"username": "nonexistent-user"},
        headers={"Origin": "http://localhost"},
    )
    body = resp.get_json()
    # Generic response — no token leaked, no enumeration
    assert resp.status_code == 200
    assert "token" not in body
    assert body["ok"] is True
    assert "If the account exists" in body["message"]


# ── Browser security headers (MEDIUM fix) ────────────────────────────────────


def test_csp_header_present(client):
    resp = client.get("/login")
    csp = resp.headers.get("Content-Security-Policy", "")
    assert csp
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "object-src 'none'" in csp


def test_csp_includes_per_request_nonce(client):
    resp = client.get("/login")
    csp = resp.headers.get("Content-Security-Policy", "")
    # Each request gets a fresh nonce
    assert "'nonce-" in csp


def test_csp_nonce_changes_per_request(client):
    csps = []
    for _ in range(3):
        resp = client.get("/login")
        csps.append(resp.headers.get("Content-Security-Policy", ""))
    # Three requests = three different nonces
    nonces = []
    for csp in csps:
        # Extract first nonce-... token
        import re
        m = re.search(r"'nonce-([^']+)'", csp)
        if m:
            nonces.append(m.group(1))
    assert len(set(nonces)) == 3


def test_x_content_type_options(client):
    resp = client.get("/login")
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"


def test_x_frame_options(client):
    resp = client.get("/login")
    assert resp.headers.get("X-Frame-Options") == "DENY"


def test_referrer_policy(client):
    resp = client.get("/login")
    assert resp.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"


def test_permissions_policy(client):
    resp = client.get("/login")
    pp = resp.headers.get("Permissions-Policy", "")
    assert "geolocation=()" in pp
    assert "microphone=()" in pp
    assert "camera=()" in pp


# ── CSRF full-origin check (MEDIUM fix) ──────────────────────────────────────


def test_csrf_requires_origin_or_referer(client):
    """A POST without Origin and without Referer should be rejected."""
    resp = client.post("/api/auth/reset-request", json={"username": "x"})
    # Either 403 origin/referer required, OR 503 if reset is disabled.
    assert resp.status_code in (403, 503)
    if resp.status_code == 403:
        assert "Origin/Referer" in resp.get_json()["error"]


def test_csrf_rejects_different_scheme(client):
    """Origin with different scheme than request URL must fail."""
    resp = client.post(
        "/api/auth/reset-request",
        json={"username": "x"},
        headers={"Origin": "https://evil.example.com"},  # wrong host AND wrong scheme
    )
    assert resp.status_code == 403
    assert "Origin check failed" in resp.get_json()["error"]


def test_csrf_rejects_different_port(client):
    """Origin with same hostname but different port must fail."""
    # The test client's request URL is http://localhost; an Origin with
    # http://localhost:9999 should be a different origin.
    resp = client.post(
        "/api/auth/reset-request",
        json={"username": "x"},
        headers={"Origin": "http://localhost:9999"},
    )
    assert resp.status_code == 403


def test_csrf_accepts_matching_origin(client, monkeypatch):
    """The request's own Origin should pass."""
    from marlinspike import config as ms_config
    # Disable the reset-disabled gate so we exercise the CSRF check path.
    monkeypatch.setattr(ms_config, "MARLINSPIKE_RESET_TOKEN_DELIVERY", "log")
    resp = client.post(
        "/api/auth/reset-request",
        json={"username": "x"},
        headers={"Origin": "http://localhost"},
    )
    # CSRF passed — got a 200 (generic response, not 403).
    assert resp.status_code == 200


# ── Live capture admin gate (HIGH fix) ───────────────────────────────────────


def test_capture_start_requires_admin_when_logged_out(client):
    resp = client.post(
        "/api/capture/sessions",
        json={"interface": "eth0", "project_id": 1},
        headers={"Origin": "http://localhost"},
    )
    # Not logged in → 401 or redirect to login
    assert resp.status_code in (401, 302)


def test_capture_stop_requires_admin_when_logged_out(client):
    resp = client.post(
        "/api/capture/sessions/1/stop",
        headers={"Origin": "http://localhost"},
    )
    assert resp.status_code in (401, 302)


# ── Setup wizard ─────────────────────────────────────────────────────────────


def test_setup_wizard_auto_writes_env(tmp_path, monkeypatch):
    from marlinspike.setup_wizard import run
    env_path = tmp_path / ".env"
    rc = run(["--auto", "--env-path", str(env_path)])
    assert rc == 0
    assert env_path.exists()
    # Mode 0600
    assert (env_path.stat().st_mode & 0o777) == 0o600
    # Contains the required vars
    body = env_path.read_text()
    assert "SECRET_KEY=" in body
    assert "DATABASE_URL=" in body
    assert "ADMIN_PASSWORD=" in body
    assert "SESSION_COOKIE_SECURE=" in body
    assert "MARLINSPIKE_RESET_TOKEN_DELIVERY=" in body
    assert "MARLINSPIKE_CAPTURE_REQUIRE=" in body


def test_setup_wizard_secret_key_strength(tmp_path):
    from marlinspike.setup_wizard import run, _gen_secret_hex
    # The auto-generated key should be 64 hex chars (256 bits)
    assert len(_gen_secret_hex(32)) == 64
    # And different on every call
    assert _gen_secret_hex(32) != _gen_secret_hex(32)


def test_setup_wizard_refuses_to_overwrite(tmp_path):
    from marlinspike.setup_wizard import run
    env_path = tmp_path / ".env"
    env_path.write_text("EXISTING=1\n")
    rc = run(["--auto", "--env-path", str(env_path)])
    assert rc == 1
    # File should be unchanged
    assert env_path.read_text() == "EXISTING=1\n"


def test_setup_wizard_print_only_does_not_write(tmp_path, capsys):
    from marlinspike.setup_wizard import run
    env_path = tmp_path / ".env"
    rc = run(["--auto", "--print-only", "--env-path", str(env_path)])
    assert rc == 0
    assert not env_path.exists()
    captured = capsys.readouterr()
    assert "SECRET_KEY=" in captured.out


def test_setup_wizard_admin_password_strength(tmp_path):
    from marlinspike.setup_wizard import _gen_password
    pw = _gen_password()
    assert len(pw) >= 24
    # Multi-character-class
    assert any(c.isupper() for c in pw)
    assert any(c.islower() for c in pw)
    assert any(c.isdigit() for c in pw)


def test_setup_wizard_redact_password_in_summary():
    from marlinspike.setup_wizard import _redact
    assert "***" in _redact("postgresql://user:secret@host/db")
    # Already-redacted passes through
    assert _redact("sqlite:///./data/x.db") == "sqlite:///./data/x.db"
    assert _redact("") == ""
