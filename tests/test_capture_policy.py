"""Tests for capture policy gates (v3.5.3).

Covers:
* System-wide interface allowlist (MARLINSPIKE_CAPTURE_INTERFACE_ALLOWLIST)
* Per-project capture_policy: enabled=false rejection
* allowed_interfaces intersection with system allowlist
* max_session_duration_s cap + audit emission
* operator_warning propagation in start-session response
* GET/PUT /api/capture/policy/<pid> endpoint shape
* Policy endpoint is admin-or-owner only (non-owner non-admin gets 404)
"""

from __future__ import annotations

import json
import os
import sys
import unittest.mock as mock

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-capture-policy")
# Disable dev insecure cookie flag so test client session cookies work.
os.environ.setdefault("MARLINSPIKE_DEV_INSECURE_COOKIES", "true")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

_CSRF_HEADERS = {"Origin": "http://localhost"}


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def flask_app():
    import marlinspike.config as _cfg
    _cfg.DATABASE_URL = "sqlite:///:memory:"

    from marlinspike.app import create_app
    application = create_app()
    application.config["TESTING"] = True
    application.config["WTF_CSRF_ENABLED"] = False

    with application.app_context():
        from marlinspike.auth import create_user
        from marlinspike.models import User, Project, db
        # Admin user for most tests.
        try:
            create_user("policy_admin", "adminpass", role="admin")
        except Exception:
            pass
        # Non-admin for ownership tests.
        try:
            create_user("policy_other", "otherpass", role="user")
        except Exception:
            pass

        admin = User.query.filter_by(username="policy_admin").first()
        other = User.query.filter_by(username="policy_other").first()

        # Each user gets a Default project.
        for u in (admin, other):
            if not Project.query.filter_by(user_id=u.id, name="Default").first():
                db.session.add(Project(user_id=u.id, name="Default"))
        db.session.commit()

    return application


def _make_client(app, username, password):
    client = app.test_client()
    client.post(
        "/login",
        data={"username": username, "password": password},
        headers=_CSRF_HEADERS,
        follow_redirects=False,
    )
    return client


@pytest.fixture(scope="module")
def admin_client(flask_app):
    return _make_client(flask_app, "policy_admin", "adminpass"), flask_app


@pytest.fixture(scope="module")
def other_client(flask_app):
    return _make_client(flask_app, "policy_other", "otherpass"), flask_app


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def _get_or_create_project(app, username, name):
    from marlinspike.models import User, Project, db
    with app.app_context():
        u = User.query.filter_by(username=username).first()
        p = Project.query.filter_by(user_id=u.id, name=name).first()
        if p is None:
            p = Project(user_id=u.id, name=name)
            db.session.add(p)
            db.session.commit()
        return p.id, u.id


def _set_project_policy(app, pid, policy_dict):
    from marlinspike.models import Project, db
    with app.app_context():
        p = db.session.get(Project, pid)
        p.capture_policy = json.dumps(policy_dict) if policy_dict is not None else None
        db.session.commit()


# ---------------------------------------------------------------------------
# _resolve_interface_allowlist unit tests (no HTTP, no DB)
# ---------------------------------------------------------------------------

def test_resolve_allowlist_no_restriction():
    """Both system and project unset → None (any interface allowed)."""
    from marlinspike.capture.api import _resolve_interface_allowlist
    assert _resolve_interface_allowlist({}) is None


def test_resolve_allowlist_system_only(monkeypatch):
    from marlinspike import config as ms_config
    from marlinspike.capture.api import _resolve_interface_allowlist
    monkeypatch.setattr(ms_config, "MARLINSPIKE_CAPTURE_INTERFACE_ALLOWLIST", ["eth0", "eth1"])
    result = _resolve_interface_allowlist({})
    assert set(result) == {"eth0", "eth1"}


def test_resolve_allowlist_project_only(monkeypatch):
    from marlinspike import config as ms_config
    from marlinspike.capture.api import _resolve_interface_allowlist
    monkeypatch.setattr(ms_config, "MARLINSPIKE_CAPTURE_INTERFACE_ALLOWLIST", [])
    result = _resolve_interface_allowlist({"allowed_interfaces": ["eth0", "tap0"]})
    assert set(result) == {"eth0", "tap0"}


def test_resolve_allowlist_intersection(monkeypatch):
    """System=[eth0,eth1], project=[eth1,eth2] → intersection=[eth1]."""
    from marlinspike import config as ms_config
    from marlinspike.capture.api import _resolve_interface_allowlist
    monkeypatch.setattr(ms_config, "MARLINSPIKE_CAPTURE_INTERFACE_ALLOWLIST", ["eth0", "eth1"])
    result = _resolve_interface_allowlist({"allowed_interfaces": ["eth1", "eth2"]})
    assert result == ["eth1"]


def test_resolve_allowlist_empty_intersection(monkeypatch):
    """System=[eth0], project=[eth1] → empty list (nothing permitted)."""
    from marlinspike import config as ms_config
    from marlinspike.capture.api import _resolve_interface_allowlist
    monkeypatch.setattr(ms_config, "MARLINSPIKE_CAPTURE_INTERFACE_ALLOWLIST", ["eth0"])
    result = _resolve_interface_allowlist({"allowed_interfaces": ["eth1"]})
    assert result == []


# ---------------------------------------------------------------------------
# _validate_policy_body unit tests
# ---------------------------------------------------------------------------

def test_validate_policy_unknown_key():
    from marlinspike.capture.api import _validate_policy_body
    err = _validate_policy_body({"enabled": True, "bad_key": "x"})
    assert err is not None
    assert "bad_key" in err


def test_validate_policy_valid_full():
    from marlinspike.capture.api import _validate_policy_body
    assert _validate_policy_body({
        "enabled": True,
        "allowed_interfaces": ["eth0"],
        "max_session_duration_s": 3600,
        "max_total_bytes": None,
        "operator_warning": "Check scope first.",
    }) is None


def test_validate_policy_enabled_not_bool():
    from marlinspike.capture.api import _validate_policy_body
    err = _validate_policy_body({"enabled": "yes"})
    assert err is not None


def test_validate_policy_max_duration_negative():
    from marlinspike.capture.api import _validate_policy_body
    err = _validate_policy_body({"max_session_duration_s": -1})
    assert err is not None


def test_validate_policy_empty_body():
    from marlinspike.capture.api import _validate_policy_body
    assert _validate_policy_body({}) is None


# ---------------------------------------------------------------------------
# HTTP endpoint tests — policy GET / PUT
# ---------------------------------------------------------------------------

def test_get_policy_returns_empty_for_new_project(flask_app, admin_client):
    client, app = admin_client
    pid, _ = _get_or_create_project(app, "policy_admin", "GetPolicyTest")
    _set_project_policy(app, pid, None)

    resp = client.get(f"/api/capture/policy/{pid}", headers=_CSRF_HEADERS)
    assert resp.status_code == 200
    j = resp.get_json()
    assert j["ok"] is True
    assert j["policy"] == {}
    assert j["project_id"] == pid


def test_put_policy_sets_and_returns(flask_app, admin_client):
    client, app = admin_client
    pid, _ = _get_or_create_project(app, "policy_admin", "PutPolicyTest")
    _set_project_policy(app, pid, None)

    body = {
        "enabled": True,
        "allowed_interfaces": ["eth0"],
        "max_session_duration_s": 3600,
        "operator_warning": "OT scope — confirm before capture.",
    }
    resp = client.put(
        f"/api/capture/policy/{pid}",
        json=body,
        headers={**_CSRF_HEADERS, "Content-Type": "application/json"},
    )
    assert resp.status_code == 200
    j = resp.get_json()
    assert j["ok"] is True
    assert j["policy"]["enabled"] is True
    assert j["policy"]["allowed_interfaces"] == ["eth0"]
    assert j["policy"]["operator_warning"] == "OT scope — confirm before capture."


def test_put_policy_rejects_unknown_keys(flask_app, admin_client):
    client, app = admin_client
    pid, _ = _get_or_create_project(app, "policy_admin", "BadKeyTest")

    resp = client.put(
        f"/api/capture/policy/{pid}",
        json={"enabled": True, "rogue_field": "x"},
        headers={**_CSRF_HEADERS, "Content-Type": "application/json"},
    )
    assert resp.status_code == 400
    j = resp.get_json()
    assert j["ok"] is False
    assert "rogue_field" in j["error"]


def test_policy_endpoint_non_owner_non_admin(flask_app, admin_client, other_client):
    """Non-admin user that doesn't own the project should get 404."""
    _, app = admin_client
    pid, _ = _get_or_create_project(app, "policy_admin", "OwnerTest")

    other, _ = other_client
    resp = other.get(f"/api/capture/policy/{pid}", headers=_CSRF_HEADERS)
    # Not owner, not admin → 404.
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# start_session gate tests — patch capd out entirely
# ---------------------------------------------------------------------------

def _mock_capture_deps(monkeypatch, flask_app):
    """Patch capd client and session manager so start_session runs without a real capd."""
    import marlinspike.capture.api as cap_api
    import marlinspike.capture.sessions as sessions_mod

    monkeypatch.setattr(sessions_mod.manager, "active_session_count", lambda: 0)
    monkeypatch.setattr(sessions_mod.manager, "acquire_interface", lambda iface, sid: None)
    monkeypatch.setattr(sessions_mod.manager, "release_interface", lambda iface, sid: None)
    monkeypatch.setattr(sessions_mod.manager, "register_hub", lambda hub: None)

    fake_client = mock.MagicMock()
    fake_client.start.return_value = {"output_dir": "/tmp/test-capture"}
    monkeypatch.setattr(cap_api, "_client", lambda: fake_client)

    import marlinspike.capture.consumer as consumer_mod
    monkeypatch.setattr(consumer_mod, "make_listener",
                        lambda **kw: (lambda path: None))

    fake_hub = mock.MagicMock()
    fake_hub.last_frame = None
    monkeypatch.setattr(sessions_mod, "StatsHub", lambda **kw: fake_hub)

    return fake_client


def test_start_session_system_allowlist_denied(flask_app, monkeypatch, admin_client):
    """System allowlist blocks the requested interface → 403."""
    from marlinspike import config as ms_config
    monkeypatch.setattr(ms_config, "MARLINSPIKE_CAPTURE_INTERFACE_ALLOWLIST", ["eth0"])
    monkeypatch.setattr(ms_config, "LIVE_CAPTURE_ENABLED", True)

    client, app = admin_client
    pid, _ = _get_or_create_project(app, "policy_admin", "AllowlistDenied")
    _set_project_policy(app, pid, None)
    _mock_capture_deps(monkeypatch, app)

    resp = client.post(
        "/api/capture/sessions",
        json={"project_id": pid, "interface": "eth1"},
        headers={**_CSRF_HEADERS, "Content-Type": "application/json"},
    )
    assert resp.status_code == 403
    j = resp.get_json()
    assert j["ok"] is False
    assert "eth1" in j["error"]


def test_start_session_system_allowlist_allowed(flask_app, monkeypatch, admin_client):
    """System allowlist permits the requested interface → accepted (201)."""
    from marlinspike import config as ms_config
    monkeypatch.setattr(ms_config, "MARLINSPIKE_CAPTURE_INTERFACE_ALLOWLIST", ["eth0", "eth1"])
    monkeypatch.setattr(ms_config, "LIVE_CAPTURE_ENABLED", True)

    client, app = admin_client
    pid, _ = _get_or_create_project(app, "policy_admin", "AllowlistAllowed")
    _set_project_policy(app, pid, None)
    _mock_capture_deps(monkeypatch, app)

    resp = client.post(
        "/api/capture/sessions",
        json={"project_id": pid, "interface": "eth1"},
        headers={**_CSRF_HEADERS, "Content-Type": "application/json"},
    )
    assert resp.status_code == 201
    assert resp.get_json()["ok"] is True


def test_start_session_project_disabled(flask_app, monkeypatch, admin_client):
    """Project capture_policy.enabled=false → 403."""
    from marlinspike import config as ms_config
    monkeypatch.setattr(ms_config, "MARLINSPIKE_CAPTURE_INTERFACE_ALLOWLIST", [])
    monkeypatch.setattr(ms_config, "LIVE_CAPTURE_ENABLED", True)

    client, app = admin_client
    pid, _ = _get_or_create_project(app, "policy_admin", "ProjectDisabled")
    _set_project_policy(app, pid, {"enabled": False})
    _mock_capture_deps(monkeypatch, app)

    resp = client.post(
        "/api/capture/sessions",
        json={"project_id": pid, "interface": "eth0"},
        headers={**_CSRF_HEADERS, "Content-Type": "application/json"},
    )
    assert resp.status_code == 403
    j = resp.get_json()
    assert j["ok"] is False
    assert "disabled" in j["error"].lower()


def test_start_session_allowlist_intersection_denied(flask_app, monkeypatch, admin_client):
    """System=[eth0], project=[eth1] → intersection empty → 403."""
    from marlinspike import config as ms_config
    monkeypatch.setattr(ms_config, "MARLINSPIKE_CAPTURE_INTERFACE_ALLOWLIST", ["eth0"])
    monkeypatch.setattr(ms_config, "LIVE_CAPTURE_ENABLED", True)

    client, app = admin_client
    pid, _ = _get_or_create_project(app, "policy_admin", "IntersectDenied")
    _set_project_policy(app, pid, {"allowed_interfaces": ["eth1"]})
    _mock_capture_deps(monkeypatch, app)

    resp = client.post(
        "/api/capture/sessions",
        json={"project_id": pid, "interface": "eth1"},
        headers={**_CSRF_HEADERS, "Content-Type": "application/json"},
    )
    assert resp.status_code == 403
    assert resp.get_json()["ok"] is False


def test_start_session_allowlist_intersection_allowed(flask_app, monkeypatch, admin_client):
    """System=[eth0,eth1], project=[eth1,eth2] → intersection=[eth1] → eth1 allowed."""
    from marlinspike import config as ms_config
    monkeypatch.setattr(ms_config, "MARLINSPIKE_CAPTURE_INTERFACE_ALLOWLIST", ["eth0", "eth1"])
    monkeypatch.setattr(ms_config, "LIVE_CAPTURE_ENABLED", True)

    client, app = admin_client
    pid, _ = _get_or_create_project(app, "policy_admin", "IntersectAllowed")
    _set_project_policy(app, pid, {"allowed_interfaces": ["eth1", "eth2"]})
    _mock_capture_deps(monkeypatch, app)

    resp = client.post(
        "/api/capture/sessions",
        json={"project_id": pid, "interface": "eth1"},
        headers={**_CSRF_HEADERS, "Content-Type": "application/json"},
    )
    assert resp.status_code == 201
    assert resp.get_json()["ok"] is True


def test_start_session_duration_cap_applied(flask_app, monkeypatch, admin_client):
    """Request 7200s with project cap of 3600s → applied duration is 3600s, audit emitted."""
    from marlinspike import config as ms_config
    monkeypatch.setattr(ms_config, "MARLINSPIKE_CAPTURE_INTERFACE_ALLOWLIST", [])
    monkeypatch.setattr(ms_config, "LIVE_CAPTURE_ENABLED", True)

    client, app = admin_client
    pid, _ = _get_or_create_project(app, "policy_admin", "DurationCap")
    _set_project_policy(app, pid, {"max_session_duration_s": 3600})

    audit_calls = []
    import marlinspike.capture.api as cap_api
    monkeypatch.setattr(cap_api, "audit", lambda event, **kw: audit_calls.append((event, kw)))
    _mock_capture_deps(monkeypatch, app)

    resp = client.post(
        "/api/capture/sessions",
        json={"project_id": pid, "interface": "eth0", "max_duration_s": 7200},
        headers={**_CSRF_HEADERS, "Content-Type": "application/json"},
    )
    assert resp.status_code == 201
    j = resp.get_json()
    assert j["ok"] is True
    # The stored session must have the capped duration.
    assert j["session"]["max_duration_s"] == 3600

    # Audit event for the cap must be present.
    cap_events = [e for e, _ in audit_calls if e == "capture.policy_capped"]
    assert len(cap_events) >= 1
    kw_detail = next(kw for e, kw in audit_calls if e == "capture.policy_capped")
    detail = json.loads(kw_detail["detail"])
    assert detail["requested"] == 7200
    assert detail["applied"] == 3600


def test_start_session_total_bytes_cap_applied(flask_app, monkeypatch, admin_client):
    """Request a 20 MiB ring with a 5 MiB policy cap → ring settings are reduced."""
    from marlinspike import config as ms_config
    monkeypatch.setattr(ms_config, "MARLINSPIKE_CAPTURE_INTERFACE_ALLOWLIST", [])
    monkeypatch.setattr(ms_config, "LIVE_CAPTURE_ENABLED", True)

    client, app = admin_client
    pid, _ = _get_or_create_project(app, "policy_admin", "BytesCap")
    _set_project_policy(app, pid, {"max_total_bytes": 5 * 1024 * 1024})

    audit_calls = []
    import marlinspike.capture.api as cap_api
    monkeypatch.setattr(cap_api, "audit", lambda event, **kw: audit_calls.append((event, kw)))
    _mock_capture_deps(monkeypatch, app)

    resp = client.post(
        "/api/capture/sessions",
        json={
            "project_id": pid,
            "interface": "eth0",
            "ring_filesize_kb": 2048,
            "ring_files": 10,
        },
        headers={**_CSRF_HEADERS, "Content-Type": "application/json"},
    )
    assert resp.status_code == 201
    j = resp.get_json()
    assert j["ok"] is True

    retained_bytes = j["session"]["ring_filesize_kb"] * 1024 * j["session"]["ring_files"]
    assert retained_bytes <= 5 * 1024 * 1024

    kw_detail = next(kw for e, kw in audit_calls if e == "capture.policy_capped" and '"field": "max_total_bytes"' in kw["detail"])
    detail = json.loads(kw_detail["detail"])
    assert detail["requested"] == 2048 * 1024 * 10
    assert detail["applied"] == retained_bytes


def test_start_session_operator_warning_propagated(flask_app, monkeypatch, admin_client):
    """operator_warning present in policy → included in start response."""
    from marlinspike import config as ms_config
    monkeypatch.setattr(ms_config, "MARLINSPIKE_CAPTURE_INTERFACE_ALLOWLIST", [])
    monkeypatch.setattr(ms_config, "LIVE_CAPTURE_ENABLED", True)

    client, app = admin_client
    pid, _ = _get_or_create_project(app, "policy_admin", "WarningProp")
    warning_msg = "OT engagement — confirm scope before starting capture."
    _set_project_policy(app, pid, {"operator_warning": warning_msg})

    import marlinspike.capture.api as cap_api
    monkeypatch.setattr(cap_api, "audit", lambda *a, **kw: None)
    _mock_capture_deps(monkeypatch, app)

    resp = client.post(
        "/api/capture/sessions",
        json={"project_id": pid, "interface": "eth0"},
        headers={**_CSRF_HEADERS, "Content-Type": "application/json"},
    )
    assert resp.status_code == 201
    j = resp.get_json()
    assert j["ok"] is True
    assert j.get("operator_warning") == warning_msg
