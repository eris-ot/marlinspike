"""Tests for Bet 2: AssetTag / FindingNote models, contextual severity, and CRUD API."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from unittest import mock

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret-key-bet2")


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def app():
    from marlinspike.app import create_app
    application = create_app()
    application.config["TESTING"] = True
    application.config["WTF_CSRF_ENABLED"] = False
    return application


@pytest.fixture(scope="module")
def db(app):
    from marlinspike.models import db as _db
    with app.app_context():
        _db.create_all()
        yield _db


@pytest.fixture()
def ctx(app, db):
    """Push an app context for each test; roll back after."""
    with app.app_context():
        yield


def _make_user(db, username, password="pw"):
    from marlinspike.auth import create_user
    try:
        user = create_user(username, password)
        db.session.commit()
        return user
    except Exception:
        db.session.rollback()
        from marlinspike.models import User
        return User.query.filter_by(username=username).first()


def _make_project(db, user_id, name="Test Project"):
    from marlinspike.models import Project
    proj = Project(user_id=user_id, name=name)
    db.session.add(proj)
    db.session.commit()
    return proj


_ORIGIN = "http://localhost"
_H = {"Origin": _ORIGIN}  # CSRF-safe header for mutating requests


def _login(client, username, password="pw"):
    return client.post(
        "/login",
        data={"username": username, "password": password},
        headers={"Origin": _ORIGIN},
        follow_redirects=True,
    )


def _inject_session(app, client, user):
    """Directly inject an authenticated session into the test client, bypassing login rate limits."""
    with client.session_transaction() as sess:
        sess["user"] = user.username
        sess["user_id"] = user.id
        sess["role"] = user.role
        sess["session_version"] = user.session_version or 1


# ── Model tests ──────────────────────────────────────────────────────────────

def test_asset_tag_uniqueness_constraint(ctx, db):
    """(project_id, asset_key) must be unique; duplicate insert should raise."""
    import sqlalchemy.exc
    from marlinspike.models import AssetTag

    user = _make_user(db, "uq_test_user")
    proj = _make_project(db, user.id, "UQ Project")

    t1 = AssetTag(project_id=proj.id, asset_key="aa:bb:cc:dd:ee:ff")
    db.session.add(t1)
    db.session.commit()

    t2 = AssetTag(project_id=proj.id, asset_key="aa:bb:cc:dd:ee:ff")
    db.session.add(t2)
    with pytest.raises((sqlalchemy.exc.IntegrityError, Exception)):
        db.session.commit()
    db.session.rollback()


def test_asset_tag_different_projects_same_key(ctx, db):
    """Same asset_key in different projects is allowed."""
    from marlinspike.models import AssetTag

    user = _make_user(db, "multiproj_user")
    p1 = _make_project(db, user.id, "Proj A")
    p2 = _make_project(db, user.id, "Proj B")

    db.session.add(AssetTag(project_id=p1.id, asset_key="10.0.0.1"))
    db.session.add(AssetTag(project_id=p2.id, asset_key="10.0.0.1"))
    db.session.commit()  # should not raise


# ── _finding_signature tests ──────────────────────────────────────────────────

def test_finding_signature_stable():
    """Same finding data must always produce the same signature."""
    from marlinspike.app import _finding_signature

    finding = {
        "category": "CROSS_PURDUE",
        "affected_nodes": ["10.0.0.1", "10.0.0.2"],
        "affected_edges": [],
    }
    sig1 = _finding_signature(finding)
    sig2 = _finding_signature(finding)
    assert sig1 == sig2
    assert len(sig1) == 32


def test_finding_signature_node_order_independent():
    """Node ordering must not affect the signature."""
    from marlinspike.app import _finding_signature

    f1 = {"category": "CROSS_PURDUE", "affected_nodes": ["10.0.0.1", "10.0.0.2"]}
    f2 = {"category": "CROSS_PURDUE", "affected_nodes": ["10.0.0.2", "10.0.0.1"]}
    assert _finding_signature(f1) == _finding_signature(f2)


def test_finding_signature_different_categories_differ():
    """Different categories must produce different signatures."""
    from marlinspike.app import _finding_signature

    f1 = {"category": "CROSS_PURDUE", "affected_nodes": ["10.0.0.1"]}
    f2 = {"category": "CLEARTEXT_ENG", "affected_nodes": ["10.0.0.1"]}
    assert _finding_signature(f1) != _finding_signature(f2)


# ── Contextual severity tests ─────────────────────────────────────────────────

def test_contextual_severity_high_plus_critical_asset():
    """HIGH finding with a critical-tagged affected node should bump to CRITICAL."""
    from marlinspike.app import _apply_contextual_severity

    findings = [{
        "category": "CROSS_PURDUE",
        "severity": "HIGH",
        "affected_nodes": ["10.0.0.5"],
    }]
    asset_tags = {"10.0.0.5": {"criticality": "critical", "asset_key": "10.0.0.5"}}
    result = _apply_contextual_severity(findings, asset_tags, {})
    assert result[0]["contextual_severity"] == "CRITICAL"
    assert "critical" in result[0]["contextual_severity_reason"]


def test_contextual_severity_already_critical_does_not_exceed():
    """CRITICAL with a critical-tagged asset must remain CRITICAL (cap)."""
    from marlinspike.app import _apply_contextual_severity

    findings = [{"category": "S7_PROGRAM_ACCESS", "severity": "CRITICAL", "affected_nodes": ["10.0.0.1"]}]
    asset_tags = {"10.0.0.1": {"criticality": "critical", "asset_key": "10.0.0.1"}}
    result = _apply_contextual_severity(findings, asset_tags, {})
    assert result[0]["contextual_severity"] == "CRITICAL"


def test_contextual_severity_medium_all_low_drops():
    """MEDIUM finding where all affected nodes are low-tagged should drop to LOW."""
    from marlinspike.app import _apply_contextual_severity

    findings = [{
        "category": "NO_AUTH_OBSERVED",
        "severity": "MEDIUM",
        "affected_nodes": ["10.0.1.1", "10.0.1.2"],
    }]
    asset_tags = {
        "10.0.1.1": {"criticality": "low", "asset_key": "10.0.1.1"},
        "10.0.1.2": {"criticality": "low", "asset_key": "10.0.1.2"},
    }
    result = _apply_contextual_severity(findings, asset_tags, {})
    assert result[0]["contextual_severity"] == "LOW"
    assert "low" in result[0]["contextual_severity_reason"]


def test_contextual_severity_partial_low_unchanged():
    """If only some (not all) affected nodes are low-tagged, severity unchanged."""
    from marlinspike.app import _apply_contextual_severity

    findings = [{"category": "CLEARTEXT_ENG", "severity": "HIGH", "affected_nodes": ["10.0.0.1", "10.0.0.2"]}]
    asset_tags = {
        "10.0.0.1": {"criticality": "low", "asset_key": "10.0.0.1"},
        # 10.0.0.2 untagged
    }
    result = _apply_contextual_severity(findings, asset_tags, {})
    assert result[0]["contextual_severity"] == "HIGH"
    assert result[0]["contextual_severity_reason"] == "unchanged"


def test_contextual_severity_info_floor():
    """INFO with all low-tagged nodes must remain INFO (floor)."""
    from marlinspike.app import _apply_contextual_severity

    findings = [{"category": "EXTERNAL_IPS_OBSERVED", "severity": "INFO", "affected_nodes": ["10.0.0.1"]}]
    asset_tags = {"10.0.0.1": {"criticality": "low", "asset_key": "10.0.0.1"}}
    result = _apply_contextual_severity(findings, asset_tags, {})
    assert result[0]["contextual_severity"] == "INFO"


def test_contextual_severity_note_attached(ctx, db):
    """Notes matching the finding signature should appear in the enriched finding."""
    from marlinspike.app import _apply_contextual_severity, _finding_signature
    from marlinspike.models import FindingNote

    user = _make_user(db, "note_ctx_user")
    proj = _make_project(db, user.id, "Note Context Project")
    finding = {"category": "CROSS_PURDUE", "severity": "HIGH", "affected_nodes": ["10.0.5.1"]}
    sig = _finding_signature(finding)

    note = FindingNote(
        project_id=proj.id,
        finding_signature=sig,
        report_filename="test.json",
        status="accepted",
        body="Accepted risk.",
        author_id=user.id,
    )
    db.session.add(note)
    db.session.commit()

    notes_by_sig = {sig: {
        "id": note.id,
        "status": note.status,
        "body": note.body,
        "author_id": note.author_id,
        "report_filename": note.report_filename,
        "created_at": None,
        "updated_at": None,
    }}
    result = _apply_contextual_severity([finding], {}, notes_by_sig)
    assert result[0]["note"] is not None
    assert result[0]["note"]["status"] == "accepted"


# ── API round-trip tests ──────────────────────────────────────────────────────

def _client(app, username):
    """Return a logged-in Flask test client using direct session injection (avoids rate limits)."""
    c = app.test_client()
    with app.app_context():
        from marlinspike.models import User
        user = User.query.filter_by(username=username).first()
    _inject_session(app, c, user)
    return c


def test_asset_tag_put_then_get(app, db):
    with app.app_context():
        user = _make_user(db, "at_put_user")
        proj = _make_project(db, user.id, "API Proj A")
        uid, pid = user.id, proj.id

    c = _client(app, "at_put_user")
    rv = c.put(
        f"/api/projects/{pid}/asset-tags/aa:bb:cc:dd:ee:ff",
        json={"owner": "ops", "criticality": "high", "zone": "Level2"},
        headers=_H,
    )
    assert rv.status_code == 200
    data = rv.get_json()
    assert data["asset_key"] == "aa:bb:cc:dd:ee:ff"
    assert data["owner"] == "ops"
    assert data["criticality"] == "high"

    rv2 = c.get(f"/api/projects/{pid}/asset-tags")
    assert rv2.status_code == 200
    tags = rv2.get_json()["asset_tags"]
    assert any(t["asset_key"] == "aa:bb:cc:dd:ee:ff" for t in tags)


def test_asset_tag_upsert_updates(app, db):
    with app.app_context():
        user = _make_user(db, "at_upsert_user")
        proj = _make_project(db, user.id, "API Upsert Proj")
        pid = proj.id

    c = _client(app, "at_upsert_user")
    c.put(f"/api/projects/{pid}/asset-tags/10.0.0.99", json={"criticality": "low"}, headers=_H)
    rv = c.put(f"/api/projects/{pid}/asset-tags/10.0.0.99", json={"criticality": "critical"}, headers=_H)
    assert rv.status_code == 200
    assert rv.get_json()["criticality"] == "critical"


def test_asset_tag_delete(app, db):
    with app.app_context():
        user = _make_user(db, "at_del_user")
        proj = _make_project(db, user.id, "Del Proj")
        pid = proj.id

    c = _client(app, "at_del_user")
    c.put(f"/api/projects/{pid}/asset-tags/del-me", json={"criticality": "low"}, headers=_H)
    rv = c.delete(f"/api/projects/{pid}/asset-tags/del-me", headers=_H)
    assert rv.status_code == 204

    rv2 = c.get(f"/api/projects/{pid}/asset-tags")
    tags = rv2.get_json()["asset_tags"]
    assert not any(t["asset_key"] == "del-me" for t in tags)


def test_asset_tag_invalid_criticality(app, db):
    with app.app_context():
        user = _make_user(db, "at_val_user")
        proj = _make_project(db, user.id, "Validation Proj")
        pid = proj.id

    c = _client(app, "at_val_user")
    rv = c.put(
        f"/api/projects/{pid}/asset-tags/10.0.0.1",
        json={"criticality": "extreme"},
        headers=_H,
    )
    assert rv.status_code == 400


def test_finding_note_put_then_get(app, db):
    from marlinspike.app import _finding_signature
    with app.app_context():
        user = _make_user(db, "fn_put_user")
        proj = _make_project(db, user.id, "Note Proj A")
        pid = proj.id
        sig = _finding_signature({"category": "CROSS_PURDUE", "affected_nodes": ["10.0.0.1"]})

    c = _client(app, "fn_put_user")
    rv = c.put(
        f"/api/projects/{pid}/notes/{sig}",
        json={"report_filename": "report.json", "status": "accepted", "body": "Risk accepted."},
        headers=_H,
    )
    assert rv.status_code == 200
    d = rv.get_json()
    assert d["status"] == "accepted"
    assert d["body"] == "Risk accepted."

    rv2 = c.get(f"/api/projects/{pid}/notes")
    notes = rv2.get_json()["notes"]
    assert any(n["finding_signature"] == sig for n in notes)


def test_finding_note_filter_by_report(app, db):
    from marlinspike.app import _finding_signature
    with app.app_context():
        user = _make_user(db, "fn_filter_user")
        proj = _make_project(db, user.id, "Note Filter Proj")
        pid = proj.id
        sig1 = _finding_signature({"category": "CLEARTEXT_ENG", "affected_nodes": ["10.0.0.2"]})
        sig2 = _finding_signature({"category": "MODBUS_WRITE_ANON", "affected_nodes": ["10.0.0.3"]})

    c = _client(app, "fn_filter_user")
    c.put(f"/api/projects/{pid}/notes/{sig1}", json={"report_filename": "r1.json", "status": "open"}, headers=_H)
    c.put(f"/api/projects/{pid}/notes/{sig2}", json={"report_filename": "r2.json", "status": "open"}, headers=_H)

    rv = c.get(f"/api/projects/{pid}/notes?report=r1.json")
    notes = rv.get_json()["notes"]
    assert all(n["report_filename"] == "r1.json" for n in notes)
    assert any(n["finding_signature"] == sig1 for n in notes)


def test_owner_scoping_asset_tags(app, db):
    """User B cannot access User A's project asset tags — expects 404."""
    with app.app_context():
        user_a = _make_user(db, "scope_a_user")
        user_b = _make_user(db, "scope_b_user")
        proj_a = _make_project(db, user_a.id, "A Private Proj")
        pid_a = proj_a.id

    c_a = _client(app, "scope_a_user")
    c_b = _client(app, "scope_b_user")

    c_a.put(f"/api/projects/{pid_a}/asset-tags/secret-asset", json={"criticality": "critical"}, headers=_H)

    rv = c_b.get(f"/api/projects/{pid_a}/asset-tags")
    assert rv.status_code == 404


def test_owner_scoping_notes(app, db):
    """User B cannot access User A's project notes — expects 404."""
    from marlinspike.app import _finding_signature
    with app.app_context():
        user_a = _make_user(db, "nscope_a_user")
        user_b = _make_user(db, "nscope_b_user")
        proj_a = _make_project(db, user_a.id, "A Note Private Proj")
        pid_a = proj_a.id
        sig = _finding_signature({"category": "CROSS_PURDUE", "affected_nodes": []})

    c_a = _client(app, "nscope_a_user")
    c_b = _client(app, "nscope_b_user")

    c_a.put(f"/api/projects/{pid_a}/notes/{sig}", json={"report_filename": "r.json", "status": "open"}, headers=_H)

    rv = c_b.get(f"/api/projects/{pid_a}/notes")
    assert rv.status_code == 404
