"""Tests for project sharing: ProjectMember model, _get_project_for_user role
gating, the membership CRUD API, and cross-user access through shared routes."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret-key-sharing")


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


_ORIGIN = "http://localhost"
_H = {"Origin": _ORIGIN}


def _make_user(db, username, password="pw") -> int:
    """Create the user (idempotent) and return its id."""
    from marlinspike.auth import create_user
    from marlinspike.models import User
    try:
        user = create_user(username, password)
        db.session.commit()
    except Exception:
        db.session.rollback()
        user = User.query.filter_by(username=username).first()
    return user.id


def _make_project(db, user_id, name="Shared Project") -> int:
    from marlinspike.models import Project
    proj = Project(user_id=user_id, name=name)
    db.session.add(proj)
    db.session.commit()
    return proj.id


def _add_member(db, project_id, user_id, role, invited_by=None):
    from marlinspike.models import ProjectMember
    db.session.add(ProjectMember(
        project_id=project_id, user_id=user_id, role=role, invited_by=invited_by
    ))
    db.session.commit()


def _client(app, username):
    """Return a test client with an injected session for ``username``."""
    from marlinspike.models import User
    c = app.test_client()
    with app.app_context():
        u = User.query.filter_by(username=username).first()
        ident = (u.username, u.id, u.role, u.session_version or 1)
    with c.session_transaction() as sess:
        sess["user"], sess["user_id"], sess["role"], sess["session_version"] = ident
    return c


# ── Model ─────────────────────────────────────────────────────────────────────

def test_project_member_uniqueness(app, db):
    """(project_id, user_id) must be unique."""
    import sqlalchemy.exc
    from marlinspike.models import ProjectMember

    with app.app_context():
        owner_id = _make_user(db, "uq_owner")
        guest_id = _make_user(db, "uq_guest")
        pid = _make_project(db, owner_id, "UQ Share")
        _add_member(db, pid, guest_id, "viewer")

        db.session.add(ProjectMember(project_id=pid, user_id=guest_id, role="editor"))
        with pytest.raises((sqlalchemy.exc.IntegrityError, Exception)):
            db.session.commit()
        db.session.rollback()


# ── _get_project_for_user role gating ─────────────────────────────────────────

@pytest.mark.parametrize(
    "member_role,min_role,expect_access",
    [
        (None, "viewer", False),     # non-member
        ("viewer", "viewer", True),
        ("viewer", "editor", False),
        ("viewer", "owner", False),
        ("editor", "viewer", True),
        ("editor", "editor", True),
        ("editor", "owner", False),
        ("owner", "owner", True),
    ],
)
def test_get_project_for_user_role_gate(app, db, member_role, min_role, expect_access):
    from marlinspike.app import _get_project_for_user

    with app.app_context():
        owner_id = _make_user(db, f"gate_owner_{member_role}_{min_role}")
        guest_id = _make_user(db, f"gate_guest_{member_role}_{min_role}")
        pid = _make_project(db, owner_id, "Gate Proj")
        if member_role is not None:
            _add_member(db, pid, guest_id, member_role)

    with app.test_request_context():
        from flask import session
        session["user_id"] = guest_id
        resolved = _get_project_for_user(pid, min_role)
        assert (resolved is not None) is expect_access


def test_get_project_for_user_creator_always_owner(app, db):
    from marlinspike.app import _get_project_for_user

    with app.app_context():
        owner_id = _make_user(db, "creator_owner")
        pid = _make_project(db, owner_id, "Creator Proj")

    with app.test_request_context():
        from flask import session
        session["user_id"] = owner_id
        assert _get_project_for_user(pid, "owner") is not None


def test_get_project_for_user_no_session_or_missing(app, db):
    from marlinspike.app import _get_project_for_user

    with app.app_context():
        owner_id = _make_user(db, "missing_owner")
        pid = _make_project(db, owner_id, "Missing Proj")

    with app.test_request_context():
        assert _get_project_for_user(pid) is None  # no user_id in session

    with app.test_request_context():
        from flask import session
        session["user_id"] = owner_id
        assert _get_project_for_user(999999) is None  # project does not exist


# ── Membership CRUD API ───────────────────────────────────────────────────────

def test_members_list_includes_creator_and_members(app, db):
    with app.app_context():
        owner_id = _make_user(db, "list_owner")
        guest_id = _make_user(db, "list_guest")
        pid = _make_project(db, owner_id, "List Proj")
        _add_member(db, pid, guest_id, "editor", invited_by=owner_id)

    rv = _client(app, "list_owner").get(f"/api/projects/{pid}/members")
    assert rv.status_code == 200
    members = {m["user_id"]: m for m in rv.get_json()["members"]}
    assert members[owner_id]["role"] == "owner"
    assert members[owner_id]["is_creator"] is True
    assert members[guest_id]["role"] == "editor"
    assert members[guest_id]["is_creator"] is False


def test_member_add_update_remove_flow(app, db):
    with app.app_context():
        owner_id = _make_user(db, "flow_owner")
        guest_id = _make_user(db, "flow_guest")
        pid = _make_project(db, owner_id, "Flow Proj")

    c = _client(app, "flow_owner")

    rv = c.post(f"/api/projects/{pid}/members", json={"username": "flow_guest", "role": "viewer"}, headers=_H)
    assert rv.status_code == 200
    assert rv.get_json()["role"] == "viewer"

    # Re-adding upserts the role rather than erroring.
    rv = c.post(f"/api/projects/{pid}/members", json={"username": "flow_guest", "role": "editor"}, headers=_H)
    assert rv.status_code == 200
    assert rv.get_json()["role"] == "editor"

    rv = c.put(f"/api/projects/{pid}/members/{guest_id}", json={"role": "owner"}, headers=_H)
    assert rv.status_code == 200

    rv = c.delete(f"/api/projects/{pid}/members/{guest_id}", headers=_H)
    assert rv.status_code == 200
    from marlinspike.models import ProjectMember
    with app.app_context():
        assert ProjectMember.query.filter_by(project_id=pid, user_id=guest_id).first() is None


def test_member_add_validation(app, db):
    with app.app_context():
        owner_id = _make_user(db, "val_owner")
        pid = _make_project(db, owner_id, "Val Proj")

    c = _client(app, "val_owner")

    rv = c.post(f"/api/projects/{pid}/members", json={"username": "val_owner", "role": "bogus"}, headers=_H)
    assert rv.status_code == 400

    rv = c.post(f"/api/projects/{pid}/members", json={"username": "nobody_here", "role": "viewer"}, headers=_H)
    assert rv.status_code == 404

    rv = c.post(f"/api/projects/{pid}/members", json={"username": "val_owner", "role": "viewer"}, headers=_H)
    assert rv.status_code == 409  # creator is already owner


def test_member_routes_reject_non_owner(app, db):
    with app.app_context():
        owner_id = _make_user(db, "ro_owner")
        editor_id = _make_user(db, "ro_editor")
        pid = _make_project(db, owner_id, "RO Proj")
        _add_member(db, pid, editor_id, "editor")

    c = _client(app, "ro_editor")
    # An editor member may list but may not mutate membership.
    assert c.get(f"/api/projects/{pid}/members").status_code == 200
    rv = c.post(f"/api/projects/{pid}/members", json={"username": "ro_owner", "role": "viewer"}, headers=_H)
    assert rv.status_code == 404


def test_member_update_cannot_target_creator(app, db):
    with app.app_context():
        owner_id = _make_user(db, "cc_owner")
        pid = _make_project(db, owner_id, "CC Proj")

    c = _client(app, "cc_owner")
    rv = c.put(f"/api/projects/{pid}/members/{owner_id}", json={"role": "viewer"}, headers=_H)
    assert rv.status_code == 400
    rv = c.delete(f"/api/projects/{pid}/members/{owner_id}", headers=_H)
    assert rv.status_code == 400


# ── Cross-user access through shared project routes ───────────────────────────

def test_shared_viewer_can_read_but_not_write(app, db):
    """A viewer member reads asset-tags from the creator's project but cannot
    mutate them; promoting to editor unlocks writes."""
    with app.app_context():
        owner_id = _make_user(db, "x_owner")
        guest_id = _make_user(db, "x_guest")
        pid = _make_project(db, owner_id, "X Proj")
        _add_member(db, pid, guest_id, "viewer")

    gc = _client(app, "x_guest")

    assert gc.get(f"/api/projects/{pid}/asset-tags").status_code == 200

    rv = gc.put(
        f"/api/projects/{pid}/asset-tags/10.0.0.5",
        json={"criticality": "high"},
        headers=_H,
    )
    assert rv.status_code == 404  # viewer lacks editor rights

    with app.app_context():
        from marlinspike.models import ProjectMember
        m = ProjectMember.query.filter_by(project_id=pid, user_id=guest_id).first()
        m.role = "editor"
        db.session.commit()

    rv = gc.put(
        f"/api/projects/{pid}/asset-tags/10.0.0.5",
        json={"criticality": "high"},
        headers=_H,
    )
    assert rv.status_code == 200


def test_non_member_denied(app, db):
    with app.app_context():
        owner_id = _make_user(db, "nm_owner")
        _make_user(db, "nm_stranger")
        pid = _make_project(db, owner_id, "NM Proj")

    rv = _client(app, "nm_stranger").get(f"/api/projects/{pid}/asset-tags")
    assert rv.status_code == 404


def test_projects_list_reports_shared_projects(app, db):
    with app.app_context():
        owner_id = _make_user(db, "pl_owner")
        guest_id = _make_user(db, "pl_guest")
        own_id = _make_project(db, guest_id, "Guest Own")
        shared_id = _make_project(db, owner_id, "Owner Shared")
        _add_member(db, shared_id, guest_id, "editor")

    rv = _client(app, "pl_guest").get("/api/projects")
    assert rv.status_code == 200
    by_id = {p["id"]: p for p in rv.get_json()["projects"]}
    assert by_id[own_id]["is_owner"] is True
    assert by_id[own_id]["member_role"] == "owner"
    assert by_id[shared_id]["is_owner"] is False
    assert by_id[shared_id]["member_role"] == "editor"
