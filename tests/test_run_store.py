"""Tests for marlinspike.run_store — durable scan-state persistence."""

from __future__ import annotations

import json
import os

# Set DATABASE_URL BEFORE importing marlinspike — config reads at import time.
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret-runstore")

import pytest

from marlinspike import run_store
from marlinspike.app import create_app
from marlinspike.models import ScanHistory, User, db


@pytest.fixture
def app():
    """Flask app against an isolated SQLite for each test."""
    application = create_app()
    application.config["TESTING"] = True
    application.config["WTF_CSRF_ENABLED"] = False
    application.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    with application.app_context():
        db.drop_all()
        db.create_all()
    yield application


@pytest.fixture
def app_ctx(app):
    with app.app_context():
        yield


@pytest.fixture
def user(app_ctx):
    u = User(username="ru", password_hash="x", role="admin")
    db.session.add(u)
    db.session.commit()
    return u


def test_record_start_creates_row_with_recovery_columns(app_ctx, user):
    run_store.record_start(
        "run-1",
        user_id=user.id,
        project_id=None,
        command="chain",
        scan_profile="full",
        pcap_source="x.pcap",
        pcap_hash="abc",
        pcap_path="/tmp/x.pcap",
        report_path="/tmp/r.json",
        engine_pid=12345,
        engine_argv=["python", "-u", "-m", "marlinspike", "--pcap", "/tmp/x.pcap"],
        timeout_s=600,
    )
    rec = ScanHistory.query.filter_by(run_id="run-1").first()
    assert rec is not None
    assert rec.status == "running"
    assert rec.engine_pid == 12345
    argv = json.loads(rec.engine_argv)
    assert argv[0] == "python"
    assert "marlinspike" in argv
    assert rec.timeout_at is not None
    assert rec.recovery_state is None


def test_record_start_with_no_timeout(app_ctx, user):
    run_store.record_start(
        "run-2",
        user_id=user.id,
        project_id=None,
        command="dissect",
        scan_profile="fast",
        pcap_source=None,
        pcap_hash=None,
        pcap_path="/tmp/x.pcap",
        report_path="/tmp/r.json",
        engine_pid=None,
        engine_argv=None,
        timeout_s=0,
    )
    rec = ScanHistory.query.filter_by(run_id="run-2").first()
    assert rec.timeout_at is None
    assert rec.engine_pid is None
    assert rec.engine_argv is None


def test_record_finish_clears_pid_and_writes_recovery_state(app_ctx, user):
    run_store.record_start(
        "run-3",
        user_id=user.id,
        project_id=None,
        command="chain",
        scan_profile="full",
        pcap_source="x.pcap",
        pcap_hash="abc",
        pcap_path="/tmp/x.pcap",
        report_path="/tmp/r.json",
        engine_pid=999,
        engine_argv=["python", "-m", "marlinspike"],
    )
    run_store.record_finish(
        "run-3",
        status="completed",
        node_count=12,
        edge_count=20,
        recovery_state="reaped_completed",
    )
    rec = ScanHistory.query.filter_by(run_id="run-3").first()
    assert rec.status == "completed"
    assert rec.node_count == 12
    assert rec.edge_count == 20
    assert rec.recovery_state == "reaped_completed"
    assert rec.engine_pid is None  # cleared on terminal
    assert rec.completed_at is not None


def test_get_active_for_recovery_returns_only_running(app_ctx, user):
    for run_id, status in [("a", "running"), ("b", "completed"), ("c", "running"), ("d", "failed")]:
        rec = ScanHistory(
            run_id=run_id, user_id=user.id, command="chain", status=status,
        )
        db.session.add(rec)
    db.session.commit()
    active = run_store.get_active_for_recovery()
    assert {r.run_id for r in active} == {"a", "c"}


def test_get_active_count_per_user(app_ctx, user):
    other = User(username="other", password_hash="y", role="user")
    db.session.add(other)
    db.session.commit()
    for run_id, uid in [("u1a", user.id), ("u1b", user.id), ("u2a", other.id)]:
        rec = ScanHistory(run_id=run_id, user_id=uid, command="chain", status="running")
        db.session.add(rec)
    db.session.commit()
    assert run_store.get_active_count() == 3
    assert run_store.get_active_count(user_id=user.id) == 2
    assert run_store.get_active_count(user_id=other.id) == 1


def test_get_returns_degraded_view(app_ctx, user):
    run_store.record_start(
        "run-view",
        user_id=user.id,
        project_id=None,
        command="chain",
        scan_profile="full",
        pcap_source="x.pcap",
        pcap_hash="abc",
        pcap_path="/tmp/x.pcap",
        report_path="/tmp/r.json",
        engine_pid=100,
        engine_argv=["python", "-m", "marlinspike"],
    )
    view = run_store.get("run-view")
    assert view is not None
    assert view["run_id"] == "run-view"
    assert view["status"] == "running"
    assert view["engine_pid"] == 100
    assert view["engine_argv"][0] == "python"
    assert view["timeout_at"] is not None
    assert view["finished_at"] is None


def test_get_missing_run_returns_none(app_ctx):
    assert run_store.get("nonexistent") is None


def test_update_pid_swap_for_chunked_scan(app_ctx, user):
    run_store.record_start(
        "run-chunk",
        user_id=user.id,
        project_id=None,
        command="chain",
        scan_profile="full",
        pcap_source="big.pcap",
        pcap_hash="abc",
        pcap_path="/tmp/big.pcap",
        report_path="/tmp/r.json",
        engine_pid=1000,
        engine_argv=["editcap", "-c", "10000"],
    )
    # Chunked scan starts a new subprocess for each chunk
    run_store.update_pid("run-chunk", 1001, ["python", "-m", "marlinspike", "dissect"])
    rec = ScanHistory.query.filter_by(run_id="run-chunk").first()
    assert rec.engine_pid == 1001
    argv = json.loads(rec.engine_argv)
    assert argv[-1] == "dissect"


def test_record_start_idempotent_on_run_id_collision(app_ctx, user):
    """Re-recording the same run_id updates rather than throwing."""
    run_store.record_start(
        "run-dup",
        user_id=user.id, project_id=None, command="chain", scan_profile="full",
        pcap_source="x.pcap", pcap_hash="abc",
        pcap_path="/tmp/x.pcap", report_path="/tmp/r.json",
        engine_pid=100, engine_argv=["python", "-m", "marlinspike"],
    )
    run_store.record_start(
        "run-dup",
        user_id=user.id, project_id=None, command="chain", scan_profile="fast",
        pcap_source="x.pcap", pcap_hash="abc",
        pcap_path="/tmp/x.pcap", report_path="/tmp/r.json",
        engine_pid=200, engine_argv=["python", "-m", "marlinspike"],
    )
    # Should be one row, with the second pid
    rows = ScanHistory.query.filter_by(run_id="run-dup").all()
    assert len(rows) == 1
    assert rows[0].engine_pid == 200
    assert rows[0].scan_profile == "fast"
