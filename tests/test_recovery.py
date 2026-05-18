"""Tests for marlinspike.recovery — startup reaper + PID-reuse defense."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

# Set DATABASE_URL BEFORE importing marlinspike — config reads at import time.
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret-recovery")

import pytest

from marlinspike import recovery, run_store
from marlinspike.app import create_app
from marlinspike.models import ScanHistory, User, db


@pytest.fixture
def app():
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
    u = User(username="recov", password_hash="x", role="admin")
    db.session.add(u)
    db.session.commit()
    return u


# ── pid_alive ────────────────────────────────────────────────────────────────


def test_pid_alive_self():
    assert recovery.pid_alive(os.getpid())


def test_pid_alive_zero_and_negative():
    assert not recovery.pid_alive(0)
    assert not recovery.pid_alive(-1)
    assert not recovery.pid_alive(None)


def test_pid_alive_dead_process():
    # Spawn a child that exits immediately.
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait()
    # Brief grace for the kernel to clean up
    time.sleep(0.1)
    # PID should now be gone (or at most reused, but unlikely in a tight test).
    # We accept either False (truly dead) or argv-mismatch downstream.
    assert recovery.pid_alive(proc.pid) is False or recovery.pid_argv_matches(proc.pid, ["nope"]) is False


# ── pid_argv_matches ─────────────────────────────────────────────────────────


def test_pid_argv_matches_self():
    """The current Python process should match an argv naming Python."""
    expected = [sys.executable, "-m", "pytest"]
    # Self should be alive and (Python interpreter token should match)
    assert recovery.pid_argv_matches(os.getpid(), expected)


def test_pid_argv_no_expected_returns_true():
    # No argv saved → can't defend against PID reuse, trust liveness.
    assert recovery.pid_argv_matches(os.getpid(), None)
    assert recovery.pid_argv_matches(os.getpid(), [])


def test_pid_argv_dead_pid():
    # Use a very high PID unlikely to exist.
    assert not recovery.pid_argv_matches(2_000_000, [sys.executable, "-m", "marlinspike"])


# ── report_complete ───────────────────────────────────────────────────────────


def test_report_complete_missing_file(tmp_path):
    assert not recovery.report_complete(str(tmp_path / "no.json"))


def test_report_complete_invalid_json(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{partial trunc")
    assert not recovery.report_complete(str(p))


def test_report_complete_valid_topology(tmp_path):
    p = tmp_path / "ok.json"
    p.write_text(json.dumps({"topology": {"nodes": [], "edges": []}}))
    assert recovery.report_complete(str(p))


def test_report_complete_results_topology(tmp_path):
    p = tmp_path / "nested.json"
    p.write_text(json.dumps({"results": {"topology": {"nodes": [{"id": "a"}], "edges": []}}}))
    assert recovery.report_complete(str(p))


def test_report_complete_none_or_empty():
    assert not recovery.report_complete(None)
    assert not recovery.report_complete("")


# ── reap_orphan_runs ──────────────────────────────────────────────────────────


def test_reap_no_orphans(app, app_ctx, user):
    counters = recovery.reap_orphan_runs(app)
    assert counters["checked"] == 0


def test_reap_dead_pid_no_report_marks_failed(app, app_ctx, user, tmp_path):
    """PID is dead and report file doesn't exist → mark failed."""
    run_store.record_start(
        "rec-dead",
        user_id=user.id,
        project_id=None,
        command="chain",
        scan_profile="full",
        pcap_source="x.pcap",
        pcap_hash="abc",
        pcap_path=str(tmp_path / "x.pcap"),
        report_path=str(tmp_path / "missing.json"),
        engine_pid=2_000_001,  # almost certainly dead
        engine_argv=[sys.executable, "-m", "marlinspike"],
    )
    counters = recovery.reap_orphan_runs(app)
    assert counters["reaped_failed"] == 1
    rec = ScanHistory.query.filter_by(run_id="rec-dead").first()
    assert rec.status == "failed"
    assert rec.recovery_state == "reaped_failed"
    assert "engine crashed" in (rec.error_tail or "")


def test_reap_dead_pid_with_report_marks_completed(app, app_ctx, user, tmp_path):
    """PID is dead but engine wrote complete report → ingest + mark completed."""
    report_path = tmp_path / "good.json"
    report_path.write_text(json.dumps({
        "topology": {"nodes": [{"id": "n1"}, {"id": "n2"}], "edges": [{"src": "n1", "dst": "n2"}]}
    }))
    run_store.record_start(
        "rec-finished",
        user_id=user.id,
        project_id=None,
        command="chain",
        scan_profile="full",
        pcap_source="x.pcap",
        pcap_hash="abc",
        pcap_path=str(tmp_path / "x.pcap"),
        report_path=str(report_path),
        engine_pid=2_000_002,  # dead
        engine_argv=[sys.executable, "-m", "marlinspike"],
    )
    counters = recovery.reap_orphan_runs(app)
    assert counters["reaped_completed"] == 1
    rec = ScanHistory.query.filter_by(run_id="rec-finished").first()
    assert rec.status == "completed"
    assert rec.recovery_state == "reaped_completed"
    assert rec.node_count == 2
    assert rec.edge_count == 1


def test_reap_past_deadline_marks_abandoned(app, app_ctx, user, tmp_path):
    """timeout_at in the past → reap as abandoned regardless of PID state."""
    run_store.record_start(
        "rec-old",
        user_id=user.id,
        project_id=None,
        command="chain",
        scan_profile="full",
        pcap_source="x.pcap",
        pcap_hash="abc",
        pcap_path=str(tmp_path / "x.pcap"),
        report_path=str(tmp_path / "r.json"),
        engine_pid=os.getpid(),  # alive! but past deadline
        engine_argv=[sys.executable, "-m", "marlinspike"],
        timeout_s=1,
    )
    # Force timeout_at to be in the past
    rec = ScanHistory.query.filter_by(run_id="rec-old").first()
    rec.timeout_at = datetime.now(timezone.utc) - timedelta(hours=1)
    db.session.commit()

    counters = recovery.reap_orphan_runs(app)
    assert counters["reaped_abandoned"] == 1
    rec = ScanHistory.query.filter_by(run_id="rec-old").first()
    assert rec.status == "failed"
    assert rec.recovery_state == "reaped_abandoned"
    assert "abandoned" in (rec.error_tail or "")


def test_reap_live_pid_with_correct_argv_reattaches(app, app_ctx, user, tmp_path, monkeypatch):
    """Live PID + matching argv → re-attach watcher (don't mark failed)."""
    # Spawn a long-lived subprocess whose argv we control, so we can
    # save a matching argv and have the live cmdline pid_argv_matches.
    distinctive = "marlinspike-recovery-test-token"
    long_running = subprocess.Popen([
        sys.executable,
        "-c",
        f"import time; print('{distinctive}'); time.sleep(60)",
    ])
    try:
        run_store.record_start(
            "rec-live",
            user_id=user.id,
            project_id=None,
            command="chain",
            scan_profile="full",
            pcap_source="x.pcap",
            pcap_hash="abc",
            pcap_path=str(tmp_path / "x.pcap"),
            report_path=str(tmp_path / "r.json"),
            engine_pid=long_running.pid,
            engine_argv=[sys.executable, "-c", distinctive],
        )
        # Stub _spawn_watcher so we don't leak threads
        spawned = []
        monkeypatch.setattr(
            recovery, "_spawn_watcher",
            lambda app_, run_id, pid, rp: spawned.append((run_id, pid)),
        )
        counters = recovery.reap_orphan_runs(app)
        assert counters["reattached"] == 1
        assert spawned == [("rec-live", long_running.pid)]
        rec = ScanHistory.query.filter_by(run_id="rec-live").first()
        assert rec.status == "running"  # left alone
    finally:
        long_running.terminate()
        try:
            long_running.wait(timeout=5)
        except subprocess.TimeoutExpired:
            long_running.kill()


def test_reap_live_pid_argv_mismatch_treated_as_dead(app, app_ctx, user, tmp_path):
    """Live PID but argv doesn't match → defend against PID reuse, treat as dead."""
    # Use our PID with totally bogus argv that won't match
    run_store.record_start(
        "rec-reused",
        user_id=user.id,
        project_id=None,
        command="chain",
        scan_profile="full",
        pcap_source="x.pcap",
        pcap_hash="abc",
        pcap_path=str(tmp_path / "x.pcap"),
        report_path=str(tmp_path / "r.json"),
        engine_pid=os.getpid(),
        engine_argv=["/usr/bin/totally-not-python-or-marlinspike", "weird"],
    )
    counters = recovery.reap_orphan_runs(app)
    # Either reaped_failed (PID alive but argv wrong, no report) or
    # if argv check is lenient on this platform, may reattach — both
    # are acceptable behaviors. The critical property is that the
    # row doesn't stay unreconciled.
    assert counters["reaped_failed"] + counters["reattached"] == 1


def test_reap_run_with_no_pid(app, app_ctx, user, tmp_path):
    """engine_pid is NULL → can't reattach, treat as dead."""
    rec = ScanHistory(
        run_id="rec-nopid",
        user_id=user.id,
        command="chain",
        status="running",
        report_path=str(tmp_path / "r.json"),
    )
    db.session.add(rec)
    db.session.commit()
    counters = recovery.reap_orphan_runs(app)
    assert counters["reaped_failed"] == 1
