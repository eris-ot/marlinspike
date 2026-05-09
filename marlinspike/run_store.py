"""Run state persistence — durable subset of scan lifecycle.

Lives alongside ``marlinspike.app._run_registry``, which holds host-local
Popen handles and the live stdout buffer needed to stream scan output to
the browser. ``_run_registry`` evaporates when Flask exits; the columns
written here survive in ``scan_history`` so the reaper in
``marlinspike.recovery`` can reconcile in-flight scans on the next boot.

Functions are intentionally flat — there's only one backend today
(SQLAlchemy → ``ScanHistory``). When cloudmarlin needs Valkey-backed
run state for sub-second cross-pod polling, a parallel implementation
can live next to these and be selected by ``MARLINSPIKE_RUN_STORE``.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from marlinspike import config
from marlinspike.models import ScanHistory, db

log = logging.getLogger("marlinspike.run_store")


def record_start(
    run_id: str,
    *,
    user_id: int,
    project_id: int | None,
    command: str,
    scan_profile: str,
    pcap_source: str | None,
    pcap_hash: str | None,
    pcap_path: str,
    report_path: str,
    engine_pid: int | None,
    engine_argv: list[str] | None,
    timeout_s: int | None = None,
) -> None:
    """Insert (or update) a ScanHistory row at scan launch time.

    ``engine_pid`` and ``engine_argv`` are the PID-reuse defense: on
    recovery we verify both the PID is alive AND its cmdline matches
    the saved argv before we assume the process is still our scan.

    ``timeout_s`` defaults to ``MARLINSPIKE_SCAN_TIMEOUT_S`` (config).
    A null deadline means recovery cannot time-bound the scan and will
    rely on PID-liveness alone.
    """
    if timeout_s is None:
        timeout_s = config.MARLINSPIKE_SCAN_TIMEOUT_S
    timeout_at = (
        datetime.now(timezone.utc) + timedelta(seconds=timeout_s)
        if timeout_s and timeout_s > 0
        else None
    )

    rec = ScanHistory.query.filter_by(run_id=run_id).first()
    if rec is None:
        rec = ScanHistory(run_id=run_id, user_id=user_id)
        db.session.add(rec)

    rec.user_id = user_id
    rec.project_id = project_id
    rec.command = command
    rec.scan_profile = scan_profile
    rec.pcap_source = pcap_source
    rec.pcap_hash = pcap_hash
    rec.status = "running"
    rec.report_path = report_path
    rec.pcap_path = pcap_path
    rec.engine_pid = engine_pid
    rec.engine_argv = json.dumps(engine_argv) if engine_argv else None
    rec.timeout_at = timeout_at
    rec.recovery_state = None

    db.session.commit()


def update_pid(run_id: str, engine_pid: int | None, engine_argv: list[str] | None) -> None:
    """Update engine_pid + argv for chunked scans whose pid changes per stage.

    Called from the chunked-reader child supervisor each time a new
    subprocess is spawned. Best-effort — failures are logged, not raised.
    """
    try:
        rec = ScanHistory.query.filter_by(run_id=run_id).first()
        if rec is None:
            return
        rec.engine_pid = engine_pid
        rec.engine_argv = json.dumps(engine_argv) if engine_argv else None
        db.session.commit()
    except Exception:
        db.session.rollback()
        log.debug("update_pid failed for run_id=%s", run_id, exc_info=True)


def record_finish(
    run_id: str,
    *,
    status: str,
    error_tail: str | None = None,
    node_count: int | None = None,
    edge_count: int | None = None,
    recovery_state: str | None = None,
) -> None:
    """Persist final scan status and clear recovery hooks.

    ``recovery_state`` (None / 'reattached' / 'reaped_completed' /
    'reaped_failed' / 'reaped_abandoned') is left for diagnostics so an
    operator can grep ``scan_history`` for runs that were resurrected
    rather than completing cleanly.
    """
    try:
        rec = ScanHistory.query.filter_by(run_id=run_id).first()
        if rec is None:
            return
        rec.status = status
        rec.completed_at = datetime.now(timezone.utc)
        if error_tail is not None:
            rec.error_tail = error_tail
        if node_count is not None:
            rec.node_count = node_count
        if edge_count is not None:
            rec.edge_count = edge_count
        if recovery_state is not None:
            rec.recovery_state = recovery_state
        # Clear the live-process pointer once the run is terminal.
        rec.engine_pid = None
        db.session.commit()
    except Exception:
        db.session.rollback()
        log.warning("record_finish failed for run_id=%s", run_id, exc_info=True)


def get_active_for_recovery() -> list[ScanHistory]:
    """Return ScanHistory rows still marked 'running' — input to the reaper."""
    return ScanHistory.query.filter_by(status="running").all()


def get_active_count(user_id: int | None = None) -> int:
    """Cross-process active-scan count for the concurrency check.

    Used when ``MARLINSPIKE_RUN_STORE=db`` to make per-tier concurrency
    correct across Gunicorn workers. The default ``memory`` backend
    keeps reading ``_run_registry`` for backwards compatibility.
    """
    q = ScanHistory.query.filter_by(status="running")
    if user_id is not None:
        q = q.filter_by(user_id=user_id)
    return q.count()


def get(run_id: str) -> dict[str, Any] | None:
    """Return a degraded-but-renderable view of a scan from durable state.

    Used by status endpoints when ``_run_registry`` doesn't have the
    run — typically after Flask restart. Returns None if no row exists.
    """
    rec = ScanHistory.query.filter_by(run_id=run_id).first()
    if rec is None:
        return None
    try:
        argv = json.loads(rec.engine_argv) if rec.engine_argv else None
    except json.JSONDecodeError:
        argv = None
    return {
        "run_id": rec.run_id,
        "user_id": rec.user_id,
        "project_id": rec.project_id,
        "command": rec.command,
        "scan_profile": rec.scan_profile,
        "status": rec.status,
        "started_at": rec.started_at.isoformat() if rec.started_at else None,
        "finished_at": rec.completed_at.isoformat() if rec.completed_at else None,
        "report_path": rec.report_path,
        "pcap_path": rec.pcap_path,
        "engine_pid": rec.engine_pid,
        "engine_argv": argv,
        "timeout_at": rec.timeout_at.isoformat() if rec.timeout_at else None,
        "recovery_state": rec.recovery_state,
        "node_count": rec.node_count or 0,
        "edge_count": rec.edge_count or 0,
        "error_tail": rec.error_tail,
    }
