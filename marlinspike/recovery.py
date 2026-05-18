"""Mid-scan recovery — reconcile scans left ``running`` after Flask restart.

When the Flask process dies mid-scan (deploy, OOM, crash, host reboot),
the engine subprocess is reparented to init/launchd and usually keeps
running to completion — writing its report file as if nothing happened.
But the in-memory ``_run_registry`` is gone, so the user sees their scan
stuck in ``running`` forever.

This module fixes that. On every ``create_app()`` boot, ``reap_orphan_runs``
walks ``ScanHistory`` rows still marked ``running`` and reconciles each one:

  * **Engine still alive (PID matches saved argv)** — re-attach a
    polling thread that watches the report file. When the engine exits,
    ingest the report and mark completed/failed normally.
  * **Engine dead, report complete** — engine finished after Flask
    died but before we restarted; ingest report, mark completed.
  * **Engine dead, report missing/partial** — engine crashed or host
    rebooted; mark failed with a diagnostic ``error_tail``.
  * **Past timeout_at** — abandoned; mark failed.

PID-reuse defense: a bare ``os.kill(pid, 0)`` check is unsafe because PIDs
get recycled. We additionally compare the live process's argv against the
``engine_argv`` we saved at scan launch — if they don't match, the PID
belongs to someone else and we treat the original engine as dead.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone

from marlinspike import config, run_store
from marlinspike.models import ScanHistory

log = logging.getLogger("marlinspike.recovery")


# ── PID liveness ──────────────────────────────────────────────────────────────


def pid_alive(pid: int) -> bool:
    """True if a process with this PID exists and is signalable.

    Note: alone, this is **not** a safe identity check — PIDs get reused.
    Always pair with ``pid_argv_matches`` before assuming the live
    process is the one you started.
    """
    if pid is None or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        # The PID exists but we can't signal it — sufficient for liveness.
        return True
    except OSError:
        return False


def pid_argv_matches(pid: int, expected_argv: list[str] | None) -> bool:
    """True if the live PID's command line matches ``expected_argv``.

    Defends against PID reuse: a freshly spawned shell can land on the
    same PID our engine had. We verify by reading the process's argv
    and comparing to what we saved at scan launch.

    Linux: ``/proc/<pid>/cmdline`` (NUL-separated argv).
    macOS: ``ps -p <pid> -o command=`` (best-effort; falls back to
    matching the first 2-3 tokens since macOS may truncate or quote).
    Other platforms: returns True (best-effort, assume match).
    """
    if not expected_argv:
        # No argv saved → no defense possible; trust the liveness check.
        return True

    if sys.platform.startswith("linux"):
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                raw = f.read()
            actual = raw.split(b"\x00")
            actual = [a.decode("utf-8", errors="replace") for a in actual if a]
        except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
            return False
        return _live_argv_matches(actual, expected_argv)

    if sys.platform == "darwin":
        try:
            result = subprocess.run(
                ["ps", "-p", str(pid), "-o", "command="],
                capture_output=True,
                text=True,
                timeout=2,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False
        if result.returncode != 0:
            return False
        cmdline = result.stdout.strip()
        if not cmdline:
            return False
        # ps returns one space-joined string. Tokenise and apply the
        # same matching policy as Linux.
        return _live_argv_matches(cmdline.split(), expected_argv)

    return True


def _live_argv_matches(actual: list[str], expected: list[str]) -> bool:
    """True if the live argv is plausibly the same process we started.

    Looks for at least one *distinctive* token from ``expected`` (non-empty,
    non-flag) appearing in ``actual``. For our engine that's typically
    ``marlinspike`` or a PCAP path.

    Why not also require interpreter basename to match? On macOS, Python
    is launched via a framework wrapper whose basename (``Python``) doesn't
    match ``sys.executable``'s basename (``python3.14``) — the cmdline ps
    reports differs from the path we'd save in argv. The distinctive-token
    check alone is sufficient PID-reuse defense: a shell that landed on
    the recycled PID won't have ``marlinspike`` in its argv.
    """
    if not actual or not expected:
        return False
    actual_blob = " ".join(actual)
    for token in expected[1:]:
        if not token or token.startswith("-"):
            continue
        if token in actual_blob:
            return True
    return False


# ── Report-side check ─────────────────────────────────────────────────────────


def report_complete(report_path: str | None) -> bool:
    """True if the engine finished writing its report.

    We use a structural check (``json.load`` succeeds and ``topology``
    key is present) rather than just file existence, because the engine
    may have died mid-write and left a truncated file.
    """
    if not report_path or not os.path.isfile(report_path):
        return False
    try:
        with open(report_path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return False
    # The engine writes 'topology' at the top level (or nested under 'results').
    return "topology" in data or "results" in data


def _ingest_completed_report(rec: ScanHistory) -> None:
    """Pull node/edge counts from the finished report and mark completed."""
    node_count = 0
    edge_count = 0
    try:
        with open(rec.report_path) as f:
            data = json.load(f)
        topo = data.get("results", {}).get("topology", data.get("topology", {}))
        node_count = len(topo.get("nodes", []))
        edge_count = len(topo.get("edges", []))
    except Exception:
        log.debug("recovery: report parse failed for %s", rec.run_id, exc_info=True)
    run_store.record_finish(
        rec.run_id,
        status="completed",
        node_count=node_count,
        edge_count=edge_count,
        recovery_state="reaped_completed",
    )
    log.info(
        "recovery: ingested completed report for run %s (nodes=%d, edges=%d)",
        rec.run_id,
        node_count,
        edge_count,
    )


# ── Reaper ────────────────────────────────────────────────────────────────────


def reap_orphan_runs(app) -> dict:
    """Reconcile every scan row left ``running`` from a previous boot.

    Returns a counters dict for logging / metrics:
        {
            "checked": N,
            "reattached": N,        # engine still alive, watcher spawned
            "reaped_completed": N,  # engine finished, report ingested
            "reaped_failed": N,     # engine dead, report missing/partial
            "reaped_abandoned": N,  # past timeout_at
        }
    """
    counters = {
        "checked": 0,
        "reattached": 0,
        "reaped_completed": 0,
        "reaped_failed": 0,
        "reaped_abandoned": 0,
    }

    with app.app_context():
        active = run_store.get_active_for_recovery()
        counters["checked"] = len(active)

        if not active:
            return counters

        log.info("recovery: %d scan(s) left running from previous boot", len(active))

        now = datetime.now(timezone.utc)

        for rec in active:
            try:
                argv = json.loads(rec.engine_argv) if rec.engine_argv else None
            except json.JSONDecodeError:
                argv = None

            # Past deadline → abandoned.
            if rec.timeout_at:
                deadline = rec.timeout_at
                if deadline.tzinfo is None:
                    deadline = deadline.replace(tzinfo=timezone.utc)
                if now > deadline:
                    run_store.record_finish(
                        rec.run_id,
                        status="failed",
                        error_tail=(
                            f"abandoned — scan exceeded {config.MARLINSPIKE_SCAN_TIMEOUT_S}s "
                            f"deadline before Flask restart could observe completion"
                        ),
                        recovery_state="reaped_abandoned",
                    )
                    counters["reaped_abandoned"] += 1
                    log.info("recovery: reaped abandoned run %s (past deadline)", rec.run_id)
                    continue

            alive = (
                rec.engine_pid is not None
                and pid_alive(rec.engine_pid)
                and pid_argv_matches(rec.engine_pid, argv)
            )

            if alive:
                # Orphan still running — spawn watcher.
                _spawn_watcher(app, rec.run_id, rec.engine_pid, rec.report_path)
                counters["reattached"] += 1
                log.info(
                    "recovery: re-attached watcher to live engine pid=%s for run %s",
                    rec.engine_pid,
                    rec.run_id,
                )
                continue

            # PID dead. Did it write a report before it died?
            if report_complete(rec.report_path):
                _ingest_completed_report(rec)
                counters["reaped_completed"] += 1
                continue

            # PID dead, no report → engine crashed or host rebooted.
            run_store.record_finish(
                rec.run_id,
                status="failed",
                error_tail=(
                    "engine crashed mid-scan (Flask was unable to observe completion). "
                    "PCAP is preserved; retry from the report viewer or upload page."
                ),
                recovery_state="reaped_failed",
            )
            counters["reaped_failed"] += 1
            log.info("recovery: reaped failed run %s (engine pid=%s dead, no report)",
                     rec.run_id, rec.engine_pid)

    if any(v > 0 for k, v in counters.items() if k != "checked"):
        log.info("recovery: counters=%s", counters)

    return counters


# ── Watcher (re-attach to live orphan) ────────────────────────────────────────


def _spawn_watcher(app, run_id: str, engine_pid: int, report_path: str) -> None:
    """Background thread that polls a re-attached engine until it exits.

    We can't read the live stdout (the original Popen pipes were closed
    when Flask died), so the user loses live tail for re-attached runs.
    Status moves from ``running`` → ``completed`` / ``failed`` based on
    PID liveness + report completeness, just like the original
    finalization path.
    """
    t = threading.Thread(
        target=_watch_loop,
        args=(app, run_id, engine_pid, report_path),
        daemon=True,
        name=f"ms-recover-{run_id[:8]}",
    )
    t.start()


def _watch_loop(app, run_id: str, engine_pid: int, report_path: str) -> None:
    """Poll PID + report file. When PID dies, finalize from disk."""
    poll_interval = 2.0
    with app.app_context():
        while True:
            time.sleep(poll_interval)
            if pid_alive(engine_pid):
                continue
            # PID gone — engine finished (or died).
            if report_complete(report_path):
                rec = ScanHistory.query.filter_by(run_id=run_id).first()
                if rec is not None:
                    _ingest_completed_report(rec)
            else:
                run_store.record_finish(
                    run_id,
                    status="failed",
                    error_tail=(
                        "re-attached engine exited without writing a complete report"
                    ),
                    recovery_state="reattached",
                )
            return
