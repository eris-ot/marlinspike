"""Rotation consumer.

When capd reports a closed PCAP file, we enqueue a scan against it
using the same engine that processes uploaded captures. The resulting
report lands in the session's project reports directory and shows up
in the workbench like any other report.

This is intentionally simple: one subprocess per rotated file, no
chunking, no in-process scan registry. The engine emits its JSON
report, we log status, done. Heavyweight scan bookkeeping
(ScanHistory rows, live progress) can be layered on later.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import threading
import uuid
from pathlib import Path

from marlinspike import config

log = logging.getLogger(__name__)


def _project_reports_dir(user_id: int, project_id: int | None) -> str:
    pid = str(project_id) if project_id is not None else "unassigned"
    return os.path.join(config.REPORTS_DIR, str(user_id), pid)


def _safe_stem(path: str) -> str:
    stem = os.path.splitext(os.path.basename(path))[0]
    return re.sub(r"[^a-zA-Z0-9._-]", "_", stem)[:60]


def enqueue_scan(*, pcap_path: str, user_id: int, project_id: int | None,
                 session_uuid: str, scan_profile: str = "fast") -> threading.Thread:
    """Spawn an engine subprocess for one closed PCAP.

    Returns the worker thread (already started). The thread waits for
    the engine to exit and logs status. Errors are recorded in the
    log only — we don't surface them through the SSE stream because
    capd's stats stream is the wrong channel for engine outcomes.
    """
    out_dir = _project_reports_dir(user_id, project_id)
    os.makedirs(out_dir, exist_ok=True)

    run_id = str(uuid.uuid4())
    prefix = _safe_stem(pcap_path) or "live"
    report_filename = f"{prefix}-marlinspike-{run_id[:8]}.json"
    report_path = os.path.join(out_dir, report_filename)

    args: list[str] = list(config.MARLINSPIKE_ENGINE_CMD)
    args += ["--pcap", pcap_path]
    if config.MARLINSPIKE_DPI_ENGINE:
        args += ["--dpi-engine", config.MARLINSPIKE_DPI_ENGINE]
    if config.MARLINSPIKE_DPI_BIN:
        args += ["--dpi-binary", config.MARLINSPIKE_DPI_BIN]
    if scan_profile == "fast":
        args.append("--fast")
    args += ["--collapse-threshold", "50", "--no-grassmarlin", "-o", report_path, "chain"]

    log.info("session=%s queueing scan for %s -> %s", session_uuid, pcap_path, report_path)

    def _run() -> None:
        try:
            proc = subprocess.Popen(
                args,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                cwd=config.REPORTS_DIR,
            )
        except Exception:
            log.exception("session=%s failed to spawn engine for %s", session_uuid, pcap_path)
            return

        # Drain stdout into the log; the engine produces a lot of progress
        # noise that we don't need to retain.
        assert proc.stdout is not None
        tail: list[str] = []
        for line in proc.stdout:
            line = line.rstrip("\n")
            log.debug("session=%s engine: %s", session_uuid, line)
            tail.append(line)
            if len(tail) > 50:
                del tail[:25]

        rc = proc.wait()
        if rc == 0:
            log.info("session=%s scan complete: %s", session_uuid, report_path)
        else:
            log.warning("session=%s scan failed rc=%d for %s; tail=%s",
                        session_uuid, rc, pcap_path, " | ".join(tail[-5:]))

    t = threading.Thread(target=_run, daemon=True, name=f"capture-scan-{run_id[:8]}")
    t.start()
    return t


def make_listener(user_id: int, project_id: int | None, session_uuid: str,
                  scan_profile: str = "fast"):
    """Build a closure suitable for `StatsHub.add_file_listener`."""
    def _on_file_closed(pcap_path: str) -> None:
        if not pcap_path or not Path(pcap_path).exists():
            log.warning("session=%s file_closed %s missing on disk; skipping",
                        session_uuid, pcap_path)
            return
        enqueue_scan(
            pcap_path=pcap_path, user_id=user_id, project_id=project_id,
            session_uuid=session_uuid, scan_profile=scan_profile,
        )
    return _on_file_closed
