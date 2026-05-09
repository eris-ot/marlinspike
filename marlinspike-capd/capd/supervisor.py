"""dumpcap supervisor.

Owns one dumpcap subprocess per CaptureSession. Rotation is delegated to
dumpcap via -b. We poll the active rotation file's size to emit
real-time bytes/sec stats; on each rotation we mark the previous file
as closed so the consumer side (the web app) can scan it. dumpcap's
exit summary gives us the authoritative drop count.
"""

from __future__ import annotations

import glob
import logging
import os
import re
import shutil
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

log = logging.getLogger("capd.supervisor")

# 200MB × 10 files = ~2GB ring per session, per user spec.
DEFAULT_FILESIZE_KB = 200_000
DEFAULT_FILES = 10

# dumpcap "Packets captured: N" / "Packets dropped: N" appear at exit.
_PKTS_RE = re.compile(r"Packets captured:\s*(\d+)")
_DROPS_RE = re.compile(r"Packets dropped:\s*(\d+)")


@dataclass
class CaptureConfig:
    session_id: str
    interface: str
    bpf_filter: str = ""
    output_dir: Path = field(default_factory=Path)
    filesize_kb: int = DEFAULT_FILESIZE_KB
    files: int = DEFAULT_FILES
    max_duration_s: int = 0  # 0 = no cap; web app enforces its own deadline


@dataclass
class CaptureStats:
    ts: float
    bytes_total: int
    bytes_per_sec: float
    current_file: str | None
    file_index: int
    files_closed: list[str]
    running: bool


class CaptureSupervisor:
    """One instance per active capture session."""

    def __init__(self, cfg: CaptureConfig, dumpcap_path: str | None = None):
        if not cfg.session_id or not cfg.session_id.replace("-", "").replace("_", "").isalnum():
            # session_id ends up in a path; refuse anything that could traverse.
            raise ValueError("session_id must be alphanumeric (with - or _)")
        self.cfg = cfg
        self.dumpcap = dumpcap_path or shutil.which("dumpcap")
        if not self.dumpcap:
            raise RuntimeError("dumpcap not found on PATH")

        self._proc: subprocess.Popen | None = None
        self._stderr_thread: threading.Thread | None = None
        self._stderr_buf: list[str] = []
        self._lock = threading.Lock()

        self._started_at: float | None = None
        self._last_poll_ts: float = 0.0
        self._last_poll_bytes: int = 0

        # Closed-file tracking. We don't open or read these — we just
        # name them so the consumer side can pick them up. dumpcap
        # writes a sequence cap_00001_<ts>.pcapng, cap_00002_<ts>.pcapng…
        self._known_files: set[str] = set()
        self._previous_active: str | None = None
        self._closed_emitted: list[str] = []

        # Authoritative tallies (parsed from dumpcap exit output).
        self.final_packets: int | None = None
        self.final_drops: int | None = None

    # ── lifecycle ────────────────────────────────────────────

    def start(self) -> None:
        if self._proc is not None:
            raise RuntimeError("supervisor already started")

        out_dir = Path(self.cfg.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / "cap.pcapng"

        argv: list[str] = [
            self.dumpcap,
            "-i", self.cfg.interface,
            "-q",                                  # less console noise
            "-n",                                  # don't try to resolve names
            "-b", f"filesize:{int(self.cfg.filesize_kb)}",
            "-b", f"files:{int(self.cfg.files)}",
            "-w", str(out_path),
        ]
        if self.cfg.bpf_filter.strip():
            argv += ["-f", self.cfg.bpf_filter.strip()]
        if self.cfg.max_duration_s and self.cfg.max_duration_s > 0:
            argv += ["-a", f"duration:{int(self.cfg.max_duration_s)}"]

        log.info("session=%s spawning %s", self.cfg.session_id, " ".join(argv))
        self._proc = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self._started_at = time.time()
        self._stderr_thread = threading.Thread(
            target=self._consume_stderr, daemon=True,
            name=f"capd-stderr-{self.cfg.session_id}",
        )
        self._stderr_thread.start()

    def stop(self, timeout: float = 5.0) -> CaptureStats:
        if self._proc is None:
            return self._snapshot(running=False)

        # SIGINT lets dumpcap flush + emit its summary line.
        try:
            self._proc.send_signal(signal.SIGINT)
        except ProcessLookupError:
            pass
        try:
            self._proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            log.warning("session=%s dumpcap didn't exit on SIGINT, killing", self.cfg.session_id)
            self._proc.kill()
            self._proc.wait(timeout=2.0)

        if self._stderr_thread is not None:
            self._stderr_thread.join(timeout=2.0)

        # Final stats from stderr summary.
        joined = "\n".join(self._stderr_buf)
        m = _PKTS_RE.search(joined)
        if m:
            self.final_packets = int(m.group(1))
        m = _DROPS_RE.search(joined)
        if m:
            self.final_drops = int(m.group(1))

        # The active file at stop time is now closed too.
        snap = self._snapshot(running=False, finalize=True)
        self._proc = None
        return snap

    def is_running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    # ── stats ────────────────────────────────────────────────

    def poll(self) -> CaptureStats:
        return self._snapshot(running=self.is_running(), finalize=False)

    def _snapshot(self, running: bool, finalize: bool = False) -> CaptureStats:
        out_dir = Path(self.cfg.output_dir)
        files = sorted(glob.glob(str(out_dir / "cap_*.pcapng")))
        active = files[-1] if files else None

        # Detect rotation: anything we previously saw as "active" but
        # which is no longer the newest file is closed and ready for the
        # consumer to ingest.
        newly_closed: list[str] = []
        if self._previous_active and self._previous_active != active:
            if self._previous_active not in self._closed_emitted:
                newly_closed.append(self._previous_active)
                self._closed_emitted.append(self._previous_active)
        for f in files:
            if f != active and f not in self._closed_emitted:
                newly_closed.append(f)
                self._closed_emitted.append(f)
        # On finalize, the active file itself is closed.
        if finalize and active and active not in self._closed_emitted:
            newly_closed.append(active)
            self._closed_emitted.append(active)

        self._previous_active = active

        # Bytes total = closed files (final size) + active file (current size).
        bytes_total = 0
        for f in files:
            with self._lock:
                try:
                    bytes_total += os.path.getsize(f)
                except OSError:
                    pass

        now = time.time()
        bps = 0.0
        if self._last_poll_ts and now > self._last_poll_ts:
            bps = max(0.0, (bytes_total - self._last_poll_bytes) / (now - self._last_poll_ts))
        self._last_poll_ts = now
        self._last_poll_bytes = bytes_total

        return CaptureStats(
            ts=now,
            bytes_total=bytes_total,
            bytes_per_sec=bps,
            current_file=active,
            file_index=len(files),
            files_closed=newly_closed,
            running=running,
        )

    # ── internal ─────────────────────────────────────────────

    def _consume_stderr(self) -> None:
        assert self._proc is not None
        if self._proc.stderr is None:
            return
        for line in self._proc.stderr:
            line = line.rstrip("\n")
            with self._lock:
                self._stderr_buf.append(line)
                # Cap memory; an OOMing capd helps no one.
                if len(self._stderr_buf) > 500:
                    del self._stderr_buf[:250]
            log.debug("session=%s dumpcap: %s", self.cfg.session_id, line)


def stats_loop(supervisor: CaptureSupervisor, on_stats: Callable[[CaptureStats], None],
               interval_s: float = 1.0, stop_event: threading.Event | None = None) -> None:
    """Convenience polling loop — blocks until stop_event is set or capture exits."""
    while True:
        if stop_event is not None and stop_event.is_set():
            return
        stats = supervisor.poll()
        on_stats(stats)
        if not stats.running:
            return
        time.sleep(interval_s)
