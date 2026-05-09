"""In-process state for active capture sessions.

One `StatsHub` per active session. The hub owns a single
`stream_stats` generator from capd, fans frames out to N SSE
subscribers, and notifies registered listeners (the rotation
consumer) of `files_closed` events. This keeps capd's load constant
regardless of how many browsers are watching.

A per-interface lock prevents two analysts from grabbing eth1
simultaneously — the DB still has the durable record, but the lock
protects the start path from the inevitable race.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Iterable, Iterator

from .client import CapdClient, CapdError, CapdUnavailable

log = logging.getLogger(__name__)

# How long the hub buffers the most recent stats frames so a
# late-joining SSE client can immediately show a populated panel
# instead of staring at a blank screen until the next tick.
_REPLAY_BUFFER = 8


@dataclass
class _Subscriber:
    queue: deque
    cond: threading.Condition
    closed: bool = False


@dataclass
class StatsHub:
    session_uuid: str
    client: CapdClient
    interval_s: float = 1.0

    _thread: threading.Thread | None = field(default=None, init=False)
    _stop_event: threading.Event = field(default_factory=threading.Event, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)
    _subscribers: list[_Subscriber] = field(default_factory=list, init=False)
    _file_listeners: list[Callable[[str], None]] = field(default_factory=list, init=False)
    _last_frames: deque = field(default_factory=lambda: deque(maxlen=_REPLAY_BUFFER), init=False)
    _last_seen_files_total: int = field(default=0, init=False)
    _running: bool = field(default=False, init=False)
    _final_frame: dict | None = field(default=None, init=False)

    # ── lifecycle ────────────────────────────────────────────

    def start(self) -> None:
        with self._lock:
            if self._thread is not None:
                return
            self._running = True
            self._thread = threading.Thread(
                target=self._run, daemon=True,
                name=f"capture-stats-{self.session_uuid[:8]}",
            )
            self._thread.start()

    def shutdown(self) -> None:
        self._stop_event.set()
        with self._lock:
            for sub in self._subscribers:
                with sub.cond:
                    sub.closed = True
                    sub.cond.notify_all()

    def join(self, timeout: float = 2.0) -> None:
        t = self._thread
        if t is not None:
            t.join(timeout=timeout)

    def is_running(self) -> bool:
        return self._running

    @property
    def last_frame(self) -> dict | None:
        with self._lock:
            return self._last_frames[-1] if self._last_frames else None

    # ── pubsub ──────────────────────────────────────────────

    def subscribe(self) -> Iterator[dict]:
        """Generator that yields stats frames, including a small replay of
        the most recent frames so a fresh SSE client gets immediate data."""
        sub = _Subscriber(queue=deque(maxlen=64), cond=threading.Condition())
        with self._lock:
            for frame in self._last_frames:
                sub.queue.append(frame)
            self._subscribers.append(sub)

        try:
            while True:
                with sub.cond:
                    while not sub.queue and not sub.closed:
                        sub.cond.wait(timeout=15.0)
                        # Wake periodically so SSE keep-alives can be emitted by the caller.
                        if not sub.queue and not sub.closed:
                            yield {"type": "keepalive", "ts": time.time()}
                    if sub.closed and not sub.queue:
                        return
                    while sub.queue:
                        frame = sub.queue.popleft()
                        yield frame
                        if not frame.get("running", True) and frame.get("type") == "stats":
                            return
        finally:
            with self._lock:
                with contextlib_suppress(ValueError):
                    self._subscribers.remove(sub)

    def add_file_listener(self, fn: Callable[[str], None]) -> None:
        with self._lock:
            self._file_listeners.append(fn)

    # ── worker thread ────────────────────────────────────────

    def _run(self) -> None:
        try:
            for frame in self.client.stream_stats(self.session_uuid, interval_s=self.interval_s):
                if self._stop_event.is_set():
                    break
                self._handle_frame(frame)
                if not frame.get("running", True):
                    self._final_frame = frame
                    break
        except CapdUnavailable as exc:
            log.warning("StatsHub %s: capd unavailable: %s", self.session_uuid, exc)
            self._broadcast({"type": "error", "error": f"capd unavailable: {exc}",
                             "session_id": self.session_uuid, "running": False, "ts": time.time()})
        except CapdError as exc:
            log.warning("StatsHub %s: capd error: %s", self.session_uuid, exc)
            self._broadcast({"type": "error", "error": str(exc),
                             "session_id": self.session_uuid, "running": False, "ts": time.time()})
        except Exception:
            log.exception("StatsHub %s crashed", self.session_uuid)
        finally:
            self._running = False
            with self._lock:
                for sub in self._subscribers:
                    with sub.cond:
                        sub.closed = True
                        sub.cond.notify_all()

    def _handle_frame(self, frame: dict) -> None:
        files_closed: Iterable[str] = frame.get("files_closed") or ()
        listeners: list[Callable[[str], None]]
        with self._lock:
            self._last_frames.append(frame)
            listeners = list(self._file_listeners)
        for path in files_closed:
            for fn in listeners:
                try:
                    fn(path)
                except Exception:
                    log.exception("file listener crashed for %s", path)
        self._broadcast(frame)

    def _broadcast(self, frame: dict) -> None:
        with self._lock:
            subs = list(self._subscribers)
        for sub in subs:
            with sub.cond:
                if sub.closed:
                    continue
                sub.queue.append(frame)
                sub.cond.notify_all()


# ── session manager ──────────────────────────────────────────

class CaptureSessionManager:
    """Per-process registry of active StatsHubs + per-interface locking.

    Multi-worker deployments are out of scope for v1: gunicorn workers
    each run their own manager. The DB CaptureSession row is the source
    of truth for cross-worker visibility, and the per-interface lock
    enforced here is best-effort — capd's own start RPC will return
    `session already running` if there's a real conflict.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._hubs: dict[str, StatsHub] = {}
        self._iface_locks: dict[str, str] = {}  # interface → session_uuid

    def acquire_interface(self, interface: str, session_uuid: str) -> str | None:
        """Returns None on success, or the holder's session_uuid on conflict."""
        with self._lock:
            holder = self._iface_locks.get(interface)
            if holder and holder != session_uuid:
                return holder
            # `any` blocks all real ifaces and vice versa.
            if interface == "any" and any(k != "any" for k in self._iface_locks):
                return next(iter(self._iface_locks.values()))
            if interface != "any" and "any" in self._iface_locks:
                return self._iface_locks["any"]
            self._iface_locks[interface] = session_uuid
            return None

    def release_interface(self, interface: str, session_uuid: str) -> None:
        with self._lock:
            holder = self._iface_locks.get(interface)
            if holder == session_uuid:
                self._iface_locks.pop(interface, None)

    def register_hub(self, hub: StatsHub) -> None:
        with self._lock:
            self._hubs[hub.session_uuid] = hub

    def get_hub(self, session_uuid: str) -> StatsHub | None:
        with self._lock:
            return self._hubs.get(session_uuid)

    def drop_hub(self, session_uuid: str) -> StatsHub | None:
        with self._lock:
            return self._hubs.pop(session_uuid, None)

    def active_session_count(self) -> int:
        with self._lock:
            return sum(1 for h in self._hubs.values() if h.is_running())


# Module-level singleton: one manager per Flask process.
manager = CaptureSessionManager()


# ── small helper (avoids contextlib import noise above) ──────

class contextlib_suppress:
    def __init__(self, *exc): self.exc = exc
    def __enter__(self): return self
    def __exit__(self, t, v, tb): return t is not None and issubclass(t, self.exc)
