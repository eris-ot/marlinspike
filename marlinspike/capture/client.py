"""Synchronous capd client.

Length-prefixed JSON over a unix-domain socket. One connection per
operation for simple methods; one long-lived connection for the
streaming `stats` method (so we get back-pressure for free if the
consumer falls behind).
"""

from __future__ import annotations

import contextlib
import json
import logging
import socket
import struct
from dataclasses import dataclass
from typing import Iterator

log = logging.getLogger(__name__)

_LEN_PREFIX = 4
_MAX_MESSAGE_BYTES = 1 << 20


class CapdError(RuntimeError):
    pass


class CapdUnavailable(CapdError):
    """Raised when the socket can't be reached. Surfaces as a 503 in the API."""


@dataclass
class Interface:
    name: str
    mac: str | None
    ips: list[str]
    is_up: bool
    is_loopback: bool
    is_virtual: bool
    mtu: int | None
    speed_mbps: int | None

    @classmethod
    def from_dict(cls, d: dict) -> "Interface":
        return cls(
            name=d["name"], mac=d.get("mac"), ips=list(d.get("ips") or []),
            is_up=bool(d.get("is_up")), is_loopback=bool(d.get("is_loopback")),
            is_virtual=bool(d.get("is_virtual")),
            mtu=d.get("mtu"), speed_mbps=d.get("speed_mbps"),
        )


class CapdClient:
    def __init__(self, socket_path: str, timeout: float = 5.0):
        self.socket_path = socket_path
        self.timeout = timeout

    # ── single-shot ───────────────────────────────────────────

    def list_interfaces(self, include_virtual: bool = False) -> list[Interface]:
        resp = self._call("list_interfaces", {"include_virtual": include_virtual})
        return [Interface.from_dict(d) for d in resp.get("interfaces", [])]

    def validate_bpf(self, filter_str: str, link_type: int = 1) -> tuple[bool, str | None]:
        resp = self._call("validate_bpf", {"filter": filter_str, "link_type": link_type})
        return bool(resp.get("ok")), resp.get("error")

    def start(self, *, session_id: str, interface: str, bpf_filter: str = "",
              ring_filesize_kb: int = 200_000, ring_files: int = 10,
              max_duration_s: int = 0) -> dict:
        resp = self._call("start", {
            "session_id": session_id,
            "interface": interface,
            "bpf": bpf_filter,
            "ring_filesize_kb": ring_filesize_kb,
            "ring_files": ring_files,
            "max_duration_s": max_duration_s,
        })
        if not resp.get("ok"):
            raise CapdError(resp.get("error") or "capd start failed")
        return resp

    def stop(self, session_id: str) -> dict:
        # Stop can take a few seconds (dumpcap SIGINT + flush).
        resp = self._call("stop", {"session_id": session_id}, timeout=15.0)
        if not resp.get("ok"):
            raise CapdError(resp.get("error") or "capd stop failed")
        return resp

    def version(self) -> dict:
        return self._call("version", {})

    # ── streaming ─────────────────────────────────────────────

    def stream_stats(self, session_id: str, interval_s: float = 1.0) -> Iterator[dict]:
        """Long-lived generator yielding stats frames until the session ends or the caller stops iterating."""
        sock = self._connect(timeout=None)
        try:
            _send_json(sock, {"method": "stats", "params": {
                "session_id": session_id, "interval_s": interval_s,
            }})
            while True:
                frame = _recv_json(sock)
                if frame is None:
                    return
                yield frame
                if not frame.get("running", True):
                    return
        finally:
            with contextlib.suppress(OSError):
                sock.close()

    # ── internals ─────────────────────────────────────────────

    def _connect(self, timeout: float | None) -> socket.socket:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if timeout is not None:
            sock.settimeout(timeout)
        try:
            sock.connect(self.socket_path)
        except (FileNotFoundError, ConnectionRefusedError, PermissionError) as exc:
            sock.close()
            raise CapdUnavailable(f"capd unreachable at {self.socket_path}: {exc}") from exc
        except OSError as exc:
            sock.close()
            raise CapdUnavailable(f"capd unreachable at {self.socket_path}: {exc}") from exc
        return sock

    def _call(self, method: str, params: dict, timeout: float | None = None) -> dict:
        sock = self._connect(timeout=timeout if timeout is not None else self.timeout)
        try:
            _send_json(sock, {"method": method, "params": params})
            resp = _recv_json(sock)
            if resp is None:
                raise CapdError(f"capd closed connection on method={method}")
            return resp
        finally:
            with contextlib.suppress(OSError):
                sock.close()

    # ── liveness probe ────────────────────────────────────────

    def is_reachable(self) -> bool:
        try:
            self.version()
        except CapdUnavailable:
            return False
        except CapdError:
            return False
        return True


# ── wire helpers ──────────────────────────────────────────────

def _recv_exact(sock: socket.socket, n: int) -> bytes | None:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def _recv_json(sock: socket.socket) -> dict | None:
    header = _recv_exact(sock, _LEN_PREFIX)
    if header is None:
        return None
    (length,) = struct.unpack(">I", header)
    if length <= 0 or length > _MAX_MESSAGE_BYTES:
        raise CapdError(f"capd sent oversized frame: {length} bytes")
    body = _recv_exact(sock, length)
    if body is None:
        return None
    return json.loads(body.decode("utf-8"))


def _send_json(sock: socket.socket, obj: dict) -> None:
    body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    sock.sendall(struct.pack(">I", len(body)) + body)
