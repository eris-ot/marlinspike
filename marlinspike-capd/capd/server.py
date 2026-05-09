"""uds JSON-RPC server.

Length-prefixed JSON over a unix-domain socket. The web app is the only
client; we authenticate it by SO_PEERCRED and reject any uid not in the
allow-list (defaults to the socket owner's uid + 0). One request → one
response, except `stats` which streams `{type:"stats", ...}` frames
until the supervisor exits or the client disconnects.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable

from . import bpf, interfaces
from .supervisor import CaptureConfig, CaptureSupervisor

log = logging.getLogger("capd.server")

# Length-prefix size. 4 bytes big-endian = max 4GB per message; we cap
# much lower in practice.
_LEN_PREFIX = 4
_MAX_MESSAGE_BYTES = 1 << 20  # 1 MiB; way more than any of our messages need


@dataclass
class ServerConfig:
    socket_path: Path
    capture_root: Path
    allowed_uids: set[int]


class CapdServer:
    def __init__(self, cfg: ServerConfig):
        self.cfg = cfg
        self._sessions: dict[str, CaptureSupervisor] = {}
        self._sessions_lock = asyncio.Lock()

    # ── public entry ──────────────────────────────────────────

    async def serve(self) -> None:
        sock_path = str(self.cfg.socket_path)
        try:
            os.unlink(sock_path)
        except FileNotFoundError:
            pass
        # Create the socket so we can chmod it before accept().
        srv_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv_sock.bind(sock_path)
        os.chmod(sock_path, 0o660)
        srv_sock.listen(16)

        loop = asyncio.get_running_loop()
        srv_sock.setblocking(False)
        log.info("capd listening on %s (allowed uids: %s)", sock_path, sorted(self.cfg.allowed_uids))

        try:
            while True:
                client_sock, _ = await loop.sock_accept(srv_sock)
                asyncio.create_task(self._handle_client(client_sock))
        finally:
            srv_sock.close()
            try:
                os.unlink(sock_path)
            except FileNotFoundError:
                pass

    # ── per-connection handler ────────────────────────────────

    async def _handle_client(self, client_sock: socket.socket) -> None:
        peer_uid = _peer_uid(client_sock)
        if peer_uid is None or peer_uid not in self.cfg.allowed_uids:
            log.warning("rejecting client uid=%s (allowed=%s)", peer_uid, sorted(self.cfg.allowed_uids))
            try:
                await _send_json_async(client_sock, {"ok": False, "error": "unauthorized"})
            finally:
                client_sock.close()
            return

        try:
            while True:
                msg = await _recv_json_async(client_sock)
                if msg is None:
                    return
                resp = await self._dispatch(msg, client_sock)
                # `stats` streams; dispatch handles its own writes.
                if resp is not None:
                    await _send_json_async(client_sock, resp)
        except Exception:
            log.exception("client handler crashed")
        finally:
            client_sock.close()

    # ── dispatch ──────────────────────────────────────────────

    async def _dispatch(self, msg: dict, client_sock: socket.socket) -> dict | None:
        method = (msg or {}).get("method")
        params: dict[str, Any] = (msg or {}).get("params") or {}
        log.debug("dispatch method=%s", method)

        if method == "list_interfaces":
            return {"ok": True, "interfaces": interfaces.list_interfaces(
                include_virtual=bool(params.get("include_virtual", False))
            )}

        if method == "validate_bpf":
            link_type = int(params.get("link_type", bpf.DLT_EN10MB))
            res = bpf.validate(str(params.get("filter", "")), link_type=link_type)
            return {"ok": res.ok, "error": res.error}

        if method == "start":
            return await self._start_session(params)

        if method == "stop":
            return await self._stop_session(str(params.get("session_id", "")))

        if method == "stats":
            await self._stream_stats(client_sock, str(params.get("session_id", "")),
                                     float(params.get("interval_s", 1.0)))
            return None

        if method == "version":
            try:
                pcap_version = bpf.libpcap_version()
            except OSError as exc:
                pcap_version = f"unavailable: {exc}"
            return {"ok": True, "capd_version": _capd_version(), "libpcap": pcap_version}

        return {"ok": False, "error": f"unknown method: {method}"}

    async def _start_session(self, params: dict[str, Any]) -> dict:
        session_id = str(params.get("session_id", "")).strip()
        interface = str(params.get("interface", "")).strip()
        bpf_filter = str(params.get("bpf", "") or params.get("bpf_filter", ""))
        filesize_kb = int(params.get("ring_filesize_kb") or params.get("filesize_kb") or 200_000)
        files = int(params.get("ring_files") or params.get("files") or 10)
        max_duration_s = int(params.get("max_duration_s") or 0)

        if not session_id:
            return {"ok": False, "error": "session_id required"}
        if not interface:
            return {"ok": False, "error": "interface required"}

        # Pre-flight: BPF must compile.
        link_type = bpf.DLT_LINUX_SLL2 if interface == "any" else bpf.DLT_EN10MB
        v = bpf.validate(bpf_filter, link_type=link_type)
        if not v.ok:
            return {"ok": False, "error": f"bpf invalid: {v.error}"}

        # Pre-flight: interface must exist.
        if interface != "any" and interfaces.find_interface(interface) is None:
            return {"ok": False, "error": f"interface not found: {interface}"}

        out_dir = Path(self.cfg.capture_root) / session_id
        cfg = CaptureConfig(
            session_id=session_id,
            interface=interface,
            bpf_filter=bpf_filter,
            output_dir=out_dir,
            filesize_kb=filesize_kb,
            files=files,
            max_duration_s=max_duration_s,
        )

        async with self._sessions_lock:
            if session_id in self._sessions and self._sessions[session_id].is_running():
                return {"ok": False, "error": f"session {session_id} already running"}
            try:
                sup = CaptureSupervisor(cfg)
                sup.start()
            except Exception as exc:
                log.exception("start failed for session=%s", session_id)
                return {"ok": False, "error": str(exc)}
            self._sessions[session_id] = sup

        return {"ok": True, "session_id": session_id, "output_dir": str(out_dir)}

    async def _stop_session(self, session_id: str) -> dict:
        async with self._sessions_lock:
            sup = self._sessions.get(session_id)
            if sup is None:
                return {"ok": False, "error": f"unknown session: {session_id}"}

        # Stop is blocking (it waits up to 5s for SIGINT). Run in
        # default executor so the asyncio loop stays responsive.
        loop = asyncio.get_running_loop()
        stats = await loop.run_in_executor(None, sup.stop)

        async with self._sessions_lock:
            self._sessions.pop(session_id, None)

        return {
            "ok": True,
            "session_id": session_id,
            "packets": sup.final_packets,
            "drops": sup.final_drops,
            "bytes_total": stats.bytes_total,
            "files_closed": stats.files_closed,
        }

    async def _stream_stats(self, client_sock: socket.socket, session_id: str, interval_s: float) -> None:
        sup = self._sessions.get(session_id)
        if sup is None:
            await _send_json_async(client_sock, {"ok": False, "error": f"unknown session: {session_id}"})
            return

        interval_s = max(0.25, min(10.0, interval_s))
        while True:
            stats = sup.poll()
            frame = {
                "type": "stats",
                "session_id": session_id,
                "ts": stats.ts,
                "bytes_total": stats.bytes_total,
                "bytes_per_sec": stats.bytes_per_sec,
                "current_file": stats.current_file,
                "file_index": stats.file_index,
                "files_closed": stats.files_closed,
                "running": stats.running,
            }
            try:
                await _send_json_async(client_sock, frame)
            except (BrokenPipeError, ConnectionResetError):
                return
            if not stats.running:
                return
            await asyncio.sleep(interval_s)


# ── wire helpers ──────────────────────────────────────────────

def _capd_version() -> str:
    from . import __version__
    return __version__


def _peer_uid(sock: socket.socket) -> int | None:
    """SO_PEERCRED on Linux, LOCAL_PEEREID on macOS/BSD."""
    try:
        if sys.platform.startswith("linux"):
            # struct ucred: pid (i32), uid (u32), gid (u32) = 12 bytes
            data = sock.getsockopt(socket.SOL_SOCKET, 17, 12)  # 17 = SO_PEERCRED
            _, uid, _ = struct.unpack("iII", data)
            return uid
        if sys.platform == "darwin":
            # LOCAL_PEEREID returns euid then egid. Use getsockopt at level
            # SOL_LOCAL (0) opt LOCAL_PEEREID (1) struct xucred — easier:
            # use SO_PEERCRED-ish path via os.getpeername fallback.
            # macOS specific: getpeereid() — but ctypes-free path is to
            # use socket.getsockopt with LOCAL_PEERCRED (1) returning xucred.
            try:
                from socket import SOL_LOCAL  # type: ignore[attr-defined]
            except ImportError:
                SOL_LOCAL = 0
            # xucred: cr_version(u32), cr_uid(u32), cr_ngroups(i16), cr_groups[16](u32) = 4+4+2+4*16 = 74,
            # padded — request a generous buffer and unpack uid.
            buf = sock.getsockopt(SOL_LOCAL, 1, 76)
            # cr_version (u32 LE), cr_uid (u32 LE)
            _, uid = struct.unpack_from("II", buf, 0)
            return uid
    except OSError:
        return None
    return None


async def _recv_exact(sock: socket.socket, n: int) -> bytes | None:
    loop = asyncio.get_running_loop()
    out = bytearray()
    while len(out) < n:
        chunk = await loop.sock_recv(sock, n - len(out))
        if not chunk:
            return None
        out.extend(chunk)
    return bytes(out)


async def _recv_json_async(sock: socket.socket) -> dict | None:
    header = await _recv_exact(sock, _LEN_PREFIX)
    if header is None:
        return None
    (length,) = struct.unpack(">I", header)
    if length <= 0 or length > _MAX_MESSAGE_BYTES:
        log.warning("bad message length: %d", length)
        return None
    body = await _recv_exact(sock, length)
    if body is None:
        return None
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        log.warning("malformed json from client: %s", exc)
        return {}


async def _send_json_async(sock: socket.socket, obj: dict) -> None:
    body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    if len(body) > _MAX_MESSAGE_BYTES:
        raise ValueError("message too large")
    loop = asyncio.get_running_loop()
    await loop.sock_sendall(sock, struct.pack(">I", len(body)) + body)
