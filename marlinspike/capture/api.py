"""Flask blueprint mounted at /api/capture/*.

The blueprint is the only thing app.py needs to know about — it
talks to capd through `client.CapdClient`, parks active state in
`sessions.manager`, and persists durable rows to `CaptureSession`.

All endpoints require login; project-scoped endpoints additionally
verify the project belongs to the calling user.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import datetime, timezone

from flask import Blueprint, Response, jsonify, request, session, stream_with_context

from marlinspike import config
from marlinspike.audit import audit
from marlinspike.auth import admin_required, login_required


def _capture_control_required(view_func):
    """Apply the active capture-control policy.

    Defaults to admin-only (``MARLINSPIKE_CAPTURE_REQUIRE=admin``).
    With ``MARLINSPIKE_CAPTURE_REQUIRE=any``, any authenticated user
    can start/stop captures (legacy v3.5.1 behaviour).

    Live capture drives a privileged sidecar (``capd``) holding
    ``CAP_NET_RAW`` — granting capture-start to a low-privilege account
    is effectively granting raw socket access on the engagement
    network. Default-admin is the safe posture.
    """
    from marlinspike import config as _ms_config
    if _ms_config.MARLINSPIKE_CAPTURE_REQUIRE == "any":
        return login_required(view_func)
    return admin_required(view_func)
from marlinspike.capture import consumer
from marlinspike.capture.client import CapdClient, CapdError, CapdUnavailable
from marlinspike.capture.sessions import StatsHub, manager
from marlinspike.models import CaptureSession, Project, SavedFilter, db

log = logging.getLogger(__name__)

bp = Blueprint("capture", __name__, url_prefix="/api/capture")


def _client() -> CapdClient:
    return CapdClient(config.LIVE_CAPTURE_SOCKET, timeout=float(config.LIVE_CAPTURE_TIMEOUT_S))


def _require_project(project_id) -> Project | None:
    if project_id is None:
        return None
    try:
        pid = int(project_id)
    except (ValueError, TypeError):
        return None
    return Project.query.filter_by(id=pid, user_id=session["user_id"]).first()


def _serialize(s: CaptureSession) -> dict:
    return {
        "id": s.id,
        "session_uuid": s.session_uuid,
        "project_id": s.project_id,
        "interface": s.interface,
        "bpf_filter": s.bpf_filter,
        "ring_filesize_kb": s.ring_filesize_kb,
        "ring_files": s.ring_files,
        "max_duration_s": s.max_duration_s,
        "status": s.status,
        "started_at": s.started_at.isoformat() if s.started_at else None,
        "stopped_at": s.stopped_at.isoformat() if s.stopped_at else None,
        "capture_dir": s.capture_dir,
        "bytes_captured": s.bytes_captured,
        "packets_captured": s.packets_captured,
        "drop_count": s.drop_count,
        "rotation_count": s.rotation_count,
        "error_tail": s.error_tail,
    }


# ── capd reachability ────────────────────────────────────────

@bp.route("/health", methods=["GET"])
@login_required
def health():
    if not config.LIVE_CAPTURE_ENABLED:
        return jsonify({"enabled": False, "reachable": False, "reason": "disabled by config"}), 200
    try:
        info = _client().version()
        return jsonify({"enabled": True, "reachable": True, **info}), 200
    except CapdUnavailable as exc:
        return jsonify({"enabled": True, "reachable": False, "error": str(exc)}), 200
    except CapdError as exc:
        return jsonify({"enabled": True, "reachable": False, "error": str(exc)}), 200


# ── interfaces & validation ──────────────────────────────────

@bp.route("/interfaces", methods=["GET"])
@login_required
def list_interfaces():
    if not config.LIVE_CAPTURE_ENABLED:
        return jsonify({"ok": False, "error": "live capture disabled"}), 503
    include_virtual = request.args.get("include_virtual", "0") in ("1", "true", "yes", "on")
    try:
        ifaces = _client().list_interfaces(include_virtual=include_virtual)
    except CapdUnavailable as exc:
        return jsonify({"ok": False, "error": str(exc)}), 503
    except CapdError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 502
    return jsonify({"ok": True, "interfaces": [
        {
            "name": i.name, "mac": i.mac, "ips": i.ips, "is_up": i.is_up,
            "is_loopback": i.is_loopback, "is_virtual": i.is_virtual,
            "mtu": i.mtu, "speed_mbps": i.speed_mbps,
        }
        for i in ifaces
    ]})


@bp.route("/validate-bpf", methods=["POST"])
@login_required
def validate_bpf():
    if not config.LIVE_CAPTURE_ENABLED:
        return jsonify({"ok": False, "error": "live capture disabled"}), 503
    body = request.get_json(silent=True) or {}
    filter_str = str(body.get("filter", ""))
    link_type = int(body.get("link_type", 1))
    try:
        ok, err = _client().validate_bpf(filter_str, link_type=link_type)
    except CapdUnavailable as exc:
        return jsonify({"ok": False, "error": str(exc)}), 503
    return jsonify({"ok": ok, "error": err})


# ── session lifecycle ────────────────────────────────────────

@bp.route("/sessions", methods=["POST"])
@_capture_control_required
def start_session():
    if not config.LIVE_CAPTURE_ENABLED:
        return jsonify({"ok": False, "error": "live capture disabled"}), 503

    body = request.get_json(silent=True) or {}
    interface = str(body.get("interface", "")).strip()
    bpf_filter = str(body.get("bpf_filter", "") or body.get("bpf", ""))
    ring_filesize_kb = int(body.get("ring_filesize_kb") or 200_000)
    ring_files = int(body.get("ring_files") or 10)
    max_duration_s = int(body.get("max_duration_s") or 0)
    project = _require_project(body.get("project_id"))

    if not interface:
        return jsonify({"ok": False, "error": "interface required"}), 400
    if project is None:
        return jsonify({"ok": False, "error": "valid project_id required"}), 400

    # Per-host concurrency cap.
    if manager.active_session_count() >= config.LIVE_CAPTURE_MAX_CONCURRENT:
        return jsonify({
            "ok": False,
            "error": f"max {config.LIVE_CAPTURE_MAX_CONCURRENT} concurrent live captures reached",
        }), 409

    session_uuid = str(uuid.uuid4())
    holder = manager.acquire_interface(interface, session_uuid)
    if holder is not None:
        return jsonify({"ok": False, "error": f"interface {interface} in use by session {holder[:8]}"}), 409

    cs = CaptureSession(
        session_uuid=session_uuid,
        user_id=session["user_id"],
        project_id=project.id,
        interface=interface,
        bpf_filter=bpf_filter,
        ring_filesize_kb=ring_filesize_kb,
        ring_files=ring_files,
        max_duration_s=max_duration_s,
        status="pending",
    )
    db.session.add(cs)
    db.session.commit()

    # Ask capd to start. We do this after the DB row exists so the row
    # is the durable record even if the start RPC times out.
    client = _client()
    try:
        resp = client.start(
            session_id=session_uuid,
            interface=interface,
            bpf_filter=bpf_filter,
            ring_filesize_kb=ring_filesize_kb,
            ring_files=ring_files,
            max_duration_s=max_duration_s,
        )
    except (CapdUnavailable, CapdError) as exc:
        cs.status = "failed"
        cs.error_tail = str(exc)
        cs.stopped_at = datetime.now(timezone.utc)
        db.session.commit()
        manager.release_interface(interface, session_uuid)
        status_code = 503 if isinstance(exc, CapdUnavailable) else 502
        return jsonify({"ok": False, "error": str(exc)}), status_code

    cs.status = "running"
    cs.started_at = datetime.now(timezone.utc)
    cs.capture_dir = resp.get("output_dir")
    db.session.commit()

    # Wire up the StatsHub: it streams capd → SSE subscribers AND
    # triggers the rotation consumer for each closed pcap.
    hub = StatsHub(session_uuid=session_uuid, client=client)
    hub.add_file_listener(consumer.make_listener(
        user_id=cs.user_id, project_id=cs.project_id,
        session_uuid=session_uuid, scan_profile="fast",
    ))
    manager.register_hub(hub)
    hub.start()

    audit("capture.start", target_type="capture_session", target_id=cs.id,
          detail=json.dumps({"interface": interface, "bpf": bpf_filter, "project_id": project.id}))

    return jsonify({"ok": True, "session": _serialize(cs)}), 201


@bp.route("/sessions/<int:sid>/stop", methods=["POST"])
@_capture_control_required
def stop_session(sid: int):
    is_admin = session.get("role") == "admin"
    q = CaptureSession.query.filter_by(id=sid)
    if not is_admin:
        q = q.filter_by(user_id=session["user_id"])
    cs = q.first()
    if cs is None:
        return jsonify({"ok": False, "error": "not found"}), 404
    admin_override = is_admin and cs.user_id != session["user_id"]
    if cs.status not in ("running", "pending"):
        return jsonify({"ok": True, "session": _serialize(cs), "note": "already stopped"})

    cs.status = "stopping"
    db.session.commit()

    try:
        resp = _client().stop(cs.session_uuid)
    except CapdUnavailable as exc:
        cs.status = "failed"
        cs.error_tail = f"stop failed: {exc}"
        cs.stopped_at = datetime.now(timezone.utc)
        db.session.commit()
        manager.release_interface(cs.interface, cs.session_uuid)
        manager.drop_hub(cs.session_uuid)
        return jsonify({"ok": False, "error": str(exc), "session": _serialize(cs)}), 503
    except CapdError as exc:
        cs.status = "failed"
        cs.error_tail = f"stop failed: {exc}"
        cs.stopped_at = datetime.now(timezone.utc)
        db.session.commit()
        manager.release_interface(cs.interface, cs.session_uuid)
        manager.drop_hub(cs.session_uuid)
        return jsonify({"ok": False, "error": str(exc), "session": _serialize(cs)}), 502

    cs.status = "stopped"
    cs.stopped_at = datetime.now(timezone.utc)
    cs.bytes_captured = int(resp.get("bytes_total") or 0)
    if resp.get("packets") is not None:
        cs.packets_captured = int(resp["packets"])
    if resp.get("drops") is not None:
        cs.drop_count = int(resp["drops"])
    files_closed = resp.get("files_closed") or []
    cs.rotation_count = max(cs.rotation_count, len(files_closed))
    db.session.commit()

    # Tear down hub + locks.
    hub = manager.drop_hub(cs.session_uuid)
    if hub is not None:
        hub.shutdown()
    manager.release_interface(cs.interface, cs.session_uuid)

    audit("capture.stop" if not admin_override else "capture.admin_stop",
          target_type="capture_session", target_id=cs.id,
          detail=json.dumps({
              "packets": cs.packets_captured, "drops": cs.drop_count,
              "bytes": cs.bytes_captured,
              "owner_user_id": cs.user_id if admin_override else None,
          }))

    return jsonify({"ok": True, "session": _serialize(cs), "admin_override": admin_override})


@bp.route("/sessions/<int:sid>", methods=["GET"])
@login_required
def get_session(sid: int):
    is_admin = session.get("role") == "admin"
    q = CaptureSession.query.filter_by(id=sid)
    if not is_admin:
        q = q.filter_by(user_id=session["user_id"])
    cs = q.first()
    if cs is None:
        return jsonify({"ok": False, "error": "not found"}), 404
    out = _serialize(cs)
    hub = manager.get_hub(cs.session_uuid)
    if hub is not None and hub.last_frame:
        out["last_frame"] = hub.last_frame
    return jsonify({"ok": True, "session": out})


@bp.route("/sessions", methods=["GET"])
@login_required
def list_sessions():
    project_id = request.args.get("project_id", type=int)
    status_filter = request.args.get("status")
    limit = min(max(request.args.get("limit", 50, type=int), 1), 500)
    show_all = request.args.get("all") in ("1", "true", "yes", "on")
    is_admin = session.get("role") == "admin"

    q = CaptureSession.query
    if not (is_admin and show_all):
        q = q.filter_by(user_id=session["user_id"])
    if project_id is not None:
        q = q.filter_by(project_id=project_id)
    if status_filter:
        q = q.filter_by(status=status_filter)
    rows = q.order_by(CaptureSession.id.desc()).limit(limit).all()

    return jsonify({"ok": True, "sessions": [_serialize(r) for r in rows]})


# ── SSE stats fan-out ────────────────────────────────────────

@bp.route("/sessions/<int:sid>/stream", methods=["GET"])
@login_required
def stream_session(sid: int):
    cs = CaptureSession.query.filter_by(id=sid, user_id=session["user_id"]).first()
    if cs is None:
        return jsonify({"ok": False, "error": "not found"}), 404

    hub = manager.get_hub(cs.session_uuid)
    if hub is None:
        # No active hub — return a one-shot frame describing the final state.
        def _final_only():
            yield "event: final\n"
            yield f"data: {json.dumps(_serialize(cs))}\n\n"
        return Response(stream_with_context(_final_only()),
                        mimetype="text/event-stream")

    @stream_with_context
    def _gen():
        # Comment line forces the browser to flush the response head.
        yield ": connected\n\n"
        try:
            for frame in hub.subscribe():
                yield f"data: {json.dumps(frame)}\n\n"
        except GeneratorExit:
            return

    resp = Response(_gen(), mimetype="text/event-stream")
    resp.headers["Cache-Control"] = "no-cache, no-store"
    resp.headers["X-Accel-Buffering"] = "no"  # disable nginx buffering
    return resp


# ── saved filters ────────────────────────────────────────────

def _serialize_filter(f: SavedFilter) -> dict:
    return {
        "id": f.id,
        "project_id": f.project_id,
        "user_id": f.user_id,
        "name": f.name,
        "expression": f.expression,
        "created_at": f.created_at.isoformat() if f.created_at else None,
    }


@bp.route("/filters", methods=["GET"])
@login_required
def list_filters():
    project_id = request.args.get("project_id", type=int)
    if project_id is None:
        return jsonify({"ok": False, "error": "project_id required"}), 400
    if _require_project(project_id) is None:
        return jsonify({"ok": False, "error": "project not found"}), 404
    rows = SavedFilter.query.filter_by(project_id=project_id) \
                            .order_by(SavedFilter.name.asc()).all()
    return jsonify({"ok": True, "filters": [_serialize_filter(r) for r in rows]})


@bp.route("/filters", methods=["POST"])
@login_required
def create_filter():
    body = request.get_json(silent=True) or {}
    project_id = body.get("project_id")
    name = (body.get("name") or "").strip()
    expression = (body.get("expression") or "").strip()

    if not name or len(name) > 80:
        return jsonify({"ok": False, "error": "name required (1-80 chars)"}), 400
    if not expression:
        return jsonify({"ok": False, "error": "expression required"}), 400
    project = _require_project(project_id)
    if project is None:
        return jsonify({"ok": False, "error": "project not found"}), 404

    existing = SavedFilter.query.filter_by(project_id=project.id, name=name).first()
    if existing is not None:
        return jsonify({"ok": False, "error": "filter with this name already exists"}), 409

    f = SavedFilter(
        project_id=project.id,
        user_id=session["user_id"],
        name=name,
        expression=expression,
    )
    db.session.add(f)
    db.session.commit()
    return jsonify({"ok": True, "filter": _serialize_filter(f)}), 201


@bp.route("/filters/<int:fid>", methods=["DELETE"])
@login_required
def delete_filter(fid: int):
    f = SavedFilter.query.get(fid)
    if f is None:
        return jsonify({"ok": False, "error": "not found"}), 404
    if _require_project(f.project_id) is None:
        return jsonify({"ok": False, "error": "not found"}), 404
    db.session.delete(f)
    db.session.commit()
    return jsonify({"ok": True})
