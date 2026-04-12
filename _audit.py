"""MarlinSpike standalone — immutable audit logging."""

import json
import logging

from flask import request, session

from _models import AuditLog, db

log = logging.getLogger("marlinspike.audit")


def audit(event_type, *, target_type=None, target_id=None, status="success",
          detail=None, actor_user_id=None, actor_username=None,
          actor_role=None, ip_address=None):
    """Write an immutable audit log entry.

    Auto-populates actor from flask.session and IP from flask.request
    when not explicitly provided.  Never raises — silently rolls back
    on failure so audit calls never break normal operations.
    """
    try:
        if actor_user_id is None:
            actor_user_id = session.get("user_id")
        if actor_username is None:
            actor_username = session.get("user")
        if actor_role is None:
            actor_role = session.get("role")
        if ip_address is None:
            try:
                ip_address = request.remote_addr
            except RuntimeError:
                pass

        category = event_type.split(".")[0] if "." in event_type else event_type
        detail_json = json.dumps(detail, default=str) if detail is not None else None

        entry = AuditLog(
            event_type=event_type,
            category=category,
            actor_user_id=actor_user_id,
            actor_username=actor_username,
            actor_role=actor_role,
            target_type=target_type,
            target_id=str(target_id) if target_id is not None else None,
            status=status,
            ip_address=ip_address,
            detail=detail_json,
        )
        db.session.add(entry)
        db.session.commit()
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass
        log.warning("Failed to write audit entry: %s", event_type, exc_info=True)
