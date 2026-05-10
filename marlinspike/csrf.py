"""MarlinSpike — CSRF token helpers (v3.5.4).

Provides per-session CSRF tokens as the primary CSRF defense.  The
existing origin/referer check in app.py is kept as defense-in-depth.

Token lifecycle
---------------
* **Mint** — ``csrf_token()`` lazily mints a 32-byte URL-safe token
  into ``session['_csrf']`` on first call per session.  Subsequent
  calls return the same token for the lifetime of the session.
* **Rotate** — call ``rotate_csrf()`` on login / session fixation
  events.  This pops the stored token so the next ``csrf_token()``
  call mints a fresh one.
* **Validate** — ``validate_csrf(candidate)`` performs a constant-time
  compare (``secrets.compare_digest``) against the session token.
  Returns ``False`` if the session has no token or the candidate is
  empty/None.
"""

import secrets

from flask import session


def csrf_token() -> str:
    """Return the CSRF token for the current session, minting one if absent."""
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]


def validate_csrf(candidate: str | None) -> bool:
    """Validate *candidate* against the current session token.

    Uses ``secrets.compare_digest`` for constant-time comparison to
    prevent timing-oracle attacks.  Returns ``False`` when either side
    is missing.
    """
    if not candidate:
        return False
    stored = session.get("_csrf")
    if not stored:
        return False
    # compare_digest requires same type on both sides
    return secrets.compare_digest(
        stored.encode() if isinstance(stored, str) else stored,
        candidate.encode() if isinstance(candidate, str) else candidate,
    )


def rotate_csrf() -> None:
    """Drop the current session CSRF token so a fresh one is minted next access.

    Call this on any session-fixation event (login, password change,
    privilege escalation).  The next call to ``csrf_token()`` will
    produce a new token.
    """
    session.pop("_csrf", None)
