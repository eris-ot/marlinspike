"""MarlinSpike — configuration constants.

Path resolution
---------------
The package may be imported from a checked-out source tree (where ``data/``,
``rules/`` and ``presets/`` live next to the ``marlinspike/`` directory) or
from a pip-installed location (where those project assets need to be supplied
externally). Two anchors:

* ``PACKAGE_DIR`` — directory of this file (always inside the installed package).
* ``PROJECT_ROOT`` — repo root in dev; in production, override with the
  ``MARLINSPIKE_PROJECT_ROOT`` environment variable to point at the directory
  that holds ``data/``, ``rules/`` and ``presets/``.

Individual asset directories may also be overridden directly via env vars
(``MARLINSPIKE_DATA_DIR``, ``MARLINSPIKE_RULES_DIR``, ``MARLINSPIKE_PRESETS_BAKED_DIR``).

``BASE_DIR`` is retained as an alias for ``PROJECT_ROOT`` for backwards
compatibility with code that does ``config.BASE_DIR``.
"""

import os
import sys


_TRUE_VALUES = {"true", "1", "yes", "on"}


def _env_bool(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in _TRUE_VALUES

# Secret key for Flask sessions
SECRET_KEY = os.environ.get("SECRET_KEY", "")

# Admin bootstrap password (if empty, one is generated on first run)
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")

# Paths
PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.environ.get(
    "MARLINSPIKE_PROJECT_ROOT", os.path.dirname(PACKAGE_DIR)
)
BASE_DIR = PROJECT_ROOT  # backwards-compatible alias for v2.x callers
DATA_DIR = os.environ.get("MARLINSPIKE_DATA_DIR", os.path.join(PROJECT_ROOT, "data"))
RULES_DIR = os.environ.get("MARLINSPIKE_RULES_DIR", os.path.join(PROJECT_ROOT, "rules"))
REPORTS_DIR = os.path.join(DATA_DIR, "reports")
UPLOADS_DIR = os.path.join(DATA_DIR, "uploads")
SUBMISSIONS_DIR = os.path.join(DATA_DIR, "submissions")

# Engine subprocess invocation. The web app shells out to the analysis engine
# via ``python -m marlinspike <args>``; ``-u`` keeps stdout unbuffered so that
# live tail of scan output works.
PYTHON_EXE = os.environ.get("MARLINSPIKE_PYTHON", sys.executable or "python")
MARLINSPIKE_ENGINE_CMD = [PYTHON_EXE, "-u", "-m", "marlinspike"]

MARLINSPIKE_DPI_BIN = os.environ.get("MARLINSPIKE_DPI_BIN", "")
MARLINSPIKE_DPI_ENGINE = os.environ.get("MARLINSPIKE_DPI_ENGINE", "auto")
MARLINSPIKE_MITRE_ENABLED = os.environ.get("MARLINSPIKE_MITRE_ENABLED", "true").lower() in ("true", "1", "yes")
MARLINSPIKE_MITRE_MODULE = os.environ.get("MARLINSPIKE_MITRE_MODULE", "plugins.marlinspike_mitre")
MARLINSPIKE_MITRE_RULES = os.environ.get(
    "MARLINSPIKE_MITRE_RULES",
    os.path.join(RULES_DIR, "mitre", "base.yaml"),
)
MARLINSPIKE_ARP_ENABLED = os.environ.get("MARLINSPIKE_ARP_ENABLED", "true").lower() in ("true", "1", "yes")
MARLINSPIKE_ARP_MODULE = os.environ.get("MARLINSPIKE_ARP_MODULE", "plugins.marlinspike_arp")
MARLINSPIKE_ARP_RULES = os.environ.get(
    "MARLINSPIKE_ARP_RULES",
    os.path.join(RULES_DIR, "arp", "base.yaml"),
)
MARLINSPIKE_APT_ENABLED = os.environ.get("MARLINSPIKE_APT_ENABLED", "true").lower() in ("true", "1", "yes")
MARLINSPIKE_APT_MODULE = os.environ.get("MARLINSPIKE_APT_MODULE", "plugins.marlinspike_apt")
MARLINSPIKE_APT_RULES = os.environ.get(
    "MARLINSPIKE_APT_RULES",
    os.path.join(RULES_DIR, "apt", "base.yaml"),
)
MARLINSPIKE_CISA_ENABLED = os.environ.get("MARLINSPIKE_CISA_ENABLED", "true").lower() in ("true", "1", "yes")
MARLINSPIKE_CISA_MODULE = os.environ.get("MARLINSPIKE_CISA_MODULE", "plugins.marlinspike_cisa")
MARLINSPIKE_CISA_RULES = os.environ.get(
    "MARLINSPIKE_CISA_RULES",
    os.path.join(RULES_DIR, "cisa", "base.yaml"),
)

# Preset PCAPs (volume-backed, admin-editable at runtime)
PRESETS_DIR = os.path.join(DATA_DIR, "presets")

# Baked-in presets (copied to DATA_DIR on first boot)
PRESETS_BAKED_DIR = os.environ.get(
    "MARLINSPIKE_PRESETS_BAKED_DIR", os.path.join(PROJECT_ROOT, "presets")
)

# Upload limits
PCAP_MAX_SIZE = int(os.environ.get("PCAP_MAX_SIZE", 5 * 1024 * 1024 * 1024))  # 5 GB
PCAP_PROCESS_SIZE = int(os.environ.get("PCAP_PROCESS_SIZE", 5 * 1024 * 1024 * 1024))  # 5 GB (chunked pipeline handles large files)

# Database — no default. The previous v3.5.1 default
# ``postgresql://marlinspike:marlinspike@localhost:5432/marlinspike`` was
# a predictable credential that attackers who know the project could try
# directly. v3.5.2 removes the default. Set DATABASE_URL explicitly
# (production: a strong password; dev: ``sqlite:///./data/dev.db`` or
# similar). create_app() refuses to start when this is empty unless
# MARLINSPIKE_ALLOW_NO_DATABASE_URL=true is set (test-only escape hatch).
DATABASE_URL = os.environ.get("DATABASE_URL", "")
ALLOW_NO_DATABASE_URL = _env_bool("MARLINSPIKE_ALLOW_NO_DATABASE_URL", default=False)

# Server
PORT = int(os.environ.get("PORT", 5001))
HOST = os.environ.get("HOST", "0.0.0.0")

# Rate limiting backend. Leave empty for single-process dev/test to use
# in-memory counters. Production deployments should point this at a shared
# backend so auth/upload throttles survive restarts and span workers.
# Example: redis://ratelimit:6379/0
RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "").strip()

# Session cookies. v3.5.2 flipped the default to True (production-safe).
# When the app is reached over plain HTTP (dev or behind a TLS-terminating
# proxy that re-issues plain HTTP internally), set
# MARLINSPIKE_DEV_INSECURE_COOKIES=true to opt out. The legacy
# SESSION_COOKIE_SECURE env var still works and overrides this default.
_dev_insecure = _env_bool("MARLINSPIKE_DEV_INSECURE_COOKIES", default=False)
SESSION_COOKIE_SECURE = _env_bool("SESSION_COOKIE_SECURE", default=not _dev_insecure)

# Run cleanup
RUN_CLEANUP_SECONDS = 3600

# Run state backend. ``memory`` (legacy) tracks active runs in a
# process-local dict — fine for single-worker deployments. ``db``
# routes the active-run count and concurrency check through
# ``scan_history`` so multiple Gunicorn workers share a consistent view.
# See ``docs/run-store-and-recovery.md``.
MARLINSPIKE_RUN_STORE = os.environ.get("MARLINSPIKE_RUN_STORE", "memory").lower()

# Per-scan deadline. The recovery reaper marks rows still ``running``
# past this many seconds since ``started_at`` as ``failed`` with an
# abandoned reason. Set to 0 to disable (unbounded scans).
MARLINSPIKE_SCAN_TIMEOUT_S = int(os.environ.get("MARLINSPIKE_SCAN_TIMEOUT_S", "3600"))

# OCSF v1.4.0 emit. When true, every chain-style scan that produces a
# ``report.json`` also writes a sibling ``report.ocsf.ndjson`` containing
# OCSF Detection Finding (2004) records for the application-layer
# findings (risk_findings, c2_indicators, malware_findings,
# mitre_classifications). Wire-derived Bronze events get OCSF emit by
# ``marlinspike-dpi`` itself when called with ``--format ocsf``;
# concatenate the two streams for a complete OCSF view of one capture.
# See marlinspike.emit.ocsf and docs/ocsf-emit.md.
MARLINSPIKE_EMIT_OCSF = _env_bool("MARLINSPIKE_EMIT_OCSF", default=True)

# MITRE ATT&CK Navigator v4.5 layer JSON emit. When true, every chain
# scan that produces MITRE classifications also writes per-domain
# Navigator layer files (``<basename>.navigator.ics.json`` and/or
# ``<basename>.navigator.enterprise.json``). Defenders can drop these
# directly into a hosted ATT&CK Navigator instance for visualisation.
# See marlinspike.emit.navigator and docs/ocsf-emit.md.
MARLINSPIKE_EMIT_NAVIGATOR = _env_bool("MARLINSPIKE_EMIT_NAVIGATOR", default=True)

# STIX 2.1 bundle emit. When true, every chain scan also writes
# ``<basename>.stix.json`` — risk_findings + c2_indicators +
# malware_findings + mitre_classifications mapped to STIX indicators
# / attack-patterns / sightings. Stable IDs (UUIDv5) so re-running
# emit is reproducible.
MARLINSPIKE_EMIT_STIX = _env_bool("MARLINSPIKE_EMIT_STIX", default=True)

# Sigma rule emit. When true, every chain scan that produces
# Sigma-translatable findings (CROSS_PURDUE / ICS_EXTERNAL_COMMS /
# CLEARTEXT_REMOTE_ACCESS / CLEARTEXT_ENG / MODBUS_WRITE_ANON /
# C2_BEACONING / MALWARE_IOC_MATCH) writes ``<basename>.sigma.yml``,
# a multi-document YAML stream of Sigma rules targeting Zeek conn.log
# / dns.log / modbus.log.
MARLINSPIKE_EMIT_SIGMA = _env_bool("MARLINSPIKE_EMIT_SIGMA", default=True)

# ── Security knobs ──────────────────────────────────────────────────────────
#
# Password reset token delivery. The reset-request endpoint USED to return
# the token in the HTTP response, which made it an unauthenticated account
# takeover (anyone who knew a username could reset that account). Fixed in
# v3.5.2: the token is never returned in the response. Operators choose how
# tokens are delivered:
#
#   "disabled" (default) — the reset endpoint returns 503. Use a different
#                          recovery path (admin manually resets via DB or CLI).
#   "file"               — token written to
#                          ${DATA_DIR}/instance/reset-tokens/<username>-<ts>.txt
#                          mode 0600, owner-readable only. Operator delivers
#                          to the user out-of-band.
#   "log"                — token printed to stderr only. For dev / single-host
#                          deployments where the operator watches the log.
#                          Container logs may persist this; not for production.
#
# Cloudmarlin and other wrappers can override by replacing the
# ``deliver_reset_token`` hook (see marlinspike.auth).
MARLINSPIKE_RESET_TOKEN_DELIVERY = os.environ.get(
    "MARLINSPIKE_RESET_TOKEN_DELIVERY", "disabled"
).lower()

# Live capture session control (start/stop) requires admin role by default.
# Set to "any" to permit any logged-in user to start/stop capture sessions.
# Live capture drives a privileged sidecar with CAP_NET_RAW; leaving this
# at "admin" prevents low-privilege accounts from initiating packet capture
# on host interfaces.
MARLINSPIKE_CAPTURE_REQUIRE = os.environ.get(
    "MARLINSPIKE_CAPTURE_REQUIRE", "admin"
).lower()

# Allowed origins for CSRF check. Default: derived from request.url_root
# (the request's own scheme+host+port). Set to a comma-separated list to
# allow additional origins (e.g. "https://app.example.com,https://admin.example.com").
# Empty means "request origin only".
MARLINSPIKE_ALLOWED_ORIGINS = [
    o.strip().rstrip("/")
    for o in os.environ.get("MARLINSPIKE_ALLOWED_ORIGINS", "").split(",")
    if o.strip()
]

# Live capture (capd sidecar). Disabled by default; enable per-deployment.
LIVE_CAPTURE_ENABLED = _env_bool("LIVE_CAPTURE_ENABLED", default=False)
LIVE_CAPTURE_SOCKET = os.environ.get(
    "LIVE_CAPTURE_SOCKET", "/var/run/marlinspike-capd.sock"
)
LIVE_CAPTURE_TIMEOUT_S = float(os.environ.get("LIVE_CAPTURE_TIMEOUT_S", "5"))
LIVE_CAPTURE_MAX_CONCURRENT = int(os.environ.get("LIVE_CAPTURE_MAX_CONCURRENT", "2"))

# System-wide interface allowlist. When unset, any interface is permitted.
# When set to a comma-separated list, only those interfaces may be captured on.
# Example: MARLINSPIKE_CAPTURE_INTERFACE_ALLOWLIST=eth0,eth1
# Use to prevent capture on management NICs.
_raw_iface_allowlist = os.environ.get("MARLINSPIKE_CAPTURE_INTERFACE_ALLOWLIST", "").strip()
MARLINSPIKE_CAPTURE_INTERFACE_ALLOWLIST: list[str] = [
    i.strip() for i in _raw_iface_allowlist.split(",") if i.strip()
]
