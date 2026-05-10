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

# Preset PCAPs (volume-backed, admin-editable at runtime)
PRESETS_DIR = os.path.join(DATA_DIR, "presets")

# Baked-in presets (copied to DATA_DIR on first boot)
PRESETS_BAKED_DIR = os.environ.get(
    "MARLINSPIKE_PRESETS_BAKED_DIR", os.path.join(PROJECT_ROOT, "presets")
)

# Upload limits
PCAP_MAX_SIZE = int(os.environ.get("PCAP_MAX_SIZE", 5 * 1024 * 1024 * 1024))  # 5 GB
PCAP_PROCESS_SIZE = int(os.environ.get("PCAP_PROCESS_SIZE", 5 * 1024 * 1024 * 1024))  # 5 GB (chunked pipeline handles large files)

# Database
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://marlinspike:marlinspike@localhost:5432/marlinspike",
)

# Server
PORT = int(os.environ.get("PORT", 5001))
HOST = os.environ.get("HOST", "0.0.0.0")
SESSION_COOKIE_SECURE = _env_bool("SESSION_COOKIE_SECURE", default=False)

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

# Live capture (capd sidecar). Disabled by default; enable per-deployment.
LIVE_CAPTURE_ENABLED = _env_bool("LIVE_CAPTURE_ENABLED", default=False)
LIVE_CAPTURE_SOCKET = os.environ.get(
    "LIVE_CAPTURE_SOCKET", "/var/run/marlinspike-capd.sock"
)
LIVE_CAPTURE_TIMEOUT_S = float(os.environ.get("LIVE_CAPTURE_TIMEOUT_S", "5"))
LIVE_CAPTURE_MAX_CONCURRENT = int(os.environ.get("LIVE_CAPTURE_MAX_CONCURRENT", "2"))
