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

# Live capture (capd sidecar). Disabled by default; enable per-deployment.
LIVE_CAPTURE_ENABLED = _env_bool("LIVE_CAPTURE_ENABLED", default=False)
LIVE_CAPTURE_SOCKET = os.environ.get(
    "LIVE_CAPTURE_SOCKET", "/var/run/marlinspike-capd.sock"
)
LIVE_CAPTURE_TIMEOUT_S = float(os.environ.get("LIVE_CAPTURE_TIMEOUT_S", "5"))
LIVE_CAPTURE_MAX_CONCURRENT = int(os.environ.get("LIVE_CAPTURE_MAX_CONCURRENT", "2"))
