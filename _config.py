"""MarlinSpike standalone — configuration constants."""

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
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
REPORTS_DIR = os.path.join(DATA_DIR, "reports")
UPLOADS_DIR = os.path.join(DATA_DIR, "uploads")
SUBMISSIONS_DIR = os.path.join(DATA_DIR, "submissions")

# MarlinSpike module path
MARLINSPIKE_PY = os.path.join(BASE_DIR, "marlinspike.py")
PYTHON_EXE = os.environ.get("MARLINSPIKE_PYTHON", sys.executable or "python")
MARLINSPIKE_DPI_BIN = os.environ.get("MARLINSPIKE_DPI_BIN", "")
MARLINSPIKE_DPI_ENGINE = os.environ.get("MARLINSPIKE_DPI_ENGINE", "auto")
MARLINSPIKE_MITRE_ENABLED = os.environ.get("MARLINSPIKE_MITRE_ENABLED", "true").lower() in ("true", "1", "yes")
MARLINSPIKE_MITRE_MODULE = os.environ.get("MARLINSPIKE_MITRE_MODULE", "plugins.marlinspike_mitre")
MARLINSPIKE_MITRE_RULES = os.environ.get(
    "MARLINSPIKE_MITRE_RULES",
    os.path.join(BASE_DIR, "rules", "mitre", "base.yaml"),
)

# Preset PCAPs (volume-backed, admin-editable at runtime)
PRESETS_DIR = os.path.join(DATA_DIR, "presets")

# Baked-in presets (copied to DATA_DIR on first boot)
PRESETS_BAKED_DIR = os.path.join(BASE_DIR, "presets")

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
