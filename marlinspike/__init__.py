"""MarlinSpike — passive OT/IT network topology mapping and risk analysis.

This package exposes the Flask application factory and SQLAlchemy database
handle so downstream projects (e.g. cloudmarlin) can wrap or extend the app
without forking the source tree.

Public API:
    create_app() -> Flask           — application factory
    db                              — shared SQLAlchemy instance
    __version__                     — package version
"""

__version__ = "3.6.0"

# Lazy re-exports so `import marlinspike` does not pull Flask at import time.
__all__ = ["__version__", "create_app", "db"]


def __getattr__(name):
    if name == "create_app":
        from marlinspike.app import create_app
        return create_app
    if name == "db":
        from marlinspike.models import db
        return db
    raise AttributeError(f"module 'marlinspike' has no attribute {name!r}")
