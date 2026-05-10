"""marlinspike-db — thin wrapper around Flask-Migrate CLI commands.

Operators use this instead of learning Flask-Migrate's invocation conventions::

    python -m marlinspike.db upgrade        # advance to latest migration
    python -m marlinspike.db downgrade      # roll back one step
    python -m marlinspike.db current        # show current DB revision
    python -m marlinspike.db stamp head     # mark existing DB as baseline
    python -m marlinspike.db migrate -m "add widget table"  # generate migration
    python -m marlinspike.db history        # list migration history
    python -m marlinspike.db --help         # show available subcommands

Environment
-----------
DATABASE_URL and SECRET_KEY must be set (or MARLINSPIKE_ALLOW_NO_DATABASE_URL /
MARLINSPIKE_ALLOW_GENERATED_SECRET for dev/test).  All other MarlinSpike env
vars are honoured as normal.

Exit codes: 0 on success, non-zero on failure (Alembic / Flask-Migrate
propagates its own exit codes through the Click framework).
"""

from __future__ import annotations

import sys


def main() -> None:
    """Entry point for the ``marlinspike-db`` console script."""
    try:
        from flask_migrate import upgrade as _  # noqa: F401 — validate dep present
    except ImportError:
        print(
            "flask-migrate is not installed.  Install it with:\n"
            "    pip install marlinspike[migrations]\n",
            file=sys.stderr,
        )
        sys.exit(1)

    # Build a minimal Flask app — enough to give Flask-Migrate a db + app context.
    # We avoid importing create_app() because that runs the full bootstrap
    # (admin creation, recovery, preset sync) which we don't want in a DB tool.
    from flask import Flask
    from flask_migrate import Migrate
    from flask_sqlalchemy import SQLAlchemy

    from marlinspike import config
    from marlinspike.models import db

    app = Flask(__name__)

    db_url = config.DATABASE_URL
    if not db_url:
        if config.ALLOW_NO_DATABASE_URL:
            db_url = "sqlite:///:memory:"
        else:
            print(
                "DATABASE_URL is not set.  "
                "Set it before running marlinspike-db.",
                file=sys.stderr,
            )
            sys.exit(1)

    app.config["SQLALCHEMY_DATABASE_URI"] = db_url
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.secret_key = config.SECRET_KEY or "cli-placeholder"

    db.init_app(app)

    import pathlib

    # Locate the migrations/ directory relative to this file.
    _pkg_dir = pathlib.Path(__file__).parent
    _migrations_dir = _pkg_dir.parent / "migrations"
    if not _migrations_dir.is_dir():
        print(
            f"migrations/ directory not found at {_migrations_dir}.\n"
            "marlinspike-db requires the source tree (not a bare pip install).",
            file=sys.stderr,
        )
        sys.exit(1)

    migrate = Migrate(app, db, directory=str(_migrations_dir))

    # Delegate to Flask-Migrate's Click group.
    # We re-invoke as if the user called `flask db <args>`, but without
    # requiring the FLASK_APP env var.
    from flask_migrate import cli as migrate_cli

    with app.app_context():
        # Click group registered as "db" by Flask-Migrate
        db_group = app.cli.commands.get("db")  # type: ignore[attr-defined]
        if db_group is None:
            # Fallback: use the migrate_cli directly
            db_group = migrate_cli

        # Strip argv[0] (the script name); Click handles the rest.
        args = sys.argv[1:]
        if not args:
            args = ["--help"]

        try:
            db_group.main(args=args, standalone_mode=True)
        except SystemExit:
            raise
        except Exception as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
