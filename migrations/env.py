"""Alembic environment — wired to the MarlinSpike Flask app and models.

This file follows the Flask-Migrate template pattern closely so that both
``flask db upgrade`` (CLI) and the programmatic ``flask_migrate.upgrade()``
call inside create_app() use the same app-context engine (not a NullPool
standalone engine).

For the standalone Alembic CLI (without Flask), set DATABASE_URL in the
environment and run ``alembic -c migrations/alembic.ini upgrade head``.
"""

from __future__ import annotations

import logging
import os
from logging.config import fileConfig

from alembic import context

# ---------------------------------------------------------------------------
# Alembic Config object
# ---------------------------------------------------------------------------
config = context.config

# Interpret the config file for Python logging when not running under Flask.
if config.config_file_name is not None:
    try:
        fileConfig(config.config_file_name)
    except Exception:
        pass

logger = logging.getLogger("alembic.env")


# ---------------------------------------------------------------------------
# Engine / metadata resolution
# ---------------------------------------------------------------------------

def _is_flask_context() -> bool:
    """Return True when running inside a Flask application context."""
    try:
        from flask import current_app
        _ = current_app.extensions  # will raise RuntimeError if no ctx
        return True
    except RuntimeError:
        return False


def get_engine():
    """Return the SQLAlchemy engine, preferring the Flask-app bound engine."""
    if _is_flask_context():
        from flask import current_app
        db = current_app.extensions["migrate"].db
        # Flask-SQLAlchemy >= 3.x uses .engine directly; get_engine() is
        # deprecated and removed in 3.2.
        try:
            return db.engine
        except AttributeError:
            return db.get_engine()
    # Standalone CLI fallback: build an engine from DATABASE_URL.
    from sqlalchemy import create_engine
    from sqlalchemy.pool import NullPool

    url = (
        config.get_main_option("sqlalchemy.url")
        or os.environ.get("DATABASE_URL", "")
    )
    if not url:
        raise RuntimeError(
            "No database URL for Alembic.  Set DATABASE_URL or sqlalchemy.url."
        )
    return create_engine(url, poolclass=NullPool)


def get_metadata():
    """Return the SQLAlchemy MetaData, from Flask context if available."""
    if _is_flask_context():
        from flask import current_app
        db = current_app.extensions["migrate"].db
        if hasattr(db, "metadatas"):
            return db.metadatas[None]
        return db.metadata
    # Standalone: import models directly.
    from marlinspike.models import db
    return db.metadata


# ---------------------------------------------------------------------------
# Offline migration (generate SQL without connecting)
# ---------------------------------------------------------------------------

def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (emit SQL to stdout)."""
    if _is_flask_context():
        from flask import current_app
        url = get_engine().url.render_as_string(hide_password=False)
    else:
        url = (
            config.get_main_option("sqlalchemy.url")
            or os.environ.get("DATABASE_URL", "")
        )

    context.configure(
        url=url,
        target_metadata=get_metadata(),
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


# ---------------------------------------------------------------------------
# Online migration (connect to the DB and apply)
# ---------------------------------------------------------------------------

def run_migrations_online() -> None:
    """Run migrations in 'online' mode using the app-bound engine."""

    def process_revision_directives(ctx, revision, directives):
        if getattr(config.cmd_opts, "autogenerate", False):
            script = directives[0]
            if script.upgrade_ops.is_empty():
                directives[:] = []
                logger.info("No changes in schema detected.")

    # Collect configure_args from Flask-Migrate when available.
    if _is_flask_context():
        from flask import current_app
        conf_args = dict(current_app.extensions["migrate"].configure_args)
        if conf_args.get("process_revision_directives") is None:
            conf_args["process_revision_directives"] = process_revision_directives
    else:
        conf_args = {
            "compare_type": True,
            "render_as_batch": True,
            "process_revision_directives": process_revision_directives,
        }

    connectable = get_engine()

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=get_metadata(),
            **conf_args,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
