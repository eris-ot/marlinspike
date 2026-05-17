"""Tests for the Alembic migration baseline (v3.5.4).

These tests verify that:
  1. The baseline migration (0001_baseline) applies cleanly to an empty DB.
  2. Running upgrade() a second time is a no-op (idempotent).
  3. The schema produced by Alembic matches what db.create_all() would produce,
     so existing deployments that stamp at head don't see a schema diff on the
     next autogenerate run.

Environment notes
-----------------
All tests use a temporary file-based SQLite database so that Alembic's
online path (which opens a connection through the app's shared pool) works
correctly.  We never touch DATABASE_URL — only app.config.

If flask-migrate is not installed (bare test environment without the
``migrations`` extra) the tests are skipped cleanly.
"""

from __future__ import annotations

import os
import pathlib

import pytest

# ---------------------------------------------------------------------------
# Guard: skip the whole module when flask-migrate is absent.
# ---------------------------------------------------------------------------
flask_migrate = pytest.importorskip("flask_migrate", reason="flask-migrate not installed")
pytest.importorskip("alembic.runtime.migration", reason="alembic not installed")

# Env guard so the test suite doesn't fail when these are unset in CI.
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-alembic-migrations")

MIGRATIONS_DIR = pathlib.Path(__file__).parent.parent / "migrations"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_app(db_url: str):
    """Create a minimal Flask app wired to the given database URL.

    We do NOT call create_app() here — that would run the full bootstrap
    (admin creation, recovery, preset sync).  We only need the db/Migrate
    objects to exercise the migration layer.

    Returns (app, db) where db is the Flask-SQLAlchemy extension bound to app.
    """
    from flask import Flask
    from flask_migrate import Migrate
    from marlinspike.models import db

    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = db_url
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.secret_key = "test-secret"

    db.init_app(app)
    Migrate(app, db, directory=str(MIGRATIONS_DIR), render_as_batch=True)
    return app, db


def _table_names(app, db) -> set[str]:
    from sqlalchemy import inspect as sa_inspect
    with app.app_context():
        insp = sa_inspect(db.engine)
        return set(insp.get_table_names())


def _column_names(app, db, table: str) -> set[str]:
    from sqlalchemy import inspect as sa_inspect
    with app.app_context():
        insp = sa_inspect(db.engine)
        return {col["name"] for col in insp.get_columns(table)}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_db(tmp_path):
    """Return a file-based SQLite URL in a temporary directory."""
    db_file = tmp_path / "test_migrations.db"
    return f"sqlite:///{db_file}"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_migrations_directory_exists():
    """Smoke: migrations/ is present and has at least one version file."""
    assert MIGRATIONS_DIR.is_dir(), f"migrations/ not found at {MIGRATIONS_DIR}"
    versions = list((MIGRATIONS_DIR / "versions").glob("*.py"))
    assert versions, "No migration version files found in migrations/versions/"


def test_baseline_applies_to_empty_db(tmp_db):
    """The 0001_baseline migration should create all tables from scratch."""
    from flask_migrate import upgrade

    app, db = _make_app(tmp_db)
    with app.app_context():
        upgrade()

    tables = _table_names(app, db)

    expected_tables = {
        "users",
        "projects",
        "project_members",
        "scan_history",
        "password_reset_tokens",
        "asset_tags",
        "finding_notes",
        "audit_log",
        "ioc_lists",
        "ioc_entries",
        "capture_sessions",
        "saved_filters",
        "alembic_version",  # Alembic tracking table
    }
    assert expected_tables <= tables, (
        f"Missing tables after baseline migration: {expected_tables - tables}"
    )


def test_upgrade_is_idempotent(tmp_db):
    """Running upgrade() twice should be a no-op (no errors, no duplicate work)."""
    from flask_migrate import upgrade

    app, db = _make_app(tmp_db)
    with app.app_context():
        upgrade()  # first run — applies baseline
        upgrade()  # second run — should be a no-op

        # Verify still at head revision after double-run.
        from alembic.runtime.migration import MigrationContext
        with db.engine.connect() as conn:
            ctx = MigrationContext.configure(conn)
            current = ctx.get_current_revision()

    assert current == "0002", f"Expected revision '0002', got {current!r}"


def test_recovery_columns_present(tmp_db):
    """v3.4.0 recovery columns must exist after baseline migration."""
    from flask_migrate import upgrade

    app, db = _make_app(tmp_db)
    with app.app_context():
        upgrade()

    required_recovery_cols = {
        "pcap_path",
        "engine_pid",
        "engine_argv",
        "timeout_at",
        "recovery_state",
    }
    cols = _column_names(app, db, "scan_history")
    missing = required_recovery_cols - cols
    assert not missing, (
        f"Recovery columns missing from scan_history after baseline migration: {missing}"
    )


def test_schema_matches_create_all(tmp_path):
    """Alembic baseline should produce the same columns as db.create_all().

    This guards against schema drift between models.py and the migration file,
    which would cause autogenerate to emit spurious ALTER TABLE statements the
    first time a developer runs ``flask db migrate`` post-upgrade.
    """
    from flask import Flask
    from flask_migrate import Migrate, upgrade
    from sqlalchemy import create_engine
    from sqlalchemy import inspect as sa_inspect
    from marlinspike.models import db

    # --- DB A: populated via Alembic upgrade ---
    db_a_path = tmp_path / "schema_alembic.db"
    app_a = Flask("test_alembic_a")
    app_a.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_a_path}"
    app_a.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app_a.secret_key = "test"
    db.init_app(app_a)
    Migrate(app_a, db, directory=str(MIGRATIONS_DIR), render_as_batch=True)

    with app_a.app_context():
        upgrade()

    # --- DB B: populated via db.create_all() ---
    db_b_path = tmp_path / "schema_create_all.db"
    app_b = Flask("test_alembic_b")
    app_b.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_b_path}"
    app_b.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app_b.secret_key = "test"
    db.init_app(app_b)

    with app_b.app_context():
        db.create_all()

    # --- Compare column sets for every application table ---
    def get_columns(db_path):
        engine = create_engine(f"sqlite:///{db_path}")
        insp = sa_inspect(engine)
        result = {}
        for tname in insp.get_table_names():
            if tname == "alembic_version":
                continue
            result[tname] = {col["name"] for col in insp.get_columns(tname)}
        engine.dispose()
        return result

    cols_alembic = get_columns(db_a_path)
    cols_create_all = get_columns(db_b_path)

    assert set(cols_alembic.keys()) == set(cols_create_all.keys()), (
        f"Table set mismatch.\n"
        f"  Alembic only: {set(cols_alembic) - set(cols_create_all)}\n"
        f"  create_all only: {set(cols_create_all) - set(cols_alembic)}"
    )

    for table in cols_create_all:
        alembic_cols = cols_alembic.get(table, set())
        create_all_cols = cols_create_all[table]
        assert alembic_cols == create_all_cols, (
            f"Column mismatch on {table!r}:\n"
            f"  Alembic only:     {alembic_cols - create_all_cols}\n"
            f"  create_all only:  {create_all_cols - alembic_cols}"
        )
