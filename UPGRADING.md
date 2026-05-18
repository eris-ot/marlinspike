# Upgrading MarlinSpike

## v3.5.6 → v3.6.0 — enrichment runs in the engine

Enrichment (MITRE / ARP / APT / CISA) moved out of the web app
(`app.py:_finalize_run`) into the engine (`marlinspike/enrich.py`, called by
`chain`). There is **no schema or database migration** and no API change.

**Behavior change — headless callers only.** `engine.py chain` and
`chain-from-conversations` now run the enrichment plugins by default and merge
them into `report.json` (`extensions` + plugin-sourced `risk_findings`).
Previously a headless `chain` produced a core-only report and only the web
app added enrichment.

- To keep the old core-only output (e.g. a fast/triage path), pass
  `--no-enrich`. Enrichment is also skippable per-plugin via the existing
  `MARLINSPIKE_<MITRE|ARP|APT|CISA>_ENABLED=false`.
- A slow or failing plugin is logged and skipped — it never fails the chain.
- `report.json` is now self-complete after `chain`; consumers no longer need
  to read the `*-mitre.json` / `*-arp.json` / … sidecars separately (the
  sidecars are still written, unchanged).
- The web app is unaffected: it delegates to the same `marlinspike.enrich`
  implementation; rendering and the viewer behave exactly as before.

No action required for web/Docker deployments. Headless / batch / CI callers
that depend on the exact previous `chain` output should add `--no-enrich`.

## v3.5.3 → v3.5.4 — Alembic migrations

v3.5.4 replaces the ad-hoc `db.create_all()` + `ALTER TABLE ADD COLUMN IF NOT
EXISTS` startup path with [Alembic](https://alembic.sqlalchemy.org/) managed
via [Flask-Migrate](https://flask-migrate.readthedocs.io/).  The v3.4 recovery
columns (`pcap_path`, `engine_pid`, `engine_argv`, `timeout_at`,
`recovery_state`) are included in the baseline migration.

### What changed

- `migrations/` directory added at repo root containing `env.py`, version
  scripts, and `alembic.ini`.
- `create_app()` now calls `flask_migrate.upgrade()` instead of the ad-hoc
  ALTER TABLE loop.  The fallback to `db.create_all()` is preserved for
  environments where the migrations tree is absent (bare `pip install`) or
  `MARLINSPIKE_ALLOW_NO_DATABASE_URL=true` (test mode).
- New console script `marlinspike-db` (requires `marlinspike[migrations]`).
- New optional-dependency group: `pip install marlinspike[migrations]`.

### Existing deployments (v3.5.x or earlier)

Your database schema was already created by the legacy `db.create_all()` path.
You **must stamp the database at the baseline revision** before the first boot
of v3.5.4 — otherwise Alembic will attempt to re-create every table and fail.

```sh
# 1. Install the new extras
pip install "marlinspike[migrations]"

# 2. Stamp the existing database at the baseline (no DDL is run)
marlinspike-db stamp head

# 3. Upgrade to v3.5.4 normally; create_app() will find the DB already at head
systemctl restart marlinspike  # or docker compose up -d --build
```

Docker Compose one-liner (runs inside the running container):

```sh
docker compose exec app python -m marlinspike.db stamp head
docker compose up -d --build
```

### Fresh deployments

Nothing to do.  The first `create_app()` boot runs `alembic upgrade head`
automatically and creates the full schema including all recovery columns.

### Day-to-day migration workflow (developers / operators)

```sh
# Check which revision the target DB is at
python -m marlinspike.db current

# Advance the DB to the latest migration (run after git pull)
python -m marlinspike.db upgrade

# Roll back one step
python -m marlinspike.db downgrade

# After editing marlinspike/models.py: auto-generate a new migration
python -m marlinspike.db migrate -m "add widget column to users"
# Review the generated file in migrations/versions/, then commit it.
```

### Bare `pip install` (no source tree)

If you install only the wheel (not the source tree), the `migrations/`
directory is absent.  `create_app()` detects this and falls back to
`db.create_all()` with a log warning.  No action required; behaviour is
identical to v3.5.3 in this scenario.  To opt in to Alembic tracking,
supply the migrations tree alongside the installed package and set
`MARLINSPIKE_PROJECT_ROOT` accordingly.

### Breaking changes

**None for standalone deployments that follow the stamp step above.**
The schema on disk is unchanged; only the tracking mechanism is new.

Deployments that skip the stamp step on an existing database will see Alembic
errors on the next `create_app()` boot (tables already exist).  Recovery:

```sh
marlinspike-db stamp head
```

Then restart.

---

## v3.3.0 → v3.4.0 — Mid-scan recovery

v3.4.0 fixes a long-standing reliability gap: when the Flask process
died mid-scan (deploy, OOM, container restart, host reboot), in-flight
``scan_history`` rows were stuck in ``running`` forever. The engine
subprocess was reparented to ``init`` / ``launchd`` and usually ran to
completion — but marlinspike had no way to find it again, and the only
recovery was a manual SQL update.

v3.4.0 ships a startup reaper that walks ``scan_history`` on every
``create_app()`` boot and reconciles each row.

### What's new

- New module ``marlinspike/run_store.py`` — persists the recovery
  essentials (engine PID, engine argv, deadline) on ``scan_history``.
- New module ``marlinspike/recovery.py`` — boot-time reaper +
  PID-reuse defense + watcher thread for re-attached engines.
- ``scan_history`` gains five nullable columns: ``pcap_path``,
  ``engine_pid``, ``engine_argv``, ``timeout_at``, ``recovery_state``.
  Materialised by the existing ``db.create_all()`` plus per-column
  ``ALTER TABLE … ADD COLUMN`` migration loop in ``create_app()`` — no
  Alembic step.
- Two new env vars (both safe defaults):
  - ``MARLINSPIKE_RUN_STORE`` (``memory`` / ``db``, default ``memory``)
  - ``MARLINSPIKE_SCAN_TIMEOUT_S`` (default ``3600``)

See [docs/run-store-and-recovery.md](docs/run-store-and-recovery.md)
for the operator-facing reference.

### Breaking changes

**None for the standalone path.** Defaults preserve v3.3.x behaviour:
- ``MARLINSPIKE_RUN_STORE=memory`` → existing ``_run_registry`` flow.
- New columns are nullable; existing rows untouched.
- The blanket "mark all running scans as interrupted on boot"
  behaviour is **replaced** by per-row reconciliation. If you were
  relying on the blanket interruption (e.g. tests that assumed every
  surviving ``running`` row would flip to ``interrupted``), you'll
  now see those rows transition to ``failed`` /
  ``completed`` / stay ``running`` based on actual engine state.

### Wrapper / cloudmarlin guidance

If you run multiple Gunicorn workers (cloudmarlin's horizontal-scale
target), set:

```sh
MARLINSPIKE_RUN_STORE=db
```

This routes ``_get_active_runs(user_id=...)`` through ``scan_history``
instead of the per-worker ``_run_registry`` dict — required for
cross-worker per-tier concurrency limits to be correct. Without it,
a user can run ``tier_limit × num_workers`` concurrent scans because
each worker only sees its own runs.

The concurrency hook contract (``set_concurrent_check_fn``) is
unchanged; only the underlying active-run lookup switches backend.

### Smoke test

```sh
# Start a long-running scan via the UI.
ps aux | grep "python.*-m marlinspike --pcap"   # note the engine PID

# Kill Flask only (leave the engine running):
docker restart marlinspike-web                  # or systemctl restart

# Observe the reaper on restart:
docker logs marlinspike-web 2>&1 | grep recovery
# Expected: "recovery: 1 scan(s) left running from previous boot"
#           "recovery: re-attached watcher to live engine pid=NNN ..."

# Scan completes normally; status flips to 'completed' once engine exits.
```

### Migration checklist

- [ ] Update ``marlinspike`` package to v3.4.0
- [ ] Confirm ``scan_history`` has the new columns (``\d scan_history``
      in psql, or ``PRAGMA table_info(scan_history)`` in sqlite)
- [ ] If running ``-w >1``: set ``MARLINSPIKE_RUN_STORE=db``
- [ ] Optional: tune ``MARLINSPIKE_SCAN_TIMEOUT_S`` for your largest
      expected scan (default 1 hour). Set to ``0`` to disable
      abandonment reaping entirely.

## v3.2.0 → v3.2.1 — CSP nonce migration

All `<style>` and `<script>` block elements in the 18 standard templates now
carry a `nonce="{{ csp_nonce }}"` attribute.

**No action required for standalone marlinspike deployments.** The
``{{ csp_nonce }}`` expression renders as an empty string when the variable is
not defined in the Jinja context, which is the default for uncustomised
deployments.

**If you are running a downstream wrapper** (e.g. cloudmarlin) that injects
a CSP nonce via a Jinja context processor:

1. Register your context processor *before* any template renders — e.g. after
   calling ``marlinspike.create_app()`` and before the first request.
2. The context variable must be named ``csp_nonce``; the templates reference it
   by that exact name.
3. Update your CSP ``style-src`` and ``script-src`` directives to use
   ``'nonce-<value>'`` instead of ``'unsafe-inline'``.  The ``'self'`` source
   and all other directives are unaffected.
4. **Known gap:** marlinspike's templates still contain 166 inline event
   handlers (``onclick=``, ``oninput=``, ``onchange=``) and 452 ``style="..."``
   attributes that are not covered by nonces.  If your CSP removes
   ``'unsafe-inline'`` from ``script-src`` / ``style-src``, those attributes
   will be blocked by compliant browsers on any marlinspike-served page.
   Eliminating them requires converting event handlers to ``addEventListener``
   calls and inline styles to CSS classes — planned for a future release.
   For now, wrapper deployments that serve marlinspike authenticated routes
   under a strict nonce-only CSP will see broken interactive elements on those
   pages until this work is complete.


## v2.4.x → v3.0.0 — Package restructure

v3.0.0 turns MarlinSpike from a flat directory of scripts into a real Python
package. The application logic, behaviour, REST API, database schema, and
plugin contracts are unchanged. What changed is **where the source lives** and
**how you run it**.

### Why

Downstream consumers (notably the cloudmarlin SaaS wrapper) need to
`import marlinspike; create_app(...)` and extend the application without
forking the tree. The old layout — top-level `app.py`, underscore-prefixed
helpers — couldn't be imported as a single namespace, couldn't be
`pip install`-ed, and couldn't be wrapped without monkey-patching.

### File moves

| v2.x path                | v3.x path                       |
|--------------------------|---------------------------------|
| `app.py`                 | `marlinspike/app.py`            |
| `_aggregate.py`          | `marlinspike/aggregate.py`      |
| `_audit.py`              | `marlinspike/audit.py`          |
| `_auth.py`               | `marlinspike/auth.py`           |
| `_config.py`             | `marlinspike/config.py`         |
| `_i18n.py`               | `marlinspike/i18n.py`           |
| `_models.py`             | `marlinspike/models.py`         |
| `_ms_engine.py`          | `marlinspike/engine.py`         |
| `marlinspike.py` (script)| `marlinspike/__main__.py`       |
| `templates/`             | `marlinspike/templates/`        |
| `static/`                | `marlinspike/static/`           |
| (none)                   | `marlinspike/__init__.py`       |
| (none)                   | `pyproject.toml`                |

Deleted top-level compatibility shims: `auth.py`, `config.py`, `models.py`.
These previously did `from _auth import *` etc. and exist only to satisfy
tooling that imported `auth` / `config` / `models` directly. With the package
in place they would shadow real submodules and were removed.

Unchanged at top level: `data/`, `rules/`, `presets/`, `plugins/`, `tests/`,
`scripts/`, `docs/`, `windows/`, `msengine/`, `marlinspike-dpi/`,
`translations/`, `Dockerfile`, `docker-compose.yml`, `deploy.sh`,
`requirements.txt`, `setup_cython.py`.

### Import changes

```python
# v2.x
from _auth import login_required
from _models import db, User
import _config as config
from _ms_engine import main

# v3.x
from marlinspike.auth import login_required
from marlinspike.models import db, User
from marlinspike import config
from marlinspike.engine import main

# v3.x — public API for wrappers
from marlinspike import create_app, db, __version__
```

### Running the engine and the web app

| Action                   | v2.x command                          | v3.x command                                |
|--------------------------|---------------------------------------|---------------------------------------------|
| Run the analysis engine  | `python marlinspike.py --pcap …`      | `python -m marlinspike --pcap …`            |
| Start the web app        | `python app.py`                       | `python -m marlinspike.app`                 |
| Console-script (after `pip install`) | n/a                       | `marlinspike --pcap …`                      |

The web app subprocess invocation also changed: `MARLINSPIKE_PY` is gone,
replaced by `MARLINSPIKE_ENGINE_CMD = [PYTHON_EXE, "-u", "-m", "marlinspike"]`.
Existing call sites in `app.py` were updated automatically. If you have
out-of-tree code that constructed engine commands using `config.MARLINSPIKE_PY`,
switch to:

```python
args = list(config.MARLINSPIKE_ENGINE_CMD) + ["--pcap", path, ...]
```

### Path resolution

`config.BASE_DIR` is preserved as an alias for the new `PROJECT_ROOT`. Code
that does `os.path.join(config.BASE_DIR, "rules", ...)` continues to work
unchanged in a checked-out source tree.

For pip-installed deployments where the package lives under `site-packages/`
but `data/`, `rules/`, and `presets/` live elsewhere, override paths via
environment variables:

| Env var                              | Default                              |
|--------------------------------------|--------------------------------------|
| `MARLINSPIKE_PROJECT_ROOT`           | parent of the `marlinspike/` package |
| `MARLINSPIKE_DATA_DIR`               | `${PROJECT_ROOT}/data`               |
| `MARLINSPIKE_RULES_DIR`              | `${PROJECT_ROOT}/rules`              |
| `MARLINSPIKE_PRESETS_BAKED_DIR`      | `${PROJECT_ROOT}/presets`            |

### Installation

```sh
# Editable install for local development (pulls deps from pyproject.toml)
pip install -e .

# Or, for a containerised build, the existing Dockerfile takes care of it.
docker compose up --build
```

### Wrapper / extension hook points

`v3.0.0` ships the package layout, pip-installability, and one extension
helper:

* **`@csrf_exempt`** (in `marlinspike.auth`) — opts a view function out of the
  global `Origin`/`Referer` check so wrappers can register webhook endpoints
  that legitimately receive cross-origin POSTs (Stripe, GitHub, SCIM, OAuth):

  ```python
  from marlinspike.auth import csrf_exempt

  @app.route("/billing/webhook", methods=["POST"])
  @csrf_exempt
  def stripe_webhook():
      ...
  ```

* **`set_concurrent_check_fn`** (in `marlinspike.app`) — replaces the global
  single-scan limit with a wrapper-supplied policy. Useful for SaaS deployments
  that need per-user or per-tier concurrency:

  ```python
  from marlinspike.app import set_concurrent_check_fn, _get_active_runs

  def per_tier_limit(user_id):
      tier_limit = lookup_tier_limit(user_id)             # your code
      active = len(_get_active_runs(user_id=user_id))     # marlinspike helper
      return active, tier_limit

  set_concurrent_check_fn(per_tier_limit)
  ```

  When no hook is installed, behaviour is unchanged (1 scan globally).

The next phase (planned for v3.1) will:

- Refactor `create_app()` to accept `extra_blueprints`, `extra_template_dirs`,
  `extra_static_dirs`, and an `on_user_created` callback.
- Extract the route surface inside `marlinspike/app.py` into per-domain
  blueprints (`auth`, `uploads`, `scans`, `reports`, `users`, `audit`,
  `system`, `dashboard`).

Wrappers can already:

```python
from marlinspike import create_app, db
from sqlalchemy import Column, Integer, ForeignKey

# Extend the shared SQLAlchemy metadata with new tables.
class Subscription(db.Model):
    __tablename__ = "subscriptions"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    # …

app = create_app()
# Register additional Flask blueprints / before_request hooks here.
```

### Cython users

`setup_cython.py` now compiles `marlinspike/engine.py`, `marlinspike/auth.py`,
`marlinspike/models.py`, `marlinspike/config.py`. Run from the repo root as
before:

```sh
python setup_cython.py build_ext --inplace
```

### Deployment

`deploy.sh --ui-only` now rsyncs the entire `marlinspike/` package into the
container instead of individual top-level files. The full deploy path
(`deploy.sh` without `--ui-only`) rebuilds the Docker image and is unaffected
by the layout change apart from the new COPY targets in the Dockerfile.

### Smoke tests

```sh
python -c "from marlinspike import create_app, db, __version__; print(__version__)"
# 3.0.0

python -m pytest tests/

python -m marlinspike --help
```

## v3.2.x → v3.3.0 — Live capture (opt-in)

v3.3.0 adds the optional `marlinspike-capd` sidecar daemon for live
PCAP capture from a SPAN port or tap. The web app's posture, the
report contract, the engine, and every existing endpoint are
unchanged. **You only need to act on this upgrade if you want live
capture.** If you don't, the new feature is invisible and inert.

### What's new

- New sub-package `marlinspike-capd/` (privileged daemon, ~600 LOC,
  one pip dep: `psutil`). Ships with a Dockerfile and a hardened
  systemd unit.
- New tables `capture_sessions` and `saved_filters`, materialised by
  the existing `db.create_all()` on startup. No column-level
  migration on existing tables.
- New nav entry **Live Capture** (`/capture`). Visible to all users
  but the start form is disabled when capd is not reachable.
- `templates/live.html` renamed to `templates/scan_progress.html`
  (used as the in-progress scan viewer at `/api/runs/<run_id>/live` —
  URL unchanged, only the underlying template filename moved). If
  you have a downstream fork that imports or references the template
  by name, update the reference.

### Activating live capture

In the web app environment (e.g. `.env` for compose):

```sh
LIVE_CAPTURE_ENABLED=true
LIVE_CAPTURE_SOCKET=/var/run/marlinspike-capd/marlinspike-capd.sock
LIVE_CAPTURE_TIMEOUT_S=5
LIVE_CAPTURE_MAX_CONCURRENT=2
```

Then bring up capd in one of three modes — see
[INSTALL.md](INSTALL.md) for details. The shortest path:

```sh
docker compose --profile capture up -d --build
```

This boots capd as a sidecar with `cap_add: [NET_RAW, NET_ADMIN]` and
`network_mode: host` (Linux only — Docker Desktop on macOS/Windows
can't expose physical NICs to a container).

### Leaving live capture off

Do nothing. `LIVE_CAPTURE_ENABLED` defaults to `false`, capd is not
required, and the new endpoints all return 503 with a clear reason.
Old deploy scripts and existing compose stacks continue to work.

### Smoke tests

```sh
# capd alone
sudo -u marlinspike-capd marlinspike-capd list-interfaces
sudo -u marlinspike-capd marlinspike-capd validate-bpf "tcp port 502"

# Through the web app
curl --cookie /tmp/c.txt http://127.0.0.1:5001/api/capture/health
# {"enabled": true, "reachable": true, "libpcap": "libpcap version 1.10.x", ...}
```

### Why

The GrassMarlin parity gap was live capture. We chose a
sidecar-daemon split rather than granting the web app `CAP_NET_RAW`
because the cost of a compromised web app jumping to "raw socket on
the engagement network" was unacceptable. The uds JSON-RPC between
capd and the web app is now a stable contract — see
[COMPATIBILITY.md](COMPATIBILITY.md).
