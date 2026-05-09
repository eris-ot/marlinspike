# Upgrading MarlinSpike

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
