# Upgrading MarlinSpike

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
