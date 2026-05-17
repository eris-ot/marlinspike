# Installation and Deployment

## Local Docker Deployment

1. Copy the example environment file.

```bash
cp .env.example .env
```

2. Set strong values for:

- `DB_PASSWORD`
- `SECRET_KEY`
- `ADMIN_PASSWORD`

Keep `SESSION_COOKIE_SECURE=true` for HTTPS and reverse-proxy deployments. Only set it to `false` for plain-HTTP local development at `http://127.0.0.1:5001`.

Docker Compose now defaults `RATELIMIT_STORAGE_URI` to the bundled Redis service so login, reset, and upload throttles are shared across restarts and workers. Leave it blank in `.env` unless you want to point at a different Redis/Valkey instance.

3. Build and start the stack.

```bash
docker compose up -d --build
```

4. Check the application logs.

```bash
docker compose logs -f app
```

5. Open the app at `http://127.0.0.1:5001`.

If `ADMIN_PASSWORD` is blank, the first boot generates a random admin password and writes it to `/app/data/instance/admin-bootstrap-password.txt` inside the app container. Change it immediately after first login and delete the file.

### Optional malware stage

The Stage 4b malware IOC engine and published rule packs are optional at build time. By default the Compose and Docker build now point at current public GitHub refs. If you want to build without that layer, set these to empty values in `.env` before building:

```bash
MARLINSPIKE_MALWARE_REPO=
MARLINSPIKE_MALWARE_REF=
MARLINSPIKE_MALWARE_RULES_REPO=
MARLINSPIKE_MALWARE_RULES_REF=
```

MarlinSpike will still build and run without that optional engine; Stage 4b malware matching will simply be skipped at runtime.

## Common Commands

```bash
docker compose ps
docker compose logs -f app
docker compose down
docker compose restart app
```

## Persistent Data

MarlinSpike stores runtime data in named Docker volumes so rebuilds do not remove user content:

- `marlinspike-data` contains uploads, reports, presets, and archived submissions
- `marlinspike-pgdata` contains PostgreSQL data

Inside the app container, the important paths are:

- `/app/data/reports`
- `/app/data/uploads`
- `/app/data/submissions`
- `/app/data/presets`

## Reverse Proxy

The application listens on `127.0.0.1:5001` by default through Docker Compose. If you publish it on the public internet, place it behind a reverse proxy and TLS terminator such as nginx, Caddy, or Traefik.

Use the proxy to terminate TLS and forward only the app port internally. Keep the app bound to localhost unless you have a deliberate reason to expose it directly.

When you are serving MarlinSpike behind HTTPS, leave `SESSION_COOKIE_SECURE=true` in `.env` so the session cookie stays marked secure. Only turn it off for local plain-HTTP development.

## Upgrades

For a normal code update, pull the latest changes and rebuild the containers:

```bash
git pull
docker compose up -d --build
```

For a quick UI-only change, you can often restart the app after copying the updated template or static file into place. If the engine modules change, do a full rebuild so the updated source is packaged into the container.

## Backups

Back up both the database and the data volume before major upgrades:

```bash
docker compose exec db pg_dump -U marlinspike marlinspike > marlinspike.sql
```

Also copy the `marlinspike-data` volume contents or archive the mounted data directory used by your deployment.

## Remote Deployment

The included `deploy.sh` script is now generic. Set `REMOTE` to an SSH destination and optionally override `REMOTE_DIR` and `BACKUP_DIR`.

```bash
REMOTE=deploy@example-host ./deploy.sh
```

For a staging target:

```bash
REMOTE=deploy@staging-host ./deploy-dev.sh
```

## Live Capture (optional, Linux only)

MarlinSpike can drive its own live capture from a SPAN port or tap via the optional `marlinspike-capd` sidecar. The web app stays unprivileged; capd holds `CAP_NET_RAW` and supervises `dumpcap` with ring-buffer rotation. Each rotated PCAP is consumed by the existing analysis pipeline and reports accumulate in the project workbench.

There are three deployment modes:

### 1. No live capture (default)

Don't install or enable capd. The web app boots normally. The `Live Capture` nav link shows a banner explaining how to enable it. No elevated capabilities anywhere in the stack.

### 2. Bundled (Docker Compose)

```bash
# In .env
LIVE_CAPTURE_ENABLED=true

# Start the stack with the capture profile.
docker compose --profile capture up -d --build
```

This launches `marlinspike-capd` alongside `app` and `db`. Compose creates two shared volumes:

- `capd-socket` — the unix-domain socket the web app connects to
- `capd-captures` — rotated PCAPs (read-only mount in `app`, read-write in `capd`)

The capd container runs with `cap_add: [NET_RAW, NET_ADMIN]` and `network_mode: host` so it can see the physical NICs. The web container is unchanged.

> **Linux only.** Docker Desktop on macOS / Windows cannot expose physical interfaces to a container, so live capture is a no-op there.

### 3. Native systemd

Install capd directly on the engagement host alongside a containerised or native MarlinSpike web app.

```bash
cd marlinspike-capd
pip install .
sudo ./systemd/install.sh
```

Then in the web app environment:

```bash
LIVE_CAPTURE_ENABLED=true
LIVE_CAPTURE_SOCKET=/var/run/marlinspike-capd/marlinspike-capd.sock
```

The web app's process group must be able to read the socket — the install script provisions a `marlinspike` group; add the user the web app runs as to that group, or override with `SOCK_GROUP=...` when running the installer.

### Verifying live capture

```bash
# capd direct
sudo -u marlinspike-capd marlinspike-capd list-interfaces
sudo -u marlinspike-capd marlinspike-capd validate-bpf "tcp port 502"

# From the web app
curl --cookie-jar /tmp/c.txt -d 'username=admin&password=...' http://127.0.0.1:5001/login
curl --cookie /tmp/c.txt http://127.0.0.1:5001/api/capture/health
```

A reachable capd reports `{"reachable": true, "libpcap": "libpcap version ..."}`.

### Live-capture environment variables

| variable | default | description |
|---|---|---|
| `LIVE_CAPTURE_ENABLED` | `false` | Master switch. Off by default. |
| `LIVE_CAPTURE_SOCKET` | `/var/run/marlinspike-capd.sock` | uds path; both processes must agree. |
| `LIVE_CAPTURE_TIMEOUT_S` | `5` | Per-RPC timeout in seconds. |
| `LIVE_CAPTURE_MAX_CONCURRENT` | `2` | Per-host cap on active capture sessions. |
| `MARLINSPIKE_CAPTURE_INTERFACE_ALLOWLIST` | *(unset)* | Comma-separated list of interface names that capture is permitted on (e.g. `eth0,eth1`). When unset, any interface is allowed. Use to prevent captures on management NICs. |

## Mid-scan recovery (v3.4.0+)

When the Flask process restarts mid-scan, the engine subprocess is
reparented to init/launchd and runs to completion. v3.4.0 added a
startup reaper that walks `scan_history WHERE status='running'` and
reconciles each row via saved PID + argv (PID-reuse defense). See
[docs/run-store-and-recovery.md](docs/run-store-and-recovery.md) for
full operator reference.

| variable | default | description |
|---|---|---|
| `MARLINSPIKE_RUN_STORE` | `memory` | `memory` (legacy in-process registry) or `db` (active-run lookup via `scan_history`). Set to `db` for multi-worker Gunicorn so per-tier concurrency limits stay correct across workers. |
| `MARLINSPIKE_SCAN_TIMEOUT_S` | `3600` | Per-scan deadline. Reaper marks rows still `running` past this many seconds since `started_at` as `failed`. Set to `0` to disable abandonment reaping. |

For cloudmarlin and any deployment running `gunicorn -w N` with `N>1`,
**`MARLINSPIKE_RUN_STORE=db` is required** — the default `memory` mode
keeps active runs in a per-worker dict, which means worker A doesn't
see worker B's runs. Per-tier concurrency silently breaks (a user can
run `tier_limit × num_workers` scans), and `/api/runs/<id>/status`
returns 404 when the load balancer hits a different worker than the
one that started the scan.

## Scope

MarlinSpike is a PCAP analysis tool with optional live capture. Capture with your own tooling (Wireshark, tshark, a tap, a span port) and upload PCAPs through the web UI, drive the engine from the CLI, or use the live-capture mode above to feed captures directly from an interface.

```bash
marlinspike --pcap /path/to/capture.pcap chain
```

For continuous multi-sensor collection across many hosts and centralized OT network monitoring, see [FATHOM](https://github.com/eris-ot).
