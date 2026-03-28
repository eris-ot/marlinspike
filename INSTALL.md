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

For local HTTP use, leave `SESSION_COOKIE_SECURE=false` so the browser will send the session cookie back to `http://127.0.0.1:5001`. Only set `SESSION_COOKIE_SECURE=true` when you are behind a TLS-terminating reverse proxy and serving the app over HTTPS.

3. Build and start the stack.

```bash
docker compose up -d --build
```

4. Check the application logs.

```bash
docker compose logs -f app
```

5. Open the app at `http://127.0.0.1:5001`.

If `ADMIN_PASSWORD` is blank, the first boot generates a random admin password and prints it to the container logs.

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

When you are serving MarlinSpike behind HTTPS, set `SESSION_COOKIE_SECURE=true` in `.env` before starting the app so the session cookie is marked secure.

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

## Live Capture

Live capture depends on `tshark` inside the application container and should only be enabled on an authorized physical interface. It is meant for controlled local use, not broad public exposure.
