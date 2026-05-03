#!/usr/bin/env bash
# Deploy MarlinSpike to a remote host over SSH.
# Usage: REMOTE=deploy@example-host ./deploy.sh [--rebuild] [--ui-only]
# Required env:
#   REMOTE      SSH destination, for example deploy@example-host
# Optional env:
#   REMOTE_DIR  Remote application path (default: /opt/marlinspike)
#   BACKUP_DIR  Remote backup path (default: <REMOTE_DIR>-backups)

set -euo pipefail

REMOTE="${REMOTE:-}"
REMOTE_DIR="${REMOTE_DIR:-/opt/marlinspike}"
BACKUP_DIR="${BACKUP_DIR:-${REMOTE_DIR}-backups}"
LOCAL_DIR="$(cd "$(dirname "$0")" && pwd)"

if [[ -z "$REMOTE" ]]; then
    echo "ERROR: set REMOTE to an SSH destination, for example deploy@example-host"
    exit 1
fi

REBUILD=false
UI_ONLY=false
for arg in "$@"; do
    case "$arg" in
        --rebuild)  REBUILD=true ;;
        --ui-only)  UI_ONLY=true ;;
    esac
done

ENGINE_VERSION=$(grep -m1 'version:' "$LOCAL_DIR/marlinspike/engine.py" | sed 's/.*version: *//')
APP_VERSION=$(grep -m1 'APP_VERSION' "$LOCAL_DIR/marlinspike/app.py" | sed 's/.*"\(.*\)".*/\1/')

# ── UI-only fast deploy ──────────────────────────────────────
if $UI_ONLY; then
    CONTAINER=$(ssh "$REMOTE" "docker ps -q --filter name=marlinspike-app" 2>/dev/null || true)
    if [[ -z "$CONTAINER" ]]; then
        echo "ERROR: marlinspike-app container is not running. Use full deploy instead."
        exit 1
    fi

    echo "=== MarlinSpike UI-Only Deploy (app v${APP_VERSION}) ==="
    echo "  Container: $CONTAINER"

    # 1. Lightweight backup of UI files on remote
    echo ""
    echo "[1/4] Backing up UI files on remote..."
    ssh "$REMOTE" "\
        mkdir -p $BACKUP_DIR && \
        docker cp $CONTAINER:/app/marlinspike - 2>/dev/null | gzip > $BACKUP_DIR/ui-v${APP_VERSION}-pre-marlinspike.tar.gz \
    " && echo "  OK" || echo "  SKIP (backup failed, continuing)"

    # 2. Rsync only UI files to remote staging area
    echo ""
    echo "[2/4] Syncing UI files..."
    rsync -avz --delete \
        --exclude '__pycache__' \
        "$LOCAL_DIR/marlinspike/" \
        "$REMOTE:$REMOTE_DIR/marlinspike/"

    # 3. docker cp into running container + restart
    echo ""
    echo "[3/4] Copying into container & restarting..."
    ssh "$REMOTE" "\
        docker cp $REMOTE_DIR/marlinspike/. $CONTAINER:/app/marlinspike/ && \
        docker restart $CONTAINER \
    "

    # 4. Verify
    echo ""
    echo "[4/4] Checking status..."
    sleep 3
    ssh "$REMOTE" "docker ps --filter name=marlinspike-app --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'"

    echo ""
    echo "=== UI-Only Deploy Complete (app v${APP_VERSION}) ==="
    echo "  Note: Changes live in container layer. Next full deploy catches up the image."
    exit 0
fi

# ── Full deploy ──────────────────────────────────────────────
echo "=== MarlinSpike Deploy (engine v${ENGINE_VERSION}, app v${APP_VERSION}) ==="
echo "  Local:  $LOCAL_DIR"
echo "  Remote: $REMOTE:$REMOTE_DIR"

# Backup remote before overwriting
echo ""
echo "[1/4] Backing up remote → $BACKUP_DIR/marlinspike-v${ENGINE_VERSION}-pre.tar.gz ..."
ssh "$REMOTE" "\
    mkdir -p $BACKUP_DIR && \
    tar czf $BACKUP_DIR/marlinspike-v${ENGINE_VERSION}-pre.tar.gz \
        --exclude='data' \
        --exclude='__pycache__' \
        --exclude='venv' \
        -C $(dirname $REMOTE_DIR) $(basename $REMOTE_DIR) 2>/dev/null \
" && echo "  OK" || echo "  SKIP (no existing deployment)"

# Sync files
echo ""
echo "[2/4] Syncing files..."
rsync -avz --delete \
    --exclude '__pycache__' \
    --exclude '*.pyc' \
    --exclude '.git/' \
    --exclude '.github/' \
    --exclude '.claude/' \
    --exclude 'CLAUDE.md' \
    --exclude 'AGENTS.md' \
    --exclude '.logbook/' \
    --exclude '.smoke/' \
    --exclude '.venv/' \
    --exclude '.venv-*/' \
    --exclude 'node_modules/' \
    --exclude 'marlinspike-dpi/' \
    --exclude 'windows/build/' \
    --exclude 'windows/wine-lab/' \
    --exclude '.DS_Store' \
    --include 'data/oui.json' \
    --exclude 'data/**' \
    --exclude 'presets/' \
    --exclude 'backups/' \
    --exclude '.env*' \
    --exclude 'venv/' \
    "$LOCAL_DIR/" "$REMOTE:$REMOTE_DIR/"
rsync -avz \
    "$LOCAL_DIR/presets/README.md" \
    "$REMOTE:$REMOTE_DIR/presets/README.md"

echo ""
echo "[3/4] Building & restarting container..."
if $REBUILD; then
    ssh "$REMOTE" "cd $REMOTE_DIR && docker compose down && docker compose build --no-cache && docker compose up -d"
else
    ssh "$REMOTE" "cd $REMOTE_DIR && docker compose up -d --build"
fi

echo ""
echo "[4/4] Checking status..."
sleep 3
ssh "$REMOTE" "docker ps --filter name=marlinspike-app --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'"

echo ""
echo "=== Deployed MarlinSpike (engine v${ENGINE_VERSION}, app v${APP_VERSION}) ==="
