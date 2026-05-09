#!/usr/bin/env bash
# Install marlinspike-capd as a systemd service.
#
# Run as root. Idempotent — safe to re-run.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "must run as root (use sudo)" >&2
  exit 1
fi

UNIT_SRC="$(cd "$(dirname "$0")" && pwd)/marlinspike-capd.service"
UNIT_DST="/etc/systemd/system/marlinspike-capd.service"
SOCK_GROUP="${SOCK_GROUP:-marlinspike}"   # group the web app runs as

if ! id marlinspike-capd >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin marlinspike-capd
fi
if ! getent group "$SOCK_GROUP" >/dev/null; then
  groupadd --system "$SOCK_GROUP"
fi
# Web app's group needs to talk to the socket. capd creates the socket
# 0660 owned by capd:capd; we tweak the group via socket file ACLs at
# capd start (or you can adjust UMask via systemd drop-in).

install -m 0644 "$UNIT_SRC" "$UNIT_DST"
systemctl daemon-reload
systemctl enable --now marlinspike-capd.service

echo
echo "marlinspike-capd installed."
echo "  systemctl status marlinspike-capd"
echo "  journalctl -u marlinspike-capd -f"
echo
echo "Set in the MarlinSpike web app environment:"
echo "  LIVE_CAPTURE_ENABLED=true"
echo "  LIVE_CAPTURE_SOCKET=/var/run/marlinspike-capd/marlinspike-capd.sock"
