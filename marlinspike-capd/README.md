# marlinspike-capd

Privileged sidecar capture daemon for MarlinSpike. Owns `CAP_NET_RAW` /
`CAP_NET_ADMIN`, supervises `dumpcap`, and exposes a small uds JSON-RPC
API to the unprivileged MarlinSpike web app.

## Why a sidecar

MarlinSpike's web app runs unprivileged. Live capture needs raw-packet
access, which would otherwise force the web process to inherit dangerous
capabilities. capd isolates that surface: it does only three things —
enumerate interfaces, validate BPF filters, and run `dumpcap` with
rotation — and talks to the web app exclusively over a unix-domain
socket guarded by SO_PEERCRED.

## Install

```bash
pip install -e ./marlinspike-capd
```

`dumpcap` (Wireshark) and `libpcap` must be present on the host.

## CLI

```bash
# List physical interfaces (filters out docker*, veth*, br-*, tun*, wg*, tailscale*).
python -m capd list-interfaces
python -m capd list-interfaces --all

# Validate a BPF filter without opening any interface.
python -m capd validate-bpf "tcp port 502 or tcp port 102"

# Run the daemon.
sudo python -m capd serve --socket /var/run/marlinspike-capd.sock
```

## Protocol

JSON over uds, length-prefixed (4-byte big-endian length, then UTF-8
JSON). One request → one response, except `stats` which streams. See
`capd/server.py` for the canonical schema.

## License

AGPL-3.0-or-later. See repo root `LICENSE`.
