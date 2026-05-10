# Live Capture

MarlinSpike can drive its own packet capture from a SPAN port, tap, or
inline interface. The capture is **passive**: capd opens the interface
in promiscuous mode but never transmits — same posture as Wireshark or
GrassMarlin.

This document is for the analyst running an engagement. For deployment
and packaging, see [INSTALL.md](../INSTALL.md). For the platform
matrix, see [COMPATIBILITY.md](../COMPATIBILITY.md).

---

## When to use it

Live capture replaces the workflow of "run tshark in another terminal,
copy the PCAP into MarlinSpike, refresh." It's the right call when:

- You have **physical or SPAN access** to OT traffic on the engagement
  host and want triage results without context switching.
- You need a **rolling capture** — a 2 GB ring on a noisy network so
  you don't fill the disk during a multi-hour assessment.
- You want **multiple analysts** reviewing the same engagement to see
  reports as they roll out of the rotation.

It's the wrong call when:

- The PCAPs already exist (use the upload path instead — same engine).
- You need **continuous, multi-sensor, centralized** collection across
  many sites — that's what FATHOM is for.
- You're running on a host you don't control or in a Docker bridge
  network — capd needs `CAP_NET_RAW` and visibility of the physical
  NIC, neither of which exists in a default container.

---

## How it works

Two processes, one socket:

```
┌─ marlinspike (web app, unprivileged) ──┐    ┌─ marlinspike-capd (privileged) ─┐
│                                        │uds │                                 │
│  /capture page                         │◄──►│  enumerates interfaces          │
│  /api/capture/* blueprint              │    │  validates BPF                  │
│  starts/stops sessions                 │    │  supervises dumpcap             │
│  consumes rotated PCAPs into the       │    │  emits stats over the socket    │
│  same scan pipeline as uploads         │    │                                 │
└────────────────────────────────────────┘    └─────────────────────────────────┘
                                                          │
                                              writes rotated PCAPs to
                                              /var/lib/marlinspike/captures/<session>/
```

The web app **never** opens raw sockets. capd holds the elevated
capabilities; the web app talks to it over a unix-domain socket
authenticated by `SO_PEERCRED` (Linux) / `LOCAL_PEEREID` (macOS).

When capd rotates a PCAP, the web app picks up the closed file and
runs the regular MarlinSpike analysis chain against it. The resulting
report lands in the project the capture session is attributed to,
exactly as if you'd uploaded that PCAP yourself.

---

## The /capture page

![/capture page with capd unreachable — capd-status pill, new-capture form with project picker, interface dropdown, BPF input, saved-filter row, ring config, history table](screenshots/29-capture-page.png)

*The screenshot above is captured with `capd` not running, so the
status pill reads `capd unreachable` (red) and the interface
dropdown shows the underlying error. With capd up, the pill is
green and the dropdown lists physical NICs plus `any`.*

Once `LIVE_CAPTURE_ENABLED=true` and capd is reachable, the **Live
Capture** entry in the nav is the single screen for all live-capture
work.

### Header

A status pill in the upper-right tells you whether the daemon is up.
Three states:

| pill | meaning |
|---|---|
| `capd reachable` (green) | Daemon answering version pings. Includes the libpcap version it's linked against. |
| `capd unreachable` (red) | Socket exists but no answer, or socket missing. The new-capture form is disabled. |
| `Disabled` (amber) | `LIVE_CAPTURE_ENABLED=false`. Banner above explains how to turn it on. |

### New capture (left panel)

| field | what it does |
|---|---|
| **Project** | Which project the rotated reports get attributed to. Defaults to your current project. |
| **Interface** | Live-enumerated from capd. Only physical NICs by default — toggle **Show virtual / loopback** to also see `lo`, `docker0`, `veth*`, `tun*`, `wg*`, `tailscale*`, etc. The Linux **`any`** pseudo-device is always available; on Linux it captures from every interface simultaneously. |
| **Saved filters** | Per-project library of named BPF expressions. Pick one to populate the filter, **Save** to store the current expression under a name, **×** to delete the selected one. See [Saved-filter library](#saved-filter-library) below. |
| **BPF capture filter** | Standard libpcap syntax. Validated live (debounced 350ms) — green "OK" or a red error appears under the field as you type. Empty filter = capture everything. |
| **Rotation size (KB)** | Maximum size of one PCAP file in the ring. Default 200000 (200MB). |
| **Ring depth (files)** | How many rotation files to keep. Default 10. Total disk per session = `filesize × files`. The defaults give you a 2 GB rolling window. |
| **Max duration (seconds)** | Hard stop after this many seconds. `0` = run until you stop it manually (or the per-session disk limit hits the ring cap). |
| **Start capture** | Disabled until: an interface is selected and the BPF either is empty or compiled successfully. |

### Active captures (right panel)

One card per running session with:

- A pulsing red dot while running, gray and static when stopped.
- Live counters that update once per second over Server-Sent Events:
  packets observed, drops reported by dumpcap, total bytes on disk,
  current write rate.
- A red **Stop** button. Stop is graceful: capd sends `SIGINT` to
  dumpcap, which flushes the active file and emits its summary line
  with authoritative packet/drop totals.

### History (below)

Stopped and failed sessions, newest first. Filter expression and final
counters preserved for later reference. Reports produced during the
session are not in this table — they live alongside upload-driven
reports under the project.

---

## BPF cookbook for OT

BPF is libpcap's capture-filter language. It runs **before** packets
hit the kernel buffer, so a tight filter is the difference between
capturing a quiet Modbus subnet for a week and filling a 2 GB ring in
ninety seconds. capd validates with `pcap_compile_nopcap` so a syntax
error appears the moment you tab out — you never start a capture that
will exit immediately.

### OT protocol filters

```
# Modbus / TCP
tcp port 502

# Siemens S7
tcp port 102

# DNP3
tcp port 20000 or udp port 20000

# IEC 60870-5-104
tcp port 2404

# EtherNet/IP + CIP
tcp port 44818 or udp port 44818 or udp port 2222

# OPC-UA
tcp port 4840 or tcp port 4843

# BACnet/IP
udp port 47808

# PROFINET (real-time)
ether proto 0x8892

# GOOSE / SV (IEC 61850)
ether proto 0x88b8 or ether proto 0x88ba

# OMRON FINS
udp port 9600 or tcp port 9600

# All the above in one line — handy for an unknown OT site:
tcp port 502 or tcp port 102 or tcp port 20000 or udp port 20000 \
  or tcp port 2404 or tcp port 44818 or udp port 44818 or udp port 2222 \
  or tcp port 4840 or udp port 47808 or ether proto 0x8892 \
  or ether proto 0x88b8 or ether proto 0x88ba
```

### Excluding noise

```
# Exclude a chatty management VLAN
not vlan 100

# Exclude broadcast/multicast (be careful — kills GOOSE, IGMP, ARP)
not broadcast and not multicast

# Exclude a specific noisy host
not host 10.10.20.5

# Subnet scope only
net 10.20.0.0/16
```

### Composing

```
# OT + the engineering workstation but nothing else
(tcp port 502 or tcp port 102 or tcp port 44818) or host 10.10.10.50

# Drop the SPAN port's own management traffic
not (host 10.0.0.1 and port 22)
```

The full reference is `pcap-filter(7)`.

---

## Saved-filter library

The saved-filter library is **per-project**. The same project might
have a "Modbus only" filter for a Modbus-heavy zone and a "broad OT"
filter for the wider site walkthrough.

- Filters are scoped to a single project. They follow the same access
  rules as the project itself.
- The **(project_id, name)** pair is unique — you'll get a 409
  Conflict if you try to save a duplicate name in the same project.
- The save dialog accepts 1–80 characters. Use names that mean
  something six months from now: `modbus-zone-3` is better than
  `filter1`.

The HTTP API is documented under `/api/capture/filters` in the source.
GET, POST, DELETE; project ownership is enforced server-side.

---

## What happens during a session

1. **Click Start.** The web app inserts a `CaptureSession` row in the
   database (`status=pending`), then asks capd to start. If capd
   refuses (interface missing, BPF invalid against the chosen DLT,
   permission error) the row is marked `failed` with `error_tail`
   populated — you have a durable record of every attempt, even the
   ones that never wrote a packet.
2. **dumpcap runs.** capd spawns
   `dumpcap -i <iface> -f "<bpf>" -b filesize:N -b files:M -w cap.pcapng`,
   inheriting `CAP_NET_RAW` from capd. dumpcap rotates the file every
   N kilobytes; capd notices via directory polling.
3. **Stats stream.** capd polls the active file's size once per
   second and emits a stats frame: bytes total, bytes/sec, current
   file index, list of files newly closed since the last frame.
4. **Reports roll in.** For each closed PCAP, the web app starts a
   normal MarlinSpike scan with `--fast` profile by default. Reports
   land in the same project directory as upload-driven reports and
   appear on the project dashboard with their normal title.
5. **Click Stop.** Web app marks the session `stopping`, capd sends
   `SIGINT` to dumpcap. dumpcap flushes the active file, writes its
   summary line ("Packets captured: X / Packets dropped: Y"), and
   exits. capd parses the summary and returns the authoritative
   totals. The session row becomes `stopped` with final counters.

If you close the browser tab, the capture keeps running. Reopen
`/capture` and the active panel re-attaches to the in-flight session.

---

## Per-project capture policy

Each project can carry an optional `capture_policy` JSON blob that tightens or
blocks capture for that project independently of the system-wide defaults. This
is useful for multi-tenant deployments and OT engagements where individual
project scope must be enforced at the config layer.

### Policy schema

```json
{
  "enabled": true,
  "allowed_interfaces": ["eth0"],
  "max_session_duration_s": 3600,
  "max_total_bytes": null,
  "operator_warning": "OT engagement — confirm scope before starting capture."
}
```

All fields are optional. A missing field means "use the system default."

| field | type | effect |
|---|---|---|
| `enabled` | `bool` | When `false`, all capture starts for this project are rejected with 403. |
| `allowed_interfaces` | `[string]` | Intersected with `MARLINSPIKE_CAPTURE_INTERFACE_ALLOWLIST`. Empty intersection → 403. |
| `max_session_duration_s` | `int \| null` | Caps `max_duration_s` from the start request. Original-vs-applied values are logged with `audit("capture.policy_capped", …)`. |
| `max_total_bytes` | `int \| null` | Reserved field; not yet enforced by the start-session gate (future use). |
| `operator_warning` | `string \| null` | When present, the string is returned in the start-session response body as `operator_warning`. The web UI shows a confirmation modal before submitting. |

### Gate order in `start_session`

Gates fire in this order; the first rejection short-circuits:

1. **project.enabled** — if `false`, immediate 403.
2. **Interface allowlist** — effective list = `MARLINSPIKE_CAPTURE_INTERFACE_ALLOWLIST` ∩ `policy.allowed_interfaces`. When either side is unset, the other side is used as-is. 403 if the requested interface is not in the effective list.
3. **Duration cap** — `max_duration_s` in the request is silently clamped to `max_session_duration_s`. An `audit("capture.policy_capped", …)` event records the original and applied values.
4. **operator_warning** — non-blocking; passed through to the 201 response and surfaced as a confirmation modal in the UI.

### System-wide interface allowlist

`MARLINSPIKE_CAPTURE_INTERFACE_ALLOWLIST` is a comma-separated list of NIC names
set in the web app's environment. When set, it applies to **all projects**,
independently of per-project policy. Per-project `allowed_interfaces` is
intersected with the system allowlist; a project cannot grant access to an
interface the system allowlist prohibits.

```
MARLINSPIKE_CAPTURE_INTERFACE_ALLOWLIST=eth0,eth1
```

When unset, no system-level interface restriction applies.

### Policy API

| method | URL | access | description |
|---|---|---|---|
| `GET` | `/api/capture/policy/<pid>` | admin or project owner | Returns current policy dict + `effective_allowed_interfaces` (post-intersection). |
| `PUT` | `/api/capture/policy/<pid>` | admin or project owner | Sets the policy. Validates shape; rejects unknown keys with 400. Emits `audit("capture.policy_set", …)`. |

Both endpoints return 404 to callers who are neither admin nor the project owner.

---

## Concurrency and locking

- **Per-host cap:** `LIVE_CAPTURE_MAX_CONCURRENT` (default 2). When
  reached, new starts fail with 409. Bump if your engagement laptop
  has the cores and the sniffing fanout.
- **Per-interface lock:** capd refuses two sessions on the same
  interface. The web app surfaces this as
  *"interface eth1 in use by session 9b3c…"*.
- **`any` is special:** capturing `any` blocks any other interface
  start, and any interface running blocks an `any` start. This
  matches what dumpcap would do anyway and prevents double-counting.
- **Multi-worker:** the in-process per-interface lock is best-effort.
  The capd start RPC is the authoritative refusal point, so even if
  two gunicorn workers race, only one capture actually runs.

---

## Troubleshooting

**`capd unreachable`.** The web app can't reach the socket.

- Is `LIVE_CAPTURE_ENABLED=true` set in the web app's environment?
- Does the socket exist? Default path is
  `/var/run/marlinspike-capd/marlinspike-capd.sock`. Check with
  `ls -l <path>` from inside the web container.
- Is the web app's process group able to read it? capd creates the
  socket `0660 capd:capd` by default; the web app must be in capd's
  primary group, or you need to relax permissions (the systemd unit
  ships with hardened defaults).

**Start succeeds but no rotation reports appear.**

- Is `dumpcap` actually capturing? Check capd's logs
  (`journalctl -u marlinspike-capd` or `docker compose logs capd`)
  for spawn lines.
- Is the BPF too tight? An empty ring means dumpcap is running but
  the filter is matching zero packets. Stop, drop the filter, start
  again to confirm there's traffic on the interface at all.
- Did the engine subprocess crash? The consumer logs failures with
  the engine's stderr tail at WARNING level.

**`failed: bpf invalid`.** The BPF didn't compile against the chosen
interface's DLT. The most common cause is using an Ethernet-only
filter on a `any` capture; capd validates `any` against
`DLT_LINUX_SLL2` so e.g. `ether proto …` is rejected. Pick a real
interface, or rephrase without ether-layer predicates.

**Disk filling.** Each session's ring is bounded
(`filesize_kb × files`), but rotated reports live indefinitely. Old
PCAPs are stored under `<capture_root>/<session_uuid>/` and are not
deleted on session stop — that was intentional, so you can re-scan or
ship them later. Garbage-collect old session directories manually
when the engagement ends.

**Macs / Windows.** Live capture only works on a Linux host. Docker
Desktop on macOS / Windows can't expose physical interfaces to a
container; capd will run, BPF validation will work, but no real
captures will succeed. For development, run the daemon natively on
the macOS host (`pip install ./marlinspike-capd; marlinspike-capd
serve --socket /tmp/capd.sock`) and point the web app at that path.

---

## Anatomy in code

If you need to extend or audit:

| component | path | role |
|---|---|---|
| capd daemon | `marlinspike-capd/capd/` | privileged sidecar, ~600 LOC |
| uds protocol | `marlinspike-capd/capd/server.py` | length-prefixed JSON, methods documented in dispatch |
| Python client | `marlinspike/capture/client.py` | sync wrapper for the daemon |
| stats fan-out | `marlinspike/capture/sessions.py` | one capd stream → N SSE subscribers per session |
| rotation consumer | `marlinspike/capture/consumer.py` | spawns engine for each closed PCAP |
| HTTP blueprint | `marlinspike/capture/api.py` | `/api/capture/*` routes |
| workbench page | `marlinspike/templates/capture.html` | the UI you've been reading about |

The **uds JSON-RPC** between capd and the web app is the compatibility
boundary between the two processes; see
[COMPATIBILITY.md](../COMPATIBILITY.md). New capd versions must
accept old web-app calls; the web app must tolerate fields it doesn't
know.
