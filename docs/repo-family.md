# MarlinSpike Repo Family

MarlinSpike is moving from a single mixed repository toward a repo family with one suite repo and several focused component repos.

## Repo Model

- `marlinspike`
  The suite repo. This is the integration home and the one clone for teams that want everything together.
- `marlinspike-msengine`
  The core analysis engine repo. Internal package and CLI name: `msengine`.
- `marlinspike-workbench`
  The web UI repo. It reads report artifacts, manages projects, and can optionally invoke `msengine`.
- `marlinspike-mitre`
  Shared MITRE ATT&CK plugin repo. It is designed to be vendored into MarlinSpike and Fathom.
- `marlinspike-plugins`
  Python plugin monorepo for report-consuming extensions such as ATT&CK, IEC 62443, and PERA overlays.
- `marlinspike-engines`
  Rust engine workspace for packet-facing and event-heavy components such as DPI and malware/event matching.
  - `marlinspike-dpi`: deep packet inspection engine
  - `marlinspike-malware`: IOC/signature matching engine consuming Bronze-derived observables, invoked in Stage 4b
- `marlinspike-capd`
  Optional privileged sidecar daemon for live PCAP capture (Linux only). Currently lives at `marlinspike-capd/` inside the suite repo as a sub-package — Python, ~600 LOC, holds `CAP_NET_RAW`, supervises `dumpcap` with ring-buffer rotation, and exposes a uds JSON-RPC to the unprivileged workbench. The protocol between capd and the workbench is the **second** stable contract in the suite (the first being the report artifact); see [COMPATIBILITY.md](../COMPATIBILITY.md). Operator guide: [docs/live-capture.md](live-capture.md).

## One Clone For Everything

The suite repo vendors component repos as subrepos using `git subtree`.

That means:

- normal `git clone` behavior for users who want the whole stack
- no git-submodule setup burden
- component repos can still have their own release cycles
- the suite repo can pin a known-good combination of engine, workbench, plugins, and engines

The component repos are intended to be authoritative. The suite repo is the integration surface that vendors, pins, and documents a compatible set.

The bootstrap helper for the subtree workflow lives at [`scripts/update-subtrees.sh`](../scripts/update-subtrees.sh).
The engine bootstrap sync helper lives at [`scripts/sync-msengine-bootstrap.sh`](../scripts/sync-msengine-bootstrap.sh).
The MITRE bootstrap sync helper lives at [`scripts/sync-mitre-bootstrap.sh`](../scripts/sync-mitre-bootstrap.sh).

## Contract Boundary

The MarlinSpike report artifact remains the core handoff:

1. `msengine` produces a report artifact from captured traffic.
2. `marlinspike-workbench` consumes that artifact for review, triage, and collaboration.
3. Python plugins consume the same finished report and emit sidecar artifacts.
4. Rust engines may produce upstream artifacts or event streams that feed `msengine` or other components.

The workbench is intentionally usable without a local engine binary if reports were generated elsewhere.

`marlinspike-capd` introduces a **second** contract surface: the uds JSON-RPC between the privileged capture daemon and the unprivileged workbench. New capd versions must accept old workbench calls; the workbench must tolerate fields it doesn't recognize. The contract is documented inline in `marlinspike-capd/capd/server.py` and reflected in `marlinspike/capture/client.py`.

## Current Transition State

The current repository still contains both engine and workbench code while the split is being prepared. The target direction is:

- root `marlinspike` repo becomes the suite/integration repo
- engine code extracts to `marlinspike-msengine`
- Flask web UI extracts to `marlinspike-workbench`
- shared MITRE logic lives in `marlinspike-mitre`
- plugin and Rust engine families get their own dedicated homes

The first bootstrap subtree prefix now exists:

- `msengine/`
  Contains packaging metadata plus a mirrored copy of the current engine code and OUI data.

Until the cutover is complete, the root `_ms_engine.py` file remains the operational source in the suite and `scripts/sync-msengine-bootstrap.sh` keeps the subtree copy aligned.

The MITRE plugin currently uses a similar bootstrap pattern, but with a standalone sibling repo instead of a subtree-managed monorepo:

- authoritative source: `marlinspike-mitre`
- vendored runtime copy in this suite: `plugins/marlinspike_mitre/` and `rules/mitre/`
- refresh helper: `scripts/sync-mitre-bootstrap.sh`

See [COMPATIBILITY.md](../COMPATIBILITY.md) for the compatibility model and [docs/extensibility-contracts.md](extensibility-contracts.md) for interface boundaries.
