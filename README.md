# MarlinSpike

Current release: `2.0.3`

MarlinSpike is a ground-up passive OT/ICS network analysis platform built in the tradition of GrassMarlin-style topology mapping, but wrapped in a multi-user web workbench designed for real engagements. It analyzes PCAP and PCAPNG captures, builds a topology graph, infers Purdue levels, fingerprints vendors, and surfaces responder-grade risk indicators such as cross-zone communication, cleartext services, beaconing, suspicious external communications, and DNS exfiltration, then exports everything as portable JSON report artifacts that travel with the team.

![MarlinSpike Hero](docs/screenshots/00-hero.png)

**Designed for on-site team engagements** — multi-user, zero-JS core workflows, `1 core / 1 GB RAM`, and portable JSON report artifacts.

**1.1M packets -> 46 nodes, 1,344 edges, 432 findings in 29 seconds.**

Repository: [github.com/riverrisk/marlinspike](https://github.com/riverrisk/marlinspike)

## What MarlinSpike Is

MarlinSpike is not just a topology viewer and it is not just a packet parser.

It is a field-deployable analyst platform built around four ideas:

- Passive OT/ICS analysis first: capture files in, no packets sent back onto the network.
- Ground-up GrassMarlin-style replacement: modern topology reconstruction, protocol-aware classification, and analyst-friendly reporting without inheriting the old single-user desktop model.
- Multi-user workbench: projects, uploads, reports, history, administration, and a shared URL the whole engagement team can use at once.
- Portable report contract: the engine can run headlessly, produce report artifacts, and those artifacts can be reviewed in the built-in workbench or consumed elsewhere.

The result is a different operating model than a desktop analyzer. MarlinSpike is meant to be dropped onto a temporary engagement host, fed captures from taps, SPAN ports, or external collection, and used collaboratively during triage and assessment.

## Design Principles

MarlinSpike is built around a few practical constraints:

- The engine remains standalone and can produce report artifacts headlessly.
- The report artifact is the handoff between packet analysis and downstream review.
- The primary workflow is `project -> scan -> report -> workbench -> triage actions`.
- Core web workflows remain usable without client-side JavaScript.
- The codebase stays intentionally extensible for working OT/ICS responders, not just systems programmers.

Interactive browser features can improve speed and convenience, but the core triage experience should still be accessible directly from rendered HTML.

## Highlights

- Passive analysis only: no active scanning or packet transmission
- OT protocol parsing for Modbus, EtherNet/IP, S7, DNP3, PROFINET, OPC UA, BACnet, and more
- Expanded Rust DPI substrate via `marlinspike-dpi`: 34 protocol dissectors, Bronze v2 event output, frame-integrity inspection, ICMP anomaly inspection, and stateful L2 anomaly analysis
- Topology construction with Purdue-level inference and vendor fingerprinting
- Risk surfacing for remote access exposure, C2-like beaconing, suspicious external channels, DNS entropy anomalies, policy violations, full MITRE ATT&CK mapping with tactics, sub-techniques, matrix views, response guidance, and IEC 62443 SR-oriented remediation guidance
- Flask web UI with an upgraded multi-mode analyst workbench, project management, report viewer, baseline/drift comparison, asset inventory, scan history, and a source-backed `/capabilities` detection coverage catalog
- Docker Compose deployment with PostgreSQL backing the application
- Optional Rust DPI stage via [`marlinspike-dpi`](https://github.com/riverrisk/marlinspike-dpi), built into the image from a pinned GitHub ref while Python analysis and report shaping remain above it
- MITRE ATT&CK runtime surfaces sourced from the standalone [`marlinspike-mitre`](https://github.com/riverrisk/marlinspike-mitre) repo at a pinned GitHub ref during image build
- Optional Stage 4b malware IOC runtime sourced from standalone `marlinspike-malware` and `marlinspike-malware-rules` repos when their build args are provided

## Quick Start

1. Clone the repository and enter the project directory.

```bash
git clone https://github.com/riverrisk/marlinspike.git
cd marlinspike
```

2. Copy the example environment file and set strong secrets.

```bash
cp .env.example .env
```

3. Build and start the stack.

```bash
docker compose up -d --build
```

4. Open the app at `http://127.0.0.1:5001` or through your reverse proxy.

On first boot, MarlinSpike creates an admin user. If `ADMIN_PASSWORD` is empty, a random password is generated and printed to the container logs.

See [INSTALL.md](INSTALL.md) for a generic deployment walkthrough.

## Documentation

If you are looking for the main repository docs, start here:

- Getting started: [INSTALL.md](INSTALL.md)
- Repo family and suite structure: [docs/repo-family.md](docs/repo-family.md)
- Compatibility model: [COMPATIBILITY.md](COMPATIBILITY.md)
- Architecture and extension boundaries: [docs/extensibility-contracts.md](docs/extensibility-contracts.md)
- Zipped report bundle format proposal: [docs/msbundle-format.md](docs/msbundle-format.md)
- End-user ATT&CK guide: [docs/mitre-attack-guide.md](docs/mitre-attack-guide.md)
- Shared MITRE plugin repo: `/Users/butterbones/marlinspike-mitre`
- Vendored ATT&CK runtime copy: [`plugins/marlinspike_mitre/`](plugins/marlinspike_mitre/) and [`rules/mitre/base.yaml`](rules/mitre/base.yaml)
- MITRE bootstrap sync helper: [`scripts/sync-mitre-bootstrap.sh`](scripts/sync-mitre-bootstrap.sh)
- Suite subtree helper: [`scripts/update-subtrees.sh`](scripts/update-subtrees.sh)
- Bootstrap engine sync helper: [`scripts/sync-msengine-bootstrap.sh`](scripts/sync-msengine-bootstrap.sh)
- Contribution and development workflow: [CONTRIBUTING.md](CONTRIBUTING.md)
- Engine and product release history: [releases.md](releases.md)
- Live viewer and streaming release history: [releases-live.md](releases-live.md)
- Analyst workspace product direction: [docs/analyst-workspace-roadmap.md](docs/analyst-workspace-roadmap.md)
- Public fingerprinting research corpus: [docs/public-fingerprint-corpus.md](docs/public-fingerprint-corpus.md)
- Preset sample library notes: [presets/README.md](presets/README.md)

The key extensibility terminology in this repository is:

- Rust engines: packet-facing and event-heavy components such as DPI
- Python plugins: report-facing analysis, enrichment, and triage logic
- YAML rule packs: declarative mappings, suppressions, and local policy

The key repo-family terminology is:

- `marlinspike`: suite repo that vendors selected component repos as subtree-based subrepos and can pin standalone build dependencies
- `marlinspike-msengine`: core engine repo, internal package and CLI name `msengine`
- `marlinspike-workbench`: web UI repo that can review reports with or without invoking the local engine
- `marlinspike-mitre`: standalone shared MITRE ATT&CK plugin repo consumed as a pinned build dependency for runtime plugin and rule surfaces
- `marlinspike-dpi`: standalone shared Rust DPI repo consumed as a pinned build dependency in the app image
- `marlinspike-malware`: standalone shared Rust IOC engine repo consumed as an optional pinned build dependency in the app image
- `marlinspike-malware-rules`: standalone shared rule-content repo consumed as an optional pinned build dependency for published IOC packs, manifests, and compiled bundle artifacts

The component repos are intended to be authoritative. The suite repo exists to pin and vendor a known-good combination for teams that want one clone with all updated parts.
The initial `msengine/` subtree prefix now exists in bootstrap form. Until full extraction completes, the root `_ms_engine.py` remains the operational engine source and [`scripts/sync-msengine-bootstrap.sh`](scripts/sync-msengine-bootstrap.sh) mirrors it into the subtree copy.
The current Docker build pins `marlinspike-dpi` to `de7ed06a28096a3da482831bc674ef0652c0e479` by default via `MARLINSPIKE_DPI_REF`, `marlinspike-mitre` to `c3583ec2d189b8cde69f2160da6a5e8e5b643f7b` via `MARLINSPIKE_MITRE_REF`, `marlinspike-malware` to `02eb369c32e5050796c76be500c009dc0cb8940d` via `MARLINSPIKE_MALWARE_REF`, and `marlinspike-malware-rules` to `99cbe9358d0a5047d9b5e57a7e4ff5eafdee9bd4` via `MARLINSPIKE_MALWARE_RULES_REF`. On March 28, 2026, the rules ref was refreshed to a valid published commit and the malware repo was confirmed publicly readable at the pinned ref. Override those build args in your environment if you need a different known-good combination. The app prefers the published `packs/` surface over the engine repo's dev/test copy when discovering rules.

## ATT&CK Walkthrough

MarlinSpike now includes a full ATT&CK implementation in the report workflow,
including ATT&CK version metadata, tactic-grouped matrix views, sub-techniques,
mitigations, and response guidance.

See the user-facing walkthrough here:

- [docs/mitre-attack-guide.md](docs/mitre-attack-guide.md)

The guide includes screenshots and explains how to move between findings,
ATT&CK mappings, assets, and topology during triage.

## Positioning: Analyst Workbench vs Desktop Tool

MarlinSpike is not a general-purpose desktop analyzer. It is purpose-built as a temporary on-site analyst workbench for OT security engagements and assessments.

| Aspect | MarlinSpike (this project) | Typical desktop GRASSMARLIN-style tools |
|------|------|------|
| **Primary Use Case** | Spin up on an IPC or field laptop during a plant-floor engagement, review team-collected PCAPs, and hand back portable assessment artifacts | Solo deep-dive analysis on a single workstation |
| **User Model** | Multi-user, project-scoped workflow with auth, admin controls, and audit history | Usually single-user first |
| **Deployment** | Lightweight Docker Compose web app with zero-JS core workflows and a `1 core / 1 GB RAM` target | Desktop GUI application with heavier client-side runtime expectations |
| **Report Workflow** | PCAP from anywhere to self-contained JSON report artifacts, viewable here or consumable elsewhere, plus PDF/PNG/CSV exports | Tool-centric workflow with tighter coupling to the local application |
| **Operational Model** | Shared URL for the engagement team, fast setup and teardown, suitable for temporary or air-gapped field use | Persistent analyst desktop environment |
| **Extensibility** | Python analysis pipeline and HTML templates that are approachable for most security teams | Often centered on compiled desktop stacks with a steeper customization path |

In short:
Drop MarlinSpike on an air-gapped or temporary engagement host, hand the URL to the team, feed it the captures you collected, export clean portable JSON reports, and tear it down when the job is done.

If you are looking for a permanent single-user desktop application with a different feature focus, MarlinSpike is not trying to be that tool, and that is intentional.

## Feature Parity with GrassMarlin

MarlinSpike is meant to replace the core passive-mapping workflow people historically used GrassMarlin for, while changing the wrapper around it from a single-user desktop app to a shared web workbench.

| Capability | MarlinSpike status | Notes |
|------|------|------|
| Passive PCAP analysis | Yes | Accepts `pcap` and `pcapng` from the web UI or the standalone engine |
| OT-aware topology mapping | Yes | Relationship map, node/edge graph, vendor hints, and Purdue inference |
| Asset inventory | Yes | Per-asset roles, services, protocols, and responder-facing context |
| Protocol-aware OT analysis | Yes | Modbus, EtherNet/IP, S7, DNP3, PROFINET, OPC UA, BACnet, IEC 104, LLDP/CDP/STP/LACP, and more |
| Risk surfacing from passive traffic | Yes | Cleartext engineering, write-capable paths, suspicious external communications, beaconing, DNS exfiltration, and Purdue violations |
| Exportable outputs | Yes | Portable JSON report artifacts, plus PDF/PNG/CSV export paths from the UI |
| Team analyst workflow | Exceeds | Project-scoped collaboration, shared URL access, history, baseline/drift review, and admin controls are first-class instead of bolted on |
| Headless analysis contract | Exceeds | The engine can run independently, emit portable report artifacts, and be reviewed later in the workbench or elsewhere |
| Thick desktop client | Different by design | Replaced with a browser-based workbench and zero-JS core workflows for temporary, shared field deployment |

### Improving Actively

- Fingerprint depth and classification confidence across more vendors and device families
- Server-rendered analyst drill-down flows in the viewer
- Richer use of Bronze-level protocol observations and extracted artifacts in the report UI
- Broader protocol-native enrichment beyond the current report contract

### Honest Boundaries

- MarlinSpike is a **PCAP analysis tool**, not a continuous monitoring platform. Capture with your own tooling (Wireshark, tshark, a tap, a span port) and bring the PCAP into MarlinSpike for analysis. For continuous live capture, multi-sensor collection, and centralized OT network monitoring, see [FATHOM](https://riverman.io/fathom).
- MarlinSpike is not an active scanner.
- MarlinSpike is not a permanent desktop thick client.
- The standalone Rust DPI engine is a dissection substrate, not the whole product.
- Some protocol coverage and higher-level scoring still live in the Python analysis layer today, by design.

## Engine Architecture

MarlinSpike keeps packet dissection separate from analyst workflow.

### Current Analysis Stack

- Stage 1: capture ingestion and validation
- Stage 2: protocol dissection
- Stage 3: topology construction, Purdue inference, and fingerprinting
- Stage 4: breach-triage and risk surfacing
- Output: portable JSON report artifact consumed by the web workbench

### DPI Engine Options

MarlinSpike can currently run Stage 2 in two ways:

- Built-in Python/tshark-based dissection via `_ms_engine.py`
- External Rust dissection via [`marlinspike-dpi`](https://github.com/riverrisk/marlinspike-dpi)

The Rust path is intentionally scoped as a standalone DPI engine. MarlinSpike can call it as an external Stage 2 parser, adapt its Bronze output back into the current report pipeline, and continue using the existing topology, triage, and reporting layers. That keeps the packet parser reusable without forcing the analyst product to collapse into the parser.

### What `marlinspike-dpi` Means Today

- It is a standalone Rust DPI engine with CLI, library, and FFI surfaces.
- It accepts classic `pcap` and `pcapng` capture input.
- It currently ships 34 protocol dissectors across OT/ICS, IT, and L2 traffic.
- It emits Bronze v2 events that MarlinSpike can consume across five families: protocol transactions, asset observations, topology observations, parse anomalies, and extracted artifacts.
- It layers additional parser-adjacent inspection through `stovetop` frame integrity checks, `icmpeeker` ICMP anomaly analysis, and `bilgepump` stateful L2 anomaly tracking.
- It replaces the dissection stage, not the higher-level breach-triage logic.

That is deliberate. MarlinSpike's value is not just decoding packets quickly. Its value is turning passive OT traffic into topology, findings, and responder decisions a team can actually use.

### Extensibility Model

MarlinSpike uses three extension surfaces on purpose:

- Rust engines: packet-facing or event-heavy components where throughput, memory safety, and parser reuse matter most. Today this primarily means DPI-style engines such as [`marlinspike-dpi`](https://github.com/riverrisk/marlinspike-dpi).
- Python plugins: report-facing analysis, enrichment, triage logic, and post-processing that operate on the portable MarlinSpike JSON artifact rather than raw packets.
- YAML rule packs: declarative mappings, enable/disable controls, site overrides, and other policy content used by plugins without turning configuration into another programming language.

In short:

- Rust finds facts in raw traffic.
- Python turns those facts into responder-facing judgments.
- YAML declares mappings and local policy.

This split is intentional. MarlinSpike is not written as "Rust for everything" because the primary app is meant to be easy to extend by the broader OT/ICS community, including responders, defenders, and consultants who may need to adjust logic during an active remediation event. Rust is excellent for memory-safe, reusable packet engines. Python remains a better fit for fast iteration, site-specific extension, and field-friendly report logic when a team is actively triaging an environment.

Current shipped example:

- `marlinspike-mitre`: authoritative sister repo at `/Users/butterbones/marlinspike-mitre`, with the app image now overlaying the runtime plugin and rule surfaces from the pinned standalone repo into [`plugins/marlinspike_mitre/`](plugins/marlinspike_mitre/) and [`rules/mitre/base.yaml`](rules/mitre/base.yaml) during build. Successful scans can emit a `-mitre.json` sidecar artifact, and the workbench viewer can load it from the report `extensions` surface.
  The current runtime exposes full ATT&CK metadata and versioning, tactics, sub-techniques, matrix-ready tactic groupings, mitigations, ATT&CK URLs, and rich response guidance in the viewer.
  User-facing interpretation notes live in [docs/mitre-attack-guide.md](docs/mitre-attack-guide.md).
- `marlinspike-malware`: authoritative sister repo at `/Users/butterbones/marlinspike-malware`, with `_ms_engine.py` invoking it as an optional Stage 4b engine. When `MARLINSPIKE_MALWARE_REPO` and `MARLINSPIKE_MALWARE_REF` are supplied during image build, the runtime binary is layered into `/opt/marlinspike-malware/bin/`.
- `marlinspike-malware-rules`: authoritative sister repo at `/Users/butterbones/marlinspike-malware-rules`, holding the published `packs/`, `manifests/index.yaml`, and compiled bundle artifacts. The current published surface is 30 packs and 921 rules. When `MARLINSPIKE_MALWARE_RULES_REPO` and `MARLINSPIKE_MALWARE_RULES_REF` are supplied during image build, those assets are layered into `/usr/share/marlinspike-malware/rules/`, and the engine points at `/usr/share/marlinspike-malware/rules/packs`.

See [`docs/extensibility-contracts.md`](docs/extensibility-contracts.md) for the concrete contract boundaries for Rust engines, Python plugins, and YAML rule packs.

If you are deciding where new work belongs, use this rule of thumb:

- If it consumes raw `pcap`, packet streams, or high-volume protocol events, it probably belongs in a Rust engine.
- If it consumes the finished MarlinSpike report artifact, it probably belongs in a Python plugin.
- If analysts should be able to tune it without code changes, it probably belongs in a YAML rule pack.

## Detection and Standards Coverage

MarlinSpike's current public detection and standards story is intentionally bounded to what the engine already emits today.

- Full MITRE ATT&CK implementation is now present through the shared `marlinspike-mitre` runtime, including ATT&CK version metadata, tactic-aware matrix output, sub-techniques, parent-technique context, mitigations, and response guidance
- `marlinspike-dpi` now contributes a broader passive-observable surface: 34 protocol dissectors, Bronze v2 event families, and parser-adjacent anomaly streams from `stovetop`, `icmpeeker`, and `bilgepump`
- Purdue Model inference and cross-level communication checks are part of the core triage workflow
- Stage 4 remediation guidance is aligned to IEC 62443 SR requirements for the finding classes currently produced by the engine
- Deployed instances publish a built-in detection coverage catalog at `/capabilities` that is explicitly framed as what MarlinSpike can detect, not what it has already detected in a given environment
- The `/capabilities` page now groups current report finding classes, `marlinspike-dpi` parser coverage, `marlinspike-malware` observable and rule coverage, and the current ATT&CK mapping set behind filterable source, type, family, severity, and search controls
- The current `marlinspike-malware` section reflects the published `marlinspike-malware-rules` content surface, now at 30 packs and 921 rules, and the ATT&CK section reflects the vendored full ATT&CK implementation shipped by `marlinspike-mitre`

This is now positioned as a full ATT&CK implementation for MarlinSpike's report-facing workflow. It is still intentionally scoped to passive-traffic evidence and analyst triage rather than a broader compliance crosswalk or every possible ATT&CK analytic.

## Feature Overview

MarlinSpike turns raw packet captures into a workflow an OT operator, asset owner, or responder can actually use.

### Analysis

- Passive PCAP and PCAPNG analysis with OT-aware protocol dissection
- Relationship map and topology reconstruction with Purdue inference
- Report-driven triage with risk findings, C2 indicators, and asset context
- Detailed asset inventory, service exposure, conversation analysis, and MAC table reporting

### Workflow

- Ad hoc scan execution from the web UI
- Multi-capture handling, including large-PCAP processing with streaming progress
- Project-scoped organization for captures and reports
- Report history, retry support, and baseline-versus-drift review between report artifacts
- Portable JSON report artifacts that can be reviewed inside MarlinSpike or elsewhere

### Administration

- Multi-user access with admin controls
- Scan history and audit trail
- System health and monitoring views
- Sample library management

## Export Support

The report workflow supports export directly from the UI:

- Print or save to PDF from the report viewer
- PNG export from the topology viewer
- CSV export from the asset inventory view

## Additional Capabilities

- Baseline and drift review with added, removed, changed, and unchanged topology comparison
- Live topology viewing during active scans
- Scan-stage progress streaming with ingest, analyze, classify, and report state visibility
- Per-user administration controls including password resets and upload limits
- Multi-report lifecycle actions including view, download, delete, and compare
- Retry of failed or interrupted scans from scan history
- Sample library administration with category management and PCAP upload/delete controls
- Capture filter input and ephemeral-port suppression controls in the scan workflow
- MAC table reporting alongside the main assessment view

## Screenshots

Click any thumbnail for the full-size image.

### Live Workflow Validation

These screenshots come from a live end-to-end smoke pass captured on March 28, 2026 against the current hosted deployment after running three preset PCAPs: `Modbus.pcap`, `S7comm.pcap`, and the 4SICS benchmark in `fast` mode. They show the core responder path from `project -> scan -> report -> workbench -> assets`.

<table>
  <tr>
    <td width="50%">
      <a href="docs/screenshots/22-live-dashboard.png">
        <img src="docs/screenshots/22-live-dashboard.png" alt="Live dashboard after deployment smoke validation" width="100%">
      </a>
      <br>
      <sub>Dashboard with the scan workspace surfaced as the operational starting point.</sub>
    </td>
    <td width="50%">
      <a href="docs/screenshots/23-live-projects.png">
        <img src="docs/screenshots/23-live-projects.png" alt="Live project workspace used during smoke validation" width="100%">
      </a>
      <br>
      <sub>Project-scoped workspace showing the engagement container used to keep the smoke outputs isolated.</sub>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <a href="docs/screenshots/24-live-scans.png">
        <img src="docs/screenshots/24-live-scans.png" alt="Live scan history with completed smoke runs" width="100%">
      </a>
      <br>
      <sub>Scan history with multiple completed runs, including the large-PCAP benchmark path.</sub>
    </td>
    <td width="50%">
      <a href="docs/screenshots/25-live-benchmark-viewer.png">
        <img src="docs/screenshots/25-live-benchmark-viewer.png" alt="Live benchmark report in the operator workbench" width="100%">
      </a>
      <br>
      <sub>The operator shell on the 4SICS benchmark report with priority targets, auth gaps, and write paths in view.</sub>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <a href="docs/screenshots/26-live-modbus-viewer.png">
        <img src="docs/screenshots/26-live-modbus-viewer.png" alt="Live Modbus report in the operator workbench" width="100%">
      </a>
      <br>
      <sub>A smaller protocol-specific validation pass against Modbus showing the same workbench flow on a focused OT capture.</sub>
    </td>
    <td width="50%">
      <a href="docs/screenshots/27-live-assets.png">
        <img src="docs/screenshots/27-live-assets.png" alt="Live assets view after smoke validation" width="100%">
      </a>
      <br>
      <sub>Assets mode turns the validated report into a sortable responder ledger with device context and risk evidence.</sub>
    </td>
  </tr>
</table>

<table>
  <tr>
    <td width="50%">
      <a href="docs/screenshots/01-topology-viewer.png">
        <img src="docs/screenshots/01-topology-viewer.png" alt="Topology viewer" width="100%">
      </a>
      <br>
      <sub>Topology viewer and analyst workbench</sub>
    </td>
    <td width="50%">
      <a href="docs/screenshots/02-report-viewer.png">
        <img src="docs/screenshots/02-report-viewer.png" alt="Assessment findings and report view" width="100%">
      </a>
      <br>
      <sub>Assessment findings and report review</sub>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <a href="docs/screenshots/03-asset-inventory.png">
        <img src="docs/screenshots/03-asset-inventory.png" alt="Asset inventory" width="100%">
      </a>
      <br>
      <sub>Asset inventory and device context</sub>
    </td>
    <td width="50%">
      <a href="docs/screenshots/06-large-pcap-streaming.png">
        <img src="docs/screenshots/06-large-pcap-streaming.png" alt="Large PCAP progress" width="100%">
      </a>
      <br>
      <sub>Large-PCAP execution with live progress</sub>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <a href="docs/screenshots/07-scan-history.png">
        <img src="docs/screenshots/07-scan-history.png" alt="Scan history" width="100%">
      </a>
      <br>
      <sub>Scan history and audit trail</sub>
    </td>
    <td width="50%">
      <a href="docs/screenshots/08-projects.png">
        <img src="docs/screenshots/08-projects.png" alt="Projects workspace" width="100%">
      </a>
      <br>
      <sub>Project-scoped workflow</sub>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <a href="docs/screenshots/09-users.png">
        <img src="docs/screenshots/09-users.png" alt="User administration" width="100%">
      </a>
      <br>
      <sub>Multi-user administration</sub>
    </td>
    <td width="50%">
      <a href="docs/screenshots/11-diff-viewer.png">
        <img src="docs/screenshots/11-diff-viewer.png" alt="Baseline and drift viewer" width="100%">
      </a>
      <br>
      <sub>Baseline and drift review</sub>
    </td>
  </tr>
</table>

### Upgraded Analyst Workbench

The analyst workbench is now structured as a full operator shell instead of a single crowded viewer. A persistent left rail carries workbench identity, report context, mode navigation, and utilities, while the center stage and right-side inspector stay focused on active triage work.

The current shell supports `Dashboard`, `Map`, `Findings`, `Evidence`, `Assets`, `Intel`, `Risk`, and `Reports` surfaces without trying to cram every workflow into the topology canvas.

This screenshot comes from a live validated report artifact after the public `marlinspike-dpi` update and shows the denser operator shell now used by the viewer.

<table>
  <tr>
    <td width="100%">
      <a href="docs/screenshots/21-workbench-operator-shell.png">
        <img src="docs/screenshots/21-workbench-operator-shell.png" alt="Operator shell with left navigation, compact status strip, and persistent inspector" width="100%">
      </a>
      <br>
      <sub>The operator shell uses a full-height navigation rail, compact status strip, single-row command bar, and persistent inspector so the first viewport stays focused on responder work.</sub>
    </td>
  </tr>
</table>

Additional screenshots show the mode-based workbench surfaces in detail.

<table>
  <tr>
    <td width="33%">
      <a href="docs/screenshots/18-workbench-evidence-mode.png">
        <img src="docs/screenshots/18-workbench-evidence-mode.png" alt="Evidence mode in the upgraded analyst workbench" width="100%">
      </a>
      <br>
      <sub>Evidence mode surfaces enriched sessions, identity clues, hunt pivots, and preserved DPI observables.</sub>
    </td>
    <td width="33%">
      <a href="docs/screenshots/19-workbench-findings-mode.png">
        <img src="docs/screenshots/19-workbench-findings-mode.png" alt="Findings mode in the upgraded analyst workbench" width="100%">
      </a>
      <br>
      <sub>Findings mode gives responders a dedicated triage surface instead of forcing everything into the map.</sub>
    </td>
    <td width="33%">
      <a href="docs/screenshots/20-workbench-assets-mode.png">
        <img src="docs/screenshots/20-workbench-assets-mode.png" alt="Assets mode in the upgraded analyst workbench" width="100%">
      </a>
      <br>
      <sub>Assets mode turns the workbench into a searchable ledger with evidence density and asset context.</sub>
    </td>
  </tr>
</table>

The older live screenshots are still useful as protocol-specific validation examples:

<table>
  <tr>
    <td width="33%">
      <a href="docs/screenshots/15-live-workbench-mqtt.png">
        <img src="docs/screenshots/15-live-workbench-mqtt.png" alt="Live MQTT analyst workbench view" width="100%">
      </a>
      <br>
      <sub>Live MQTT workbench with preserved client, topic, and asset enrichment.</sub>
    </td>
    <td width="33%">
      <a href="docs/screenshots/16-live-workbench-radius.png">
        <img src="docs/screenshots/16-live-workbench-radius.png" alt="Live RADIUS analyst workbench view" width="100%">
      </a>
      <br>
      <sub>Live RADIUS workbench with auth metadata, object refs, and triage context.</sub>
    </td>
    <td width="33%">
      <a href="docs/screenshots/17-live-workbench-ftp.png">
        <img src="docs/screenshots/17-live-workbench-ftp.png" alt="Live FTP analyst workbench view" width="100%">
      </a>
      <br>
      <sub>Live FTP workbench after the public parser panic fix shipped to production.</sub>
    </td>
  </tr>
</table>

## Configuration

The main environment variables are:

- `DB_PASSWORD`: PostgreSQL password
- `SECRET_KEY`: Flask session secret
- `ADMIN_PASSWORD`: initial admin password
- `PCAP_MAX_SIZE`: maximum accepted upload size in bytes
- `PCAP_PROCESS_SIZE`: processing cap for auto-sliced uploads in bytes

## Source Layout

The canonical application modules are:

- `_ms_engine.py`
- `_auth.py`
- `_models.py`
- `_config.py`
- `app.py`

The non-underscored modules (`auth.py`, `models.py`, `config.py`) are compatibility shims so older tooling can still import them without drifting from the real source.

## Sample Data

The public repository does not bundle third-party PCAP corpora. If you want a preset sample library, add captures under `presets/<category>/` locally or through the admin UI after deployment.

## Development

- `python3 -m py_compile app.py _auth.py _config.py _models.py _ms_engine.py`
- `docker compose up --build`

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines, including ongoing fingerprinting and enrichment work.

## Fathom

MarlinSpike is the open-source core of **Fathom**, the commercial OT security platform from [River Risk Partners](https://riverriskpartners.com).

The commercial Fathom platform adds distributed collectors, hierarchy, data diodes, forensic time-travel, and enterprise-scale baseline learning. MarlinSpike is the lightweight, open-core workbench you can spin up anywhere.

Learn more at [riverriskpartners.com](https://riverriskpartners.com).

## Acknowledgments

MarlinSpike is better because of the people who take the time to test it, read the code, and file issues or PRs. Community contributors:

- **[Michael Sargis (@MichaelMVS)](https://github.com/MichaelMVS)** — caught a silent OUI dict collision in `ICS_OUI_DB` that was causing Honeywell devices to be misidentified as GE in every report ([PR #3](https://github.com/riverrisk/marlinspike/pull/3), v2.0.3)
- **Jerrid Brown** (OTPulse) — ran real DCS packet captures through MarlinSpike and surfaced multiple classification and UX issues that drove the v2.0.1 / v2.0.2 fixes (multicast misclassification, OUI gateway-MAC misattribution, NO_AUTH_OBSERVED noise, Level 3 "Application Server" catch-all, Purdue L3 vs L4 heuristics)

If you find a bug or have a fingerprint to add, [open an issue](https://github.com/riverrisk/marlinspike/issues) or [send a PR](https://github.com/riverrisk/marlinspike/pulls) — first-time contributors very welcome.

## License

This repository is licensed under the GNU Affero General Public License v3.0. See [LICENSE](LICENSE).

## Contact

Questions? Contact me, river@riverman.io
