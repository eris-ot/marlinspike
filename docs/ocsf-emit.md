# OCSF emit

> **Audience:** operators integrating MarlinSpike with a SIEM / XDR /
> Security Lake. **TL;DR:** every chain-style scan produces
> `report.ocsf.ndjson` alongside the native `report.json`. Pipe it
> straight into your OCSF-aware ingestion.

## What gets emitted

[OCSF v1.4.0](https://schema.ocsf.io/) Detection Finding records
(class 2004) for the **application-layer findings** MarlinSpike
computes on top of aggregated Bronze events:

| Source | OCSF class | Mapping notes |
|---|---|---|
| `risk_findings[]` | Detection Finding (2004) | Severity → `severity_id`, affected_nodes → `affected_resources[]`, attack_techniques → `attacks[]`. UID is the stable finding signature (sha256 of category + sorted nodes + sorted edges). |
| `c2_indicators[]` | Detection Finding (2004) | beacon_score → `confidence`, src/dst → `src_endpoint`/`dst_endpoint`, transport → `connection_info.protocol_name`. |
| `malware_findings[]` | Detection Finding (2004) | Lowercase severity normalised. observable_field/value → `evidences[]`. Carries `references[]` and `tags[]` in `unmapped.marlinspike`. |
| `mitre_classifications[]` | Detection Finding (2004) | Confidence-derived severity. Full ATT&CK technique + tactic in `attacks[]`. |

The wire-derived Bronze events (ProtocolTransaction, AssetObservation,
ParseAnomaly) get their own native OCSF emit from
`marlinspike-dpi --format ocsf` (v1.7.0+). MarlinSpike's chain runner
invokes both streams and concatenates them into a single
`report.ocsf.ndjson`. The DPI stream comes first (one record per
event); the application-layer findings follow (one record per finding).
A consumer ingesting the file gets a complete OCSF view per capture
without having to merge files itself.

If the pinned DPI binary predates v1.7.0 (no `--format ocsf` support),
the file contains only the application-layer findings — DPI's portion
is silently empty. Bump the DPI pin to fix.

## How to enable

On by default in v3.6+. To disable:

```sh
MARLINSPIKE_EMIT_OCSF=false
```

When enabled, every chain run produces both:

```
data/reports/<user>/<project>/<filename>.json           # internal contract
data/reports/<user>/<project>/<filename>.ocsf.ndjson    # OCSF v1.4.0 NDJSON
```

## Programmatic / standalone use

Re-emit an existing report without re-running the chain:

```sh
python -m marlinspike.emit.ocsf path/to/report.json -o path/to/report.ocsf.ndjson
```

Override the capture_id stamped into `unmapped.marlinspike.capture_id`:

```sh
python -m marlinspike.emit.ocsf report.json -o out.ndjson --capture-id site42-shift3
```

From Python:

```python
from marlinspike.emit import ocsf
import json

with open("report.json") as f:
    report = json.load(f)

ndjson = ocsf.render_ndjson(report)
# or get the dicts directly:
records = ocsf.render_report(report)
```

## Sample output

```json
{
  "class_uid": 2004,
  "class_name": "Detection Finding",
  "category_uid": 2,
  "category_name": "Findings",
  "activity_id": 1,
  "type_uid": 200401,
  "type_name": "Detection Finding: Create",
  "time": 1778383800000,
  "severity_id": 5,
  "severity": "Critical",
  "confidence_id": 2,
  "confidence": "73",
  "metadata": {
    "version": "1.4.0",
    "product": {
      "name": "MarlinSpike",
      "vendor_name": "ERISFORGE Ltd.",
      "version": "3.5.1"
    }
  },
  "finding_info": {
    "uid": "c2:C2_BEACONING:192.168.89.2:8.8.8.8:53",
    "title": "C2_BEACONING",
    "desc": "Possible C2 beaconing: 192.168.89.2 -> 8.8.8.8:53 every ~10.0s ...",
    "types": ["C2_BEACONING"],
    "first_seen_time": 1778383800000
  },
  "affected_resources": [
    {"type_id": 0, "type": "Endpoint", "name": "192.168.89.2", "uid": "192.168.89.2"},
    {"type_id": 0, "type": "Endpoint", "name": "8.8.8.8", "uid": "8.8.8.8"}
  ],
  "src_endpoint": {"ip": "192.168.89.2"},
  "dst_endpoint": {"ip": "8.8.8.8", "port": 53},
  "connection_info": {"protocol_name": "UDP"},
  "unmapped": {
    "marlinspike": {
      "type": "C2_BEACONING",
      "beacon_score": 0.733,
      "interval": 10.0,
      "jitter": 0.135,
      "packets": 2731,
      "capture_id": "4SICS-GeekLounge-151020"
    }
  }
}
```

## Why some MarlinSpike richness lives in `unmapped`

OCSF v1.4 doesn't have first-class fields for everything MarlinSpike
emits — beacon_score / jitter / interval, finding category strings,
contextual_severity overlays, observable_field/value pairs. OCSF's
intended pattern is to put product-specific data in `unmapped.<product>`
so consumers can recover it without losing information. We follow
that pattern; everything in `unmapped.marlinspike.*` is MarlinSpike-
specific enrichment that didn't have a clean OCSF home.

A SIEM rule keyed on standard OCSF fields (`severity_id`,
`finding_info.title`, `affected_resources[].name`) works without
touching `unmapped`. Custom MarlinSpike-aware queries can still reach
into `unmapped.marlinspike.*` for richer context.

## What's NOT in OCSF emit (and why)

- **Topology graph** (nodes + edges) — defenders consume this in the
  workbench; SIEM rules don't operate on graph structure. If you need
  it, the native `report.json` has the topology.
- **`process_reading` events** (Sparkplug, OPC UA ReadResponse, PCCC,
  Synchrophasor) — OCSF has no class for OT process telemetry. These
  are silently dropped today; if you need them, consume Bronze JSON
  directly from `marlinspike-dpi`.
- **`extracted_artifact` events** — wire artifacts like extracted
  files; consumed by `marlinspike-malware` for IOC matching, not in
  OCSF emit.
- **Operator context** (asset tags, finding notes) — these are
  user-edited annotations, not detection findings. Not part of the
  scan output. Surface in the workbench instead.

## MITRE ATT&CK Navigator emit (sibling format)

Same scaffold, different output: the Python engine also writes ATT&CK
Navigator v4.5 layer JSON files alongside `report.ocsf.ndjson`. One
file per ATT&CK domain present in the report:

```
data/reports/<user>/<project>/<basename>.navigator.ics.json
data/reports/<user>/<project>/<basename>.navigator.enterprise.json
```

Each layer carries every technique from `mitre_classifications` and
`mitre_platform_coverage` for that domain, scored 0-100 by confidence
(observed → high score → red, inferred → mid score → orange, platform
coverage → low score → blue). Drop the file directly into a hosted
Navigator instance to visualise technique coverage.

Configuration:

```sh
MARLINSPIKE_EMIT_NAVIGATOR=true   # default
```

Standalone CLI:

```sh
python -m marlinspike.emit.navigator report.json -o report.navigator.json
# writes report.navigator.ics.json + report.navigator.enterprise.json

python -m marlinspike.emit.navigator report.json -o ics.json --domain ics-attack
```

Workbench: the **Navigator** button on the lens-strip control bar
downloads the ICS layer for the current report (Enterprise via the
endpoint `/api/reports/<filename>/navigator?domain=enterprise-attack`).

## Endpoints

| URL | What it serves |
|---|---|
| `/api/reports/<filename>/ocsf` | OCSF NDJSON sibling (or generates application-layer slice on demand if file is absent) |
| `/api/reports/<filename>/navigator?domain=ics-attack` | Navigator ICS layer (or generates from report on demand) |
| `/api/reports/<filename>/navigator?domain=enterprise-attack` | Navigator Enterprise layer |

All three accept `?project_id=N` for per-project scoping (matches the
existing report-download URL convention).

## See also

- [bronze-consumer-contract.md](bronze-consumer-contract.md) — what
  the Python consumer reads from `marlinspike-dpi` Bronze events,
  including the OCSF surface marlinspike-dpi v1.7.0 emits natively.
- OCSF schema explorer: https://schema.ocsf.io/
- OCSF on GitHub: https://github.com/ocsf/ocsf-schema
- ATT&CK Navigator: https://github.com/mitre-attack/attack-navigator
- ATT&CK Navigator hosted instance: https://mitre-attack.github.io/attack-navigator/
