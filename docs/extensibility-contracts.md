# Extensibility Contracts

This document defines the intended extension contracts for MarlinSpike.

It exists to make three boundaries explicit:

- Rust engines
- Python plugins
- YAML rule packs

These are not interchangeable. Each surface has a different job, different ownership boundary, and different stability expectations.

Some of this is already implemented today. Some of it is the target contract for the repo family the project is moving toward.

## Status Matrix

| Surface | Status | Current example | Primary input | Primary output |
| --- | --- | --- | --- | --- |
| Rust engine | Implemented today / expanding | `marlinspike-dpi`, `marlinspike-malware` | `pcap` / `pcapng` / packet events / Bronze-adjacent observables | Versioned machine-readable artifacts |
| Python plugin | Target contract | `marlinspike-mitre`, `marlinspike-iec62443`, `marlinspike-pera` | Finished MarlinSpike report JSON | Versioned sidecar JSON artifact |
| YAML rule pack | Target contract | MITRE, IEC 62443, and PERA mapping packs | Loaded by a Python plugin | Declarative rules and local policy |

## Repo Family

MarlinSpike is moving to a repo family with one suite repo and vendored component subrepos:

- `marlinspike`
  Suite repo and integration home
- `marlinspike-msengine`
  Core engine repo, internal package name `msengine`
- `marlinspike-workbench`
  Web UI and collaboration surface
- `marlinspike-plugins`
  Python plugin monorepo
- `marlinspike-engines`
  Rust engine workspace

The suite repo vendors component repos using `git subtree`, not git submodules. The contract rules in this document are meant to keep those component repos interoperable.
The component repos are intended to be authoritative. The suite repo pins and vendors compatible revisions for teams that want one clone.

## Shared Principles

All three surfaces should follow these rules:

1. The portable MarlinSpike report artifact remains the primary handoff between packet analysis and downstream analyst review.
2. Optional extensions must run headlessly. They must not require the Flask UI, a browser, or a database connection.
3. All machine-readable outputs must be deterministic and versioned.
4. Packet-facing code should not make site-policy decisions.
5. Report-facing code should not parse raw packet captures directly.
6. YAML must stay declarative. It is configuration and mapping data, not a general programming language.

## Rust Engine Contract

Status: implemented today in the Stage 2 DPI path.

### Responsibility

Rust engines own packet-facing and event-heavy work:

- reading `pcap` or `pcapng`
- protocol parsing
- transaction normalization
- extracted artifacts and structured observations
- parser-safe, high-throughput handling of raw traffic

Rust engines do not own:

- final topology scoring
- responder-facing finding text
- ATT&CK mapping
- site-specific policy
- HTML or UI behavior

### Invocation Contract

The current `marlinspike-dpi` integration expects a CLI surface equivalent to:

```bash
marlinspike-dpi --input <pcap> --capture-id <id> --output <json> --pretty
```

At minimum, a Rust engine intended for MarlinSpike integration must:

- accept an input capture path
- accept a stable capture identifier
- write JSON output to a caller-specified path
- return a non-zero exit code on failure
- emit useful stderr or stdout on failure

### marlinspike-malware Invocation

```bash
marlinspike-malware scan --rules-dir <rules> --events <json> --output <json>
```

The malware engine accepts a JSON array of `ObservedEvent` objects (extracted from Bronze conversations) and writes a JSON array of `MalwareFinding` objects. It returns exit code 0 on success, non-zero on failure.

### Output Contract

The current Stage 2 adapter in `_ms_engine.py` expects a JSON envelope with these top-level concepts:

```json
{
  "version": "engine-version",
  "input": {},
  "output": {
    "checkpoint": {},
    "events": []
  }
}
```

The event stream may contain multiple families, but MarlinSpike currently consumes these Bronze-style families:

- `protocol_transaction`
- `asset_observation`
- `topology_observation`

The engine may also emit families such as:

- `parse_anomaly`
- `extracted_artifact`

Those additional families are useful because they can feed downstream Python plugins such as malware matching without forcing DPI logic into the main app.

`marlinspike-malware` emits a different output shape — a flat JSON array of `MalwareFinding` objects rather than a Bronze event envelope. Each finding includes `rule_id`, `rule_name`, `family`, `severity`, `confidence`, `summary`, `observable_field`, `observable_value`, `event_id`, `references`, and `tags`. The orchestrating engine (`_ms_engine.py`) converts these into `c2_indicators` and `risk_findings` for the report.

### Compatibility Rules

- The JSON envelope must be versioned.
- Event family names must be stable within a contract version.
- Fields required by the MarlinSpike adapter must not silently disappear in a minor release.
- Breaking schema changes require a contract version bump and an adapter update.

### Failure Contract

- A failed engine run must return a non-zero exit code.
- A failed engine run must not pretend success with an incomplete or corrupt JSON file.
- If an engine is optional, MarlinSpike may fall back to a Python path when configured to do so.

## Python Plugin Contract

Status: target contract for report-facing extensions such as `marlinspike-mitre`, `marlinspike-iec62443`, and `marlinspike-pera`.

Current suite implementation:

- `marlinspike-mitre` is now authored in the standalone sibling repo at `marlinspike-mitre`.
- This suite keeps a vendored runtime copy at `plugins/marlinspike_mitre/`.
- Its default vendored rule pack lives at `rules/mitre/base.yaml`.
- The workbench can auto-run it after a successful scan and load the resulting `-mitre.json` sidecar under `extensions.marlinspike-mitre`.

### Responsibility

Python plugins own report-facing logic:

- enrichment
- correlation
- responder-facing classification
- ATT&CK mapping
- IOC and malware matching
- standards crosswalks
- site-specific post-processing

Python plugins consume the finished MarlinSpike report artifact rather than raw packets. That keeps the primary app approachable for the wider OT/ICS community and makes field changes realistic during live remediation work.

### Invocation Contract

A Python plugin should be runnable as a headless CLI. The preferred shape is:

```bash
python -m marlinspike_plugin_name \
  --input-report <report.json> \
  --output <artifact.json>
```

Optional flags may include:

- `--rules <yaml>`
- `--site-rules <yaml>`
- `--merge-report <enriched-report.json>`
- `--strict`

The plugin must not mutate the input report in place.

Current `marlinspike-mitre` CLI example:

```bash
python3 -m plugins.marlinspike_mitre \
  --input-report report.json \
  --output report-mitre.json \
  --rules rules/mitre/base.yaml
```

### Input Contract

The required input is a finished MarlinSpike report JSON. Plugins may read:

- `capture_info`
- `conversations`
- `protocol_summary`
- `port_summary`
- `nodes`
- `edges`
- `risk_findings`
- `c2_indicators`
- `mac_table`

The report artifact is the primary input contract. A plugin may also read sidecar artifacts, but that should be optional rather than required for baseline operation.

### Output Contract

A Python plugin should emit a sidecar JSON artifact with a stable envelope:

```json
{
  "artifact_type": "plugin_output",
  "plugin_id": "marlinspike-plugin-name",
  "plugin_version": "0.1.0",
  "contract_version": 1,
  "generated_at": "2026-03-26T00:00:00Z",
  "input_report": "report.json",
  "summary": {},
  "data": {},
  "warnings": []
}
```

Plugin-specific content belongs inside `data`.

If a merged report is requested, the preferred location is:

```json
{
  "extensions": {
    "marlinspike-plugin-name": {
      "artifact_type": "plugin_output"
    }
  }
}
```

The sidecar artifact remains authoritative. A merged report is a convenience copy for downstream review.

Examples:

- `marlinspike-mitre` would emit ATT&CK classifications, confidence, and evidence references.
- `marlinspike-iec62443` would emit standards mappings, control families, and evidence references.
- `marlinspike-pera` would emit PERA model classifications and zone-context overlays.

### Evidence Contract

Plugins should reference concrete evidence rather than producing ungrounded assertions.

Preferred evidence references:

- stable finding IDs
- stable indicator IDs
- node IPs or MACs
- edge identifiers
- artifact hashes

If the base report does not yet carry stable finding or indicator IDs, a plugin may emit deterministic derived IDs temporarily, but stable report-native IDs are preferred for long-term compatibility.

### Workbench View Contract

Plugins may optionally contribute analyst-facing views to the workbench, but only through a declarative schema.

This is the key boundary:

- the workbench owns the shell, navigation, layout, styling, and rendering behavior
- a plugin may contribute structured view data for one or more workbench locations
- a plugin must not inject arbitrary HTML, CSS, or JavaScript into the viewer

That keeps the operator experience coherent while still letting repo-family modules expose richer context.

Preferred merged-report shape:

```json
{
  "extensions": {
    "marlinspike-plugin-name": {
      "artifact_type": "plugin_output",
      "summary": {},
      "data": {},
      "workbench_views": []
    }
  }
}
```

Each `workbench_views` entry should follow this shape:

```json
{
  "view_id": "technique-coverage",
  "title": "Technique Coverage",
  "nav_label": "Coverage",
  "location": "intel",
  "badge": "6",
  "summary": "Observed and inferred ATT&CK classifications for this report.",
  "order": 20,
  "blocks": []
}
```

Supported `location` values:

- `dashboard`
- `map`
- `findings`
- `evidence`
- `assets`
- `intel`
- `risk`
- `reports`

Supported block types:

- `metric_strip`
- `key_value`
- `chip_list`
- `table`
- `records`
- `markdown`

Block shapes:

```json
{
  "type": "metric_strip",
  "title": "Coverage Summary",
  "items": [
    { "label": "Observed", "value": "4", "tone": "positive" },
    { "label": "Inferred", "value": "2", "tone": "warn" }
  ]
}
```

```json
{
  "type": "key_value",
  "title": "Pack Metadata",
  "items": [
    { "label": "Pack", "value": "ATT&CK OT Base" },
    { "label": "Version", "value": "2026.03" }
  ]
}
```

```json
{
  "type": "chip_list",
  "title": "Mapped Categories",
  "items": ["C2_DNS_EXFIL", "CROSS_PURDUE"]
}
```

```json
{
  "type": "table",
  "title": "Top Techniques",
  "columns": ["Technique", "Basis", "Confidence"],
  "rows": [
    ["T1048", "observed", "0.95"],
    ["T1132", "observed", "0.82"]
  ]
}
```

```json
{
  "type": "records",
  "title": "Responder Notes",
  "items": [
    {
      "title": "T1048 Exfiltration Over Alternative Protocol",
      "subtitle": "Observed",
      "body": "Mapped from DNS exfil and high-entropy queries.",
      "chips": ["T1048", "DNS", "Exfiltration"]
    }
  ]
}
```

```json
{
  "type": "markdown",
  "title": "Analyst Guidance",
  "text": "Review the affected engineering workstation and validate expected DNS destinations."
}
```

Compatibility rules:

- `view_id`, `title`, and at least one valid block are required for a view to render
- unknown `location` values fall back to `intel`
- unknown block types must be ignored rather than breaking the viewer
- plugins should keep view payloads concise and evidence-oriented
- workbench views are optional enrichment, not the authoritative plugin artifact

Recommended usage:

- use `dashboard` for lightweight plugin KPIs or quick-read summaries
- use `evidence`, `intel`, or `risk` for analyst-facing deep dives
- use `reports` for portable artifact supplements that should remain visible in exported review flows
- avoid duplicating large sections of the base MarlinSpike report unless the plugin adds new interpretation or pivots

### Failure Contract

- A plugin must return a non-zero exit code for real execution failures.
- No-match results are not failures. They should produce a valid artifact with empty results.
- Optional plugins should not cause the core scan to fail unless strict mode is explicitly requested.

### Non-Goals

Python plugins should not:

- parse raw packet captures as their primary interface
- depend on Flask routes or Jinja templates
- require online lookups for baseline operation
- embed arbitrary rule logic inside YAML templates

### Concrete Artifact Example: `marlinspike-iec62443`

Illustrative target shape:

```json
{
  "artifact_type": "plugin_output",
  "plugin_id": "marlinspike-iec62443",
  "plugin_version": "0.1.0",
  "contract_version": 1,
  "generated_at": "2026-03-26T00:00:00Z",
  "input_report": "example-report.json",
  "summary": {
    "mapping_total": 2,
    "sr_family_total": 2,
    "high_priority_total": 1,
    "unmapped_finding_total": 1
  },
  "data": {
    "mappings": [
      {
        "control_family": "SR 3.1",
        "title": "Communication Integrity",
        "basis": "observed",
        "confidence": 0.88,
        "mapped_from": ["CROSS_PURDUE"],
        "affected_nodes": ["10.10.20.14"],
        "evidence_refs": ["finding:cross-purdue:1"],
        "rationale": "Cross-level communication indicates conduit and communication-control review."
      }
    ],
    "coverage": {
      "mapped_findings": ["CROSS_PURDUE"],
      "unmapped_findings": ["NO_AUTH_OBSERVED"]
    }
  },
  "warnings": []
}
```

Expected meanings:

- `mappings` captures standards-facing control context.
- `coverage` shows what the plugin did not map so analysts can see the edge of current support.
- `summary` is lightweight and safe for dashboards or report viewers.

### Concrete Artifact Example: `marlinspike-mitre`

Illustrative target shape:

```json
{
  "artifact_type": "plugin_output",
  "plugin_id": "marlinspike-mitre",
  "plugin_version": "0.1.0",
  "contract_version": 1,
  "generated_at": "2026-03-26T00:00:00Z",
  "input_report": "example-report.json",
  "summary": {
    "classification_total": 3,
    "observed_total": 2,
    "inferred_total": 1,
    "unmapped_category_total": 1
  },
  "data": {
    "classifications": [
      {
        "technique_id": "T1048",
        "title": "Exfiltration Over Alternative Protocol",
        "family": "Exfiltration",
        "publication": "Published on report findings",
        "basis": "observed",
        "confidence": 0.95,
        "mapped_from": ["C2_DNS_EXFIL"],
        "affected_nodes": ["10.10.20.14", "8.8.8.8"],
        "evidence_refs": ["finding:c2-dns-exfil:1"],
        "rationale": "DNS exfil finding matched the ATT&CK exfiltration mapping."
      },
      {
        "technique_id": "T1132",
        "title": "Data Encoding",
        "family": "Exfiltration",
        "publication": "Published on report findings",
        "basis": "observed",
        "confidence": 0.82,
        "mapped_from": ["C2_DNS_EXFIL", "C2_DNS_HIGH_ENTROPY"],
        "affected_nodes": ["10.10.20.14"],
        "evidence_refs": ["finding:c2-dns-exfil:1", "finding:c2-dns-high-entropy:1"],
        "rationale": "High-entropy DNS labels suggested encoded payload transfer."
      }
    ],
    "coverage": {
      "mapped_categories": ["C2_DNS_EXFIL", "C2_DNS_HIGH_ENTROPY"],
      "unmapped_categories": ["NO_AUTH_OBSERVED"]
    }
  },
  "warnings": []
}
```

Expected meanings:

- `classifications` captures analyst-facing ATT&CK context.
- `basis` distinguishes observed mappings from weaker inferred ones.
- `coverage` shows what the plugin did not map so analysts can see the edge of current support.

## YAML Rule Pack Contract

Status: target contract for declarative content consumed by Python plugins.

### Responsibility

YAML rule packs own declarative content:

- mapping tables
- IOC lists
- ATT&CK technique mappings
- confidence defaults
- enable or disable flags
- local suppressions
- site overrides

YAML rule packs do not own:

- packet parsing
- graph traversal
- arbitrary code execution
- network access
- UI rendering

### Pack Envelope

The preferred top-level shape is:

```yaml
schema_version: 1
pack_id: marlinspike-pack-id
pack_version: "2026.03"
plugin_id: marlinspike-plugin-name
description: Short description
rules: []
```

Required top-level fields:

- `schema_version`
- `pack_id`
- `pack_version`
- `plugin_id`
- `rules`

Optional fields:

- `description`
- `references`
- `author`
- `default_enabled`

### Rule Shape

The preferred rule shape is:

```yaml
- id: example-rule
  enabled: true
  title: Example Rule
  when:
    finding_categories: ["C2_DNS_EXFIL"]
    severity: ["HIGH", "CRITICAL"]
  emit:
    techniques:
      - code: T1048
        confidence: 0.95
  references:
    - https://example.invalid/reference
```

Rule semantics should remain intentionally limited:

- equality and list membership checks
- explicit field matches
- bounded numeric thresholds
- enable or disable toggles
- metadata emission

Rule semantics should not include:

- embedded Python
- templated shell execution
- unbounded expression evaluation
- inline JavaScript

### Merge and Override Contract

Rule packs should be applied in this order:

1. base pack
2. vendor or domain pack
3. site override pack

Later packs may disable or override earlier rules by ID, but they should not silently redefine unrelated IDs.

### Validation Contract

- Invalid YAML must fail closed.
- Unknown top-level schema versions must fail closed.
- Unknown rule keys should be rejected in strict mode and warned in permissive mode.
- Plugins must validate packs before use.

## Naming and Placement

Use these names consistently in docs and future implementation:

- `marlinspike-msengine`: core engine repo, internal package and CLI name `msengine`
- `marlinspike-workbench`: web UI repo
- `marlinspike-plugins`: Python plugin monorepo
- `marlinspike-engines`: Rust engine workspace
- `marlinspike-dpi`: Rust engine
- `marlinspike-malware`: Rust engine / event matcher
- `marlinspike-mitre`: Python plugin backed by YAML rule packs
- `marlinspike-iec62443`: Python plugin backed by YAML rule packs
- `marlinspike-pera`: Python plugin backed by YAML rule packs

## Rule of Thumb

If new work is being proposed, place it by the input it consumes:

- raw packets or high-volume protocol events: Rust engine
- finished MarlinSpike report artifact: Python plugin
- analyst-tunable matching or mapping content: YAML rule pack
