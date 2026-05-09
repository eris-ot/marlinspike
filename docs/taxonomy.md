# MarlinSpike Taxonomy

> **Audience:** two readers.  
> **Operator** — wants to understand what the platform recognises and why.  
> **Developer** — is about to add a feature and needs to know where it slots in.

This document is the source of truth.  `marlinspike/taxonomy.py` is its
machine-readable companion; the two must stay in sync.  When in doubt, the
Python module wins for names and keys; this document wins for intent.

---

## Scope

The taxonomy describes the **analyst workflow graph** — entities and
relationships an OT/ICS network analyst encounters when working with
MarlinSpike reports, projects, and captures.

**Explicitly out of scope:**  
`User`, `AuditLog`, and `PasswordResetToken` are administrative/operational
records.  They exist in the database (`marlinspike/models.py`) but have no
visual treatment in the analyst graph.  Do not add chips, node shapes, or
graph edges for them.

---

## 1. Entity Types

Twelve entity types.  Each has an identity rule (how to uniquely identify one
instance), a source (where it comes from), and a visual treatment.

### 1.1 Asset

**What it is:** A network-visible endpoint — a device identified by MAC address
(primary) or IP address (fallback when no MAC is available).  Assets are
*derived* from report nodes; there is no `assets` database table.  The
canonical asset key is `asset_key` in the engine output.

**Source:** `nodes[]` array in the engine report JSON.  Aggregated cross-report
by `marlinspike/aggregate.py` using the MAC-first identity policy.

**Identity rule:** MAC address if present; IP address otherwise.  The
`aggregate.py` `_asset_key()` function implements this.

**Key properties:** `ip`, `mac`, `vendor`, `device_type`, `purdue_level`,
`protocols[]`, `role`, `asset_type` (`local`/`network`/`external`),
`auth_observed`.

**Operator-facing metadata:** `AssetTag` (DB model) overlays `owner`,
`criticality`, `zone`, `business_function` on top of engine-derived data.

**Visual treatment:**  
- Colour: `--accent-cyan`  
- Node shape: `circle` (primary node type — the most common entity in the graph)  
- Chip class: `chip-cyan`  
- Icon: monitor/screen outline (16×16 inline SVG)

---

### 1.2 Conversation

**What it is:** A directional flow between two assets on a specific protocol
and port.  One conversation = one row in `conversations[]`.  Conversations are
always per-capture; they do not aggregate cross-report (too granular, too
storage-heavy).

**Source:** `conversations[]` array in the engine report JSON.

**Identity rule:** `(src_ip, dst_ip, src_mac, dst_mac, protocol, port)` — no
stable ID field; the tuple is the key.

**Key properties:** `src_ip`, `dst_ip`, `protocol`, `port`, `transport`,
`packet_count`, `bytes_total`, `first_seen`, `last_seen`, `beacon_score`,
`beacon_interval`, `dns_queries[]`, ICS-protocol detail fields
(`modbus_functions`, `cip_identity`, `s7_functions`, etc.)

**Visual treatment:**  
- Colour: `--accent`  
- Node shape: `diamond` (edge entity — exists between two assets)  
- Chip class: `chip-accent`  
- Icon: horizontal arrow outline

---

### 1.3 Finding

**What it is:** A risk finding produced by the engine's risk stage.  Describes
a policy violation, network exposure, or suspicious pattern affecting one or
more assets.  Findings aggregate cross-report: the same `(category,
affected_nodes, affected_edges)` tuple seen across multiple captures is
deduplicated into a single Finding with an occurrence count.

**Source:** `risk_findings[]` in the engine report JSON.  Aggregated by
`aggregate.py` `_finding_key()`.

**Identity rule:** `(category, sorted(affected_nodes), sorted(affected_edges))`.

**Key properties:** `severity` (CRITICAL/HIGH/MEDIUM/LOW/INFO), `category`
(engine-defined, e.g. `EXTERNAL_IPS_OBSERVED`), `description`, `remediation`,
`affected_nodes[]`, `cvss_impact`.

**Operator-facing metadata:** `FindingNote` (DB model) adds `status` and analyst
notes to findings, keyed by `(project_id, report_filename, finding_signature)`.

**Visual treatment:**  
- Colour: `--sev-high` (default; the chip class is overridden by the actual
  severity at render time via `severity_chip_class()` from `taxonomy.py`)  
- Node shape: `triangle`  
- Chip class: `chip-high` (default; override with severity chip at render time)  
- Icon: warning triangle

> **Note for developers:** Finding chips should almost always be rendered with
> the severity override.  Use `taxonomy.severity_chip_class(finding.severity)`
> rather than the entity default.

---

### 1.4 Anomaly

**What it is:** A layer-2 anomaly detected during capture analysis — ARP
spoofing, MAC table conflicts, etc.  Distinct from Finding because anomalies
are raw detection events (no remediation guidance, no CVSS), attached to
specific packets rather than asset/edge pairs.

**Source:** `l2_anomalies[]` in the engine report JSON.

**Identity rule:** `(anomaly_type, src_mac, dst_mac, timestamp)` — no stable ID.

**Key properties:** `anomaly_type` (e.g. `arp_spoof`), `decoder`, `src_mac`,
`dst_mac`, `details.severity`, `details.reason`.

**Why separate from Finding:** Anomalies have no `category`/`affected_nodes`
structure and no remediation.  Merging them into Finding would require lossy
type-erasure.  The engine emits them as a distinct top-level key.

**Visual treatment:**  
- Colour: `--sev-medium`  
- Node shape: `diamond`  
- Chip class: `chip-medium`  
- Icon: circle-with-exclamation

---

### 1.5 C2 Indicator

**What it is:** A beaconing or command-and-control pattern detected between
two addresses — periodic, low-jitter traffic that matches C2 timing signatures.

**Source:** `c2_indicators[]` in the engine report JSON.

**Identity rule:** `(type, src, dst, port, transport)`.

**Key properties:** `type` (e.g. `C2_BEACONING`), `severity`, `src`, `dst`,
`port`, `transport`, `beacon_score`, `interval`, `jitter`, `packets`.

**Visual treatment:**  
- Colour: `--sev-critical`  
- Node shape: `hex`  
- Chip class: `chip-critical`  
- Icon: circular-arrow with exclamation

---

### 1.6 Malware Finding

**What it is:** A threat-intelligence rule match from the DPI/malware pack
system.  Each entry carries a `rule_id`, `family`, confidence score, and MITRE
ATT&CK references.  Malware findings use lowercase severity tokens
(`critical`/`high`/`medium`/`low`) — unlike engine findings which use uppercase.

**Source:** `malware_findings[]` in the engine report JSON.

**Identity rule:** `finding_id` (SHA-256 hash present in the engine output).

**Key properties:** `finding_id`, `rule_id`, `rule_name`, `family`, `severity`,
`confidence`, `summary`, `src_ip`, `dst_ip`, `references[]`, `tags[]`,
`source_feed`.

**Why separate from Finding:** Malware findings have a stable `finding_id`,
carry confidence scores, MITRE references, and source-feed attribution —
structure that doesn't fit the risk-finding schema.  They also carry different
severity vocabulary and originate from a different engine stage.

**Visual treatment:**  
- Colour: `--sev-critical`  
- Node shape: `hex`  
- Chip class: `chip-critical` (override with `severity_chip_class()` for actual severity)  
- Icon: star/burst outline

---

### 1.7 IOC List

**What it is:** A named collection of indicators of compromise, scoped to a
project.  Persisted in the `ioc_lists` DB table.

**Source:** `IocList` model (`marlinspike/models.py`).

**Identity rule:** `(project_id, name)` — enforced by unique constraint.

**Key properties:** `name`, `description`, `source` (manual/csv/misp/stix),
`entries[]` (IocEntry objects).

**Visual treatment:**  
- Colour: `--accent-amber`  
- Node shape: `square` (container entity)  
- Chip class: `chip-muted`  
- Icon: document with lines

---

### 1.8 IOC Entry

**What it is:** A single indicator value within an IOC List.  Types: `ip`,
`mac`, `oui`, `domain`, `sha256`, `md5`.

**Source:** `IocEntry` model (`marlinspike/models.py`).

**Identity rule:** `(list_id, ioc_type, value)` — enforced by unique constraint.

**Key properties:** `ioc_type`, `value`, `label`, `severity`.

**Visual treatment:**  
- Colour: `--accent-amber`  
- Node shape: `circle`  
- Chip class: `chip-muted`  
- Icon: crosshair/target

---

### 1.9 Project

**What it is:** An analyst workspace grouping scans, reports, asset tags, IOC
lists, and saved filters.

**Source:** `Project` model (`marlinspike/models.py`).

**Identity rule:** `id` (primary key); unique on `(user_id, name)`.

**Visual treatment:**  
- Colour: `--accent-green`  
- Node shape: `square`  
- Chip class: `chip-success`  
- Icon: folder/briefcase outline

---

### 1.10 Report

**What it is:** The output of one engine run against one PCAP — a JSON
document stored at `report_path` on `ScanHistory`.  Contains all the raw
entity data (nodes, edges, findings, etc.).

**Source:** `ScanHistory` model references it; report content is a JSON file
on disk.

**Identity rule:** `ScanHistory.run_id` or the report file path.

**Visual treatment:**  
- Colour: `--text-dim`  
- Node shape: `square`  
- Chip class: `chip-muted`  
- Icon: document with lines

---

### 1.11 Capture Session

**What it is:** A live-capture session managed by the `capd` sidecar.  Records
interface, BPF filter, ring buffer config, and live packet/byte counters.

**Source:** `CaptureSession` model (`marlinspike/models.py`).

**Identity rule:** `session_uuid`.

**Visual treatment:**  
- Colour: `--accent-rose`  
- Node shape: `circle`  
- Chip class: `chip-muted`  
- Icon: clock/timer outline

---

### 1.12 Protocol

**What it is:** A network protocol observed in a capture.  Not a DB model —
derived from `capture_info.protocols_seen` and `protocol_summary` in report
JSON, and from `nodes[].protocols[]`.

**Source:** Engine report JSON (`capture_info.protocols_seen`,
`protocol_summary`).

**Identity rule:** Protocol name string (case-normalised, e.g. `DNS`, `Modbus`,
`S7comm`).

**Visual treatment:**  
- Colour: `--accent`  
- Node shape: `circle`  
- Chip class: `chip-info`  
- Icon: two connected boxes (link icon)

---

## 2. Relationship Types

Twelve directional relationships.  Convention: the table shows `Source →
Target`.

| Relationship | Source | Target | Cardinality | Notes |
|---|---|---|---|---|
| `communicates_with` | Asset | Asset | M:N | Bidirectional by convention; src/dst derive from conversation `initiated_by`/`received_by` |
| `affected_by` | Finding | Asset | M:N | `risk_findings[].affected_nodes` lists IPs |
| `flagged_by_anomaly` | Anomaly | Asset | M:N | Linked via `src_mac`/`dst_mac` to Asset |
| `flagged_by_c2` | C2Indicator | Asset | 1:N | `c2_indicators[].src` and `.dst` |
| `flagged_by_malware` | MalwareFinding | Asset | M:N | `malware_findings[].src_ip`/`dst_ip` |
| `matched_by_ioc` | IocEntry | Asset | M:N | Runtime match; not persisted, computed on demand |
| `initiated_by` | Conversation | Asset | N:1 | `src_ip`/`src_mac` of the conversation |
| `received_by` | Conversation | Asset | N:1 | `dst_ip`/`dst_mac` of the conversation |
| `generates` | Conversation | Finding \| C2Indicator \| MalwareFinding | 1:M | `event_id` in malware_findings links to `conv-N` |
| `belongs_to_project` | Report \| Asset \| IocList | Project | N:1 | Project is the top-level scope |
| `contained_in_report` | Asset \| Finding \| Conversation | Report | M:N | Cross-report entities appear in multiple reports |
| `ioc_in_list` | IocEntry | IocList | N:1 | `list_id` foreign key |

---

## 3. Visual Key

This table is the authoritative mapping the workbench renderer and any Jinja
template should consult.  All colour values are CSS custom property *names*
defined in `base.html`.

| Entity | CSS Var | Chip Class | Node Shape | Icon Theme |
|---|---|---|---|---|
| Asset | `--accent-cyan` | `chip-cyan` | circle | monitor |
| Conversation | `--accent` | `chip-accent` | diamond | arrow |
| Finding | `--sev-high`* | `chip-high`* | triangle | warning triangle |
| Anomaly | `--sev-medium` | `chip-medium` | diamond | circle-exclamation |
| C2 Indicator | `--sev-critical` | `chip-critical` | hex | circular-arrow |
| Malware Finding | `--sev-critical`* | `chip-critical`* | hex | burst/star |
| IOC List | `--accent-amber` | `chip-muted` | square | document |
| IOC Entry | `--accent-amber` | `chip-muted` | circle | crosshair |
| Project | `--accent-green` | `chip-success` | square | folder |
| Report | `--text-dim` | `chip-muted` | square | document |
| Capture Session | `--accent-rose` | `chip-muted` | circle | clock |
| Protocol | `--accent` | `chip-info` | circle | link |

\* Override with `taxonomy.severity_chip_class(severity)` when rendering
individual Finding and Malware Finding items — the chip should reflect actual
severity, not the entity-type default.

### Severity → Chip override table

| Engine token | Malware token | Chip class |
|---|---|---|
| `CRITICAL` | `critical` | `chip-critical` |
| `HIGH` | `high` | `chip-high` |
| `MEDIUM` | `medium` | `chip-medium` |
| `LOW` | `low` | `chip-low` |
| `INFO` | — | `chip-info` |

---

## 4. i18n Key Namespace

Every entity type gets exactly two i18n keys:

```
taxonomy.<entity_type_value>.label          — singular
taxonomy.<entity_type_value>.label_plural   — plural
```

Examples:
- `taxonomy.asset.label` → "Asset"
- `taxonomy.asset.label_plural` → "Assets"
- `taxonomy.c2_indicator.label` → "C2 Indicator"
- `taxonomy.malware_finding.label_plural` → "Malware Findings"

These keys are present in both `en.json` and `fr.json`.  French translations
for `taxonomy.malware_finding.*` are approximate (`Détection de maliciel`) —
verify with a native speaker before a French-language release.

**Adding a new entity type:** Add it to `EntityType` in `taxonomy.py`, add a
corresponding `EntityVisual` entry to `ENTITY_VISUALS`, add both i18n keys to
`en.json` and `fr.json`, then update the count assertion in
`tests/test_taxonomy.py`.

---

## 5. Worked Examples

These examples show how a concrete surface honors the taxonomy.

### 5.1 Finding chip in a table row

A risk finding with severity `HIGH` and category `UNENCRYPTED_PROTOCOL`:

```html
<span class="chip chip-high">
  <!-- icon SVG from taxonomy.ENTITY_VISUALS[EntityType.FINDING].icon -->
  HIGH
</span>
<span>UNENCRYPTED_PROTOCOL</span>
```

Server-side Jinja:
```jinja2
{% set chip_class = finding.severity | severity_chip_class %}
<span class="chip {{ chip_class }}">{{ finding.severity }}</span>
```

Python call:
```python
from marlinspike.taxonomy import severity_chip_class
chip_class = severity_chip_class(finding["severity"])  # "chip-high"
```

### 5.2 Asset row in the asset inventory table

An asset with `device_type = "Switch/Gateway"` and `criticality = "high"` from
its `AssetTag`:

```html
<span class="chip chip-cyan">
  <!-- taxonomy.ENTITY_VISUALS[EntityType.ASSET].icon -->
</span>
<span class="mono">192.168.88.61</span>
<span class="dim">MOXA TECHNOLOGIES</span>
<span class="chip chip-high">HIGH</span>  <!-- criticality from AssetTag -->
```

The entity chip uses `chip-cyan`; the criticality override uses
`severity_chip_class("high")` → `chip-high`.

### 5.3 Topology graph node (workbench)

When the workbench renderer creates a node for an Asset:

```js
const spec = window.MS_TAXONOMY.entity_types["asset"];
// spec.node_shape  → "circle"
// spec.color_var   → "--accent-cyan"
// spec.chip_class  → "chip-cyan"
// spec.icon        → "<svg ...>"
node.style.fill = getComputedStyle(document.body).getPropertyValue(spec.color_var);
```

The taxonomy JSON is fetched once from `/api/taxonomy` (to be implemented by
the workbench agent) and cached in `window.MS_TAXONOMY`.

### 5.4 C2 Indicator chip in the IOC/threat panel

```html
<span class="chip chip-critical">
  <!-- taxonomy icon for c2_indicator -->
  C2
</span>
<span class="mono">192.168.89.2 → 8.8.8.8:53</span>
<span class="dim">every ~10s</span>
```

No severity override needed — C2 Indicator is always critical by definition.

---

## 6. Code Paths

| Concern | Location |
|---|---|
| Entity / relationship enums | `marlinspike/taxonomy.py` |
| Visual mapping | `marlinspike/taxonomy.py` · `ENTITY_VISUALS` |
| i18n keys | `marlinspike/translations/en.json`, `marlinspike/translations/fr.json` |
| i18n loader | `marlinspike/i18n.py` |
| Asset identity / aggregation | `marlinspike/aggregate.py` |
| DB models | `marlinspike/models.py` |
| Design tokens (CSS vars) | `marlinspike/templates/base.html` · `:root {}` |
| Unit tests | `tests/test_taxonomy.py` |

---

## 7. What's Deferred

These decisions are left open for downstream agents:

- **`/api/taxonomy` endpoint** — the workbench agent should add a Flask route
  that calls `taxonomy.taxonomy_export_json()` and returns it with the correct
  `Content-Type: application/json` header.  This enables the JS renderer to
  bootstrap from a single fetch.

- **Graph edge visual treatment** — edge colours and stroke styles for the
  topology graph are not specified here.  The workbench agent should derive
  them from the relationship type (e.g. `communicates_with` → `--border`;
  `flagged_by_c2` → `--sev-critical`).

- **Purdue level as a visual dimension** — Asset nodes carry `purdue_level`
  (0–5).  The workbench may choose to encode level as vertical position, ring
  colour, or label prefix.  This is rendering policy, not taxonomy.

- **`SavedFilter` taxonomy placement** — `SavedFilter` is a user-authored BPF
  expression.  It has no analyst-graph presence and is not included here.
  If a future feature surfaces saved filters in the graph (e.g. as a lens),
  it should be added then.
