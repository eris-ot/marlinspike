# MarlinSpike Bundle Format (`msbundle`)

This document defines the first-pass bundle format for MarlinSpike report
artifacts.

The goal is to move MarlinSpike from a single monolithic `report.json` file to
a portable zipped bundle that contains typed artifacts for each major stage of
analysis.

## Summary

Recommendation:

- use a zip container as the transport format
- keep a manifest as the primary contract entrypoint
- split stage outputs into independently typed JSON blocks
- allow OCSF blocks to coexist with MarlinSpike-native derived blocks
- preserve the current viewer and plugin workflow by supporting a monolith
  compatibility block during migration

Suggested file extension:

- `.msbundle.zip`

Optional future alias:

- `.msbundle`

## Why This Change

Today MarlinSpike writes a single structured report object.

Evidence in the current codebase:

- [engine.py](msengine/msengine/engine.py#L1498)
  defines `MarlinSpikeReport` with stage-oriented sections such as
  `capture_info`, `conversations`, `topology`, `nodes`, `edges`,
  `risk_findings`, and `c2_indicators`.
- [engine.py](msengine/msengine/engine.py#L4600)
  fills those sections progressively across ingestion, dissection, topology, and
  risk stages.
- [app.py](app.py#L461)
  loads the monolith report and then merges plugin sidecars through
  `extensions`.

That monolith has worked well for early product velocity, but it is starting to
carry too many layers at once:

- raw capture metadata
- dissection outputs
- topology and inventory
- detection findings
- summaries
- optional enrichments

A bundle gives MarlinSpike a cleaner long-term contract without losing the
single-file handoff experience.

## Goals

- Keep report handoff to a single portable file.
- Split the internals into typed, independently versioned blocks.
- Make room for OCSF-native layers below the MarlinSpike viewer contract.
- Keep the viewer and plugin ecosystem workable during migration.
- Allow optional enrichments such as MITRE to live in the same bundle.
- Support partial bundles for interrupted or stage-limited runs.

## Non-Goals

- Replace MarlinSpike's analyst-focused report UX with raw OCSF.
- Require every consumer to understand every block type on day one.
- Force a single canonical JSON file forever.
- Turn the zip container itself into the schema.

## Container Format

An `msbundle` is a zip archive.

Rules:

- UTF-8 JSON files only for v1 typed blocks
- no nested zip archives
- all paths use forward slashes
- one required root manifest: `manifest.json`
- optional checksum file: `checksums.json`

Suggested top-level layout:

```text
manifest.json
checksums.json
capture/capture_info.json
dissection/conversations.json
dissection/protocol_summary.json
inventory/nodes.json
inventory/mac_table.json
topology/topology.json
topology/edges.json
analysis/risk_findings.json
analysis/c2_indicators.json
analysis/port_summary.json
analysis/purdue_violations.json
analysis/malware_findings.json
ocsf/events.json
ocsf/findings.json
ocsf/assets.json
report/summary.json
report/monolith.report.json
enrichments/marlinspike-mitre.json
```

Not every block is required in every bundle.

## Manifest

`manifest.json` is the entrypoint for all consumers.

Required fields:

- `bundle_type`
  Must be `marlinspike_bundle`.
- `bundle_version`
  Bundle contract version, starting at `1`.
- `generated_at`
  UTC timestamp for bundle assembly.
- `producer`
  Producer metadata for the bundle assembler.
- `capture_id`
  Stable identifier for the analyzed capture or run.
- `blocks`
  Array describing all included blocks.

Recommended fields:

- `source`
  Original PCAP or capture source metadata.
- `completed_stages`
  Stages completed successfully.
- `interrupted`
  Whether execution stopped early.
- `compatibility`
  Notes about included backward-compatibility blocks.

Example:

```json
{
  "bundle_type": "marlinspike_bundle",
  "bundle_version": 1,
  "generated_at": "2026-03-27T12:00:00Z",
  "capture_id": "demo-report",
  "producer": {
    "name": "marlinspike",
    "version": "1.5.0"
  },
  "completed_stages": [
    "capture",
    "dissection",
    "topology",
    "risk"
  ],
  "interrupted": false,
  "blocks": [
    {
      "id": "capture_info",
      "path": "capture/capture_info.json",
      "type": "marlinspike.capture_info",
      "version": 1,
      "required": true
    },
    {
      "id": "risk_findings",
      "path": "analysis/risk_findings.json",
      "type": "marlinspike.risk_findings",
      "version": 1,
      "required": false
    },
    {
      "id": "ocsf_findings",
      "path": "ocsf/findings.json",
      "type": "ocsf.findings",
      "version": "1.0",
      "required": false
    }
  ],
  "compatibility": {
    "monolith_report_path": "report/monolith.report.json"
  }
}
```

## Block Descriptor Contract

Each `blocks[]` entry should include:

- `id`
  Stable logical block ID inside the bundle.
- `path`
  Relative path inside the zip.
- `type`
  Namespaced block type.
- `version`
  Schema version for that block.
- `required`
  Whether the bundle should be considered invalid if the block is missing.

Recommended optional fields:

- `content_type`
  Example: `application/json`
- `generated_by`
  Module metadata for the producing stage
- `depends_on`
  Logical block IDs this block was derived from
- `record_count`
  Helpful for quick validation
- `sha256`
  Optional inline integrity metadata

## Block Taxonomy

### 1. Capture Blocks

Purpose:

- source capture metadata
- ingest bookkeeping

Initial blocks:

- `capture/capture_info.json`
  Type: `marlinspike.capture_info`

Likely contents:

- PCAP path or source label
- packet count
- duration
- unique MAC/IP counts
- protocols seen

### 2. Dissection Blocks

Purpose:

- protocol and flow level output

Initial blocks:

- `dissection/conversations.json`
  Type: `marlinspike.conversations`
- `dissection/protocol_summary.json`
  Type: `marlinspike.protocol_summary`

These represent the closest current equivalent to Stage 2 outputs from
[engine.py](msengine/msengine/engine.py#L4628).

### 3. Inventory and Topology Blocks

Purpose:

- graph and asset context

Initial blocks:

- `inventory/nodes.json`
  Type: `marlinspike.nodes`
- `inventory/mac_table.json`
  Type: `marlinspike.mac_table`
- `topology/topology.json`
  Type: `marlinspike.topology`
- `topology/edges.json`
  Type: `marlinspike.edges`

### 4. Analysis Blocks

Purpose:

- risk detections and derived analyst signals

Initial blocks:

- `analysis/risk_findings.json`
  Type: `marlinspike.risk_findings`
- `analysis/c2_indicators.json`
  Type: `marlinspike.c2_indicators`
- `analysis/port_summary.json`
  Type: `marlinspike.port_summary`
- `analysis/purdue_violations.json`
  Type: `marlinspike.purdue_violations`
- `analysis/malware_findings.json` (planned)
  Type: `marlinspike.malware_findings`
  Planned block for Stage 4b IOC match results produced by the `marlinspike-malware` engine.

These correspond to the current Stage 4 surfaces in
[engine.py](msengine/msengine/engine.py#L4684).

### 5. OCSF Blocks

Purpose:

- standard inter-module and external interchange

Initial blocks:

- `ocsf/events.json`
  Type: `ocsf.events`
- `ocsf/findings.json`
  Type: `ocsf.findings`
- `ocsf/assets.json`
  Type: `ocsf.assets`

These blocks should be treated as foundational machine-to-machine artifacts.

The recommendation is:

- MarlinSpike-native blocks remain valid and useful
- OCSF blocks become the preferred shared substrate for future swappable modules

### 6. Report Blocks

Purpose:

- analyst-focused derived views
- viewer compatibility

Initial blocks:

- `report/summary.json`
  Type: `marlinspike.report_summary`
- `report/monolith.report.json`
  Type: `marlinspike.report_compat`

`report/monolith.report.json` exists only for migration and compatibility.

### 7. Enrichment Blocks

Purpose:

- plugin or sidecar style outputs that derive from other bundle blocks

Initial blocks:

- `enrichments/marlinspike-mitre.json`
  Type: `marlinspike.enrichment.mitre`

Future examples:

- IEC 62443 overlays
- PERA overlays
- baselining or diff metadata

## OCSF Positioning Inside The Bundle

OCSF should sit below the final MarlinSpike report layer, not replace it.

Recommended layering:

1. capture and dissection
2. MarlinSpike analysis
3. OCSF-normalized events and findings
4. OT-specific overlay and topology reasoning
5. report assembly and viewer consumption

This keeps the product UX intact while making lower layers more reusable.

## Compatibility Model

The viewer and plugin ecosystem cannot flip all at once.

For bundle version `1`, the bundle should support both:

- typed block consumption
- monolith compatibility consumption

That means:

- `report/monolith.report.json` should be included during migration
- viewer loaders may continue to read the monolith block first
- plugins may continue to read the monolith block first
- newer consumers can switch to direct block loading when ready

This avoids a big-bang rewrite.

## Partial and Interrupted Bundles

The current engine already tracks `completed_stages` and `interrupted` in the
monolith model.

The bundle should preserve that capability.

Rules:

- incomplete bundles are valid if `manifest.json` is present
- missing later-stage blocks are allowed when `interrupted` is `true`
- consumers must inspect `completed_stages` before assuming downstream blocks
  exist

Example:

- ingest-only run may include only capture blocks and a minimal report summary
- dissect-only run may add dissection blocks without findings

## Integrity and Validation

Optional but recommended in v1:

- `checksums.json` with SHA-256 per block path
- manifest-level `record_count` for major blocks
- block version validation before load

Consumers should fail gracefully when:

- manifest is missing
- a required block listed in the manifest is absent
- block JSON is malformed
- block type/version is unknown

## Writer Strategy

Bundle assembly should happen as a final packaging step, not by forcing every
stage to write directly into a zip stream first.

Recommended write flow:

1. run stages as usual
2. write typed JSON block files into a temporary directory
3. build `manifest.json`
4. optionally build `checksums.json`
5. zip the directory into `.msbundle.zip`

Benefits:

- easier debugging
- simpler stage retries
- easier partial bundle handling
- simpler future streaming or remote packaging workflows

## Reader Strategy

Consumers should load only what they need.

Examples:

- viewer summary page
  - manifest
  - report summary
  - monolith compatibility block during migration
- ATT&CK plugin
  - initially: monolith compatibility block
  - later: analysis + OCSF + inventory blocks directly
- asset inventory page
  - inventory blocks
  - topology blocks

This will make consumers faster and cleaner than reading one giant JSON object
every time.

## Migration Plan

### Phase 1: Bundle Wrapper Around Current Monolith

- keep generating the current `report.json`
- package it as `report/monolith.report.json`
- add a manifest and typed top-level summary block

Outcome:

- immediate single-file bundle transport
- minimal consumer churn

### Phase 2: Emit Typed MarlinSpike Blocks

- split the monolith into typed block files during bundle assembly
- keep the monolith compatibility block

Outcome:

- new consumers can read blocks directly
- old consumers still work

### Phase 3: Emit OCSF Blocks

- add `ocsf/events.json`, `ocsf/findings.json`, and `ocsf/assets.json`
- keep MarlinSpike-native blocks for topology and OT-specific reasoning

Outcome:

- standardized lower layer
- improved module portability

### Phase 4: Move Plugins and Viewer Loaders to Block-Native Reads

- update `marlinspike-mitre` and future enrichers to prefer typed blocks
- update the viewer to load bundle blocks instead of assuming a monolith

Outcome:

- monolith compatibility block becomes optional

### Phase 5: Deprecate the Monolith Block

- remove `report/monolith.report.json` only after all major consumers have moved

Outcome:

- fully modular bundle contract

## Naming Recommendations

Recommended public term:

- `MarlinSpike bundle`

Recommended technical short name:

- `msbundle`

Recommended extension:

- `.msbundle.zip`

Potential future convenience extension:

- `.msbundle`

## Open Questions

- Should the bundle support embedded raw packet-derived samples later, or remain
  JSON-only?
- Should block-level compression strategy ever vary, or should the zip archive
  remain the only compression boundary?
- Should `report/summary.json` be sufficient for quick listing pages, or do we
  need a dedicated `index.json` optimized for UI listings?
- Should the bundle manifest include explicit producer module lineage for each
  block from day one?
- When should `marlinspike-mitre` start preferring typed blocks over
  `report/monolith.report.json`?

## Recommendation

Move MarlinSpike to a zipped typed bundle now, but do it in a compatibility-safe
way:

- zip container as the handoff artifact
- manifest as the real contract
- typed block files inside
- OCSF blocks below the report layer
- monolith compatibility block during migration

That gives MarlinSpike a much stronger long-term architecture without slowing
down the viewer work already in progress.
