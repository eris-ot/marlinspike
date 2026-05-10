# Bronze Consumer Contract

`marlinspike-dpi` is the authoritative packet engine. MarlinSpike and Fathom should consume its Bronze output the same way: preserve the generic Bronze surface by default, then selectively promote a subset of fields into topology, risk, and UI behavior.

## Contract

- `marlinspike-dpi` owns packet parsing, normalization, and Bronze event emission.
- Bronze `protocol_transaction.attributes` and `protocol_transaction.object_refs` are consumer-facing data, not internal-only hints.
- Bronze `asset_observation` records are consumer-facing asset hints and should survive in compact form.
- MarlinSpike should not require a hand-written protocol branch before new Bronze enrichments become visible in reports.

## Consumer Rules

- Always preserve generic protocol passthrough on each conversation:
  - `operations_seen`
  - `protocol_attributes`
  - `protocol_object_refs`
- Preserve compact Bronze asset hints on each conversation:
  - `src_asset`
  - `dst_asset`
- Keep typed promotion logic for higher-order behavior:
  - Purdue inference
  - vendor/device role inference
  - risk scoring
  - responder prioritization

Typed promotion is optional for new protocols. Generic preservation is not.

## marlinspike-malware as Bronze Consumer

`marlinspike-malware` is a second Bronze consumer alongside the core MarlinSpike engine. It operates in Stage 4b and evaluates Bronze-derived observables against IOC detection rules.

### Observable Extraction

The orchestrator (`_ms_engine.py`) converts MarlinSpike conversations into `ObservedEvent` JSON for the malware engine. Fields extracted:

| Bronze Source | Observable Field | Example |
|---------------|-----------------|---------|
| `dns_queries` | `dns_query` | `evil.example.com` |
| Protocol name | `protocol` | `modbus`, `s7comm` |
| Five-tuple | `src_ip`, `dst_ip` | `10.0.0.10` |
| L2 addresses | `src_mac`, `dst_mac` | `aa:bb:cc:dd:ee:ff` |
| `protocol_attributes` | `any_text` | Passthrough OT protocol fields |
| `operations_seen` | `any_text` | Protocol operation strings |

### Preservation Rule

New Bronze observable fields emitted by `marlinspike-dpi` should be extractable without changes to the malware engine's observable conversion. The current extraction maps `protocol_attributes` values and `operations_seen` entries to the generic `any_text` field, which means new DPI enrichments automatically become matchable by IOC rules.

## Division Of Responsibility

- `marlinspike-dpi` changes when packet decoding, protocol coverage, Bronze schema, or parser correctness changes.
- MarlinSpike changes when we want new Bronze fields to influence topology, risk, ranking, or responder UX.
- `marlinspike-malware` changes when IOC rule content, matching logic, or the finding output schema changes. It does not change when Bronze schema changes (unless new observable field types are needed).
- Fathom follows the same Bronze preservation rules, even if it adds richer product-specific views on top.

## Compatibility Practice

- Pin `marlinspike-dpi` by commit or release tag in MarlinSpike builds.
- Validate representative PCAPs before bumping the pin.
- Treat a missing passthrough as a consumer bug.
- Treat parser panics or malformed Bronze output as a DPI bug.

## parse_anomaly — bilgepump L2 Consumer

`marlinspike-dpi` also emits `parse_anomaly` events from its `bilgepump` subsystem for stateful L2 anomaly tracking (e.g. ARP conflicts, MAC flaps, gratuitous ARP floods). These are now consumed by `_ms_engine.py` and surfaced on the report.

### Consumer Rule

- `parse_anomaly` events with `subsystem == "bilgepump"`, or whose subsystem/anomaly_type indicates L2 origin (`l2`, `arp`, `mac`, `ethernet`), are normalized into `l2_anomalies` on the report.
- Events from other subsystems (`stovetop`, `icmpeeker`, etc.) are not consumed here.

### Report Field

`l2_anomalies: list` — sorted by timestamp, empty list when no L2 anomalies were observed or when the Python/tshark dissection path is used.

Record shape:

```json
{
  "timestamp": "...",
  "anomaly_type": "...",
  "src_mac": "...",
  "dst_mac": "...",
  "src_ip":  "...",
  "dst_ip":  "...",
  "details": { "...original event attributes..." }
}
```

## Compat surface as of marlinspike-dpi v1.5.0

This section enumerates what's currently consumed vs. dropped on the
MarlinSpike Python side. Audit it whenever bumping the DPI pin.

### Event families MarlinSpike consumes

| Family | Consumer site (`marlinspike/engine.py`) | Behavior |
|---|---|---|
| `protocol_transaction` | `_apply_protocol_transaction()` (line ~650) | Aggregated into conversation rows. Generic passthrough preserved. |
| `asset_observation` | `_register_asset_observation()` (line ~493) | Asset hints normalized into `src_asset` / `dst_asset` on each conversation. |
| `topology_observation` | `_apply_topology_observation()` (line ~547) | Folded into the topology graph. |
| `parse_anomaly` | bilgepump L2 consumer (line ~906) | `subsystem == "bilgepump"` → `l2_anomalies[]` on the report. Other subsystems dropped. |
| `extracted_artifact` | `_collect_extracted_artifacts()` (line ~4757) | Forwarded to Stage 4b malware-IOC scanning. |

### Event families MarlinSpike currently drops (silently)

| Family | First emitted in | Status |
|---|---|---|
| `process_reading` | marlinspike-dpi v1.1.0 | **Dropped.** Sparkplug B / OPC UA ReadResponse / PCCC / Synchrophasor process-variable readings hit the `family_name != "protocol_transaction"` skip and are silently discarded. Worth consuming in v3.6+ — these are exactly the kind of OT operational data a defender would want surfaced. |

The dispatch is **non-exhaustive** (sequence of `if family_name == X: ... continue` checks with a final default-skip). Adding a new family in DPI does **not** crash the consumer. It just means data is unused until a consumer site is added.

### Protocol slugs in `envelope.protocol`

`_protocol_display_name(slug)` (engine.py line ~330) maps Rust slugs to display names. Defaults to `slug.replace("_", " ").title()` for unknown slugs — so new protocols render with a sensible auto-titled name without code change.

`RUST_PROTOCOL_DISPLAY_NAMES` covers (as of v3.5.x): arp, cdp, dhcp, dns, dnp3, ethernet_ip, http, lldp, modbus, opc_ua, profinet, s7comm, snmp, stp, tls.

Protocol slugs marlinspike-dpi v1.5.0 emits that fall through to the default mapping (and render as auto-titled): **sparkplug_b, synchrophasor, pccc, smb, kerberos, ldap, cclink, codesys, iolink, igmp, bacnet, iec104, iec61850, omron_fins, hart_ip, ethercat, mstp, lacp**. Add explicit display-name entries for any of these you want to ship with curated display names.

`RUST_PROTOCOL_SERVICE_PORTS` (engine.py line ~345) maps slug → set of stable service ports for the conversation aggregation key. Unknown slugs fall through to a heuristic (lowest non-ephemeral port). Adding entries here improves conversation-key stability for new protocols but isn't required.

### `protocol_transaction.operation` values

Aggregated into `operations_seen` (line ~659) without any switch — new operation strings just appear in the list. Specific operation switches in the Modbus / S7 / DNP3 / OPC-UA branches (line ~664+) compare against the *display name*, not the slug, so they only fire for protocols whose display name matches; other branches don't fire for unfamiliar protocols, but the conversation row still appears.

New operation values from v1.5.0 that aggregate without a per-operation branch: `smb1_message`, `smb2_message`, `kerberos_message`, `ldap_message`, `ldaps_traffic`, `cclink_ie_traffic`, `codesys_traffic`, `iolink_traffic`, `igmp_membership_query`, `igmp_v1_membership_report`, `igmp_v2_membership_report`, `igmp_leave_group`, `igmp_v3_membership_report`, `igmp_message`. They surface as `operations_seen` strings on the conversation; no per-operation logic fires.

### `protocol_transaction.protocol_fields` (typed enum, optional)

Added in marlinspike-dpi v1.3.0. Serialized with `skip_serializing_if = "Option::is_none"`, so absent in JSON unless the emitting decoder has migrated to the typed-emission surface. Currently populated only for Modbus.

The MarlinSpike consumer **does not read `protocol_fields` yet**. The legacy untyped fields (`attributes`, `object_refs`, top-level `operation`) remain the source of truth. Migrating to consume `protocol_fields` is v3.6+ work — the typed enum gives type-checked Modbus / S7 / DNP3 fields without parsing back from string `attributes`. Not blocking; the legacy field is retained.

## Validation

Use [`scripts/validate_bronze_passthrough.py`](scripts/validate_bronze_passthrough.py) with representative captures:

```bash
python3 scripts/validate_bronze_passthrough.py \
  --dpi-binary marlinspike-dpi/target/release/marlinspike-dpi \
  /path/to/MQTT.pcap \
  /path/to/RADIUS.pcap \
  /path/to/Syslog.pcap
```

The validation should show:

- the DPI event counts and first-transaction enrichment
- the MarlinSpike report-level passthrough keys
- whether `src_asset` / `dst_asset` enrichment survived

If Bronze shows the enrichment and MarlinSpike does not, fix the consumer before shipping the DPI bump.
