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

## Validation

Use [`scripts/validate_bronze_passthrough.py`](/Users/butterbones/riverflow/marlinspike/scripts/validate_bronze_passthrough.py) with representative captures:

```bash
python3 scripts/validate_bronze_passthrough.py \
  --dpi-binary /Users/butterbones/marlinspike-dpi/target/release/marlinspike-dpi \
  /path/to/MQTT.pcap \
  /path/to/RADIUS.pcap \
  /path/to/Syslog.pcap
```

The validation should show:

- the DPI event counts and first-transaction enrichment
- the MarlinSpike report-level passthrough keys
- whether `src_asset` / `dst_asset` enrichment survived

If Bronze shows the enrichment and MarlinSpike does not, fix the consumer before shipping the DPI bump.
