# CLI & Headless Use

The MarlinSpike engine is **standalone**. The web app is a wrapper.
You can run the engine directly from the command line — useful for:

- Headless ingestion in a pipeline (cron, CI, batch processing).
- Debugging engine output without web-app overhead.
- Generating reports on a host that *doesn't* run the workbench
  and shipping the JSON elsewhere for review.
- Comparing engine output across versions.

For the web app + workbench surfaces, see
[workbench-guide.md](workbench-guide.md). For when to use live
capture vs. CLI ingestion, see
[live-capture.md](live-capture.md).

---

## Invoking

Two equivalent forms:

```bash
# As a module (preferred — works from anywhere if marlinspike is installed)
python -m marlinspike --pcap /path/to/capture.pcap chain

# After `pip install marlinspike`, also exposed as:
marlinspike --pcap /path/to/capture.pcap chain
```

The web app uses the module form — see `MARLINSPIKE_ENGINE_CMD` in
`marlinspike/config.py`.

---

## Subcommands

The engine is structured as a **chain of stages**. You can run the
whole chain or any single stage. The full chain is what the web
app runs by default.

| subcommand | what it does |
|---|---|
| `chain` | Full chain: ingest → dissect → topology → risk. Default for most use cases. |
| `ingest` | Stage 1: capture ingestion (capinfos summary). |
| `dissect` | Stage 2: protocol dissection (tshark or marlinspike-dpi). Emits a conversations artifact. |
| `topology` | Stage 3: topology construction from a pre-built conversations artifact. |
| `risk` | Stage 4: risk surface analysis from a pre-built topology artifact. |
| `chain-from-conversations` | Topology + risk, starting from a pre-built conversations artifact (bypasses ingest+dissect). The web app uses this for chunked large-PCAP processing. |
| `analyze` | Legacy alias for `dissect`. |
| `classify` | Legacy alias for `topology`. |
| `report` | Legacy alias for `risk`. |

Most analysts only ever run `chain`.

---

## Common invocations

### Full chain on a PCAP, write JSON to current directory

```bash
python -m marlinspike --pcap /tmp/capture.pcap chain
# → marlinspike-report-20260507-194213.json
```

### Full chain, fast profile, named output

```bash
python -m marlinspike \
  --pcap /tmp/capture.pcap \
  --fast \
  -o /tmp/acme-z3-q2.json \
  chain
```

### Use the Rust DPI engine explicitly

```bash
python -m marlinspike \
  --pcap /tmp/capture.pcap \
  --dpi-engine marlinspike-dpi \
  --dpi-binary /usr/local/bin/marlinspike-dpi \
  chain
```

By default `--dpi-engine auto` will pick `marlinspike-dpi` when
the binary is on PATH and fall back to Python tshark. Set
explicitly when you want to force one or the other (e.g. for
benchmarking).

### Chunked processing for huge PCAPs

```bash
python -m marlinspike \
  --pcap /tmp/big-2gb.pcap \
  --chunk-size 300000 \
  --collapse-threshold 50 \
  chain
```

`--chunk-size N` splits the PCAP into N-packet chunks, dissects
each, merges the conversations, and runs `chain-from-conversations`.
Memory stays bounded regardless of input size; total wall-clock is
~linear in packet count.

The web app applies this automatically when uploading a PCAP
larger than `PCAP_PROCESS_SIZE`. CLI users have to opt in.

### Just the dissection stage

```bash
python -m marlinspike --pcap /tmp/capture.pcap dissect
# → produces a conversations artifact
```

Useful when you want to feed the conversations to your own tooling
without the topology / risk passes.

---

## Flags

### Input flags

| flag | default | meaning |
|---|---|---|
| `--pcap PATH` | required for `ingest`/`chain` | input PCAP/PCAPNG file |
| `--conversations PATH` | required for `topology` and `chain-from-conversations` | pre-built conversations JSON |
| `--topology PATH` | required for `risk` (when not using `chain`) | pre-built topology JSON |
| `--subnet-map PATH` | none | JSON file mapping subnets to Purdue levels (overrides default heuristics) |
| `--oui-db PATH` | bundled | ICS vendor OUI database (override for local fingerprint corpus) |

### Output flags

| flag | default | meaning |
|---|---|---|
| `-o PATH` / `--output PATH` | `marlinspike-report-<ts>.json` in cwd | report output path |
| `--yaml-map PATH` | none | also export a YAML relationship map |

### Profile flags

| flag | default | meaning |
|---|---|---|
| `--fast` | off | Fast scan: skip ephemeral edges, lower collapse threshold, skip C2 heuristics |
| `--skip-ephemeral` | off | Skip ephemeral-port (>=49152) edges (subset of `--fast`) |
| `--reassembly` | off | Enable TCP reassembly (default disabled — saves ~5x memory; v1.7.0) |

### Performance flags

| flag | default | meaning |
|---|---|---|
| `--chunk-size N` | 0 (single-pass) | Process PCAP in N-packet chunks; memory bounded |
| `--collapse-threshold N` | 50 | Collapse port-scan conversations when MAC pair has >N unique destination ports (0 disables) |

### Engine selection

| flag | default | meaning |
|---|---|---|
| `--dpi-engine {auto,python,marlinspike-dpi}` | `auto` | Stage 2 DPI engine |
| `--dpi-binary PATH` | from `MARLINSPIKE_DPI_BIN` env | Path to the Rust DPI binary |

### GrassMarlin compatibility

| flag | default | meaning |
|---|---|---|
| `--grassmarlin PATH` | none | Path to a GrassMarlin binary if you want side-by-side comparison output (legacy; not recommended) |
| `--no-grassmarlin` | true (default) | Force built-in parser only |

These exist for the v1.x parity-comparison era and are kept for
back-compat. New users can ignore them.

---

## Profiles: fast vs full

`--fast` exists because some captures are big and you don't always
need everything. The differences:

| capability | full (default) | fast |
|---|---|---|
| Ephemeral edge inclusion | yes | no |
| Collapse threshold | 50 | lower (~20) |
| C2 heuristic chain (beacon detection, DNS entropy, persistent flow analysis) | yes | no |
| Stage 4b malware IOC matching | yes (when rules loaded) | no |
| Topology + risk + ATT&CK | yes | yes |

**Pick `full`** for first-pass triage, end-of-engagement
assessment, anything you'll show an auditor. The C2 heuristics
matter.

**Pick `fast`** for: live-capture rotations (the web app's
default), CI pipelines processing many captures, sanity-checks on
huge PCAPs where you'll do `full` later on a narrowed window.

---

## Environment variables

The engine respects the same env vars as the web app:

| var | meaning |
|---|---|
| `MARLINSPIKE_DPI_BIN` | Path to `marlinspike-dpi` binary; default uses PATH |
| `MARLINSPIKE_DPI_ENGINE` | `auto` / `python` / `marlinspike-dpi`; overridden by `--dpi-engine` |
| `MARLINSPIKE_MITRE_ENABLED` | `true`/`false` — load ATT&CK plugin output (default true) |
| `MARLINSPIKE_MITRE_MODULE` | Python module path for the MITRE plugin (default `plugins.marlinspike_mitre`) |
| `MARLINSPIKE_MITRE_RULES` | Rules directory path |
| `MARLINSPIKE_ARP_ENABLED` | ARP plugin (default true) |
| `MARLINSPIKE_APT_ENABLED` | APT plugin (default true) |
| `MARLINSPIKE_RULES_DIR` | Override the rules root directory |

Plugins are auto-loaded; their findings merge into the report's
`risk_findings` via the engine's plugin bridge.

---

## Output: the report JSON

A successful chain run produces a single JSON file. Key fields:

```
{
  "product": "MarlinSpike",
  "producer": "msengine",
  "producer_version": "x.y.z",
  "report_contract_version": 1,
  "timestamp": "...",

  "capture_info": {
    "source": "...",
    "pcap_path": "...",
    "link_type": "...",
    "packet_count": ...,
    "duration_s": ...,
    "unique_macs": ...,
    "unique_ips": ...,
    "start_ts": ...,
    "end_ts": ...
  },

  "summary": { ... },
  "nodes": [ ... ],
  "edges": [ ... ],
  "conversations": [ ... ],
  "protocols": [ ... ],
  "port_summary": { ... },
  "service_ports": [ ... ],
  "risk_findings": [ ... ],
  "c2_indicators": [ ... ],
  "dns_queries": [ ... ],
  "mac_table": [ ... ],
  "arp_observations": [ ... ],
  "l2_anomalies": [ ... ],
  "malware_findings": [ ... ],
  "mitre_classifications": [ ... ],
  "apt_findings": [ ... ],
  "arp_findings": [ ... ]
}
```

The report contract is versioned via `report_contract_version`.
Downstream consumers (workbench, plugins, sidecar tooling) should
honor this. See
[bronze-consumer-contract.md](bronze-consumer-contract.md) for the
DPI side and [extensibility-contracts.md](extensibility-contracts.md)
for the consumer side.

---

## Importing CLI-generated reports into the workbench

Three ways:

1. **Drop the file into a project's reports dir.** The reports
   listing endpoint walks the project directory; copy the
   JSON to `<DATA_DIR>/reports/<user_id>/<project_id>/` and it
   shows up.
2. **Upload via the web UI.** Currently the upload UI is PCAP-only;
   report-JSON upload is roadmap.
3. **Use the API.** `POST /api/projects/<pid>/reports/import` is
   roadmap; today, copy-into-dir is the path.

CLI-generated reports use the same schema as web-generated, so
once they're in the project's reports dir they triage identically.

---

## Headless pipeline pattern

A common pattern for batch ingestion:

```bash
#!/usr/bin/env bash
# Process every PCAP in a directory; write reports to a sibling.
set -euo pipefail
shopt -s nullglob

IN_DIR="$1"
OUT_DIR="${2:-${IN_DIR}/reports}"
mkdir -p "$OUT_DIR"

for pcap in "$IN_DIR"/*.pcap "$IN_DIR"/*.pcapng; do
  name=$(basename "$pcap")
  stem="${name%.*}"
  out="$OUT_DIR/$stem.json"

  if [[ -f "$out" ]]; then
    echo "skipping $stem (already processed)"
    continue
  fi

  echo "processing $stem"
  python -m marlinspike \
    --pcap "$pcap" \
    --fast \
    --chunk-size 300000 \
    -o "$out" \
    chain
done
```

For larger / parallel pipelines, run multiple instances in
separate processes. The engine has no shared state; concurrent
runs on different inputs are safe.

---

## Comparing engine versions

Useful when verifying that a new release didn't change findings
on a known-good capture:

```bash
# Run with v3.2.0
git checkout v3.2.0
python -m marlinspike --pcap fixture.pcap -o /tmp/old.json chain

# Run with HEAD
git checkout main
python -m marlinspike --pcap fixture.pcap -o /tmp/new.json chain

# Diff
diff <(jq -S . /tmp/old.json) <(jq -S . /tmp/new.json) | head -100
```

Engine version + producer_version on the report tells you which
binary produced which JSON. The web app workbench's Compare action
does the same diff in a UI.
