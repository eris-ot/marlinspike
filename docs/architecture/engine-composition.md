# Engine composition — making the headless engine the real product boundary

Status: **implemented in v3.6.0** — `marlinspike/enrich.py` + `chain --enrich`
+ app delegates (Steps 1–3 below) · Audience: marlinspike + cloudmarlin maintainers

## TL;DR

The headless engine (`engine.py chain`) produces only the **core** report
(ingest → dissect → topology → risk + inline malware). The **enrichment layer
— MITRE / ARP / APT / CISA sidecars — is orchestrated inside the Flask app**
(`app.py:_finalize_run`), not the engine. Anything that consumes the engine
without also running the Flask app (cloudmarlin's anon path,
`cloudmarlin-engine-svc`, any CI/batch use) silently produces an
**under-enriched report**.

The fix is one structural move: lift the post-`chain` plugin sequence out of
`app.py` and into the engine, so the headless contract is a *complete enriched
report*. Everything else in the `marlinspike-*` ecosystem composes cleanly once
the engine is the true boundary.

## Current topology

```
                 pcap
                  │
                  ▼
        ┌───────────────────────┐
        │ engine.py  `chain`    │   Stage 1 ingest
        │                       │   Stage 2 dissect ──► marlinspike-dpi (Rust, subprocess,
        │                       │                        Bronze v2 / OCSF, schema-versioned)
        │                       │   Stage 3 topology
        │                       │   Stage 4 risk
        │                       │   (inline) malware ──► marlinspike-malware (Rust, subprocess)
        └───────────┬───────────┘                         + marlinspike-malware-rules (data)
                    │  report.json   ◄── HEADLESS BOUNDARY ENDS HERE
                    ▼
        ┌───────────────────────┐
        │ app.py  _finalize_run │   gated on command=="chain" + *_ENABLED
        │   _run_mitre_plugin   │ ─► report-mitre.json   (plugins/marlinspike_mitre)
        │   _run_arp_plugin     │ ─► report-arp.json     (plugins/marlinspike_arp)
        │   _run_apt_plugin     │ ─► report-apt.json     (plugins/marlinspike_apt)
        │   _run_cisa_plugin    │ ─► report-cisa.json    (plugins/marlinspike_cisa)
        └───────────┬───────────┘
                    ▼
        _load_report_with_extensions()  merges sidecars → report["extensions"][...]
```

The boundary is in the wrong place: the orchestration that makes a report
*complete* lives in the GUI process.

### Evidence (current code)

- `marlinspike/app.py:1170` `_finalize_run()` — runs MITRE/ARP/APT/CISA *after*
  the engine subprocess returns, each gated on
  `run_state.get("command") == "chain"` and `config.MARLINSPIKE_*_ENABLED`.
- `marlinspike/app.py:1420-1628` `_run_{mitre,arp,apt,cisa}_plugin()` — each is
  `subprocess.run([PYTHON_EXE, "-u", "-m", MODULE, "--input-report", report,
  "--output", sidecar, "--rules", ...])`.
- `marlinspike/app.py:1629` `_load_report_with_extensions()` — merges
  `report-*.json` sidecars under `extensions[...]`.
- `marlinspike/engine.py` — **no** MITRE/CISA/APT/ARP references. `run_chain`
  (L5122) ends at risk + inline malware.

## Ecosystem roles

| Repo | Role | Coupling |
|---|---|---|
| `marlinspike` (engine.py) | Python orchestrator + Stage 1/3/4 + inline malware | The headless core (`chain`) |
| `marlinspike-dpi` (Rust) | Stage 2 DPI, pcap → Bronze v2 / OCSF | Swappable subprocess, `--dpi-engine`, `dpi_schema_version` in report |
| `marlinspike-malware` (Rust) | IOC detection | Subprocess, `MARLINSPIKE_MALWARE_BIN` |
| `marlinspike-malware-rules` | IOC rule packs | Versioned data dep of `-malware` |
| `marlinspike-mitre` | ATT&CK enrichment lib | Vendored → `plugins/marlinspike_mitre`, sidecar envelope |
| `marlinspike-cisa` | CISA KEV / ICS advisory enrichment | Vendored → `plugins/marlinspike_cisa`, sidecar envelope |
| `marlinspike-pro` | **Stale fork** (engine 5,167 lines / rel 2.0.7 vs current 5,816) | Latent drift, no live link |
| `marlinspike-probe` / `-monitor` / `-rust` (`marlinspike-firewall`) | Rust live-capture / continuous monitor / enforcement plane | Adjacent product (FATHOM), **not** the pcap-analysis path |
| `marlinspike-oldwww` / `-www-v2` | Web assets | Duplicated; likely source of the cloudmarlin landing |

## Target

```
                 pcap
                  │
                  ▼
        ┌───────────────────────────────────────────┐
        │ engine.py  `chain`  (or `chain --enrich`)  │
        │   ingest → dissect → topology → risk       │
        │   → malware                                │
        │   → enrich:  mitre / arp / apt / cisa  ◄── moved in from app.py
        │              (same subprocess+envelope)    │
        │   → merge extensions[...]                  │
        └───────────────────────┬───────────────────┘
                                │  complete report.json   ◄── HEADLESS BOUNDARY
                ┌───────────────┼───────────────┐
                ▼               ▼               ▼
        marlinspike GUI   cloudmarlin-     CI / batch
        (renders only)    engine-svc       (complete)
```

Principles:

1. **The engine is the boundary.** `chain` emits a *complete* report
   (core + `extensions[...]`). No consumer needs the Flask app to get a
   correct artifact.
2. **The plugin envelope is the integration ABI.** Every satellite =
   `report JSON in → sidecar JSON out`, env-var-discovered, runnable as
   `python -m plugins.X` (or a binary). Already ~80% true — formalize it.
3. **Rust components are schema-versioned subprocess sidecars.** Python
   orchestrator and Rust crates rev independently behind pinned schemas
   (`dpi_schema_version` already in report metadata; do the same for malware).
4. **One source of truth per satellite.** Standalone `~/marlinspike-{mitre,cisa}`
   are canonical; `plugins/` copies are generated by a sync script, never
   hand-edited. (`marlinspike-pro` is what hand-maintained divergence looks
   like.)
5. **GUI renders, it does not orchestrate.** `app.py` consumes the complete
   report; it stops shelling out to plugins.

## Migration sketch (incremental, non-breaking)

### Step 1 — add an `enrich` stage to the engine

New `marlinspike/enrich.py` (or a section of `engine.py`) containing the
plugin-runner logic moved from `app.py`:

- Port `_run_mitre_plugin` / `_run_arp_plugin` / `_run_apt_plugin` /
  `_run_cisa_plugin` verbatim (they are already pure: `report_path` in,
  sidecar path out, subprocess + envelope). Drop their only Flask coupling —
  `run_state` stage bookkeeping — and return a simple result list instead.
- Source config from `marlinspike.config` (the `MARLINSPIKE_*_ENABLED /
  _MODULE / _RULES` vars already live there, not in `app.py`).
- Add `run_enrich(args)` and wire a subcommand:
  `sub.add_parser("enrich", ...).set_defaults(func=run_enrich)` in
  `engine.py:main()` (mirrors the existing `ingest`/`dissect`/… pattern).
  Input: `--input-report`; output: in-place sidecars + merged
  `extensions[...]`.

### Step 2 — make `chain` call `enrich`

At the end of `run_chain` (`engine.py:5122`), after the malware stage and
before final write, invoke the same enrich path, gated by a `--enrich`
flag (default **on** for `chain`; `--no-enrich` to opt out for speed/fast
profile). `chain` now writes a complete report.

### Step 3 — collapse `app.py` orchestration to consumption

`_finalize_run` (`app.py:1170`) stops calling `_run_*_plugin`; it just waits
for `chain` and reads the now-complete report. `_run_*_plugin` /
`_*_sidecar_path` / `_load_report_with_extensions` either move to
`enrich.py` or become thin readers. The GUI stage list is derived from the
report's `completed_stages` instead of being driven by `_finalize_run`.

### Step 4 — cloudmarlin consumes the complete chain

`cloudmarlin-engine-svc` already does pcap → `chain` → report. After Step 2
it gets enrichment for free — no cloudmarlin change beyond confirming
`--enrich` is on. The anon/cloud path stops silently dropping MITRE/CISA.

### Step 5 — formalize the envelope + sync

- `docs/architecture/plugin-envelope.md`: the sidecar contract (CLI args,
  JSON schema, exit codes, discovery env vars).
- `scripts/sync-plugins.sh`: vendor `~/marlinspike-{mitre,cisa}` →
  `plugins/` (replaces hand-maintenance; kills the `marlinspike-pro` failure
  mode).

### Step 6 — housekeeping (separate PRs)

- Decide `marlinspike-pro`'s fate: reconcile into the engine or archive it.
  Right now it is a 5,167-line latent fork.
- Consolidate `marlinspike-oldwww` / `-www-v2` / cloudmarlin landing to one
  web-assets source.
- Keep `-probe` / `-monitor` / `-firewall` out of the cloud pcap path; they
  are the continuous/enforcement product (FATHOM), a different surface.

## Why this ordering

Steps 1–2 are additive (new stage + flag) — nothing breaks, `chain` simply
gets more complete. Step 3 only removes now-dead orchestration once 1–2 prove
out. Step 4 is a no-op verification for cloudmarlin. This also lands the
engine in the shape the planned v3.6 monolith split wants: a self-contained
pipeline with the GUI as a pure consumer.

## Risks / notes

- **Fast profile**: enrichment adds latency. `--no-enrich` (and
  auto-off under `--fast`) keeps the quick path quick.
- **Plugin timeouts**: `app.py` uses a 120 s per-plugin `subprocess` timeout;
  preserve it in `enrich.py` so a hung plugin can't wedge `chain`.
- **Idempotency**: `enrich` on an already-enriched report must be safe
  (overwrite sidecars, re-merge) so `chain --enrich` and a later standalone
  `enrich` agree.
- **Versioning**: this doc is a proposal only — no code/semver impact. The
  implementing PRs are structural and follow the usual UPGRADING.md +
  releases.md + semver-bump rule.
