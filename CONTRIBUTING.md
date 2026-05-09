# Contributing

Thanks for contributing to MarlinSpike.

## Before You Start

- Open issues or small discussion threads are welcome for bug reports, parser gaps, UI problems, and deployment improvements.
- Keep changes focused. Small PRs are much easier to review than broad refactors.
- Avoid committing private captures, secrets, ad hoc local screenshots, or local tool metadata. Repository documentation assets under `docs/screenshots/` are the exception.

## Development Notes

- Canonical source files are `_ms_engine.py`, `_auth.py`, `_models.py`, `_config.py`, and `app.py`.
- `auth.py`, `models.py`, and `config.py` are compatibility shims only.
- The app is designed to run behind Docker Compose with PostgreSQL.
- Terminology in this repo is intentional:
  - Rust engines handle packet-facing and event-heavy work such as DPI.
  - Python plugins handle report-facing analysis, enrichment, and triage logic.
  - YAML rule packs handle declarative mappings, suppressions, and local policy.
- The current contract definitions for those surfaces live in `docs/extensibility-contracts.md`.
- The project is not aiming to rewrite the full analyst workbench in Rust. That is a deliberate product choice, not an unfinished migration.
- Rust is preferred where parser safety, throughput, and reusable low-level engines matter most. Python is retained for the primary app because it is easier for the wider OT/ICS community to extend, review, and adapt during active remediation work.

### Malware Rule Packs

IOC detection rules live in the `marlinspike-malware` engine repo (`rules/`) for development and in `marlinspike-malware-rules` for published content.

To update rules:

1. Edit YAML packs in `marlinspike-malware/rules/` or `marlinspike-malware-rules/packs/manual/`
2. Validate: `cargo run --manifest-path ~/marlinspike-malware/Cargo.toml -- validate --rules-dir <dir>`
3. Test with representative events: `cargo run -- scan --rules-dir <dir> --events test-events.json --output findings.json`
4. Ensure rule IDs are globally unique across all packs (validation catches duplicates)

Rule ID convention: `{category}-{family}-{description}` (e.g. `c2-cobaltstrike-default-beacon-uri`)

The malware engine binary and rules directory are auto-discovered at runtime. See `_ms_engine.py` functions `_find_malware_binary()` and `_find_malware_rules_dir()` for discovery paths.

## Repo Family Transition

MarlinSpike is moving from a single mixed repository toward a suite repo plus focused component repos:

- `marlinspike`: suite repo and integration home
- `marlinspike-msengine`: core engine repo, internal package and CLI name `msengine`
- `marlinspike-workbench`: web UI repo
- `marlinspike-plugins`: Python plugin monorepo
- `marlinspike-engines`: Rust engine workspace

The component repos are intended to be authoritative. The suite repo vendors them using `git subtree`, not git submodules.

Until the extraction is complete, this repository still contains both engine and workbench code. That means contributions in the current repo should still follow the existing file layout, while also respecting the future ownership boundary:

- packet-facing capture parsing, Bronze-style observables, and engine CLI changes belong to the `msengine` boundary
- Flask routes, templates, auth, projects, and report review UX belong to the `workbench` boundary
- report-consuming ATT&CK, IEC 62443, PERA, or other overlay logic should target the future `plugins` boundary
- packet or event-heavy Rust parsers should target the future `engines` boundary

See `docs/repo-family.md`, `COMPATIBILITY.md`, and `docs/extensibility-contracts.md` for the planned contract and split.

## Suite Workflow

The suite repo keeps vendored component copies in subtree prefixes. Use the helper script to inspect or sync them:

```bash
./scripts/update-subtrees.sh status
```

When you change the engine during the bootstrap phase, mirror it into the subtree copy with:

```bash
./scripts/sync-msengine-bootstrap.sh
```

When you change the shared MITRE plugin in its standalone sibling repo, refresh the vendored suite copy with:

```bash
./scripts/sync-mitre-bootstrap.sh
```

Planned subtree prefixes are:

- `msengine/`
- `workbench/`
- `plugins/`
- `engines/`

Today, `msengine/` is the first bootstrap prefix that actually exists in the suite. It contains a mirrored engine package plus packaging metadata for the future standalone repo.
The MITRE plugin follows a sister-repo bootstrap pattern from `marlinspike-mitre` into `plugins/marlinspike_mitre/` and `rules/mitre/`.

## Local Checks

Run the basic syntax check before opening a PR:

```bash
python3 -m py_compile app.py _auth.py _config.py _models.py _ms_engine.py
```

If you touched the bootstrap engine subtree, also verify the mirrored package entrypoint:

```bash
PYTHONPATH=msengine python3 -m msengine --help
```

If you make Docker-related changes, also validate the stack locally:

```bash
docker compose up --build
```

## Security and Data Handling

- Do not commit secrets, `.env` files, infrastructure-specific credentials, or internal deployment notes.
- Do not commit customer captures or bundled third-party PCAP corpora unless redistribution terms are explicitly documented.
- If you find a security issue, please report it privately before opening a public issue.
