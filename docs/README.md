# MarlinSpike Documentation

This directory holds the project's reference and operator
documentation. It is organized by intent — pick the section that
matches what you're trying to do.

## Operator docs (analyst-facing)

These cover *how to use* MarlinSpike during an engagement.

- **[getting-started.md](getting-started.md)** — *NEW USER START
  HERE.* A 30-minute follow-along tutorial taking you from
  install through your first triage, asset tag, finding note,
  IOC scan, and baseline bookmark.
- **[triage-methodology.md](triage-methodology.md)** — the analyst
  loop. Read first if you're new. The eight-step flow that ties
  every workbench surface together.
- **[workbench-guide.md](workbench-guide.md)** — every surface of the
  report viewer (v3.5 map-first reshape: lens chip strip, dockable
  inspector, slide-up drawer with seven tabbed tables, **HP-HMI
  mode** for ISA-101 control-room rendering). Reference doc you come
  back to.
- **[taxonomy.md](taxonomy.md)** — the formal entity / relationship
  vocabulary the platform uses (12 entities, 12 relationships) and
  the visual key that propagates through every chip, badge, table
  column, and graph node. Read if you're extending the platform or
  trying to understand why a particular UI surface looks the way it
  does.
- **[projects-and-engagements.md](projects-and-engagements.md)** —
  project model, Project Overview tab, multi-capture engagement
  workflow, per-user upload limits.
- **[asset-context.md](asset-context.md)** — asset tagging and
  finding notes. The contextual-severity overlay rule. How to
  capture site-specific knowledge as structured data.
- **[asset-baselines.md](asset-baselines.md)** — per-asset
  longitudinal page. Novelty-vs-baseline. The most under-used
  surface for long-running engagements.
- **[time-scrubbing-and-extract.md](time-scrubbing-and-extract.md)**
  — time-window selection and sub-PCAP carve-out for Wireshark.
- **[ioc-threat-hunting.md](ioc-threat-hunting.md)** — `/iocs` page.
  Bulk-paste indicator import, cross-report scan.
- **[live-capture.md](live-capture.md)** — the optional capd
  sidecar daemon. SPAN/tap capture with ring-buffer rotation.
  Linux only.
- **[mitre-attack-guide.md](mitre-attack-guide.md)** — how
  MarlinSpike presents MITRE ATT&CK in the workbench.
- **[i18n-and-locale.md](i18n-and-locale.md)** — bilingual UI
  (EN/FR), locale picker, what flips and what doesn't.

## Admin docs

For the person operating the MarlinSpike instance.

- **[admin-and-audit.md](admin-and-audit.md)** — `/users`,
  `/audit`, `/system`, password reset flow, session invalidation,
  admin-override on capture sessions.
- **[run-store-and-recovery.md](run-store-and-recovery.md)** — what
  happens to in-flight scans when Flask restarts (v3.4.0+); the
  startup reaper, PID-reuse defense, and the
  `MARLINSPIKE_RUN_STORE` cross-worker concurrency knob.
- **[../INSTALL.md](../INSTALL.md)** — deployment, env vars, three
  live-capture deployment modes, verification.
- **[../UPGRADING.md](../UPGRADING.md)** — version-to-version
  migration notes.

## Developer / integrator docs

For people writing plugins, building on the API, or running the
engine headlessly.

- **[cli-and-headless.md](cli-and-headless.md)** — running the
  engine without the web app, scan profiles, chunked chain,
  pipeline patterns.
- **[extensibility-contracts.md](extensibility-contracts.md)** —
  the three extension boundaries (Rust engines, Python plugins,
  YAML rule packs).
- **[bronze-consumer-contract.md](bronze-consumer-contract.md)** —
  the marlinspike-dpi → consumers Bronze event contract.
- **[msbundle-format.md](msbundle-format.md)** — proposed zipped
  bundle format for portable report artifacts.
- **[../COMPATIBILITY.md](../COMPATIBILITY.md)** — compatibility
  model, contract boundaries, platform matrix.

## Project / architecture docs

Forward-looking and structural.

- **[repo-family.md](repo-family.md)** — the suite + component
  repos model.
- **[repo-family-migration-spec.md](repo-family-migration-spec.md)**
  — internal migration spec for the split.
- **[analyst-workspace-roadmap.md](analyst-workspace-roadmap.md)**
  — product direction.
- **[defender-features-roadmap.md](defender-features-roadmap.md)**
  — defender-feature roadmap.
- **[kusanagi-competitive-gap.md](kusanagi-competitive-gap.md)** —
  competitive analysis.

## Research / corpus

- **[public-fingerprint-corpus.md](public-fingerprint-corpus.md)**
  — public ICS PCAP archive working set used for fingerprint
  validation.

---

## Other primary docs

These live at the repository root, not in `docs/`:

- **[../README.md](../README.md)** — project README.
- **[../INSTALL.md](../INSTALL.md)** — installation + deployment.
- **[../UPGRADING.md](../UPGRADING.md)** — version migration notes.
- **[../COMPATIBILITY.md](../COMPATIBILITY.md)** — compatibility
  model.
- **[../CONTRIBUTING.md](../CONTRIBUTING.md)** — contribution
  workflow.
- **[../releases.md](../releases.md)** — release history.

---

## Where to start

| if you are | start here |
|---|---|
| Brand new to MarlinSpike | [getting-started.md](getting-started.md) — 30-minute install-to-first-triage walkthrough. |
| New analyst about to triage your first capture | [triage-methodology.md](triage-methodology.md), then [workbench-guide.md](workbench-guide.md) when you need pane-level reference. |
| Setting up MarlinSpike for the first time | [../INSTALL.md](../INSTALL.md), then [admin-and-audit.md](admin-and-audit.md) for user setup. |
| Adding live capture to an existing deployment | [live-capture.md](live-capture.md) and the live-capture section of [../INSTALL.md](../INSTALL.md). |
| Writing a Python plugin | [extensibility-contracts.md](extensibility-contracts.md). |
| Running the engine headlessly in a pipeline | [cli-and-headless.md](cli-and-headless.md). |
| Doing a long-running engagement with many captures | [projects-and-engagements.md](projects-and-engagements.md), [asset-context.md](asset-context.md), [asset-baselines.md](asset-baselines.md). |
| Hunting a specific threat actor | [ioc-threat-hunting.md](ioc-threat-hunting.md). |
| Trying to understand the architecture | [../COMPATIBILITY.md](../COMPATIBILITY.md) → [repo-family.md](repo-family.md) → [extensibility-contracts.md](extensibility-contracts.md). |
