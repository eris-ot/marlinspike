# Compatibility Model

This document defines the compatibility model MarlinSpike is moving toward as the project splits into a suite repo plus focused component repos.

## Current State

Today, compatibility is mostly implicit because the engine and workbench still live in the same repository.

The target state is explicit compatibility between:

- `marlinspike` suite
- `marlinspike-msengine`
- `marlinspike-workbench`
- `marlinspike-plugins`
- `marlinspike-engines`

The component repos are intended to be authoritative. The suite repo vendors them and pins combinations known to work together.

## Core Rule

The MarlinSpike report artifact is the primary compatibility boundary.

- `msengine` produces the report
- `workbench` consumes the report
- plugins consume the report and emit sidecar artifacts
- suite releases pin combinations known to work together

## Planned Compatibility Fields

The target report envelope should include at least:

```json
{
  "product": "MarlinSpike",
  "producer": "msengine",
  "producer_version": "1.10.0",
  "report_contract_version": 1
}
```

The exact field names may be refined during extraction, but the compatibility model depends on:

- a stable producer identity
- a stable producer version
- a stable report contract version

## Report Artifact Fields

The report contract is extensible. New optional fields may be added in minor or major versions. Consumers must tolerate unknown fields gracefully.

| Field | Type | Added in | Required | Notes |
| --- | --- | --- | --- | --- |
| `malware_findings` | array of `MalwareFinding` objects | v2.0.0 | No | Empty array when malware engine is unavailable. Consumer impact: workbench displays findings in the existing findings view; plugins can read from the report. Backward compatibility: reports without this field remain valid; consumers should treat a missing field as an empty array. |

## Planned Compatibility Matrix

| Component | Compatibility anchor |
| --- | --- |
| `marlinspike` suite | Pins component versions and supported report contract versions |
| `marlinspike-msengine` | Declares the report contract versions it can emit |
| `marlinspike-workbench` | Declares the report contract versions it can ingest and review |
| `marlinspike-plugins` | Declares the report contract versions and sidecar contract versions each plugin supports |
| `marlinspike-engines` | Declares any upstream engine/event contract versions they emit |

## Workbench Rules

`marlinspike-workbench` must support two modes:

1. report review only
   Reports already exist and are imported or synchronized into the workbench.
2. local scan execution
   The workbench invokes `msengine` as an external binary and then reads the resulting report.

The second mode is optional. The first mode must remain fully supported.

## Plugin Rules

Plugins should depend on the finished report contract, not on:

- Flask routes
- database state
- internal workbench modules
- raw PCAP parsing as their primary interface

## Versioning Direction

Recommended versioning model:

- suite version: coordinated integration release
- msengine version: engine-specific release
- workbench version: UI-specific release
- plugin version: per-plugin release
- engine workspace version: per-engine or workspace release

Example:

- suite: `2.0.0`
- msengine: `2.0.0`
- workbench: `2.0.0`

## Optional Engine Compatibility: `marlinspike-malware`

`marlinspike-malware` is an optional Rust engine. Its absence does not break core analysis. The suite and msengine operate normally without it; the malware engine is loaded at runtime only when available.

When present, malware engine findings merge into the report through two existing collections:

- `c2_indicators` — findings appear with type `MALWARE_IOC_MATCH`
- `risk_findings` — findings appear with category `MALWARE_IOC_MATCH`

Rule pack versioning is independent of engine versioning. A newer or older rule pack does not require a matching engine release, and vice versa.

## Transitional Note

Until the split is complete, the current repository effectively acts as:

- suite
- engine
- workbench

That is temporary. This file exists to make the future compatibility rules explicit before the extraction work lands.

## Live Capture (`marlinspike-capd`)

Live capture is delivered by an optional sidecar daemon and has a tighter platform matrix than the rest of the suite.

| platform | live capture | notes |
|---|---|---|
| Linux (host) | supported | Native systemd unit or `network_mode: host` container. dumpcap + libpcap required. |
| Linux (Docker, bridge net) | not supported | Bridged containers cannot see physical NICs. |
| macOS | dev only | capd runs and BPF validation works, but Docker Desktop cannot expose physical interfaces. Useful for development of the IPC and UI; not for real captures inside a container. |
| Windows | not supported | Live capture would require Npcap and a Windows-native dumpcap path that capd does not yet wrap. |

The capd ↔ web-app contract is the **uds JSON-RPC** described in `marlinspike-capd/capd/server.py`. That protocol is the compatibility boundary between the privileged daemon and the unprivileged web app. We treat its method names and frame shapes as a stable contract; future capd releases must accept old web-app calls without warning, and the web app must tolerate new fields it doesn't recognize.

If live capture is disabled (`LIVE_CAPTURE_ENABLED=false`, the default), capd is not required and the web app degrades gracefully — the workbench shows a banner instructing the operator how to enable capture, and `/api/capture/*` endpoints return 503 with a clear reason.
