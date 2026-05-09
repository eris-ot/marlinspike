# Asset Baselines

The per-asset baseline page is **the longitudinal view**. The
workbench answers *"what's happening in this capture?"*; the
baseline page answers *"is this asset behaving differently than it
has been?"* across every capture in the project.

This is the most under-used surface in MarlinSpike for analysts who
haven't seen it. It's also the single most valuable surface on
long-running engagements where the same network is captured
repeatedly.

For where the baseline fits in the analyst loop, see step 7 of
[triage-methodology.md](triage-methodology.md). For the workbench's
per-asset sidebar (which links into the baseline page), see
[workbench-guide.md](workbench-guide.md#selected-asset).

---

## When to use it

- You've tagged an asset `critical` and want to know if the latest
  capture shows it doing something new.
- You're triaging a finding and want to know whether this finding
  has been *consistent* across captures or just appeared.
- You're onboarding to an engagement and want a per-asset
  high-trust profile of the network's most-watched assets.
- You're doing a post-engagement readout and need to show novelty
  ("here's what changed in the last week of captures") rather than
  every-finding-in-every-capture.
- You're hunting "weird" — a peer that appeared once two weeks ago,
  a protocol that briefly showed up, a vendor stamp that drifted.
  Single-capture views miss this.

---

## How to get there

Three click-paths:

1. **Workbench → Selected Asset sidebar → Baseline button.** Opens
   in a new tab.
2. **Workbench → Assets pane → row → Baseline column.** Same target.
3. **Direct URL** — `/projects/<pid>/assets/<asset_key>`. Useful for
   bookmarking the baseline of a specific critical asset.

The baseline page itself is full-screen — no nav clutter, focused on
the longitudinal data. Hit your browser back button to return to
the workbench.

---

## What renders

The baseline page is built by `compute_asset_baseline()` in
`marlinspike/baselines.py`. It walks every report in the project
(by capture timestamp, oldest → newest), filters for the asset
matching the `asset_key`, and emits a structured profile.

### Identity timeline

A row of identity attributes per report:

- IPs
- MACs
- Vendor
- Role
- Device type
- Purdue level

Each attribute has a stability indicator: a green dot if it hasn't
changed in the last N reports, a yellow dot for recent change
("vendor: was Schneider in reports 1–10, now Allen-Bradley in
reports 11–14 — possible vendor relabeling, possible asset swap").

This is the **drift detection** view. An asset whose vendor stamp
suddenly changes between captures is either an asset swap (real,
tag it), a fingerprint regression (engine bug, file an issue), or
something more interesting (someone replaced the device).

### Protocol mix history

A per-report column showing the asset's top-N protocols by packet
count. Side-by-side columns make trend visible at a glance:

- An asset that consistently shows Modbus / S7 / DNS in that order
  across 14 reports is healthy.
- An asset that adds an SMB column in report 12 is doing something
  new.
- An asset that loses a protocol it always had is also doing
  something new (poller failed? cable pulled? compromise that
  disabled monitoring?).

### Peer set

Every endpoint this asset has talked to, ever, with first-seen and
last-seen attribution per peer:

| peer | first-seen-report | last-seen-report | active in last N reports |
|---|---|---|---|
| `10.50.1.7` | report 1 | report 14 | 14/14 |
| `10.50.1.12` | report 1 | report 14 | 14/14 |
| `192.168.99.5` | report 11 | report 14 | 4/4 (NEW) |
| `10.50.1.99` | report 1 | report 8 | 0/4 (LOST) |

Two interpretation patterns:

- **NEW peers** — recently added to the peer set, not seen in
  earlier reports. Validate. New legitimate peer (vendor turned up
  a service, network reconfig)? Or unauthorized?
- **LOST peers** — were in the peer set, no longer present.
  Validate. Decommissioned peer? Or a poller that stopped polling?

### Finding history (cadence)

Every finding category that's ever touched this asset, with cadence:

| category | severity | seen in reports | cadence |
|---|---|---|---|
| `OT_NO_AUTH_OBSERVED` | HIGH | 14 of 14 | persistent |
| `CLEARTEXT_REMOTE_ACCESS` | HIGH | 13 of 14 | persistent (1 gap) |
| `EXTERNAL_C2_BEACON_LIKELY` | CRITICAL | 1 of 14 | new |
| `WEAK_TLS_OBSERVED` | MEDIUM | 8 of 14 | intermittent |

Cadence buckets:

- **persistent** — present in ≥80% of recent reports. *Known
  state.* Acknowledge, note, move on.
- **new** — present in the latest report, absent before. *Most
  interesting.* Investigate.
- **lost** — was persistent, now absent. *Investigate* — fixed?
  Or detection masked?
- **intermittent** — present in 20-80% of reports. *Probably
  capture-window artifacts* (the asset only does the thing
  during certain operations) but worth a glance.

### L2 / ARP anomaly cadence

If the asset has been flagged for L2/ARP anomalies (`mac_local`,
`arp_spoof`, `mac_flap`, `arp_gratuitous`), the cadence per
anomaly type:

| anomaly | seen in reports | severity history |
|---|---|---|
| `mac_flap` | 2 of 14 | HIGH (2x) |
| `arp_gratuitous` | 14 of 14 | LOW (14x) |

`arp_gratuitous` showing up in every report is normal for many
network stacks. `mac_flap` showing up in even one is interesting.

### Novelty-vs-baseline card

![Per-asset baseline page — identity, novelty card with NEW protocols/peers/findings, protocol mix per report, peer set, finding history with cadence, anomaly cadence](screenshots/44-asset-baseline.png)

This is the headline value of the page. The card answers:
*"compared to everything before the latest report, what's new?"*

```
Novelty in latest report (capture-2026-05-07-1830):
─────────────────────────────────────────────────
NEW protocols:
  • SMB (TCP 445)

NEW peers:
  • 192.168.99.5

NEW finding categories:
  • EXTERNAL_C2_BEACON_LIKELY (CRITICAL)
  • CLEARTEXT_REMOTE_ACCESS (HIGH)

LOST peers (in baseline, absent in latest):
  • 10.50.1.99

LOST protocols:
  (none)
```

This is the priority panel. If you walk into the project page on
Monday morning and the novelty card is empty for all your
critical-tagged assets, your weekend captures didn't surface
anything new. If it's populated, that's where you start.

---

## How asset_key resolves

The URL is `/projects/<pid>/assets/<asset_key>`. `asset_key` is
**MAC-first / IP-fallback**:

- If you click into the baseline from the workbench's Selected
  Asset sidebar and the asset has a MAC, `asset_key` is the MAC
  (formatted lowercase with colons: `00:1c:06:11:22:33`).
- If MAC is missing, `asset_key` is the IP.
- For external assets (Purdue 5, no MAC), `asset_key` is the IP.

The same keying is used for asset tags, so the baseline page
honors any tag you set on this asset (criticality bumps the
finding history's severity column accordingly).

If you've tagged the same physical asset under multiple keys (e.g.
the engine identified it by MAC in some reports and by IP in
others), the baseline merges them — the baseline lookup follows
the engine's own merge rules from `_merge_l2_nodes()` (v1.9.0+).

---

## The API

`GET /api/projects/<pid>/assets/<asset_key>/baseline` returns the
structured baseline as JSON:

```json
{
  "asset_key": "00:1c:06:11:22:33",
  "report_count": 14,
  "identity_timeline": [...],
  "protocol_mix_history": [...],
  "peer_set": [...],
  "finding_history": [...],
  "l2_anomaly_cadence": [...],
  "novelty": {
    "new_protocols": [...],
    "new_peers": [...],
    "new_finding_categories": [...],
    "lost_peers": [...],
    "lost_protocols": [...]
  }
}
```

Optional `?limit_reports=N` caps the window — handy when a project
has 100+ reports but you only care about the last 30 days. The
default walks the entire project.

The endpoint is project-ownership-checked (only the project owner
can read). It's pure compute — no DB write, no caching, walks the
report files on every request. Performance is bounded by report
file count + per-report parse time; in practice well under a
second on engagement-scale projects.

---

## When the baseline disagrees with the workbench

The workbench shows *one capture*. The baseline shows *all of
them*. Two common ways they disagree:

- Workbench shows a CRITICAL finding; baseline shows the same
  category as `persistent (14/14)`. The finding is real but it's
  the steady state — note it once, accept the risk, move on. Don't
  re-investigate every capture.
- Workbench shows nothing notable; baseline shows a `lost` peer
  the asset used to talk to. The current capture is "fine" but
  *something quiet stopped happening*. The lost-peer signal is
  often the most underweighted finding pattern in OT — a poller
  that stopped polling, a sensor that stopped reporting, a peer
  that was decommissioned without you knowing.

The baseline is where these become visible. The workbench can't
show you what's *not* in the current capture.

---

## Limits and roadmap

- **Trend sparklines.** v3.2.0 ships per-report columns for
  protocol-mix history. Long-term-trend visualisation
  (sparklines, anomaly-flagged dips/spikes) is roadmap.
- **Notifications on novelty.** A scan-completion webhook firing
  when an asset's profile diverges from baseline is on the
  roadmap (v3.3.0 follow-up). Today, you check the baseline
  manually after each capture.
- **Cross-project baselines.** Today, the baseline is per-project.
  Comparing the same asset across multiple projects (e.g. same
  network captured in different engagements) is roadmap and not
  trivial — different projects have different criticality tagging,
  so cross-project semantics aren't obvious yet.
