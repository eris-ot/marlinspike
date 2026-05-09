# Asset Context

The engine produces generic severity. Site-specific severity comes
from you knowing which assets matter. The asset-context layer is
how MarlinSpike captures that knowledge as structured data and
applies it back to findings.

Two related capabilities:

1. **Asset tagging** — owner, criticality, zone, business function,
   free-text notes. Per-project, MAC-first / IP-fallback keying.
2. **Finding notes** — status (`open` / `investigating` /
   `resolved` / `false_positive`) plus body, attached to a finding's
   stable signature so the note survives re-scans of the same
   capture and surfaces against the same finding in similar
   captures.

Asset tagging additionally drives a **contextual-severity overlay**:
findings touching `critical`-tagged assets get bumped one tier;
findings touching only `low`-tagged assets get dropped one tier.

This document covers the workflow and the rules. For where in the
analyst loop this fits, see step 6 of
[triage-methodology.md](triage-methodology.md).

---

## Why asset context

Generic severity from the engine is wrong on most sites.
`CLEARTEXT_REMOTE_ACCESS` is HIGH everywhere, but on a contractor
laptop in a DMZ it's already-bad-practice; on the safety system it's
a CRITICAL incident. The engine doesn't know which is which until
you tell it.

Without asset context, your only options are:

- Triage everything HIGH equally (waste of analyst time).
- Maintain the criticality map in your head or in a spreadsheet
  (doesn't survive analyst turnover, doesn't survive multiple
  captures).

With asset context:

- Tag the safety system `critical` once.
- Every future finding touching that asset auto-bumps to CRITICAL.
- The Project Overview's severity bar reflects site-specific
  reality.
- A new analyst walks into the project and sees the contextualized
  view immediately.

---

## Asset tags

Tags live in the `asset_tags` table, keyed by `(project_id,
asset_key)` with a unique constraint. `asset_key` is **MAC-first,
IP-fallback** — if the engine identified the asset by MAC, the tag
keys on MAC; if MAC is missing (rare in OT but happens for L3-only
remote endpoints), it keys on IP.

### Fields

| field | type | purpose |
|---|---|---|
| `owner` | string(120) | who's responsible — name, team, contractor company |
| `criticality` | `low` / `medium` / `high` / `critical` | drives the contextual-severity overlay |
| `zone` | string(80) | site-defined network/process zone — `safety`, `dmz`, `eng`, `process-unit-3` |
| `business_function` | string(120) | what the asset does for the business — `turbine control`, `tank gauging`, `historian` |
| `free_text` | text | anything else — install date, last patch, vendor contact |

All fields are optional. A tag with only `criticality=critical` set
is a perfectly valid tag.

### Where you tag

![Selected Asset sidebar populated — identity, evidence, peer set, vendor, and the Asset Context section at the bottom](screenshots/45-workbench-selected-asset.png)

In the workbench, click any node on the Map (or row in the Assets
pane). The **Selected Asset** sidebar opens. The **Asset Context**
section is editable inline:

- Owner: free-text input, saves on blur.
- Criticality: dropdown (`—` / `low` / `medium` / `high` /
  `critical`), saves on change.
- Zone: free-text input, saves on blur.
- Business function: free-text input, saves on blur.
- Free text: textarea, saves on blur.

Saves are PUT to `/api/projects/<pid>/asset-tags/<asset_key>`. The
update bubbles back to the workbench so contextual severity
re-applies immediately to the visible findings.

### Where tags persist

Project-scoped. A tag on `00:1c:06:11:22:33` in project A is not
visible in project B — even for the same user. This is intentional:
the same physical asset's criticality differs per engagement
context. A historian that's `high` for an internal assessment
might be `medium` for a vendor PSIRT-driven incident review where
you only care about its DMZ-facing exposure.

### MAC-first / IP-fallback keying

When an asset has both a MAC and an IP, the tag keys on MAC. This
matters because:

- IPs change (DHCP, VLAN reassignments, subnet refactors).
- MACs are stable for the lifetime of a NIC.
- Most OT devices have stable MACs across captures.

Edge cases:

- **External assets (Purdue 5)** — typically have only an IP, no
  MAC. Tag keys on IP. If the IP later changes (CDN failover, NAT
  rebalance), the tag won't transfer; create a new tag.
- **MAC-only assets** — devices observed only via L2 protocols
  (LLDP/STP/CDP) without an L3 association. Tag keys on MAC. The
  v1.9.0 fix ensures these get merged into IP-keyed counterparts
  during analysis when the same MAC later carries L3 traffic, so
  you generally won't end up with a separate MAC-only tag long-term.

---

## Contextual-severity overlay

This is the rule:

```
for each risk finding f:
    affected_tags = [tag(asset) for asset in f.affected_nodes]
    base_sev = f.severity (engine-emitted)

    if any(tag.criticality == 'critical' for tag in affected_tags):
        ctx_sev = bump_one_tier(base_sev, cap=CRITICAL)
        reason = 'asset criticality'
    elif all(tag.criticality == 'low' for tag in affected_tags) and affected_tags:
        ctx_sev = drop_one_tier(base_sev, floor=INFO)
        reason = 'asset criticality'
    else:
        ctx_sev = base_sev
        reason = None

    f.contextual_severity = ctx_sev
    f.contextual_severity_reason = reason
```

Severity tiers, ordered: `INFO < LOW < MEDIUM < HIGH < CRITICAL`.

### Bump example

- Finding category: `CLEARTEXT_REMOTE_ACCESS`
- Engine severity: HIGH
- Affected nodes: `10.50.1.5` (the safety PLC, tagged `critical`)
- → `contextual_severity = CRITICAL` with reason `asset criticality`

### Drop example

- Finding category: `WEAK_TLS_OBSERVED`
- Engine severity: MEDIUM
- Affected nodes: `192.168.40.7`, `192.168.40.8` (both tagged `low`,
  contractor laptops)
- → `contextual_severity = LOW` with reason `asset criticality`

### Mixed-criticality example (no change)

- Finding category: `EXTERNAL_C2_BEACON_LIKELY`
- Engine severity: HIGH
- Affected nodes: `10.50.1.5` (`critical`) AND `192.168.40.7` (`low`)
- → bump rule wins (`critical` is present); `contextual_severity =
  CRITICAL`.

### No-tag example (no change)

- Finding category: anything
- Engine severity: HIGH
- Affected nodes: untagged
- → `contextual_severity = HIGH` (matches base; no reason)

### Where the overlay applies

`_apply_contextual_severity()` runs server-side at report-render
time, on every report load. The overlay applies to:

- Findings pane (each row shows the contextual badge with a small
  "→ CRITICAL (asset criticality)" pill explaining the change).
- Top Findings sidebar.
- Project Overview severity bar (rolled-up findings use rolled-up
  contextual severity).
- CSV exports (the `contextual_severity` column is included).

The original engine-emitted `severity` is preserved on the report
JSON. Both fields are written; downstream tools that want to
ignore site context read `severity`, tools that want to honor it
read `contextual_severity`.

---

## Finding notes

Notes are how *you* track triage state. Per-finding, with a
status pill and a body.

### Stable signatures

Notes attach to a **stable finding signature**, not to a finding ID.
The signature is:

```
sha256-32(category + sorted(affected_nodes) + sorted(affected_edges))
```

i.e. the first 32 hex chars of the SHA-256 of the canonical-form
identity tuple.

This is what makes notes survive:

- **Re-runs of the same capture.** Different report ID, same
  signature → same note shows up.
- **Identical findings on a similar capture.** Different capture,
  same finding-shape (same category, same affected assets) → same
  note shows up. The note authoring date and body apply.
- **Engine version bumps.** As long as the category + affected-asset
  list is stable, the note follows.

What breaks the link:

- Renaming a finding category between engine versions. (We try not
  to do this gratuitously — see the engine release notes.)
- An affected asset changing identity (MAC change with no IP
  fallback, IP change for an external asset).

### Statuses

Four statuses, lifecycle in this order:

- **open** — default for a fresh note. *"This finding is real and we
  haven't done anything about it yet."*
- **investigating** — *"We're working on this."*
- **resolved** — *"We fixed the underlying issue."*
- **false_positive** — *"This finding is wrong / not actionable; we
  decided to suppress."*

A `false_positive`-statused finding still renders, but visually
deprioritized. The point is that a future analyst sees *both* the
finding and the prior decision to dismiss it — they can challenge
the dismissal if they want.

### Authoring a note

> *[screenshot needed: Findings pane row with an attached note showing the status pill (e.g. `false_positive`) and a few lines of body text inline with the finding, plus the "Edit note…" affordance]*

In the Findings pane, each finding row has an **Edit note…** button
(or **Add note…** if no note exists yet). Click → modal opens with
status dropdown and body textarea.

Status: pick one. Body: free text, markdown not rendered (yet).
Save → POST to `/api/projects/<pid>/notes`. The note carries the
finding signature, project ID, status, body, and your user ID.

The note renders inline next to the finding from then on, with the
status pill and the body visible without further clicking.

### Notes across captures

When you triage a finding in capture 1 and write *"FP — vendor
default config, accepted risk per change-control 4781"* with status
`false_positive`, then capture 2 surfaces the same finding (same
category, same nodes), capture 2 shows your note inline. New
analyst onboarding the project doesn't repeat your investigation.

### Where notes live

`finding_notes` table, project-scoped, with the unique key
`(project_id, finding_signature)`. One note per finding-signature
per project. Re-saving overwrites the existing note (the previous
text is lost — this is a v3.1.0 simplification; full edit history
is roadmap).

---

## Practical tips

- **Tag aggressively, early.** First time you see an asset, decide
  if it's `critical` / `high` / `medium` / `low` and tag it.
  Updating tags later is fine; *not* tagging means the contextual
  overlay does nothing.
- **Use `low` deliberately.** Most assets are `medium` (the default
  for "we should look at this normally"). Only flag `low` for
  things you genuinely want findings *suppressed* on — contractor
  laptops, scratch test hosts, intentionally exposed honeypots.
- **Use `critical` rarely.** Reserve for the assets where any
  finding warrants senior attention: safety systems, master DCS,
  domain controllers, critical historians, jump hosts.
- **Note false positives the first time you see them.** A note
  saying *"FP — IT-managed test asset, accepted exposure"* with
  status `false_positive` saves the next analyst from re-doing
  your investigation.
- **Don't over-status.** `open` and `false_positive` carry most
  of the operational weight. `investigating` and `resolved` are
  for engagement-internal coordination.

---

## API

The capabilities are accessible via REST as well as the workbench.
Useful for scripted bulk-tagging from a CMDB:

| route | method | what |
|---|---|---|
| `/api/projects/<pid>/asset-tags` | GET | list all tags in the project |
| `/api/projects/<pid>/asset-tags/<asset_key>` | GET | one tag |
| `/api/projects/<pid>/asset-tags/<asset_key>` | PUT | upsert a tag |
| `/api/projects/<pid>/asset-tags/<asset_key>` | DELETE | remove a tag |
| `/api/projects/<pid>/notes` | GET | list notes |
| `/api/projects/<pid>/notes` | POST | upsert a note (signature in body) |
| `/api/projects/<pid>/notes/<signature>` | DELETE | remove a note |

CSRF same-origin check applies to all writes.
