# Time-Window Scrubbing & Sub-PCAP Extract

OT captures are flat for hours. The interesting events are seconds
to minutes wide inside multi-hour traces. The time scrubber lets
you find those windows visually; the Extract button lets you carve
out a sub-PCAP scoped to the window for packet-level inspection in
Wireshark.

This document covers both. For where in the analyst loop they fit,
see step 5 of [triage-methodology.md](triage-methodology.md). For
the workbench surface they live on, see
[workbench-guide.md](workbench-guide.md#time-scrubber-v310).

---

![Time scrubber with an active drag-selection — Traffic pane below filters live to the chosen window](screenshots/47-time-scrubber-window.png)

## The histogram

Below the workbench toolbar, an adaptive packet-rate histogram
spans the full capture timeline.

### How it's built

Computed client-side from `report.conversations[].first_seen` and
`.last_seen` in the loaded report JSON. ~120 buckets, with bucket
size scaling automatically:

| capture span | bucket size |
|---|---|
| < 1 minute | sub-second |
| 1–10 minutes | seconds |
| 10–60 minutes | tens of seconds |
| 1–24 hours | minutes |
| 1+ days | hours |

The histogram has no DOM elements per packet — it counts
conversations touching each bucket. This means a long-lived
SSH session (one conversation) contributes to many buckets the
same way a single one-shot Modbus poll contributes to one. That's
a feature: spikes in *conversation count* are usually more
interesting than spikes in *packet count* for triage purposes.

### How to read it

A typical OT capture histogram is **flat** — Modbus polling at 1Hz
makes a steady baseline. What you're looking for:

- **Spikes** — sudden bursts of new conversations. New device
  joining, scan, reconfiguration, attack.
- **Dips** — drops in conversation rate. Poller failed, cable
  pulled, switch reboot, mid-capture target offline.
- **Shape changes** — baseline rate shifts permanently up or down.
  Network reconfig, new asset onboarded.

A perfectly flat histogram with no shape changes is *also* a useful
signal: the network is doing exactly what it does, no events
during the capture window. That's the right answer when the
question is "anything happen during the maintenance window?"

---

## Scrubbing

### Selecting a window

**Drag** across the histogram to select a time range. The
selection is shown as a highlighted region. Drag the edges to
adjust; click outside to clear.

The selection range shows in human-readable form below the
histogram: *"02:13:07 – 02:14:42 (95s, 4.3% of capture)"*.

### What filters live

The selection propagates through the `timeFilteredConversations()`
helper to every conversation-driven pane:

- **Traffic Statistics** — top conversations / protocol byte
  distribution / top sources / destinations all recompute from
  conversations whose `(first_seen, last_seen)` overlaps the
  window.
- **Protocol Drilldown per-pair tables** — same. Function-code
  breakdown recomputes too.
- **Findings pane** — when a finding is conversation-rooted (i.e.
  it carries a list of source conversations), it's filtered. Some
  findings (asset-level, e.g. `OT_NO_AUTH_OBSERVED` on a
  particular asset) aren't conversation-rooted and ignore the
  window — they show unfiltered with a small marker indicating
  they aren't time-scoped.
- **Selected Asset peer set** — peer entries filter to peers the
  asset talked to *during the window*.
- **Map / Risk overlay** — does NOT filter. The topology graph
  shows the full capture's structure regardless. This is
  intentional: structural views are most useful unscoped.

### What doesn't filter

- The asset inventory (Assets pane) is full-capture. An asset
  observed only outside the window still shows.
- The MAC table is full-capture.
- ATT&CK matrix is full-capture.
- The L2/ARP anomaly panel is full-capture.

If you need a strictly-scoped view, the workflow is: scrub the
window → extract the sub-PCAP → re-scan → open the new report.

### Performance

The filter helper short-circuits when no window is active.
With a window active, it walks the conversation list once per
visible pane refresh. On a 4SICS-scale capture (a few thousand
conversations) the filter is sub-millisecond per pane and the UI
is responsive while you drag. On extremely large captures
(>100k conversations), expect dragging to be visibly stuttery; the
filter still works, but you'll feel it.

---

## The Extract button

When a window is active (or even with no window — the default is
"whole capture"), conversation rows in Traffic Statistics and
Protocol Drilldown pair tables show an **Extract** button.

### What it does

Click → POST to `/api/reports/<filename>/extract` with the
conversation's tuple plus the active time window. The server runs
`tshark` + `editcap` against the originating PCAP file and streams
the result back as `application/vnd.tcpdump.pcap`. The browser
saves it as `<report-stem>-extract.pcap`.

The result file is a real, replayable, Wireshark-openable PCAP
containing only packets matching the conversation tuple AND falling
within the time window.

### Request body

```json
{
  "src": "10.50.1.7",
  "dst": "10.50.1.12",
  "port": 502,
  "protocol": "tcp",
  "time_start": 1714940000.0,
  "time_end": 1714940095.0,
  "max_packets": 500000
}
```

All fields optional. Empty `src/dst/port/protocol` extracts on the
time window only. Empty `time_start/time_end` extracts on the
conversation tuple only.

### Caps

Two hard caps the server enforces:

| cap | value | reason |
|---|---|---|
| max packets | 500,000 | requested `max_packets` is `min(req, 500_000)` |
| wall-clock timeout | 60 seconds | `tshark` is killed and 504 returned |

These exist because the extract endpoint is a real subprocess on
the engagement host and can be expensive on multi-gigabyte PCAPs
with broad filters. The 500k packet cap is enough for most
investigation scenarios; if you need more, do the extract from the
CLI directly.

If the cap is hit, the response either:

- Returns the partial PCAP (success-with-truncation), or
- Returns 504 with an error explaining the timeout.

The response headers include `X-Extract-Packet-Count` and
`X-Extract-Truncated` so the client can warn the user.

### What you get

A real PCAP. Open it in Wireshark / tshark / Zeek for packet-level
inspection. This is the right move when:

- A finding seems wrong and you want to confirm at packet level.
- You need to reproduce a vendor's claim about a packet sequence.
- You're handing evidence to a colleague who works in Wireshark
  and not MarlinSpike.
- You need to do payload-level analysis (ASN.1 decoding, protocol
  fuzzing, etc.) that MarlinSpike doesn't surface.

---

## Worked example

You're triaging `acme-zone3-2026q2/capture-2026-05-07-1830.json`.
The Operator Snapshot shows 47 findings, 4 of them CRITICAL. Skip
ahead to step 5 of the loop and check the histogram.

The histogram is flat at ~140 conv/s for 2.5 hours, then a sudden
spike to ~700 conv/s lasting about 90 seconds at 19:42:13 –
19:43:47.

You drag-select the spike. Traffic Statistics now shows the top
conversations *during the spike*: a single source IP
(`192.168.99.5`) talking to 47 distinct destinations on TCP 445,
all for ~2 seconds each.

That's SMB lateral-movement-shaped. You note the source IP, click
**Extract** on one of the conversations to grab a sample sub-PCAP.
Open in Wireshark — yes, SMB session setups, then `lsarpc` calls.

You go back to the workbench, click on `192.168.99.5` in the
topology, hit **Baseline** in the Selected Asset sidebar. The
baseline page tells you `192.168.99.5` is a NEW peer in this
report — not seen in the prior 13 captures of this project.

That's a real finding, well-rooted, and you have a sub-PCAP to
prove it. Total time: about 6 minutes.

The flat-histogram-with-a-spike is the most common useful pattern
in OT captures. Don't skip the time scrubber.

---

## Limits

- **Conversation-rooted only for the live filter.** Findings,
  panels, and tables that aren't conversation-rooted (per-asset
  findings, ATT&CK matrix, MAC table) are full-capture.
- **No multi-window selection.** One contiguous range at a time.
- **No saved windows.** The selection is in-memory; reload or new
  report = lost selection. (URL-fragment-based shareable windows
  are roadmap.)
- **Extract is whole-PCAP-bound.** Extract reads the originating
  PCAP file from disk, so it requires the PCAP to still exist in
  the project's uploads directory. If you've deleted the PCAP
  (manually or via the PCAPs tab), Extract returns 404.
- **No real-time updates.** The histogram is built from the
  loaded report. Live captures don't progressively update the
  histogram; you load the report after a rotation completes and
  the histogram reflects what's in that report.
