"""Longitudinal asset baseline computation across a time-ordered report list.

Pure compute — no Flask, no DB, no I/O.  All extraction is done over the
in-memory report dicts that ``_build_viewer_context`` produces (or the same
shape the engine writes to disk).

Entry point::

    from marlinspike.baselines import compute_asset_baseline
    result = compute_asset_baseline(reports, "aa:bb:cc:dd:ee:ff")

Returns ``None`` when the asset does not appear in any of the supplied reports
(caller should respond 404).  Otherwise returns the full longitudinal profile
dict described in the API contract.
"""
from __future__ import annotations

import os
import re
from collections import defaultdict

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_MAC_RE = re.compile(r"^[0-9a-f:]{17}$", re.IGNORECASE)


def _is_mac(key: str) -> bool:
    return bool(_MAC_RE.match(key))


def _norm_mac(mac: str) -> str:
    return mac.strip().lower()


def _report_ts(report: dict) -> str:
    """Return the best ISO timestamp string for a report."""
    ts = report.get("timestamp_start")
    if ts:
        return str(ts)
    cap = report.get("capture_info") or {}
    return str(cap.get("start_ts") or "")


def _report_filename(report: dict) -> str:
    """Return the best filename label for a report."""
    name = report.get("_report_filename")
    if name:
        return str(name)
    cap = report.get("capture_info") or {}
    pcap = cap.get("pcap_path") or ""
    if pcap:
        return os.path.basename(str(pcap))
    return ""


def _find_node(report: dict, asset_key: str, by_mac: bool) -> dict | None:
    """Return the first matching node entry for *asset_key* in *report*."""
    for node in report.get("nodes") or []:
        if by_mac:
            mac = _norm_mac(node.get("mac") or "")
            if mac == _norm_mac(asset_key):
                return node
        else:
            ip = (node.get("ip") or "").strip()
            if ip == asset_key.strip():
                return node
    return None


def _asset_ip(node: dict) -> str:
    return (node.get("ip") or "").strip()


def _sorted_unique(values) -> list[str]:
    """Return sorted unique non-empty string values."""
    return sorted({str(v).strip() for v in values if str(v).strip()})


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def compute_asset_baseline(
    reports: list[dict],
    asset_key: str,
    limit_reports: int | None = None,
) -> dict | None:
    """Return the longitudinal profile for ``asset_key`` across ``reports``.

    Parameters
    ----------
    reports:
        Ordered oldest → newest.  Each entry is a report dict with the same
        shape that ``_build_viewer_context`` consumes.
    asset_key:
        MAC (``r'^[0-9a-f:]{17}$'``, case-insensitive) or IP string.  MACs
        are matched against ``node["mac"]``; IPs against ``node["ip"]``.
    limit_reports:
        If set, consider only the most recent N reports (right-slice).

    Returns
    -------
    dict | None
        Full longitudinal profile, or ``None`` when the asset is absent from
        every supplied report.
    """
    if limit_reports is not None:
        reports = reports[-limit_reports:]

    by_mac = _is_mac(asset_key)
    matched_by = "mac" if by_mac else "ip"

    # ------------------------------------------------------------------ #
    # Pass 1 — identify which reports contain the asset and build the     #
    # per-report "presence" objects we'll reference throughout.           #
    # ------------------------------------------------------------------ #
    presences: list[dict] = []  # one per report where asset appears

    for report in reports:
        node = _find_node(report, asset_key, by_mac)
        if node is None:
            continue
        fname = _report_filename(report)
        ts = _report_ts(report)
        presences.append({
            "report": report,
            "node": node,
            "filename": fname,
            "ts": ts,
            "protocols": set(),
            "peers": set(),
            "findings": set(),
            "anomalies": set(),
            "conversation_count": 0,
            "packet_total": 0,
        })

    if not presences:
        return None

    # ------------------------------------------------------------------ #
    # identity_timeline                                                   #
    # ------------------------------------------------------------------ #
    identity_timeline: list[dict] = []
    for p in presences:
        node = p["node"]
        identity_timeline.append({
            "report": p["filename"],
            "ts": p["ts"],
            "vendor": node.get("vendor") or None,
            "device_type": node.get("device_type") or None,
            "role": node.get("role") or None,
            "purdue_level": node.get("purdue_level"),
            "system_name": node.get("system_name") or None,
            "auth_observed": bool(node.get("auth_observed")),
        })

    # ------------------------------------------------------------------ #
    # protocol_history — per-protocol, ordered list of report appearances #
    # ------------------------------------------------------------------ #
    # Determine which protocols appeared in the baseline vs latest.
    # "latest" is the last presence entry; baseline is everything before.

    # Collect protocol sets per report (from node["protocols"])
    # and conversation counts for convs aggregation.
    per_report_protocols: list[dict] = []  # [{proto: convs_count}]

    for p in presences:
        node = p["node"]
        report = p["report"]

        # Count conversations involving this asset, grouped by protocol.
        conv_counts: dict[str, int] = defaultdict(int)
        conversation_count = 0
        packet_total = 0
        asset_ip = _asset_ip(node)
        asset_mac_norm = _norm_mac(node.get("mac") or "")

        for conv in report.get("conversations") or []:
            proto = str(conv.get("protocol") or "").strip()
            if not proto:
                continue
            src_ip = (conv.get("src_ip") or "").strip()
            dst_ip = (conv.get("dst_ip") or "").strip()
            src_mac = _norm_mac(conv.get("src_mac") or "")
            dst_mac = _norm_mac(conv.get("dst_mac") or "")
            involved = False
            if asset_ip and (src_ip == asset_ip or dst_ip == asset_ip):
                involved = True
            elif asset_mac_norm and (src_mac == asset_mac_norm or dst_mac == asset_mac_norm):
                involved = True
            if involved:
                conversation_count += 1
                pkt = conv.get("packet_count") or conv.get("packets") or 0
                try:
                    pkt = int(pkt)
                except (TypeError, ValueError):
                    pkt = 0
                packet_total += pkt
                conv_counts[proto] += pkt

        # Protocols assigned to this node by the engine.
        node_protocols: set[str] = set()
        for proto in node.get("protocols") or []:
            s = str(proto).strip()
            if s:
                node_protocols.add(s)

        # Merge: any protocol in node_protocols OR with conversation traffic.
        all_protos: set[str] = node_protocols | set(conv_counts.keys())

        p["protocols"] = all_protos
        p["conversation_count"] = conversation_count
        p["packet_total"] = packet_total

        per_report_protocols.append({
            "filename": p["filename"],
            "ts": p["ts"],
            "protocols": all_protos,
            "conv_counts": dict(conv_counts),
        })

    # Determine the set of protocols seen in baseline (all but last presence)
    # and latest (last presence).
    baseline_protocol_set: set[str] = set()
    for rp in per_report_protocols[:-1]:
        baseline_protocol_set |= rp["protocols"]
    latest_protocol_set: set[str] = per_report_protocols[-1]["protocols"] if per_report_protocols else set()

    # Build protocol_history dict keyed by protocol name.
    proto_appearances: dict[str, list[dict]] = defaultdict(list)
    for rp in per_report_protocols:
        for proto in sorted(rp["protocols"]):
            proto_appearances[proto].append({
                "report": rp["filename"],
                "ts": rp["ts"],
                "convs": rp["conv_counts"].get(proto, 0),
                "is_new": proto not in baseline_protocol_set,
            })

    # ------------------------------------------------------------------ #
    # peer_history                                                        #
    # ------------------------------------------------------------------ #
    # Per report, collect peers (IP of the other end of each conversation).
    # Then aggregate: first_seen, last_seen, total convs, is_new_in_latest.
    peer_data: dict[str, dict] = {}  # peer_ip -> aggregated

    baseline_peer_set: set[str] = set()
    latest_peer_set: set[str] = set()

    for idx, p in enumerate(presences):
        node = p["node"]
        report = p["report"]
        asset_ip = _asset_ip(node)
        asset_mac_norm = _norm_mac(node.get("mac") or "")
        is_latest = (idx == len(presences) - 1)

        for conv in report.get("conversations") or []:
            src_ip = (conv.get("src_ip") or "").strip()
            dst_ip = (conv.get("dst_ip") or "").strip()
            src_mac = _norm_mac(conv.get("src_mac") or "")
            dst_mac = _norm_mac(conv.get("dst_mac") or "")

            peer_ip: str | None = None
            if asset_ip:
                if src_ip == asset_ip and dst_ip:
                    peer_ip = dst_ip
                elif dst_ip == asset_ip and src_ip:
                    peer_ip = src_ip
            if peer_ip is None and asset_mac_norm:
                if src_mac == asset_mac_norm and dst_ip:
                    peer_ip = dst_ip
                elif dst_mac == asset_mac_norm and src_ip:
                    peer_ip = src_ip

            if not peer_ip:
                continue

            pkt = conv.get("packet_count") or conv.get("packets") or 0
            try:
                pkt = int(pkt)
            except (TypeError, ValueError):
                pkt = 0

            if not is_latest:
                baseline_peer_set.add(peer_ip)
            else:
                latest_peer_set.add(peer_ip)

            p["peers"].add(peer_ip)

            if peer_ip not in peer_data:
                peer_data[peer_ip] = {
                    "peer": peer_ip,
                    "first_seen_report": p["filename"],
                    "last_seen_report": p["filename"],
                    "first_seen_ts": p["ts"],
                    "last_seen_ts": p["ts"],
                    "report_count": 1,
                    "convs_total": pkt,
                }
            else:
                entry = peer_data[peer_ip]
                entry["convs_total"] += pkt
                if p["ts"] < entry["first_seen_ts"] or (
                    p["ts"] == entry["first_seen_ts"]
                    and p["filename"] < entry["first_seen_report"]
                ):
                    entry["first_seen_report"] = p["filename"]
                    entry["first_seen_ts"] = p["ts"]
                if p["ts"] > entry["last_seen_ts"] or (
                    p["ts"] == entry["last_seen_ts"]
                    and p["filename"] > entry["last_seen_report"]
                ):
                    entry["last_seen_report"] = p["filename"]
                    entry["last_seen_ts"] = p["ts"]

    # Per-report deduplication for report_count: track (peer, filename) pairs.
    peer_report_seen: dict[str, set[str]] = defaultdict(set)
    for idx, p in enumerate(presences):
        node = p["node"]
        report = p["report"]
        asset_ip = _asset_ip(node)
        asset_mac_norm = _norm_mac(node.get("mac") or "")

        seen_in_this_report: set[str] = set()
        for conv in report.get("conversations") or []:
            src_ip = (conv.get("src_ip") or "").strip()
            dst_ip = (conv.get("dst_ip") or "").strip()
            src_mac = _norm_mac(conv.get("src_mac") or "")
            dst_mac = _norm_mac(conv.get("dst_mac") or "")

            peer_ip = None
            if asset_ip:
                if src_ip == asset_ip and dst_ip:
                    peer_ip = dst_ip
                elif dst_ip == asset_ip and src_ip:
                    peer_ip = src_ip
            if peer_ip is None and asset_mac_norm:
                if src_mac == asset_mac_norm and dst_ip:
                    peer_ip = dst_ip
                elif dst_mac == asset_mac_norm and src_ip:
                    peer_ip = src_ip

            if peer_ip and peer_ip not in seen_in_this_report:
                peer_report_seen[peer_ip].add(p["filename"])
                seen_in_this_report.add(peer_ip)

    for peer_ip, entry in peer_data.items():
        entry["report_count"] = len(peer_report_seen.get(peer_ip, set()))

    peer_history = sorted(
        (
            {
                "peer": e["peer"],
                "first_seen_report": e["first_seen_report"],
                "last_seen_report": e["last_seen_report"],
                "report_count": e["report_count"],
                "convs_total": e["convs_total"],
                "is_new_in_latest": e["peer"] not in baseline_peer_set,
            }
            for e in peer_data.values()
        ),
        key=lambda x: (x["last_seen_report"],),
        reverse=True,
    )

    # ------------------------------------------------------------------ #
    # finding_history                                                     #
    # ------------------------------------------------------------------ #
    finding_data: dict[str, dict] = {}  # category -> aggregated
    baseline_finding_set: set[str] = set()
    latest_finding_set: set[str] = set()

    for idx, p in enumerate(presences):
        node = p["node"]
        report = p["report"]
        asset_ip = _asset_ip(node)
        asset_mac_norm = _norm_mac(node.get("mac") or "")
        is_latest = (idx == len(presences) - 1)

        for finding in report.get("risk_findings") or []:
            if not isinstance(finding, dict):
                continue
            category = str(finding.get("category") or "").strip().upper()
            if not category:
                continue

            affected = finding.get("affected_nodes") or []
            asset_affected = False
            for node_ref in affected:
                ref = str(node_ref).strip()
                if asset_ip and ref == asset_ip:
                    asset_affected = True
                    break
                if asset_mac_norm and _norm_mac(ref) == asset_mac_norm:
                    asset_affected = True
                    break
            if not asset_affected:
                continue

            if not is_latest:
                baseline_finding_set.add(category)
            else:
                latest_finding_set.add(category)

            p["findings"].add(category)

            if category not in finding_data:
                finding_data[category] = {
                    "category": category,
                    "first_seen_report": p["filename"],
                    "first_seen_ts": p["ts"],
                    "last_seen_report": p["filename"],
                    "last_seen_ts": p["ts"],
                    "in_reports": 1,
                }
            else:
                entry = finding_data[category]
                entry["in_reports"] += 1
                if p["ts"] < entry["first_seen_ts"] or (
                    p["ts"] == entry["first_seen_ts"]
                    and p["filename"] < entry["first_seen_report"]
                ):
                    entry["first_seen_report"] = p["filename"]
                    entry["first_seen_ts"] = p["ts"]
                if p["ts"] > entry["last_seen_ts"] or (
                    p["ts"] == entry["last_seen_ts"]
                    and p["filename"] > entry["last_seen_report"]
                ):
                    entry["last_seen_report"] = p["filename"]
                    entry["last_seen_ts"] = p["ts"]

    finding_history = sorted(
        (
            {
                "category": e["category"],
                "first_seen_report": e["first_seen_report"],
                "last_seen_report": e["last_seen_report"],
                "in_reports": e["in_reports"],
                "is_new_in_latest": e["category"] not in baseline_finding_set,
            }
            for e in finding_data.values()
        ),
        key=lambda x: (x["last_seen_report"],),
        reverse=True,
    )

    # ------------------------------------------------------------------ #
    # anomaly_cadence                                                     #
    # ------------------------------------------------------------------ #
    anomaly_cadence: dict[str, dict] = {}

    for p in presences:
        node = p["node"]
        report = p["report"]
        asset_mac_norm = _norm_mac(node.get("mac") or "")

        for anomaly in report.get("l2_anomalies") or []:
            if not isinstance(anomaly, dict):
                continue
            atype = str(anomaly.get("anomaly_type") or "").strip()
            if not atype:
                continue

            src_mac = _norm_mac(anomaly.get("src_mac") or "")
            dst_mac = _norm_mac(anomaly.get("dst_mac") or "")
            if not asset_mac_norm:
                continue
            if src_mac != asset_mac_norm and dst_mac != asset_mac_norm:
                continue

            p["anomalies"].add(atype)

            if atype not in anomaly_cadence:
                anomaly_cadence[atype] = {
                    "reports_with_event": 1,
                    "first": p["filename"],
                    "first_ts": p["ts"],
                    "last": p["filename"],
                    "last_ts": p["ts"],
                }
            else:
                entry = anomaly_cadence[atype]
                entry["reports_with_event"] += 1
                if p["ts"] < entry["first_ts"] or (
                    p["ts"] == entry["first_ts"]
                    and p["filename"] < entry["first"]
                ):
                    entry["first"] = p["filename"]
                    entry["first_ts"] = p["ts"]
                if p["ts"] > entry["last_ts"] or (
                    p["ts"] == entry["last_ts"]
                    and p["filename"] > entry["last"]
                ):
                    entry["last"] = p["filename"]
                    entry["last_ts"] = p["ts"]

    # Strip internal _ts tracking fields from output.
    anomaly_cadence_out: dict[str, dict] = {
        atype: {
            "reports_with_event": e["reports_with_event"],
            "first": e["first"],
            "last": e["last"],
        }
        for atype, e in anomaly_cadence.items()
    }

    # ------------------------------------------------------------------ #
    # stability                                                           #
    # ------------------------------------------------------------------ #
    vendor_counts: dict[str, int] = defaultdict(int)
    role_counts: dict[str, int] = defaultdict(int)

    for p in presences:
        node = p["node"]
        vendor = str(node.get("vendor") or "").strip()
        role = str(node.get("role") or "").strip()
        if vendor:
            vendor_counts[vendor] += 1
        if role:
            role_counts[role] += 1

    vendor_stable = len(vendor_counts) <= 1
    role_stable = len(role_counts) <= 1
    role_distribution: dict[str, int] = dict(role_counts) if not role_stable else {}

    stability = {
        "vendor_stable": vendor_stable,
        "role_stable": role_stable,
        "role_distribution": role_distribution,
    }

    # ------------------------------------------------------------------ #
    # novelty_vs_baseline                                                 #
    # ------------------------------------------------------------------ #
    # baseline = all presences[:-1]; latest = presences[-1]
    # "new" = in latest but not in any baseline report
    # "lost" = in any baseline report but not in latest
    new_protocols = sorted(latest_protocol_set - baseline_protocol_set)
    lost_protocols = sorted(baseline_protocol_set - latest_protocol_set)
    new_peers = sorted(latest_peer_set - baseline_peer_set)
    lost_peers = sorted(baseline_peer_set - latest_peer_set)
    new_findings = sorted(latest_finding_set - baseline_finding_set)
    # lost_findings not in spec contract but structurally symmetric; omit.

    novelty_vs_baseline = {
        "new_protocols": new_protocols,
        "new_peers": new_peers,
        "new_findings": new_findings,
        "lost_protocols": lost_protocols,
        "lost_peers": lost_peers,
    }

    # ------------------------------------------------------------------ #
    # selected_asset_summary / cross_report_delta                         #
    # ------------------------------------------------------------------ #
    def _summarize_presence(presence: dict) -> dict:
        node = presence["node"]
        ip = _asset_ip(node)
        mac = _norm_mac(node.get("mac") or "")
        return {
            "report": presence["filename"],
            "ts": presence["ts"],
            "ip": ip or None,
            "mac": mac or None,
            "vendor": node.get("vendor") or None,
            "device_type": node.get("device_type") or None,
            "role": node.get("role") or None,
            "purdue_level": node.get("purdue_level"),
            "system_name": node.get("system_name") or None,
            "auth_observed": bool(node.get("auth_observed")),
            "protocols": _sorted_unique(presence["protocols"]),
            "protocol_count": len(presence["protocols"]),
            "peer_ips": _sorted_unique(presence["peers"]),
            "peer_count": len(presence["peers"]),
            "finding_categories": _sorted_unique(presence["findings"]),
            "finding_count": len(presence["findings"]),
            "anomaly_types": _sorted_unique(presence["anomalies"]),
            "anomaly_count": len(presence["anomalies"]),
            "conversation_count": int(presence["conversation_count"]),
            "packet_total": int(presence["packet_total"]),
        }

    first_summary = _summarize_presence(presences[0])
    previous_summary = _summarize_presence(presences[-2]) if len(presences) >= 2 else None
    last_summary = _summarize_presence(presences[-1])

    def _delta_block(previous: dict | None, latest: dict) -> dict:
        if previous is None:
            previous = {
                "report": None,
                "ts": None,
                "ip": None,
                "mac": None,
                "vendor": None,
                "device_type": None,
                "role": None,
                "purdue_level": None,
                "system_name": None,
                "auth_observed": None,
                "protocols": [],
                "peer_ips": [],
                "finding_categories": [],
                "anomaly_types": [],
            }

        identity_changes: dict[str, dict] = {}
        for field in (
            "ip",
            "mac",
            "vendor",
            "device_type",
            "role",
            "purdue_level",
            "system_name",
            "auth_observed",
        ):
            if previous.get(field) != latest.get(field):
                identity_changes[field] = {
                    "previous": previous.get(field),
                    "last": latest.get(field),
                }

        def _set_delta(field: str) -> dict:
            prev_items = set(previous.get(field) or [])
            last_items = set(latest.get(field) or [])
            added = sorted(last_items - prev_items)
            removed = sorted(prev_items - last_items)
            return {
                "added": added,
                "removed": removed,
                "previous_count": len(prev_items),
                "last_count": len(last_items),
                "added_count": len(added),
                "removed_count": len(removed),
            }

        return {
            "available": previous_summary is not None,
            "from_report": previous.get("report"),
            "from_ts": previous.get("ts"),
            "to_report": latest.get("report"),
            "to_ts": latest.get("ts"),
            "identity_changes": identity_changes,
            "protocols": _set_delta("protocols"),
            "peers": _set_delta("peer_ips"),
            "findings": _set_delta("finding_categories"),
            "anomalies": _set_delta("anomaly_types"),
        }

    selected_asset_summary = {
        "report_count": len(presences),
        "first": first_summary,
        "previous": previous_summary,
        "last": last_summary,
    }
    cross_report_delta = _delta_block(previous_summary, last_summary)

    # ------------------------------------------------------------------ #
    # Derive the "latest" IP for MAC-matched assets (may drift via DHCP). #
    # ------------------------------------------------------------------ #
    latest_node = presences[-1]["node"]

    # ------------------------------------------------------------------ #
    # Assemble result                                                     #
    # ------------------------------------------------------------------ #
    return {
        "asset_key": asset_key,
        "matched_by": matched_by,
        "first_seen_report": {
            "filename": presences[0]["filename"],
            "ts": presences[0]["ts"],
        },
        "last_seen_report": {
            "filename": presences[-1]["filename"],
            "ts": presences[-1]["ts"],
        },
        "report_count": len(presences),
        "identity_timeline": identity_timeline,
        "protocol_history": dict(proto_appearances),
        "peer_history": peer_history,
        "finding_history": finding_history,
        "anomaly_cadence": anomaly_cadence_out,
        "stability": stability,
        "novelty_vs_baseline": novelty_vs_baseline,
        "selected_asset_summary": selected_asset_summary,
        "cross_report_delta": cross_report_delta,
    }
