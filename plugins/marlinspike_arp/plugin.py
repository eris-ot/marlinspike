"""marlinspike-arp ARP poisoning detection plugin.

Consumes a finished MarlinSpike report JSON and emits a sidecar JSON artifact
containing ARP poisoning indicators reconstructed from ARP conversations.
Does NOT rely on mac_table (lossy) — rebuilds IP<->MAC bindings by walking
conversations where protocol == "ARP".
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from . import CONTRACT_VERSION, PLUGIN_ID, PLUGIN_VERSION

DEFAULT_RULES_PATH = Path(__file__).resolve().parents[2] / "rules" / "arp" / "base.yaml"

# OUI prefixes that are always router-class (factory default, expandable via rule pack)
_BUILTIN_ROUTER_OUIS: list[str] = []

CATEGORY_ATTACK = {
    "ARP_DUPLICATE_IP_CLAIM": ["T0830", "T1557.002"],
    "ARP_GATEWAY_MAC_CHANGE": ["T0830"],
    "ARP_MAC_CLAIMS_MANY_IPS": ["T0830"],
    "ARP_SCAN_BEHAVIOR": ["T0842"],
    "ARP_BROADCAST_STORM": ["T0814"],
    "ARP_GRATUITOUS_REPLY": ["T0830", "T1557.002"],
}

# Bilgepump arp_spoof reason regex: "ARP spoof: <ip> moved from <old_mac> to <new_mac>"
_BILGEPUMP_ARP_SPOOF_RE = re.compile(
    r"ARP spoof:\s*(?P<ip>\S+)\s*moved from\s*(?P<old_mac>\S+)\s*to\s*(?P<new_mac>\S+)",
    re.IGNORECASE,
)
# Bilgepump arp_gratuitous reason regex: "gratuitous ARP from <mac> claiming <ip>"
_BILGEPUMP_ARP_GRATUITOUS_RE = re.compile(
    r"gratuitous ARP from\s*(?P<mac>\S+)\s*claiming\s*(?P<ip>\S+)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _listify(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _load_json(path: Path) -> dict:
    with path.open() as fh:
        payload = json.load(fh)
    if not isinstance(payload, dict):
        raise ValueError(f"Report must be a JSON object: {path}")
    return payload


def _normalize_mac(mac: str) -> str:
    return str(mac or "").strip().lower()


def _oui_prefix(mac: str) -> str:
    """Return the first 8 characters (XX:XX:XX) of a normalized MAC as OUI prefix."""
    parts = mac.split(":")
    if len(parts) >= 3:
        return ":".join(parts[:3])
    return mac[:8]


# ---------------------------------------------------------------------------
# Rule pack loader
# ---------------------------------------------------------------------------

_REQUIRED_PACK_FIELDS = {"schema_version", "pack_id", "plugin_id"}


def _load_rule_pack(path: Path) -> dict:
    with path.open() as fh:
        payload = yaml.safe_load(fh)
    if not isinstance(payload, dict):
        raise ValueError(f"Rule pack must be a mapping: {path}")
    if int(payload.get("schema_version") or 0) != 1:
        raise ValueError(f"Unsupported ARP rule schema_version in {path}")
    if payload.get("plugin_id") != PLUGIN_ID:
        raise ValueError(f"Rule pack plugin_id mismatch in {path}: expected {PLUGIN_ID!r}")
    return payload


def _merge_packs(packs: list[dict]) -> dict:
    """Merge rule pack settings, later packs override earlier ones."""
    merged: dict[str, Any] = {
        "mac_claims_many_ips": {"threshold": 5, "enabled": True},
        "scan_targets": {"threshold": 20, "response_ratio_max": 0.2, "enabled": True},
        "broadcast_rate": {"per_minute": 100, "enabled": True},
        "duplicate_ip": {"enabled": True},
        "gateway_mac_change": {"enabled": True},
        "gratuitous_reply": {"enabled": True},
        "gateway_ip": None,
        "router_oui_allowlist": list(_BUILTIN_ROUTER_OUIS),
    }

    for pack in packs:
        settings = pack.get("settings") or {}

        # mac_claims_many_ips
        many = settings.get("mac_claims_many_ips") or {}
        if isinstance(many, dict):
            if "threshold" in many:
                merged["mac_claims_many_ips"]["threshold"] = int(many["threshold"])
            if "enabled" in many:
                merged["mac_claims_many_ips"]["enabled"] = bool(many["enabled"])

        # scan_targets
        scan = settings.get("scan_targets") or {}
        if isinstance(scan, dict):
            if "threshold" in scan:
                merged["scan_targets"]["threshold"] = int(scan["threshold"])
            if "response_ratio_max" in scan:
                merged["scan_targets"]["response_ratio_max"] = float(scan["response_ratio_max"])
            if "enabled" in scan:
                merged["scan_targets"]["enabled"] = bool(scan["enabled"])

        # broadcast_rate
        bcast = settings.get("broadcast_rate") or {}
        if isinstance(bcast, dict):
            if "per_minute" in bcast:
                merged["broadcast_rate"]["per_minute"] = int(bcast["per_minute"])
            if "enabled" in bcast:
                merged["broadcast_rate"]["enabled"] = bool(bcast["enabled"])

        # per-rule enabled toggles at top level
        if "duplicate_ip" in settings:
            entry = settings["duplicate_ip"]
            if isinstance(entry, dict) and "enabled" in entry:
                merged["duplicate_ip"]["enabled"] = bool(entry["enabled"])

        if "gateway_mac_change" in settings:
            entry = settings["gateway_mac_change"]
            if isinstance(entry, dict) and "enabled" in entry:
                merged["gateway_mac_change"]["enabled"] = bool(entry["enabled"])

        if "gratuitous_reply" in settings:
            entry = settings["gratuitous_reply"]
            if isinstance(entry, dict) and "enabled" in entry:
                merged["gratuitous_reply"]["enabled"] = bool(entry["enabled"])

        # gateway_ip (last pack wins)
        if "gateway_ip" in settings:
            merged["gateway_ip"] = settings["gateway_ip"] or None

        # router_oui_allowlist (union)
        extra_ouis = _listify(settings.get("router_oui_allowlist"))
        for oui in extra_ouis:
            oui_norm = _normalize_mac(str(oui)).rstrip(":")
            if oui_norm and oui_norm not in merged["router_oui_allowlist"]:
                merged["router_oui_allowlist"].append(oui_norm)

    return merged


# ---------------------------------------------------------------------------
# ARP conversation extraction
# ---------------------------------------------------------------------------

def _extract_arp_convs(report: dict) -> list[dict]:
    """Return all conversations where protocol == 'ARP' (case-insensitive)."""
    convs = _listify(report.get("conversations"))
    return [
        c for c in convs
        if isinstance(c, dict) and str(c.get("protocol") or "").strip().upper() == "ARP"
    ]


def _extract_arp_observations(report: dict) -> list[dict]:
    """Return per-packet ARP observations if the engine emitted them."""
    raw = report.get("arp_observations")
    if not isinstance(raw, list):
        return []
    return [obs for obs in raw if isinstance(obs, dict)]


def _extract_l2_anomalies(report: dict) -> list[dict]:
    """Return engine-emitted L2 anomalies (Rust DPI / bilgepump consumer output)."""
    raw = report.get("l2_anomalies")
    if not isinstance(raw, list):
        return []
    return [evt for evt in raw if isinstance(evt, dict)]


def _build_ip_mac_index(
    convs: list[dict],
    observations: list[dict] | None = None,
) -> tuple[
    dict[str, set[str]],   # ip -> {macs}
    dict[str, set[str]],   # mac -> {ips}
    dict[str, list[dict]], # ip -> [convs]
]:
    """Walk ARP conversations (and per-packet observations when present) to build
    bidirectional IP<->MAC mappings.

    Conversation aggregation collapses multi-IP announcements into a single
    conv with only the first observed src_ip. When arp_observations is
    available it captures every announcement at full fidelity, so we fold
    it in as a supplementary signal.
    """
    ip_to_macs: dict[str, set[str]] = defaultdict(set)
    mac_to_ips: dict[str, set[str]] = defaultdict(set)
    ip_to_convs: dict[str, list[dict]] = defaultdict(list)

    for conv in convs:
        src_mac = _normalize_mac(str(conv.get("src_mac") or ""))
        if not src_mac:
            continue

        candidate_ips: set[str] = set()

        src_ip = str(conv.get("src_ip") or "").strip()
        if src_ip and src_ip not in ("0.0.0.0", ""):
            candidate_ips.add(src_ip)

        for ip in _listify(conv.get("src_ips")):
            ip_str = str(ip or "").strip()
            if ip_str and ip_str not in ("0.0.0.0", ""):
                candidate_ips.add(ip_str)

        for ip in candidate_ips:
            ip_to_macs[ip].add(src_mac)
            mac_to_ips[src_mac].add(ip)
            ip_to_convs[ip].append(conv)

    for obs in observations or []:
        src_mac = _normalize_mac(str(obs.get("src_mac") or ""))
        src_ip = str(obs.get("src_ip") or "").strip()
        if not src_mac or not src_ip or src_ip in ("0.0.0.0",):
            continue
        ip_to_macs[src_ip].add(src_mac)
        mac_to_ips[src_mac].add(src_ip)

    return dict(ip_to_macs), dict(mac_to_ips), dict(ip_to_convs)


def _first_seen(convs: list[dict]) -> str:
    """Return the earliest timestamp string across a list of conversations."""
    timestamps: list[str] = []
    for conv in convs:
        ts = str(conv.get("first_seen") or conv.get("timestamps") or "").strip()
        if ts:
            # timestamps may be a list or a single value
            if ts.startswith("["):
                try:
                    items = json.loads(ts)
                    timestamps.extend(str(t) for t in items if t)
                except (json.JSONDecodeError, TypeError):
                    timestamps.append(ts)
            else:
                timestamps.append(ts)
    timestamps = [t for t in timestamps if t]
    if not timestamps:
        return ""
    return sorted(timestamps)[0]


# ---------------------------------------------------------------------------
# Detections
# ---------------------------------------------------------------------------

def _detect_duplicate_ip_claim(
    ip_to_macs: dict[str, set[str]],
    ip_to_convs: dict[str, list[dict]],
    settings: dict,
) -> list[dict]:
    if not settings["duplicate_ip"]["enabled"]:
        return []
    findings: list[dict] = []
    for ip in sorted(ip_to_macs):
        macs = sorted(ip_to_macs[ip])
        if len(macs) < 2:
            continue
        convs = ip_to_convs.get(ip, [])
        findings.append({
            "category": "ARP_DUPLICATE_IP_CLAIM",
            "ip": ip,
            "claimed_by_macs": macs,
            "conversation_count": len(convs),
            "first_seen": _first_seen(convs),
            "attack_techniques": CATEGORY_ATTACK["ARP_DUPLICATE_IP_CLAIM"],
            "severity": "HIGH",
            "detail": (
                f"IP {ip} is claimed by {len(macs)} distinct source MACs: "
                + ", ".join(macs)
                + ". Possible ARP poisoning or IP conflict."
            ),
        })
    return findings


def _detect_gateway_mac_change(
    ip_to_macs: dict[str, set[str]],
    ip_to_convs: dict[str, list[dict]],
    settings: dict,
) -> list[dict]:
    if not settings["gateway_mac_change"]["enabled"]:
        return []
    gateway_ip = str(settings.get("gateway_ip") or "").strip()
    if not gateway_ip:
        return []
    macs = ip_to_macs.get(gateway_ip)
    if not macs or len(macs) < 2:
        return []
    sorted_macs = sorted(macs)
    convs = ip_to_convs.get(gateway_ip, [])
    return [{
        "category": "ARP_GATEWAY_MAC_CHANGE",
        "ip": gateway_ip,
        "claimed_by_macs": sorted_macs,
        "conversation_count": len(convs),
        "first_seen": _first_seen(convs),
        "attack_techniques": CATEGORY_ATTACK["ARP_GATEWAY_MAC_CHANGE"],
        "severity": "CRITICAL",
        "detail": (
            f"Gateway IP {gateway_ip} is bound to {len(sorted_macs)} MACs: "
            + ", ".join(sorted_macs)
            + ". Primary binding may have changed — possible gateway spoofing."
        ),
    }]


def _detect_mac_claims_many_ips(
    mac_to_ips: dict[str, set[str]],
    settings: dict,
) -> list[dict]:
    if not settings["mac_claims_many_ips"]["enabled"]:
        return []
    threshold = int(settings["mac_claims_many_ips"]["threshold"])
    router_ouis = [_normalize_mac(o) for o in settings.get("router_oui_allowlist") or []]
    findings: list[dict] = []
    for mac in sorted(mac_to_ips):
        ips = sorted(mac_to_ips[mac])
        if len(ips) <= threshold:
            continue
        oui = _oui_prefix(mac)
        if any(oui == r or mac.startswith(r) for r in router_ouis):
            continue
        findings.append({
            "category": "ARP_MAC_CLAIMS_MANY_IPS",
            "mac": mac,
            "claimed_ips": ips,
            "ip_count": len(ips),
            "attack_techniques": CATEGORY_ATTACK["ARP_MAC_CLAIMS_MANY_IPS"],
            "severity": "HIGH",
            "detail": (
                f"MAC {mac} claims {len(ips)} distinct IPs (threshold: {threshold}): "
                + ", ".join(ips[:10])
                + ("..." if len(ips) > 10 else "")
                + ". Possible ARP spoofing or rogue DHCP/ARP proxy."
            ),
        })
    return findings


def _detect_scan_behavior(
    convs: list[dict],
    observations: list[dict],
    settings: dict,
) -> list[dict]:
    """Detect ARP scan behavior: one src_mac sending requests to many dst_ips with low reply ratio.

    Prefers per-packet `arp_observations` (opcode-aware, exact request/reply accounting).
    Falls back to a conversation-count proxy when observations are empty.
    """
    if not settings["scan_targets"]["enabled"]:
        return []
    threshold = int(settings["scan_targets"]["threshold"])
    ratio_max = float(settings["scan_targets"]["response_ratio_max"])

    if observations:
        return _detect_scan_from_observations(observations, threshold, ratio_max)
    return _detect_scan_from_convs(convs, threshold, ratio_max)


def _detect_scan_from_observations(
    observations: list[dict],
    threshold: int,
    ratio_max: float,
) -> list[dict]:
    """Opcode-aware scan detection using per-packet ARP observations.

    For each source MAC:
      - request_targets = distinct dst_ip values in opcode=1 frames sent by the MAC
      - replies_received = opcode=2 frames with dst_mac == this MAC
      - response_ratio = replies_received / len(request_targets)
    """
    mac_request_targets: dict[str, set[str]] = defaultdict(set)
    mac_replies_received: dict[str, int] = defaultdict(int)

    for obs in observations:
        opcode = obs.get("opcode")
        src_mac = _normalize_mac(str(obs.get("src_mac") or ""))
        dst_mac = _normalize_mac(str(obs.get("dst_mac") or ""))
        dst_ip = str(obs.get("dst_ip") or "").strip()

        if opcode == 1 and src_mac and dst_ip and dst_ip not in ("0.0.0.0", "255.255.255.255"):
            mac_request_targets[src_mac].add(dst_ip)
        elif opcode == 2 and dst_mac:
            mac_replies_received[dst_mac] += 1

    findings: list[dict] = []
    for mac in sorted(mac_request_targets):
        targets = sorted(mac_request_targets[mac])
        if len(targets) < threshold:
            continue
        replies = mac_replies_received.get(mac, 0)
        response_ratio = replies / len(targets)
        if response_ratio > ratio_max:
            continue
        findings.append({
            "category": "ARP_SCAN_BEHAVIOR",
            "mac": mac,
            "distinct_target_ips": targets,
            "target_count": len(targets),
            "replies_received": replies,
            "response_ratio": round(response_ratio, 3),
            "signal_source": "arp_observations",
            "attack_techniques": CATEGORY_ATTACK["ARP_SCAN_BEHAVIOR"],
            "severity": "MEDIUM",
            "detail": (
                f"MAC {mac} sent ARP requests to {len(targets)} distinct destination IPs "
                f"(threshold: {threshold}) and received {replies} replies "
                f"(response ratio {response_ratio:.3f}, max allowed: {ratio_max}). "
                f"Possible ARP reconnaissance."
            ),
        })
    return findings


def _detect_scan_from_convs(
    convs: list[dict],
    threshold: int,
    ratio_max: float,
) -> list[dict]:
    """Fallback proxy scan detection when arp_observations is absent.

    Approximates response ratio via distinct conversations per distinct target.
    Less accurate than opcode-aware mode but preserves detection on older reports.
    """
    mac_dst_ips: dict[str, set[str]] = defaultdict(set)
    mac_conv_count: dict[str, int] = defaultdict(int)

    for conv in convs:
        src_mac = _normalize_mac(str(conv.get("src_mac") or ""))
        if not src_mac:
            continue
        dst_ip = str(conv.get("dst_ip") or "").strip()
        if dst_ip and dst_ip not in ("0.0.0.0", "255.255.255.255", ""):
            mac_dst_ips[src_mac].add(dst_ip)
        for ip in _listify(conv.get("dst_ips")):
            ip_str = str(ip or "").strip()
            if ip_str and ip_str not in ("0.0.0.0", "255.255.255.255", ""):
                mac_dst_ips[src_mac].add(ip_str)
        mac_conv_count[src_mac] += 1

    findings: list[dict] = []
    for mac in sorted(mac_dst_ips):
        targets = sorted(mac_dst_ips[mac])
        if len(targets) < threshold:
            continue
        conv_count = mac_conv_count[mac]
        response_ratio = conv_count / max(len(targets), 1)
        if response_ratio > ratio_max:
            continue
        findings.append({
            "category": "ARP_SCAN_BEHAVIOR",
            "mac": mac,
            "distinct_target_ips": targets,
            "target_count": len(targets),
            "estimated_response_ratio": round(response_ratio, 3),
            "signal_source": "conversation_proxy",
            "attack_techniques": CATEGORY_ATTACK["ARP_SCAN_BEHAVIOR"],
            "severity": "MEDIUM",
            "detail": (
                f"MAC {mac} sent ARP toward {len(targets)} distinct destination IPs "
                f"(threshold: {threshold}) with response ratio {response_ratio:.3f} "
                f"(max allowed: {ratio_max}). Possible ARP reconnaissance. "
                f"Signal approximated from conversation counts; rerun with arp_observations "
                f"for exact opcode-based ratio."
            ),
        })
    return findings


def _detect_broadcast_storm(
    convs: list[dict],
    settings: dict,
) -> list[dict]:
    """Detect per-source ARP broadcast rate exceeding threshold per minute."""
    if not settings["broadcast_rate"]["enabled"]:
        return []
    per_minute_threshold = int(settings["broadcast_rate"]["per_minute"])

    BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

    # For each src_mac sending to broadcast dst_mac, accumulate packet counts
    # and attempt to calculate duration from timestamps.
    mac_bcast_pkts: dict[str, int] = defaultdict(int)
    mac_bcast_convs: dict[str, list[dict]] = defaultdict(list)

    for conv in convs:
        src_mac = _normalize_mac(str(conv.get("src_mac") or ""))
        dst_mac = _normalize_mac(str(conv.get("dst_mac") or ""))
        if not src_mac or dst_mac != BROADCAST_MAC:
            continue
        pkt_count = int(conv.get("packet_count") or 1)
        mac_bcast_pkts[src_mac] += pkt_count
        mac_bcast_convs[src_mac].append(conv)

    findings: list[dict] = []
    for mac in sorted(mac_bcast_pkts):
        total_pkts = mac_bcast_pkts[mac]
        conv_list = mac_bcast_convs[mac]

        # Estimate duration from timestamps if available
        all_timestamps: list[str] = []
        for conv in conv_list:
            ts_raw = conv.get("timestamps") or conv.get("first_seen") or ""
            if isinstance(ts_raw, list):
                all_timestamps.extend(str(t) for t in ts_raw if t)
            elif ts_raw:
                all_timestamps.append(str(ts_raw))

        duration_minutes = 1.0  # default: assume 1-minute window
        if len(all_timestamps) >= 2:
            try:
                sorted_ts = sorted(all_timestamps)
                # Simple heuristic: assume timestamps are Unix floats or ISO strings
                t0 = float(sorted_ts[0])
                t1 = float(sorted_ts[-1])
                delta = t1 - t0
                if delta > 0:
                    duration_minutes = delta / 60.0
            except (ValueError, TypeError):
                pass

        rate_per_minute = total_pkts / max(duration_minutes, 1.0)
        if rate_per_minute <= per_minute_threshold:
            continue

        findings.append({
            "category": "ARP_BROADCAST_STORM",
            "mac": mac,
            "broadcast_packet_count": total_pkts,
            "estimated_duration_minutes": round(duration_minutes, 2),
            "estimated_rate_per_minute": round(rate_per_minute, 1),
            "attack_techniques": CATEGORY_ATTACK["ARP_BROADCAST_STORM"],
            "severity": "HIGH",
            "detail": (
                f"MAC {mac} sent {total_pkts} ARP broadcast packets "
                f"at ~{rate_per_minute:.1f}/min "
                f"(threshold: {per_minute_threshold}/min). "
                "Possible broadcast storm or ARP flood."
            ),
        })
    return findings


def _detect_gratuitous_from_observations(
    observations: list[dict],
    settings: dict,
    existing_dedupe_keys: set[tuple[str, str]],
) -> list[dict]:
    """Emit ARP_GRATUITOUS_REPLY findings from per-packet observations.

    A gratuitous ARP is opcode=2 with src_ip == dst_ip (or `is_gratuitous` set
    by the engine). Aggregated by (src_mac, src_ip).
    """
    if not settings["gratuitous_reply"]["enabled"]:
        return []

    grouped: dict[tuple[str, str], dict] = {}
    for obs in observations:
        src_mac = _normalize_mac(str(obs.get("src_mac") or ""))
        src_ip = str(obs.get("src_ip") or "").strip()
        if not src_mac or not src_ip:
            continue

        flagged = bool(obs.get("is_gratuitous"))
        if not flagged:
            opcode = obs.get("opcode")
            dst_ip = str(obs.get("dst_ip") or "").strip()
            if opcode != 2 or dst_ip != src_ip:
                continue

        key = (src_mac, src_ip)
        if key in existing_dedupe_keys:
            continue
        entry = grouped.setdefault(key, {"count": 0, "first_seen": ""})
        entry["count"] += 1
        ts = str(obs.get("timestamp") or "").strip()
        if ts and (not entry["first_seen"] or ts < entry["first_seen"]):
            entry["first_seen"] = ts

    findings: list[dict] = []
    for (mac, ip), data in sorted(grouped.items()):
        findings.append({
            "category": "ARP_GRATUITOUS_REPLY",
            "mac": mac,
            "ip": ip,
            "packet_count": data["count"],
            "first_seen": data["first_seen"],
            "signal_source": "arp_observations",
            "attack_techniques": CATEGORY_ATTACK["ARP_GRATUITOUS_REPLY"],
            "severity": "MEDIUM",
            "detail": (
                f"MAC {mac} sent {data['count']} unsolicited (gratuitous) ARP "
                f"reply(ies) claiming {ip}. Often used to seed downstream caches "
                f"during ARP poisoning or to advertise a takeover."
            ),
        })
        existing_dedupe_keys.add((mac, ip))
    return findings


def _detect_from_l2_anomalies(
    l2_anomalies: list[dict],
    settings: dict,
    existing_dup_ips: set[str],
    existing_gratuitous_keys: set[tuple[str, str]],
) -> list[dict]:
    """Map engine-emitted bilgepump events into plugin findings.

    - bilgepump:arp_spoof    -> ARP_DUPLICATE_IP_CLAIM (if not already flagged)
    - bilgepump:arp_gratuitous -> ARP_GRATUITOUS_REPLY (if not already flagged)
    """
    if not l2_anomalies:
        return []

    dup_enabled = settings["duplicate_ip"]["enabled"]
    grat_enabled = settings["gratuitous_reply"]["enabled"]

    # Group spoof events per IP: collect every MAC observed and the earliest ts.
    spoof_by_ip: dict[str, dict[str, Any]] = {}
    grat_groups: dict[tuple[str, str], dict[str, Any]] = {}

    for evt in l2_anomalies:
        decoder = str(evt.get("decoder") or "").lower()
        details = evt.get("details") if isinstance(evt.get("details"), dict) else {}
        reason = str(evt.get("reason") or details.get("reason") or "")
        ts = str(evt.get("timestamp") or "").strip()

        if decoder == "bilgepump:arp_spoof" and dup_enabled:
            m = _BILGEPUMP_ARP_SPOOF_RE.search(reason)
            if not m:
                continue
            ip = m.group("ip").strip()
            old_mac = _normalize_mac(m.group("old_mac"))
            new_mac = _normalize_mac(m.group("new_mac"))
            if not ip or ip in existing_dup_ips:
                continue
            entry = spoof_by_ip.setdefault(ip, {"macs": set(), "first_seen": "", "events": 0})
            if old_mac:
                entry["macs"].add(old_mac)
            if new_mac:
                entry["macs"].add(new_mac)
            entry["events"] += 1
            if ts and (not entry["first_seen"] or ts < entry["first_seen"]):
                entry["first_seen"] = ts

        elif decoder == "bilgepump:arp_gratuitous" and grat_enabled:
            m = _BILGEPUMP_ARP_GRATUITOUS_RE.search(reason)
            if not m:
                continue
            mac = _normalize_mac(m.group("mac"))
            ip = m.group("ip").strip()
            if not mac or not ip:
                continue
            key = (mac, ip)
            if key in existing_gratuitous_keys:
                continue
            entry = grat_groups.setdefault(key, {"count": 0, "first_seen": ""})
            entry["count"] += 1
            if ts and (not entry["first_seen"] or ts < entry["first_seen"]):
                entry["first_seen"] = ts

    findings: list[dict] = []

    for ip in sorted(spoof_by_ip):
        data = spoof_by_ip[ip]
        macs = sorted(data["macs"])
        if len(macs) < 2:
            # Bilgepump fired on a binding change but we only captured one side.
            # Still useful — emit with whatever MAC we have, but flag in detail.
            pass
        findings.append({
            "category": "ARP_DUPLICATE_IP_CLAIM",
            "ip": ip,
            "claimed_by_macs": macs,
            "conversation_count": 0,
            "first_seen": data["first_seen"],
            "signal_source": "l2_anomalies",
            "engine_event_count": data["events"],
            "attack_techniques": CATEGORY_ATTACK["ARP_DUPLICATE_IP_CLAIM"],
            "severity": "HIGH",
            "detail": (
                f"Engine bilgepump consumer flagged ARP spoof on IP {ip} "
                f"(MACs observed: {', '.join(macs) or 'unknown'}). "
                f"Binding changed mid-capture — strong ARP poisoning signal."
            ),
        })
        existing_dup_ips.add(ip)

    for (mac, ip), data in sorted(grat_groups.items()):
        findings.append({
            "category": "ARP_GRATUITOUS_REPLY",
            "mac": mac,
            "ip": ip,
            "packet_count": data["count"],
            "first_seen": data["first_seen"],
            "signal_source": "l2_anomalies",
            "attack_techniques": CATEGORY_ATTACK["ARP_GRATUITOUS_REPLY"],
            "severity": "MEDIUM",
            "detail": (
                f"Engine bilgepump consumer flagged {data['count']} gratuitous "
                f"ARP event(s) from MAC {mac} claiming {ip}."
            ),
        })
        existing_gratuitous_keys.add((mac, ip))

    return findings


# ---------------------------------------------------------------------------
# Workbench views
# ---------------------------------------------------------------------------

def _build_workbench_views(
    findings: list[dict],
    category_counts: dict[str, int],
) -> list[dict]:
    # metric_strip: per-category counts
    metric_items = [
        {"label": cat, "value": str(category_counts.get(cat, 0)),
         "tone": "warn" if category_counts.get(cat, 0) > 0 else "neutral"}
        for cat in sorted(CATEGORY_ATTACK)
    ]

    # table: top duplicate-IP claims (sorted by number of claiming MACs desc, then IP)
    dup_findings = sorted(
        [f for f in findings if f["category"] == "ARP_DUPLICATE_IP_CLAIM"],
        key=lambda f: (-len(f["claimed_by_macs"]), f["ip"]),
    )
    table_rows = [
        [
            f["ip"],
            ", ".join(f["claimed_by_macs"]),
            str(f["conversation_count"]),
            f["first_seen"] or "",
        ]
        for f in dup_findings[:20]
    ]

    return [
        {
            "view_id": "arp-risk-summary",
            "title": "ARP Poisoning Indicators",
            "nav_label": "ARP",
            "location": "risk",
            "badge": str(len(findings)),
            "summary": "ARP poisoning and reconnaissance indicators detected from passive traffic.",
            "order": 30,
            "blocks": [
                {
                    "type": "metric_strip",
                    "title": "Finding Categories",
                    "items": metric_items,
                },
                {
                    "type": "table",
                    "title": "Top Duplicate IP Claims",
                    "columns": ["IP", "Claimed By MACs", "Conversations", "First Seen"],
                    "rows": table_rows,
                },
            ],
        }
    ]


# ---------------------------------------------------------------------------
# Main detection engine
# ---------------------------------------------------------------------------

def _detect(report: dict, settings: dict) -> dict:
    convs = _extract_arp_convs(report)
    observations = _extract_arp_observations(report)
    l2_anomalies = _extract_l2_anomalies(report)
    warnings: list[str] = []

    if not convs and not observations and not l2_anomalies:
        return {
            "findings": [],
            "summary": {
                "arp_conversation_count": 0,
                "arp_observation_count": 0,
                "l2_anomaly_count": 0,
                "finding_total": 0,
                **{cat: 0 for cat in sorted(CATEGORY_ATTACK)},
            },
            "warnings": warnings,
        }

    ip_to_macs, mac_to_ips, ip_to_convs = _build_ip_mac_index(convs, observations)

    all_findings: list[dict] = []
    dup_findings = _detect_duplicate_ip_claim(ip_to_macs, ip_to_convs, settings)
    all_findings.extend(dup_findings)
    all_findings.extend(_detect_gateway_mac_change(ip_to_macs, ip_to_convs, settings))
    all_findings.extend(_detect_mac_claims_many_ips(mac_to_ips, settings))
    all_findings.extend(_detect_scan_behavior(convs, observations, settings))
    all_findings.extend(_detect_broadcast_storm(convs, settings))

    # Dedupe keys carry across observation- and engine-derived detectors so we
    # do not emit the same gratuitous/duplicate finding twice.
    existing_dup_ips: set[str] = {f["ip"] for f in dup_findings}
    existing_grat_keys: set[tuple[str, str]] = set()

    all_findings.extend(
        _detect_gratuitous_from_observations(observations, settings, existing_grat_keys)
    )
    all_findings.extend(
        _detect_from_l2_anomalies(
            l2_anomalies, settings, existing_dup_ips, existing_grat_keys
        )
    )

    # Deterministic sort: (category, primary identifier)
    all_findings.sort(key=lambda f: (
        f["category"],
        f.get("ip") or f.get("mac") or "",
    ))

    category_counts: dict[str, int] = {cat: 0 for cat in CATEGORY_ATTACK}
    for finding in all_findings:
        cat = finding.get("category", "")
        if cat in category_counts:
            category_counts[cat] += 1

    summary = {
        "arp_conversation_count": len(convs),
        "arp_observation_count": len(observations),
        "l2_anomaly_count": len(l2_anomalies),
        "finding_total": len(all_findings),
        **category_counts,
    }

    return {
        "findings": all_findings,
        "summary": summary,
        "warnings": warnings,
    }


# ---------------------------------------------------------------------------
# Public run() entry point
# ---------------------------------------------------------------------------

def run(
    input_report: Path,
    output_path: Path,
    rule_paths: list[Path],
) -> dict:
    report = _load_json(input_report)
    packs = [_load_rule_pack(path) for path in rule_paths]
    settings = _merge_packs(packs)

    result = _detect(report, settings)

    category_counts: dict[str, int] = {
        cat: result["summary"].get(cat, 0)
        for cat in CATEGORY_ATTACK
    }
    workbench_views = _build_workbench_views(result["findings"], category_counts)

    artifact: dict[str, Any] = {
        "artifact_type": "plugin_output",
        "plugin_id": PLUGIN_ID,
        "plugin_version": PLUGIN_VERSION,
        "contract_version": CONTRACT_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input_report": input_report.name,
        "summary": result["summary"],
        "data": {
            "findings": result["findings"],
            "settings_applied": settings,
        },
        "workbench_views": workbench_views,
        "warnings": result["warnings"],
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w") as fh:
        json.dump(artifact, fh, indent=2)

    return artifact


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog=PLUGIN_ID,
        description="Detect ARP poisoning indicators from a MarlinSpike report JSON",
    )
    parser.add_argument("--input-report", required=True, help="Path to the finished MarlinSpike report JSON")
    parser.add_argument("--output", required=True, help="Path to the output sidecar JSON artifact")
    parser.add_argument("--rules", action="append", default=[], help="YAML rule pack(s) to load")
    args = parser.parse_args()

    input_report = Path(args.input_report).resolve()
    output_path = Path(args.output).resolve()
    rule_paths = [Path(p).resolve() for p in (args.rules or [])] or [DEFAULT_RULES_PATH]

    artifact = run(input_report, output_path, rule_paths)
    summary = artifact.get("summary") or {}
    print(
        f"[arp] arp_conversations={summary.get('arp_conversation_count', 0)} "
        f"arp_observations={summary.get('arp_observation_count', 0)} "
        f"l2_anomalies={summary.get('l2_anomaly_count', 0)} "
        f"findings={summary.get('finding_total', 0)} "
        f"duplicate_ip={summary.get('ARP_DUPLICATE_IP_CLAIM', 0)} "
        f"gateway_mac_change={summary.get('ARP_GATEWAY_MAC_CHANGE', 0)} "
        f"mac_many_ips={summary.get('ARP_MAC_CLAIMS_MANY_IPS', 0)} "
        f"scan={summary.get('ARP_SCAN_BEHAVIOR', 0)} "
        f"bcast_storm={summary.get('ARP_BROADCAST_STORM', 0)} "
        f"gratuitous={summary.get('ARP_GRATUITOUS_REPLY', 0)}"
    )


if __name__ == "__main__":
    main()
