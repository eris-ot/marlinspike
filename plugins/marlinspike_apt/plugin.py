"""marlinspike-apt — APT lateral-movement and reconnaissance detection.

Consumes a finished MarlinSpike report JSON and emits a sidecar artifact with
findings drawn from conversation-level fan-out patterns and behavioral
deviation. All Tier 1 detectors operate on existing report fields (no engine
widening required).

Categories:
  APT_LATERAL_MOVEMENT_SMB     — one src talks SMB (445) to N+ distinct dst hosts
  APT_LATERAL_MOVEMENT_RDP     — RDP (3389) from a non-jump-host source
  APT_LATERAL_MOVEMENT_WINRM   — WSMAN/WinRM (5985/5986) from a new source
  APT_OT_RECONNAISSANCE        — broad OT-protocol fan-out from a single src
  APT_NEW_HOST_PROTOCOL        — host initiates a protocol family inconsistent
                                 with its inferred role (behavioral baseline)
  APT_C2_BEACON                — periodic outbound beacon to an external host
                                 (uses engine beacon_score / interval / jitter)
"""

from __future__ import annotations

import argparse
import ipaddress
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from . import CONTRACT_VERSION, PLUGIN_ID, PLUGIN_VERSION

DEFAULT_RULES_PATH = Path(__file__).resolve().parents[2] / "rules" / "apt" / "base.yaml"


CATEGORY_ATTACK = {
    "APT_LATERAL_MOVEMENT_SMB":   ["T1021.002", "T1570"],
    "APT_LATERAL_MOVEMENT_RDP":   ["T1021.001"],
    "APT_LATERAL_MOVEMENT_WINRM": ["T1021.006"],
    "APT_OT_RECONNAISSANCE":      ["T0842", "T0840", "T0888"],
    "APT_NEW_HOST_PROTOCOL":      ["T1018", "T1046"],
    "APT_C2_BEACON":              ["T1071", "T1102", "T1573"],
}


# ---------------------------------------------------------------------------
# Protocol / port maps
# ---------------------------------------------------------------------------

SMB_PORTS = {139, 445}
SMB_PROTOCOLS = {"SMB", "SMB2", "SMB3", "CIFS", "NETBIOS-SSN", "NBSS"}

RDP_PORTS = {3389}
RDP_PROTOCOLS = {"RDP", "MS-RDP", "T.125"}

WINRM_PORTS = {5985, 5986}
WINRM_PROTOCOLS = {"WSMAN", "WINRM"}

OT_PORTS = {502, 44818, 102, 20000, 4840, 47808, 1089, 1090, 1091, 9600}
OT_PROTOCOLS = {
    "MODBUS", "MODBUS/TCP",
    "ENIP", "CIP", "ETHERNET/IP",
    "S7COMM", "S7COMM-PLUS",
    "DNP3", "DNP",
    "OPCUA", "OPC-UA", "OPCUA-BINARY",
    "BACNET", "BACNET/IP",
    "IEC-60870-5-104", "IEC60870", "IEC104",
    "PROFINET", "PN-DCP", "PN-RT",
}

# Protocol families a role may legitimately initiate. Roles outside this map
# are skipped (no behavioral expectation set).
ROLE_PROTOCOL_EXPECTATIONS: dict[str, set[str]] = {
    "HMI":                       OT_PROTOCOLS | {"HTTP", "HTTPS", "DNS", "NTP", "ICMP", "ARP"},
    "PLC":                       OT_PROTOCOLS | {"DNS", "NTP", "ICMP", "ARP", "LLDP", "STP"},
    "RTU":                       OT_PROTOCOLS | {"DNS", "NTP", "ICMP", "ARP"},
    "ENGINEERING WORKSTATION":   OT_PROTOCOLS | {
        "HTTP", "HTTPS", "DNS", "NTP", "ICMP", "ARP",
        "SSH", "RDP", "FTP", "SMB", "SMB2", "TELNET",
    },
    "HISTORIAN":                 OT_PROTOCOLS | {"HTTP", "HTTPS", "DNS", "NTP", "ICMP", "ARP", "SQL", "MSSQL"},
    "DATA SERVER":               {"HTTP", "HTTPS", "DNS", "NTP", "ICMP", "ARP", "SQL", "MSSQL", "POSTGRES", "MYSQL", "SMB", "SMB2"},
    "INFRASTRUCTURE SERVER":     {"HTTP", "HTTPS", "DNS", "NTP", "ICMP", "ARP", "SMTP", "LDAP", "KERBEROS", "SMB", "SMB2"},
}
# Note: transit devices (Network Infrastructure / Switch / Router / Industrial Gateway)
# are intentionally absent — we cannot reliably judge what protocols they should
# carry, especially in OT networks where industrial gateways legitimately bridge
# Modbus/EtherNet-IP/S7/etc. NHP only fires on end hosts with a known role.


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


def _proto(conv: dict) -> str:
    return str(conv.get("protocol") or "").strip().upper()


def _dst_port(conv: dict) -> int | None:
    raw = conv.get("dst_port")
    if raw in (None, "", 0):
        raw = conv.get("port")
    if raw in (None, "", 0):
        return None
    try:
        return int(raw)
    except (ValueError, TypeError):
        return None


def _src_ip(conv: dict) -> str:
    return str(conv.get("src_ip") or "").strip()


def _dst_ip(conv: dict) -> str:
    return str(conv.get("dst_ip") or "").strip()


def _is_routable(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_loopback or addr.is_multicast or addr.is_unspecified or addr.is_reserved)


def _is_external(ip: str) -> bool:
    """True if the IP is publicly routable (not RFC1918 / link-local / loopback)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_multicast
        or addr.is_link_local
        or addr.is_unspecified
        or addr.is_reserved
    )


def _norm_role(role: str) -> str:
    return str(role or "").strip().upper()


# ---------------------------------------------------------------------------
# Rule pack loader
# ---------------------------------------------------------------------------

def _load_rule_pack(path: Path) -> dict:
    with path.open() as fh:
        payload = yaml.safe_load(fh)
    if not isinstance(payload, dict):
        raise ValueError(f"Rule pack must be a mapping: {path}")
    if int(payload.get("schema_version") or 0) != 1:
        raise ValueError(f"Unsupported APT rule schema_version in {path}")
    if payload.get("plugin_id") != PLUGIN_ID:
        raise ValueError(f"Rule pack plugin_id mismatch in {path}: expected {PLUGIN_ID!r}")
    return payload


def _merge_packs(packs: list[dict]) -> dict:
    """Merge rule pack settings — later packs override earlier ones."""
    merged: dict[str, Any] = {
        "lateral_movement_smb":   {"enabled": True, "threshold": 5},
        "lateral_movement_rdp":   {"enabled": True, "threshold": 2},
        "lateral_movement_winrm": {"enabled": True, "threshold": 2},
        "ot_reconnaissance":      {"enabled": True, "threshold": 5},
        "new_host_protocol":      {"enabled": True, "min_packet_count": 3},
        "c2_beaconing": {
            "enabled": True,
            "min_score": 0.7,
            "min_interval_s": 30.0,
            "max_interval_s": 3600.0,
            "min_packet_count": 6,
            "excluded_protocols": [
                "ARP", "DNS", "MDNS", "LLMNR", "NTP", "ICMP", "ICMPV6",
                "DHCP", "DHCPV6", "STP", "LLDP", "CDP", "IGMP",
                "MODBUS", "MODBUS TCP", "MODBUS/TCP",
                "ENIP", "ETHERNET/IP", "CIP",
                "S7COMM", "S7COMM-PLUS",
                "DNP3", "DNP",
                "OPCUA", "OPC-UA", "OPCUA-BINARY",
                "BACNET", "BACNET/IP",
                "IEC-60870-5-104", "IEC60870", "IEC104",
                "PROFINET", "PN-DCP", "PN-RT",
                "GOOSE", "MMS",
            ],
            "external_dst_only": True,
        },
        "jump_hosts": [],
        "ot_polling_source_allowlist": [],
        "polling_source_roles": ["HMI", "HISTORIAN", "ENGINEERING WORKSTATION"],
    }

    for pack in packs:
        settings = pack.get("settings") or {}

        for key in ("lateral_movement_smb", "lateral_movement_rdp",
                    "lateral_movement_winrm", "ot_reconnaissance"):
            entry = settings.get(key) or {}
            if isinstance(entry, dict):
                if "threshold" in entry:
                    merged[key]["threshold"] = int(entry["threshold"])
                if "enabled" in entry:
                    merged[key]["enabled"] = bool(entry["enabled"])

        nhp = settings.get("new_host_protocol") or {}
        if isinstance(nhp, dict):
            if "enabled" in nhp:
                merged["new_host_protocol"]["enabled"] = bool(nhp["enabled"])
            if "min_packet_count" in nhp:
                merged["new_host_protocol"]["min_packet_count"] = int(nhp["min_packet_count"])

        c2 = settings.get("c2_beaconing") or {}
        if isinstance(c2, dict):
            if "enabled" in c2:
                merged["c2_beaconing"]["enabled"] = bool(c2["enabled"])
            for fkey in ("min_score", "min_interval_s", "max_interval_s"):
                if fkey in c2:
                    merged["c2_beaconing"][fkey] = float(c2[fkey])
            if "min_packet_count" in c2:
                merged["c2_beaconing"]["min_packet_count"] = int(c2["min_packet_count"])
            if "external_dst_only" in c2:
                merged["c2_beaconing"]["external_dst_only"] = bool(c2["external_dst_only"])
            if isinstance(c2.get("excluded_protocols"), list):
                merged["c2_beaconing"]["excluded_protocols"] = [
                    str(p).strip().upper() for p in c2["excluded_protocols"] if p
                ]

        for ip in _listify(settings.get("jump_hosts")):
            ip_str = str(ip or "").strip()
            if ip_str and ip_str not in merged["jump_hosts"]:
                merged["jump_hosts"].append(ip_str)

        for ip in _listify(settings.get("ot_polling_source_allowlist")):
            ip_str = str(ip or "").strip()
            if ip_str and ip_str not in merged["ot_polling_source_allowlist"]:
                merged["ot_polling_source_allowlist"].append(ip_str)

        roles = settings.get("polling_source_roles")
        if isinstance(roles, list):
            merged["polling_source_roles"] = [_norm_role(r) for r in roles if r]

    return merged


# ---------------------------------------------------------------------------
# Index builders
# ---------------------------------------------------------------------------

def _build_node_role_index(nodes: list[dict]) -> dict[str, str]:
    """Map IP -> role (uppercased), best effort."""
    role_by_ip: dict[str, str] = {}
    for node in nodes:
        ip = str(node.get("ip") or "").strip()
        if not ip:
            continue
        role = _norm_role(node.get("role") or node.get("device_type") or "")
        if role:
            role_by_ip[ip] = role
    return role_by_ip


def _matches_family(conv: dict, ports: set[int], protocols: set[str]) -> bool:
    if _proto(conv) in protocols:
        return True
    port = _dst_port(conv)
    return port is not None and port in ports


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------

def _detect_lateral_fanout(
    convs: list[dict],
    settings_key: str,
    ports: set[int],
    protocols: set[str],
    settings: dict,
    category: str,
    severity: str,
    label: str,
    jump_host_filter: bool = False,
) -> list[dict]:
    """Generic lateral-movement detector: count distinct dst per src for a port/protocol family."""
    if not settings[settings_key]["enabled"]:
        return []
    threshold = int(settings[settings_key]["threshold"])
    jump_hosts = set(settings.get("jump_hosts") or [])

    targets_by_src: dict[str, set[str]] = defaultdict(set)
    convs_by_src: dict[str, list[dict]] = defaultdict(list)

    for conv in convs:
        if not _matches_family(conv, ports, protocols):
            continue
        src = _src_ip(conv)
        dst = _dst_ip(conv)
        if not src or not dst or src == dst:
            continue
        if jump_host_filter and src in jump_hosts:
            continue
        targets_by_src[src].add(dst)
        convs_by_src[src].append(conv)

    findings: list[dict] = []
    for src in sorted(targets_by_src):
        targets = sorted(targets_by_src[src])
        if len(targets) < threshold:
            continue
        first_seen = ""
        timestamps = []
        for c in convs_by_src[src]:
            ts = c.get("first_seen") or c.get("timestamp")
            if ts:
                timestamps.append(str(ts))
        if timestamps:
            first_seen = sorted(timestamps)[0]

        findings.append({
            "category": category,
            "src_ip": src,
            "distinct_target_ips": targets,
            "target_count": len(targets),
            "first_seen": first_seen,
            "attack_techniques": CATEGORY_ATTACK[category],
            "severity": severity,
            "detail": (
                f"{label} from {src} to {len(targets)} distinct destination(s) "
                f"(threshold: {threshold}). Targets: "
                + ", ".join(targets[:8])
                + ("..." if len(targets) > 8 else "")
                + "."
            ),
        })
    return findings


def _detect_smb_lateral(convs: list[dict], settings: dict) -> list[dict]:
    return _detect_lateral_fanout(
        convs, "lateral_movement_smb", SMB_PORTS, SMB_PROTOCOLS, settings,
        category="APT_LATERAL_MOVEMENT_SMB",
        severity="HIGH",
        label="SMB lateral movement: source",
    )


def _detect_rdp_lateral(convs: list[dict], settings: dict) -> list[dict]:
    return _detect_lateral_fanout(
        convs, "lateral_movement_rdp", RDP_PORTS, RDP_PROTOCOLS, settings,
        category="APT_LATERAL_MOVEMENT_RDP",
        severity="HIGH",
        label="RDP fan-out: source",
        jump_host_filter=True,
    )


def _detect_winrm_lateral(convs: list[dict], settings: dict) -> list[dict]:
    return _detect_lateral_fanout(
        convs, "lateral_movement_winrm", WINRM_PORTS, WINRM_PROTOCOLS, settings,
        category="APT_LATERAL_MOVEMENT_WINRM",
        severity="HIGH",
        label="WinRM fan-out: source",
        jump_host_filter=True,
    )


def _detect_ot_recon(
    convs: list[dict],
    settings: dict,
    role_by_ip: dict[str, str],
) -> list[dict]:
    """Broad OT-protocol fan-out from a single src — possible reconnaissance.

    Suppressed when src is a known polling source (HMI/Historian/Engineering WS)
    or appears in the explicit ot_polling_source_allowlist.
    """
    if not settings["ot_reconnaissance"]["enabled"]:
        return []
    threshold = int(settings["ot_reconnaissance"]["threshold"])
    polling_roles = set(settings.get("polling_source_roles") or [])
    polling_allowlist = set(settings.get("ot_polling_source_allowlist") or [])

    targets_by_src: dict[str, set[str]] = defaultdict(set)
    protos_by_src: dict[str, set[str]] = defaultdict(set)

    for conv in convs:
        if not _matches_family(conv, OT_PORTS, OT_PROTOCOLS):
            continue
        src = _src_ip(conv)
        dst = _dst_ip(conv)
        if not src or not dst or src == dst:
            continue
        targets_by_src[src].add(dst)
        protos_by_src[src].add(_proto(conv) or f"port:{_dst_port(conv)}")

    findings: list[dict] = []
    for src in sorted(targets_by_src):
        targets = sorted(targets_by_src[src])
        if len(targets) < threshold:
            continue
        if src in polling_allowlist:
            continue
        src_role = role_by_ip.get(src, "")
        if src_role in polling_roles:
            continue
        findings.append({
            "category": "APT_OT_RECONNAISSANCE",
            "src_ip": src,
            "src_role": src_role or "unknown",
            "distinct_target_ips": targets,
            "target_count": len(targets),
            "ot_protocols": sorted(protos_by_src[src]),
            "attack_techniques": CATEGORY_ATTACK["APT_OT_RECONNAISSANCE"],
            "severity": "HIGH",
            "detail": (
                f"Source {src} ({src_role or 'role unknown'}) initiated OT-protocol "
                f"traffic to {len(targets)} distinct destinations (threshold: {threshold}) "
                f"using {', '.join(sorted(protos_by_src[src]))}. "
                f"Possible OT asset enumeration or pre-attack reconnaissance."
            ),
        })
    return findings


def _detect_new_host_protocol(
    convs: list[dict],
    settings: dict,
    role_by_ip: dict[str, str],
) -> list[dict]:
    """Flag a host that initiates a protocol outside its role's expected set.

    Only nodes with a role mapped in ROLE_PROTOCOL_EXPECTATIONS are evaluated;
    others are skipped (no expectation set means we cannot judge surprise).
    Aggregated per (src_ip, protocol) so each unexpected-protocol-from-host
    pair produces at most one finding.
    """
    if not settings["new_host_protocol"]["enabled"]:
        return []
    min_pkts = int(settings["new_host_protocol"]["min_packet_count"])

    grouped: dict[tuple[str, str], dict[str, Any]] = {}

    for conv in convs:
        src = _src_ip(conv)
        if not src:
            continue
        role = role_by_ip.get(src, "")
        expected = ROLE_PROTOCOL_EXPECTATIONS.get(role)
        if not expected:
            continue
        proto = _proto(conv)
        if not proto or proto in expected:
            continue
        pkt_count = int(conv.get("packet_count") or 0)
        if pkt_count < min_pkts:
            continue
        key = (src, proto)
        entry = grouped.setdefault(key, {
            "role": role,
            "dst_ips": set(),
            "packet_count": 0,
            "dst_ports": set(),
            "first_seen": "",
        })
        entry["dst_ips"].add(_dst_ip(conv))
        entry["packet_count"] += pkt_count
        port = _dst_port(conv)
        if port is not None:
            entry["dst_ports"].add(port)
        ts = conv.get("first_seen") or conv.get("timestamp")
        if ts:
            ts_str = str(ts)
            if not entry["first_seen"] or ts_str < entry["first_seen"]:
                entry["first_seen"] = ts_str

    findings: list[dict] = []
    for (src, proto), data in sorted(grouped.items()):
        dst_ips = sorted(data["dst_ips"] - {""})
        findings.append({
            "category": "APT_NEW_HOST_PROTOCOL",
            "src_ip": src,
            "src_role": data["role"],
            "unexpected_protocol": proto,
            "dst_ips": dst_ips,
            "dst_ports": sorted(data["dst_ports"]),
            "packet_count": data["packet_count"],
            "first_seen": data["first_seen"],
            "attack_techniques": CATEGORY_ATTACK["APT_NEW_HOST_PROTOCOL"],
            "severity": "MEDIUM",
            "detail": (
                f"{data['role']} {src} initiated {proto} traffic "
                f"({data['packet_count']} packets to {len(dst_ips)} destination(s)). "
                f"This protocol is not expected from a {data['role']} role and may "
                f"indicate compromise, unauthorized tooling, or a misclassified asset."
            ),
        })
    return findings


def _detect_c2_beacons(convs: list[dict], settings: dict) -> list[dict]:
    """Flag periodic outbound beacons with high regularity to (by default) external IPs."""
    cfg = settings.get("c2_beaconing") or {}
    if not cfg.get("enabled", True):
        return []

    min_score = float(cfg.get("min_score", 0.7))
    min_interval = float(cfg.get("min_interval_s", 30.0))
    max_interval = float(cfg.get("max_interval_s", 3600.0))
    min_pkts = int(cfg.get("min_packet_count", 6))
    excluded = {str(p).strip().upper() for p in (cfg.get("excluded_protocols") or [])}
    external_only = bool(cfg.get("external_dst_only", True))

    findings: list[dict] = []
    for conv in convs:
        try:
            score = float(conv.get("beacon_score") or 0.0)
        except (TypeError, ValueError):
            continue
        if score < min_score:
            continue
        try:
            interval = float(conv.get("beacon_interval") or 0.0)
        except (TypeError, ValueError):
            continue
        if interval < min_interval or interval > max_interval:
            continue
        if int(conv.get("packet_count") or 0) < min_pkts:
            continue
        proto = _proto(conv)
        if proto in excluded:
            continue
        src = _src_ip(conv)
        dst = _dst_ip(conv)
        if not src or not dst or src == dst:
            continue
        if external_only and not _is_external(dst):
            continue

        try:
            jitter = float(conv.get("beacon_jitter") or 0.0)
        except (TypeError, ValueError):
            jitter = 0.0

        findings.append({
            "category": "APT_C2_BEACON",
            "src_ip": src,
            "dst_ip": dst,
            "protocol": proto or "unknown",
            "dst_port": _dst_port(conv),
            "beacon_score": round(score, 3),
            "beacon_interval_s": round(interval, 1),
            "beacon_jitter_s": round(jitter, 3),
            "packet_count": int(conv.get("packet_count") or 0),
            "first_seen": str(conv.get("first_seen") or ""),
            "attack_techniques": CATEGORY_ATTACK["APT_C2_BEACON"],
            "severity": "HIGH",
            "detail": (
                f"Periodic outbound traffic from {src} to external {dst} "
                f"({proto or 'unknown'}, interval ~{interval:.1f}s, jitter ~{jitter:.2f}s, "
                f"score {score:.2f}). Consistent with C2 beaconing."
            ),
        })

    findings.sort(key=lambda f: (-f["beacon_score"], f["src_ip"], f["dst_ip"]))
    return findings


# ---------------------------------------------------------------------------
# Workbench views
# ---------------------------------------------------------------------------

def _build_workbench_views(findings: list[dict], category_counts: dict[str, int]) -> list[dict]:
    metric_items = [
        {"label": cat, "value": str(category_counts.get(cat, 0)),
         "tone": "warn" if category_counts.get(cat, 0) > 0 else "neutral"}
        for cat in sorted(CATEGORY_ATTACK)
    ]

    lateral_rows = []
    for f in findings:
        if not f["category"].startswith("APT_LATERAL_MOVEMENT_"):
            continue
        family = f["category"].rsplit("_", 1)[-1]
        lateral_rows.append([
            family,
            f.get("src_ip", ""),
            str(f.get("target_count", 0)),
            ", ".join(f.get("distinct_target_ips", [])[:5])
            + ("..." if len(f.get("distinct_target_ips", [])) > 5 else ""),
            f.get("first_seen", ""),
        ])

    beacon_rows = []
    for f in findings:
        if f["category"] != "APT_C2_BEACON":
            continue
        beacon_rows.append([
            f.get("src_ip", ""),
            f.get("dst_ip", ""),
            f.get("protocol", ""),
            str(f.get("dst_port") or ""),
            f"{f.get('beacon_score', 0):.2f}",
            f"{f.get('beacon_interval_s', 0):.0f}s",
            str(f.get("packet_count", 0)),
        ])

    blocks: list[dict] = [
        {
            "type": "metric_strip",
            "title": "Finding Categories",
            "items": metric_items,
        },
    ]
    if lateral_rows:
        blocks.append({
            "type": "table",
            "title": "Lateral Movement Sources",
            "columns": ["Family", "Source IP", "Targets", "Sample Targets", "First Seen"],
            "rows": lateral_rows,
        })
    if beacon_rows:
        blocks.append({
            "type": "table",
            "title": "External C2 Beacon Candidates",
            "columns": ["Source", "External Dst", "Protocol", "Port", "Score", "Interval", "Packets"],
            "rows": beacon_rows,
        })

    return [
        {
            "view_id": "apt-risk-summary",
            "title": "APT Lateral-Movement & Reconnaissance Indicators",
            "nav_label": "APT",
            "location": "risk",
            "badge": str(len(findings)),
            "summary": "APT-style lateral-movement, OT reconnaissance, behavioral anomalies, and C2 beaconing detected from passive traffic.",
            "order": 35,
            "blocks": blocks,
        }
    ]


# ---------------------------------------------------------------------------
# Main detection engine
# ---------------------------------------------------------------------------

def _detect(report: dict, settings: dict) -> dict:
    convs = [c for c in _listify(report.get("conversations")) if isinstance(c, dict)]
    nodes = [n for n in _listify(report.get("nodes")) if isinstance(n, dict)]
    role_by_ip = _build_node_role_index(nodes)

    if not convs:
        return {
            "findings": [],
            "summary": {
                "conversation_count": 0,
                "node_count": len(nodes),
                "finding_total": 0,
                **{cat: 0 for cat in sorted(CATEGORY_ATTACK)},
            },
        }

    all_findings: list[dict] = []
    all_findings.extend(_detect_smb_lateral(convs, settings))
    all_findings.extend(_detect_rdp_lateral(convs, settings))
    all_findings.extend(_detect_winrm_lateral(convs, settings))
    all_findings.extend(_detect_ot_recon(convs, settings, role_by_ip))
    all_findings.extend(_detect_new_host_protocol(convs, settings, role_by_ip))
    all_findings.extend(_detect_c2_beacons(convs, settings))

    all_findings.sort(key=lambda f: (
        f["category"],
        f.get("src_ip", ""),
        f.get("unexpected_protocol", ""),
        f.get("dst_ip", ""),
    ))

    category_counts = {cat: 0 for cat in CATEGORY_ATTACK}
    for f in all_findings:
        if f["category"] in category_counts:
            category_counts[f["category"]] += 1

    return {
        "findings": all_findings,
        "summary": {
            "conversation_count": len(convs),
            "node_count": len(nodes),
            "finding_total": len(all_findings),
            **category_counts,
        },
    }


# ---------------------------------------------------------------------------
# Public run() entry point
# ---------------------------------------------------------------------------

def run(input_report: Path, output_path: Path, rule_paths: list[Path]) -> dict:
    report = _load_json(input_report)
    packs = [_load_rule_pack(p) for p in rule_paths]
    settings = _merge_packs(packs)
    result = _detect(report, settings)

    category_counts = {cat: result["summary"].get(cat, 0) for cat in CATEGORY_ATTACK}
    workbench_views = _build_workbench_views(result["findings"], category_counts)

    artifact = {
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
        "warnings": [],
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
        description="Detect APT lateral-movement and reconnaissance indicators",
    )
    parser.add_argument("--input-report", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--rules", action="append", default=[])
    args = parser.parse_args()

    input_report = Path(args.input_report).resolve()
    output_path = Path(args.output).resolve()
    rule_paths = [Path(p).resolve() for p in (args.rules or [])] or [DEFAULT_RULES_PATH]

    artifact = run(input_report, output_path, rule_paths)
    summary = artifact["summary"]
    print(
        f"[apt] convs={summary.get('conversation_count', 0)} "
        f"nodes={summary.get('node_count', 0)} "
        f"findings={summary.get('finding_total', 0)} "
        f"smb={summary.get('APT_LATERAL_MOVEMENT_SMB', 0)} "
        f"rdp={summary.get('APT_LATERAL_MOVEMENT_RDP', 0)} "
        f"winrm={summary.get('APT_LATERAL_MOVEMENT_WINRM', 0)} "
        f"ot_recon={summary.get('APT_OT_RECONNAISSANCE', 0)} "
        f"new_proto={summary.get('APT_NEW_HOST_PROTOCOL', 0)} "
        f"c2={summary.get('APT_C2_BEACON', 0)}"
    )


if __name__ == "__main__":
    main()
