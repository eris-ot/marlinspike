"""
===============================================================================
VORACITY MODULE — MARLINSPIKE
===============================================================================

module:
    name: MarlinSpike
    id: VORACITY-MODULE-MARLINSPIKE
    version: 2.0.3
    author: River Caudle <danny@riverman.io>
    organization: River Risk Partners (Riverman Enterprises LLC)
    date_created: 2026-02-20
    date_modified: 2026-04-11
    license: Apache-2.0

classification:
    category: Passive OT Network Topology Mapping
    kill_chain_phase: [Reconnaissance]
    mitre_attack:
        - T1040   # Network Sniffing
        - T1046   # Network Service Discovery (passive variant)
        - T1016   # System Network Configuration Discovery
        - T1590   # Gather Victim Network Information
        - T1071   # Application Layer Protocol (C2 channel detection)
        - T1573   # Encrypted Channel (C2 suspect channel detection)
        - T1048   # Exfiltration Over Alternative Protocol (DNS exfil)
        - T1132   # Data Encoding (DNS subdomain entropy analysis)
        - T1029   # Scheduled Transfer (beacon interval detection)
    iec_62443:
        - SR 2.8  # Auditable events
        - SR 6.1  # Audit log accessibility

target:
    platform: Any OT network — protocol-agnostic PCAP analysis
    affected_systems:
        - Any ICS/SCADA asset visible in captured traffic
        - Verified against: Allen-Bradley, Siemens, Schneider Electric,
          Emerson, Honeywell, ABB, Yokogawa, Mitsubishi, Omron
    required_access: PCAP file or live tap/span port interface
    default_port: N/A (passive — no connections made)

vulnerability:
    primary_cve: N/A (passive reconnaissance — no vulnerability exploited)
    cvss_score: 0.0
    cvss_vector: N/A
    severity: INFO
    cwe:
        - CWE-200 (Exposure of Sensitive Information — what the capture reveals)

chain:
    description: >
        MarlinSpike performs zero-transmission OT network reconnaissance by
        analyzing network traffic from a passive capture source. Stage 1 ingests
        a PCAP file or starts a live tshark capture on a specified interface.
        Stage 2 dissects ALL protocol conversations using full five-tuple
        extraction (src/dst IP, src/dst port, transport) — OT protocols via a
        layered parser (Modbus TCP, EtherNet/IP/CIP, Profinet DCP/RT, S7comm,
        DNP3, IEC 60870-5-104, BACnet/IP, OPC-UA), IT services via a 70+ entry
        well-known port database, and unknown services via generic port labels.
        Per-conversation timing (frame.time_epoch) and DNS metadata (query names,
        types) are collected for behavioral analysis. Stage 3 constructs a
        network graph with service port profiles per node and port labels per
        edge, infers Purdue Model level assignments based on subnet topology and
        communication patterns, and fingerprints vendors from MAC OUI, CIP
        Identity, S7 system ID, and Modbus Device Identification (FC 43).
        Stage 4 scores the topology for risk indicators including C2 detection:
        jitter-resistant beacon detection via IAT histogram clustering, DNS data
        exfiltration via Shannon entropy analysis of subdomain labels, asymmetric
        flow analysis for data staging, suspect C2 channels from OT devices to
        external IPs, connection persistence scoring, port risk analysis
        (cleartext remote access, unknown high-port services, IT services on OT
        devices), and Purdue-level-aware cross-zone anomalies.
    stages:
        - stage: 1
          name: Capture Ingestion
          description: >
              Validate and index PCAP/PCAPNG input or start live tshark capture.
              Report packet count, capture duration, unique MACs/IPs, and
              detected link-layer type. Optionally filter to OT-relevant traffic
              to reduce analysis scope.
          risk: None — read-only, no transmission
        - stage: 2
          name: Protocol Dissection
          description: >
              Parse ALL protocol conversations with full five-tuple (src/dst IP,
              src/dst port, transport). OT protocol extraction: Modbus function
              codes and register ranges; CIP class/instance/service and device
              identity; S7comm CPU info and data block access; DNP3 object groups;
              IEC 60870-5-104 ASDU type IDs; Profinet DCP device names/roles;
              OPC-UA session establishment and node IDs. IT service classification
              via well-known port database (70+ entries). Per-conversation epoch
              timestamps for IAT analysis. DNS metadata extraction (query names,
              types) for entropy scoring.
          risk: None — offline PCAP analysis
        - stage: 3
          name: Topology Construction
          description: >
              Build node/edge graph with service port profiles per node and port
              labels per edge. Infer Purdue levels. Fingerprint vendors. Identify
              communication roles (initiator vs responder, master vs slave/server).
              Detect engineering workstations by protocol initiation patterns.
              Ephemeral port filtering on service profiles (>= 49152, single conn).
          risk: None — offline analysis
        - stage: 4
          name: Risk Surface Report
          description: >
              Score topology for risk indicators and C2 detection. Port analysis:
              cleartext remote access (Telnet/FTP/VNC), IT services on OT devices,
              unknown high-port services. C2 indicators: beaconing via IAT histogram
              clustering (jitter-resistant, adaptive bin width), DNS data exfil via
              Shannon entropy of subdomain labels, asymmetric flow analysis (data
              staging), suspect C2 channels (OT to external on unknown ports),
              connection persistence scoring. Cross-Purdue-level anomalies, cleartext
              engineering sessions, broadcast storms, auth gap analysis.
          risk: None — reporting only

notes: |
    - GrassMarlin integration: if `grassmarlin` binary is in PATH, MarlinSpike
      delegates dissection to GrassMarlin's headless mode and imports its output.
      If absent, falls back to built-in tshark/scapy parser (covers 90%+ of cases).
    - Live capture requires tshark (Wireshark CLI) installed and root/CAP_NET_RAW
    - Capture duration for useful topology: minimum 15 minutes; 2-4 hours recommended
      to catch scheduled polling cycles and infrequent engineering sessions
    - The built-in OUI database covers all known ICS vendor MAC prefixes as of Q1 2026;
      update with --update-oui
    - Topology artifact is cross-compatible with SiltScreen — either can feed FlowJack
    - Remediation findings from Stage 4 map directly to IEC 62443 SR requirements
      for zone/conduit design review

===============================================================================
"""

import subprocess
import signal
import json
import os
import sys
import glob
import argparse
import re
import hashlib
import time
import shutil
import tempfile
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Optional
from datetime import datetime, timezone
import ipaddress


# ---------------------------------------------------------------------------
# Graceful shutdown support
# ---------------------------------------------------------------------------

_shutdown_requested = False
_active_report = None       # MarlinSpikeReport ref — saved on shutdown
_active_report_path = None  # Output path for emergency save


def _shutdown_handler(signum, frame):
    """Handle SIGTERM/SIGINT — stop cleanly, dump what we have."""
    global _shutdown_requested
    if _shutdown_requested:
        return  # Already shutting down
    _shutdown_requested = True
    sig_name = signal.Signals(signum).name if hasattr(signal, 'Signals') else str(signum)
    print(f"\n[!] Received {sig_name} — stopping gracefully...")

    # Emergency save of partial report
    if _active_report and _active_report_path:
        _active_report.timestamp_end = datetime.now(timezone.utc).isoformat()
        _active_report.interrupted = True
        try:
            _active_report.save(_active_report_path)
            print(f"[*] Partial report saved: {_active_report_path}")
        except Exception as e:
            print(f"[!] Failed to save partial report: {e}")


# ---------------------------------------------------------------------------
# Artifact chaining support
# ---------------------------------------------------------------------------

def _find_recent_artifact(reports_dir, module_id, command):
    """Find most recent artifact file for a module command."""
    pattern = os.path.join(reports_dir, f"{module_id}-{command}-*.json")
    matches = glob.glob(pattern)
    if not matches:
        return None
    matches.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    return matches[0]


# ---------------------------------------------------------------------------
# External DPI support (marlinspike-dpi)
# ---------------------------------------------------------------------------

RUST_PROTOCOL_DISPLAY_NAMES = {
    "arp": "ARP",
    "cdp": "CDP",
    "dhcp": "DHCP",
    "dns": "DNS",
    "dnp3": "DNP3",
    "ethernet_ip": "EtherNet/IP",
    "http": "HTTP",
    "lldp": "LLDP",
    "modbus": "Modbus TCP",
    "opc_ua": "OPC-UA",
    "profinet": "PROFINET",
    "s7comm": "S7comm",
    "snmp": "SNMP",
    "stp": "STP",
    "tls": "TLS",
}

RUST_PROTOCOL_SERVICE_PORTS = {
    "dhcp": {67, 68},
    "dns": {53, 5353},
    "dnp3": {20000},
    "ethernet_ip": {44818},
    "http": {80, 8080},
    "modbus": {502},
    "opc_ua": {4840},
    "profinet": {34964},
    "s7comm": {102},
    "snmp": {161, 162},
}

RUST_S7_PROGRAM_OPERATIONS = {
    "request_download",
    "download_block",
    "download_ended",
    "start_upload",
    "upload",
    "end_upload",
    "plc_stop",
}


def _looks_like_ip(value: str) -> bool:
    """Return True when the string is a valid IP address."""
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _parse_iso_timestamp(value: str) -> Optional[float]:
    """Parse RFC3339/ISO timestamps to epoch seconds."""
    if not value:
        return None
    normalized = value.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized).timestamp()
    except ValueError:
        return None


def _compute_beacon_score_from_timestamps(timestamps):
    """Jitter-resistant beacon detection via IAT histogram clustering."""
    if len(timestamps) < 10:
        return 0.0, 0.0, 0.0
    ts = sorted(timestamps)
    deltas = [ts[i + 1] - ts[i] for i in range(len(ts) - 1)]
    deltas = [d for d in deltas if d > 0.01]
    if len(deltas) < 5:
        return 0.0, 0.0, 0.0

    median_d = sorted(deltas)[len(deltas) // 2]
    if median_d < 0.1:
        return 0.0, 0.0, 0.0

    bin_width = max(median_d * 0.1, 0.5)
    bins = defaultdict(int)
    for delta in deltas:
        bin_key = round(delta / bin_width) * bin_width
        bins[bin_key] += 1

    peak_bin = max(bins, key=bins.get)
    cluster_count = sum(
        count for bk, count in bins.items() if abs(bk - peak_bin) <= bin_width
    )
    cluster_fraction = cluster_count / len(deltas)
    interval = peak_bin
    cluster_deltas = [d for d in deltas if abs(d - peak_bin) <= bin_width]
    jitter = (
        (max(cluster_deltas) - min(cluster_deltas)) / interval
        if interval > 0 and cluster_deltas
        else 1.0
    )
    score = max(0.0, min(1.0, cluster_fraction * (1 - min(jitter, 1.0))))
    return score, interval, jitter


def _compute_dns_entropy_from_queries(query_names):
    """Average Shannon entropy of subdomain labels."""
    import math

    if not query_names:
        return 0.0

    entropies = []
    for qname in query_names:
        parts = qname.rstrip(".").split(".")
        if len(parts) <= 2:
            continue
        subdomain = ".".join(parts[:-2])
        if len(subdomain) < 4:
            continue
        freq = {}
        for char in subdomain.lower():
            freq[char] = freq.get(char, 0) + 1
        entropy = -sum(
            (count / len(subdomain)) * math.log2(count / len(subdomain))
            for count in freq.values()
        )
        entropies.append(entropy)

    return sum(entropies) / len(entropies) if entropies else 0.0


def _extract_bronze_family(event: dict):
    """Return the serde externally tagged Bronze family name and payload."""
    family = event.get("family")
    if not isinstance(family, dict) or len(family) != 1:
        return "", {}
    family_name, payload = next(iter(family.items()))
    return family_name, payload if isinstance(payload, dict) else {}


def _protocol_display_name(protocol_key: str) -> str:
    """Map Rust Bronze protocol keys to MarlinSpike display names."""
    if not protocol_key:
        return "Unknown"
    return RUST_PROTOCOL_DISPLAY_NAMES.get(protocol_key, protocol_key.replace("_", " ").title())


def _protocol_service_port(protocol_key: str, src_port: int, dst_port: int) -> int:
    """Choose the stable service port for a Bronze event."""
    service_ports = RUST_PROTOCOL_SERVICE_PORTS.get(protocol_key, set())
    if dst_port in service_ports:
        return dst_port
    if src_port in service_ports:
        return src_port
    if dst_port and dst_port < EPHEMERAL_PORT_MIN:
        return dst_port
    if src_port and src_port < EPHEMERAL_PORT_MIN:
        return src_port
    return dst_port or src_port or 0


def _append_unique_limited(bucket: list, value, limit: int = 32):
    """Append a normalized value while preserving order and capping fan-out."""
    if value is None:
        return
    text = str(value).strip()
    if not text or text in bucket:
        return
    if len(bucket) < limit:
        bucket.append(text)


def _merge_bronze_attributes(bucket: dict, attributes: dict, limit: int = 12):
    """Preserve protocol attributes generically so new DPI enrichments survive."""
    if not isinstance(attributes, dict):
        return
    for key, value in attributes.items():
        key_text = str(key).strip()
        if not key_text or value is None:
            continue
        values = bucket.setdefault(key_text, [])
        _append_unique_limited(values, value, limit=limit)


def _finalize_bronze_attributes(bucket: dict) -> dict:
    """Collapse aggregated attribute values to strings or small value lists."""
    finalized = {}
    for key in sorted(bucket):
        values = bucket.get(key) or []
        if not values:
            continue
        finalized[key] = values[0] if len(values) == 1 else values
    return finalized


def _summarize_asset_observation(asset: dict) -> dict:
    """Keep a compact, reusable summary of Bronze asset observations."""
    summary = {}
    protocols = []
    for protocol in asset.get("protocols") or []:
        _append_unique_limited(protocols, protocol, limit=16)
    if protocols:
        summary["protocols"] = protocols

    roles = []
    for role in asset.get("roles") or []:
        _append_unique_limited(roles, role, limit=12)
    if roles:
        summary["roles"] = roles

    hostnames = []
    for hostname in asset.get("hostnames") or []:
        _append_unique_limited(hostnames, hostname, limit=8)
    if hostnames:
        summary["hostnames"] = hostnames

    identifiers = {}
    for key, value in sorted((asset.get("identifiers") or {}).items()):
        text = str(value).strip() if value is not None else ""
        if text:
            identifiers[str(key)] = text
    if identifiers:
        summary["identifiers"] = identifiers

    for field_name in ("asset_key", "vendor", "model", "firmware"):
        text = str(asset.get(field_name) or "").strip()
        if text:
            summary[field_name] = text

    return summary


def _merge_asset_summary(existing: dict, incoming: dict):
    """Merge compact Bronze asset summaries without losing prior observations."""
    if not incoming:
        return

    for list_key, limit in (("protocols", 16), ("roles", 12), ("hostnames", 8)):
        if incoming.get(list_key):
            merged = existing.setdefault(list_key, [])
            for value in incoming[list_key]:
                _append_unique_limited(merged, value, limit=limit)

    if incoming.get("identifiers"):
        identifiers = existing.setdefault("identifiers", {})
        for key, value in incoming["identifiers"].items():
            text = str(value).strip()
            if text and not identifiers.get(key):
                identifiers[key] = text

    for scalar_key in ("asset_key", "vendor", "model", "firmware"):
        text = str(incoming.get(scalar_key) or "").strip()
        if text and not existing.get(scalar_key):
            existing[scalar_key] = text


def _normalize_bronze_flow(envelope: dict, tx: dict):
    """Normalize Bronze request/response events to initiator -> responder."""
    protocol_key = (envelope.get("protocol") or "").lower()
    src_port = int(envelope.get("src_port") or 0)
    dst_port = int(envelope.get("dst_port") or 0)
    service_port = _protocol_service_port(protocol_key, src_port, dst_port)
    status = (tx.get("status") or "").lower()

    reverse = False
    if status == "response":
        reverse = service_port and src_port == service_port and dst_port != service_port
    elif status == "request":
        reverse = service_port and src_port == service_port and dst_port != service_port
    elif service_port and src_port == service_port and dst_port != service_port:
        reverse = True

    if reverse:
        return {
            "src_ip": envelope.get("dst_ip") or "",
            "dst_ip": envelope.get("src_ip") or "",
            "src_mac": envelope.get("dst_mac") or "",
            "dst_mac": envelope.get("src_mac") or "",
            "src_port": dst_port,
            "dst_port": src_port,
            "service_port": service_port,
            "transport": (envelope.get("transport") or "").lower(),
            "protocol_key": protocol_key,
        }

    return {
        "src_ip": envelope.get("src_ip") or "",
        "dst_ip": envelope.get("dst_ip") or "",
        "src_mac": envelope.get("src_mac") or "",
        "dst_mac": envelope.get("dst_mac") or "",
        "src_port": src_port,
        "dst_port": dst_port,
        "service_port": service_port,
        "transport": (envelope.get("transport") or "").lower(),
        "protocol_key": protocol_key,
    }


def _register_asset_observation(asset_state: dict, l2_asset_state: dict, event: dict, asset: dict):
    """Capture asset observations from Bronze for later conversation enrichment."""
    envelope = event.get("envelope", {})
    identifiers = asset.get("identifiers") or {}
    protocols = set(asset.get("protocols") or [])
    asset_key = asset.get("asset_key") or ""
    ip_key = identifiers.get("ip") or (asset_key if _looks_like_ip(asset_key) else "")
    asset_summary = _summarize_asset_observation(asset)

    if ip_key and asset_summary:
        _merge_asset_summary(asset_state.setdefault(ip_key, {}).setdefault("bronze_asset", {}), asset_summary)

    if "ethernet_ip" in protocols or "cip" in protocols:
        if ip_key:
            asset_state.setdefault(ip_key, {})["cip_identity"] = {
                "vendor_id": identifiers.get("cip_vendor_id", ""),
                "device_type": identifiers.get("cip_device_type", ""),
                "product_code": identifiers.get("cip_product_code", ""),
                "serial_number": identifiers.get("cip_serial_number", ""),
                "revision": identifiers.get("cip_revision", ""),
                "product_name": asset.get("model", "") or "",
                "vendor_name": asset.get("vendor", "") or "",
            }

    if "modbus" in protocols:
        if ip_key:
            asset_state.setdefault(ip_key, {})["modbus_identity"] = dict(identifiers)

    if protocols & {"lldp", "cdp", "stp"}:
        mac_key = identifiers.get("mac") or envelope.get("src_mac") or ""
        if mac_key:
            existing = l2_asset_state.setdefault(mac_key, {})
            if "lldp" in protocols:
                existing.update(
                    {
                        "source": "lldp",
                        "system_name": asset.get("vendor", "") or "",
                        "system_desc": asset.get("model", "") or "",
                    }
                )
            elif "cdp" in protocols:
                hostnames = asset.get("hostnames") or []
                existing.update(
                    {
                        "source": "cdp",
                        "system_name": hostnames[0] if hostnames else asset.get("asset_key", ""),
                        "system_desc": asset.get("model", "") or "",
                        "software_version": asset.get("firmware", "") or "",
                    }
                )
            elif "stp" in protocols:
                existing.update({"source": "stp"})


def _apply_topology_observation(conversation_state: dict, l2_asset_state: dict, event: dict, observation: dict):
    """Convert Bronze topology observations into L2 discovery conversations."""
    envelope = event.get("envelope", {})
    protocol_key = (envelope.get("protocol") or "").lower()
    protocol = _protocol_display_name(protocol_key)
    src_mac = envelope.get("src_mac") or observation.get("local_id") or ""
    dst_mac = envelope.get("dst_mac") or observation.get("remote_id") or ""
    key = ("l2", protocol_key, src_mac, dst_mac)
    aggregate = conversation_state.setdefault(
        key,
        {
            "src_ip": "",
            "dst_ip": "",
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "protocol": protocol,
            "port": 0,
            "packet_count": 0,
            "bytes_total": 0,
            "first_seen": envelope.get("timestamp") or "",
            "last_seen": envelope.get("timestamp") or "",
            "modbus_functions": set(),
            "modbus_writes": 0,
            "cip_identity": {},
            "pn_identity": {},
            "s7_functions": set(),
            "s7_program_access": False,
            "dnp3_objects": set(),
            "opc_sessions": [],
            "opc_no_security": False,
            "bacnet_identity": {},
            "iec104_typeids": set(),
            "iec104_causes": set(),
            "omron_identity": {},
            "mms_identity": {},
            "goose_identity": {},
            "src_port": 0,
            "transport": (envelope.get("transport") or "").lower(),
            "src_ports_seen": set(),
            "timestamps": [],
            "dns_queries": set(),
            "dns_query_types": set(),
            "dns_entropy": 0.0,
            "l2_discovery": {},
            "operations_seen": [],
            "protocol_attributes": {},
            "protocol_object_refs": [],
            "src_asset": {},
            "dst_asset": {},
        },
    )

    aggregate["packet_count"] += int(envelope.get("packet_count") or 1)
    aggregate["bytes_total"] += int(envelope.get("bytes_count") or 0)
    aggregate["first_seen"] = min(aggregate["first_seen"], envelope.get("timestamp") or aggregate["first_seen"])
    aggregate["last_seen"] = max(aggregate["last_seen"], envelope.get("timestamp") or aggregate["last_seen"])
    ts = _parse_iso_timestamp(envelope.get("timestamp") or "")
    if ts is not None:
        aggregate["timestamps"].append(ts)

    l2_data = aggregate["l2_discovery"]
    l2_data.update(l2_asset_state.get(src_mac, {}))
    obs_type = observation.get("observation_type")
    if obs_type == "lldp_neighbor":
        l2_data.setdefault("source", "lldp")
        if observation.get("remote_id"):
            l2_data["chassis_id"] = observation["remote_id"]
        if observation.get("description"):
            ports = l2_data.setdefault("ports", [])
            port_entry = {"id": observation["description"], "desc": ""}
            if port_entry not in ports:
                ports.append(port_entry)
        if observation.get("capabilities"):
            l2_data["capabilities"] = list(observation["capabilities"])
    elif obs_type == "cdp_neighbor":
        l2_data.setdefault("source", "cdp")
        if observation.get("remote_id") and not l2_data.get("system_name"):
            l2_data["system_name"] = observation["remote_id"]
        if observation.get("description"):
            ports = l2_data.setdefault("ports", [])
            port_entry = {"id": observation["description"], "desc": ""}
            if port_entry not in ports:
                ports.append(port_entry)
        if observation.get("metadata", {}).get("native_vlan"):
            vlans = l2_data.setdefault("vlans", [])
            native_vlan = observation["metadata"]["native_vlan"]
            if native_vlan not in vlans:
                vlans.append(native_vlan)
    elif obs_type == "stp_topology":
        l2_data.setdefault("source", "stp")
        if observation.get("remote_id"):
            l2_data["stp_root"] = observation["remote_id"]
        if observation.get("local_id"):
            l2_data["stp_bridge"] = observation["local_id"]
        metadata = observation.get("metadata") or {}
        if metadata.get("root_path_cost"):
            l2_data["stp_root_cost"] = metadata["root_path_cost"]
        if metadata.get("port_id"):
            l2_data["stp_port"] = metadata["port_id"]
        if observation.get("description"):
            l2_data["stp_type"] = observation["description"]


def _apply_protocol_transaction(aggregate: dict, tx: dict, flow: dict):
    """Map Bronze protocol transactions onto MarlinSpike conversation fields."""
    operation = tx.get("operation") or ""
    protocol_key = flow["protocol_key"]
    protocol = aggregate["protocol"]
    aggregate["src_ports_seen"].add(flow["src_port"])
    if aggregate["src_port"] == 0 and flow["src_port"]:
        aggregate["src_port"] = flow["src_port"]
    if operation:
        _append_unique_limited(aggregate["operations_seen"], operation, limit=32)
    _merge_bronze_attributes(aggregate["protocol_attributes"], tx.get("attributes") or {})
    for object_ref in tx.get("object_refs") or []:
        _append_unique_limited(aggregate["protocol_object_refs"], object_ref, limit=32)

    if protocol == "Modbus TCP":
        if operation:
            aggregate["modbus_functions"].add(operation)
        if operation.startswith("write_"):
            aggregate["modbus_writes"] += 1

    elif protocol == "S7comm":
        if operation:
            aggregate["s7_functions"].add(operation)
        if operation in RUST_S7_PROGRAM_OPERATIONS:
            aggregate["s7_program_access"] = True

    elif protocol == "DNP3":
        if operation:
            aggregate["dnp3_objects"].add(operation)

    elif protocol == "OPC-UA":
        attributes = tx.get("attributes") or {}
        service_type = attributes.get("service_type") or operation
        if service_type:
            aggregate["opc_sessions"].append(service_type)

    elif protocol == "DNS":
        for query in tx.get("object_refs") or []:
            if query:
                aggregate["dns_queries"].add(query)

    elif protocol_key == "profinet":
        attributes = tx.get("attributes") or {}
        if attributes:
            aggregate["pn_identity"].update(
                {
                    "service_type": attributes.get("service_type", ""),
                    "frame_id": attributes.get("frame_id", ""),
                }
            )


def _build_port_summary_from_conversations(conversations: list) -> dict:
    """Build port summary compatible with the existing viewer/report surface."""
    summary = {}
    bucket = defaultdict(
        lambda: {
            "port": 0,
            "transport": "",
            "protocol": "",
            "category": "",
            "connections": 0,
            "bytes": 0,
            "peers": set(),
        }
    )
    for conv in conversations:
        if conv.port <= 0:
            continue
        key = (conv.port, conv.transport)
        item = bucket[key]
        item["port"] = conv.port
        item["transport"] = conv.transport
        item["protocol"] = conv.protocol
        if conv.port in OT_PROTOCOLS:
            item["category"] = "OT"
        elif conv.port in WELL_KNOWN_PORTS:
            item["category"] = WELL_KNOWN_PORTS[conv.port][1]
        elif conv.port >= EPHEMERAL_PORT_MIN:
            item["category"] = "Ephemeral"
        else:
            item["category"] = "Unknown"
        item["connections"] += 1
        item["bytes"] += conv.bytes_total
        if conv.dst_ip:
            item["peers"].add(conv.dst_ip)

    for (port, transport), item in bucket.items():
        key = f"{port}/{transport}" if transport else str(port)
        summary[key] = {
            "port": item["port"],
            "transport": item["transport"],
            "protocol": item["protocol"],
            "category": item["category"],
            "connections": item["connections"],
            "bytes": item["bytes"],
            "unique_peers": len(item["peers"]),
        }
    return summary


def _build_conversations_from_bronze(output: dict) -> list:
    """Adapt Bronze JSON emitted by marlinspike-dpi to MarlinSpike conversations."""
    payload = output.get("output") or {}
    events = payload.get("events") or []
    aggregates = {}
    asset_state = {}
    l2_asset_state = {}

    for event in events:
        family_name, family_payload = _extract_bronze_family(event)
        if family_name == "asset_observation":
            _register_asset_observation(asset_state, l2_asset_state, event, family_payload)
            continue
        if family_name == "topology_observation":
            _apply_topology_observation(aggregates, l2_asset_state, event, family_payload)
            continue
        if family_name != "protocol_transaction":
            continue

        envelope = event.get("envelope", {})
        flow = _normalize_bronze_flow(envelope, family_payload)
        key = (
            flow["src_ip"],
            flow["dst_ip"],
            flow["src_mac"],
            flow["dst_mac"],
            flow["protocol_key"],
            flow["service_port"],
            flow["transport"],
        )
        aggregate = aggregates.setdefault(
            key,
            {
                "src_ip": flow["src_ip"],
                "dst_ip": flow["dst_ip"],
                "src_mac": flow["src_mac"],
                "dst_mac": flow["dst_mac"],
                "protocol": _protocol_display_name(flow["protocol_key"]),
                "port": flow["service_port"],
                "packet_count": 0,
                "bytes_total": 0,
                "first_seen": envelope.get("timestamp") or "",
                "last_seen": envelope.get("timestamp") or "",
                "modbus_functions": set(),
                "modbus_writes": 0,
                "cip_identity": {},
                "pn_identity": {},
                "s7_functions": set(),
                "s7_program_access": False,
                "dnp3_objects": set(),
                "opc_sessions": [],
                "opc_no_security": False,
                "bacnet_identity": {},
                "iec104_typeids": set(),
                "iec104_causes": set(),
                "omron_identity": {},
                "mms_identity": {},
                "goose_identity": {},
                "src_port": flow["src_port"],
                "transport": flow["transport"],
                "src_ports_seen": set(),
                "timestamps": [],
                "dns_queries": set(),
                "dns_query_types": set(),
                "dns_entropy": 0.0,
                "l2_discovery": {},
                "operations_seen": [],
                "protocol_attributes": {},
                "protocol_object_refs": [],
                "src_asset": {},
                "dst_asset": {},
            },
        )

        aggregate["packet_count"] += int(envelope.get("packet_count") or 1)
        aggregate["bytes_total"] += int(envelope.get("bytes_count") or 0)
        aggregate["first_seen"] = min(aggregate["first_seen"], envelope.get("timestamp") or aggregate["first_seen"])
        aggregate["last_seen"] = max(aggregate["last_seen"], envelope.get("timestamp") or aggregate["last_seen"])
        ts = _parse_iso_timestamp(envelope.get("timestamp") or "")
        if ts is not None:
            aggregate["timestamps"].append(ts)

        _apply_protocol_transaction(aggregate, family_payload, flow)

    conversations = []
    for aggregate in aggregates.values():
        for ip_key in (aggregate["dst_ip"], aggregate["src_ip"]):
            identity = asset_state.get(ip_key, {})
            if identity.get("cip_identity") and not aggregate["cip_identity"]:
                aggregate["cip_identity"] = identity["cip_identity"]
            if identity.get("modbus_identity") and aggregate["protocol"] == "Modbus TCP":
                modbus_identity = identity["modbus_identity"]
                if modbus_identity and not aggregate["modbus_functions"]:
                    aggregate["modbus_functions"].add("read_device_identification")

        src_identity = asset_state.get(aggregate["src_ip"], {})
        dst_identity = asset_state.get(aggregate["dst_ip"], {})
        _merge_asset_summary(aggregate["src_asset"], src_identity.get("bronze_asset") or {})
        _merge_asset_summary(aggregate["dst_asset"], dst_identity.get("bronze_asset") or {})

        beacon_score, beacon_interval, beacon_jitter = _compute_beacon_score_from_timestamps(aggregate["timestamps"])
        dns_queries = sorted(aggregate["dns_queries"])
        dns_entropy = _compute_dns_entropy_from_queries(dns_queries)

        conversations.append(
            Conversation(
                src_ip=aggregate["src_ip"],
                dst_ip=aggregate["dst_ip"],
                src_mac=aggregate["src_mac"],
                dst_mac=aggregate["dst_mac"],
                protocol=aggregate["protocol"],
                port=aggregate["port"],
                packet_count=aggregate["packet_count"],
                bytes_total=aggregate["bytes_total"],
                first_seen=aggregate["first_seen"],
                last_seen=aggregate["last_seen"],
                modbus_functions=sorted(aggregate["modbus_functions"]),
                modbus_writes=aggregate["modbus_writes"],
                cip_identity=aggregate["cip_identity"],
                pn_identity=aggregate["pn_identity"],
                s7_functions=sorted(aggregate["s7_functions"]),
                s7_program_access=aggregate["s7_program_access"],
                dnp3_objects=sorted(aggregate["dnp3_objects"]),
                opc_sessions=aggregate["opc_sessions"],
                opc_no_security=aggregate["opc_no_security"],
                bacnet_identity=aggregate["bacnet_identity"],
                iec104_typeids=sorted(aggregate["iec104_typeids"]),
                iec104_causes=sorted(aggregate["iec104_causes"]),
                omron_identity=aggregate["omron_identity"],
                mms_identity=aggregate["mms_identity"],
                goose_identity=aggregate["goose_identity"],
                src_port=aggregate["src_port"],
                transport=aggregate["transport"],
                src_ports_seen=sorted(p for p in aggregate["src_ports_seen"] if p),
                beacon_score=beacon_score,
                beacon_interval=beacon_interval,
                beacon_jitter=beacon_jitter,
                dns_queries=dns_queries[:200],
                dns_query_types=sorted(aggregate["dns_query_types"]),
                dns_entropy=dns_entropy,
                l2_discovery=aggregate["l2_discovery"],
                operations_seen=aggregate["operations_seen"],
                protocol_attributes=_finalize_bronze_attributes(aggregate["protocol_attributes"]),
                protocol_object_refs=aggregate["protocol_object_refs"],
                src_asset=aggregate["src_asset"],
                dst_asset=aggregate["dst_asset"],
            )
        )

    return conversations


def _run_marlinspike_dpi(binary_path: str, pcap_path: str, capture_id: str) -> dict:
    """Run the external marlinspike-dpi CLI and return its Bronze JSON."""
    resolved = shutil.which(binary_path) or binary_path
    if not resolved or not os.path.exists(resolved):
        raise FileNotFoundError(f"marlinspike-dpi binary not found: {binary_path}")

    with tempfile.NamedTemporaryFile(prefix="marlinspike-dpi-", suffix=".json", delete=False) as tmp:
        output_path = tmp.name

    cmd = [
        resolved,
        "--input",
        pcap_path,
        "--capture-id",
        capture_id,
        "--output",
        output_path,
        "--pretty",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            stdout = (result.stdout or "").strip()
            detail = stderr or stdout or f"exit code {result.returncode}"
            raise RuntimeError(f"marlinspike-dpi failed: {detail}")
        with open(output_path) as f:
            return json.load(f)
    finally:
        try:
            os.unlink(output_path)
        except FileNotFoundError:
            pass


def _dissect_with_selected_engine(pcap_path: str, args, capture_id: str):
    """Dispatch Stage 2 to the selected DPI engine with safe fallback."""
    requested_engine = getattr(args, "dpi_engine", "auto") or "auto"
    binary_path = getattr(args, "dpi_binary", "") or os.environ.get("MARLINSPIKE_DPI_BIN", "marlinspike-dpi")
    wants_rust = requested_engine in {"auto", "marlinspike-dpi"}
    rust_binary_ok = bool(shutil.which(binary_path) or os.path.exists(binary_path))

    if wants_rust:
        if not rust_binary_ok:
            if requested_engine == "marlinspike-dpi":
                raise FileNotFoundError(f"marlinspike-dpi binary not found: {binary_path}")
            print("[*] marlinspike-dpi not found — falling back to built-in parser")
        else:
            try:
                dpi_output = _run_marlinspike_dpi(binary_path, pcap_path, capture_id)
                conversations = _build_conversations_from_bronze(dpi_output)
                port_summary = _build_port_summary_from_conversations(conversations)
                metadata = {
                    "engine": "marlinspike-dpi",
                    "version": dpi_output.get("version", ""),
                    "input": dpi_output.get("input", {}),
                    "checkpoint": (dpi_output.get("output") or {}).get("checkpoint", {}),
                    "schema_version": ((dpi_output.get("output") or {}).get("checkpoint", {}) or {}).get("schema_version", ""),
                }
                print(f"[*] marlinspike-dpi parsed {len(conversations):,} conversations")
                return conversations, port_summary, metadata
            except Exception as exc:
                if requested_engine == "marlinspike-dpi":
                    raise
                print(f"[*] marlinspike-dpi failed ({exc}) — falling back to built-in parser")

    dissector = OTProtocolDissector(
        pcap_path,
        chunk_size=getattr(args, "chunk_size", 0),
        collapse_threshold=getattr(args, "collapse_threshold", 50),
    )
    conversations = dissector.dissect()
    return conversations, getattr(dissector, "port_summary", {}), {"engine": "python", "version": ""}


# ---------------------------------------------------------------------------
# Module metadata
# ---------------------------------------------------------------------------

MODULE_META = {
    # ── Identity ──────────────────────────────────────────
    "name": "MarlinSpike",
    "id": "VORACITY-MODULE-MARLINSPIKE",
    "version": "2.0.0",
    "author": "River Caudle <danny@riverman.io>",
    "organization": "River Risk Partners",
    "date_created": "2026-02-20",
    "date_modified": "2026-03-27",

    # ── Classification ────────────────────────────────────
    "group": "Recon & Discovery",
    "category": "Passive OT Network Topology Mapping",
    "severity": "INFO",
    "primary_cve": "N/A (passive — no exploit)",
    "cvss_score": 0.0,
    "kill_chain_phase": ["Reconnaissance"],
    "mitre_attack": ["T1040", "T1046", "T1016", "T1590"],
    "iec_62443": ["SR 2.8", "SR 6.1"],

    # ── Targeting ─────────────────────────────────────────
    "affected_systems": ["Any ICS/SCADA asset visible in captured traffic"],
    "required_access": "PCAP file or tap/span port interface — zero transmission",
    "default_port": 0,
    "default_target": "N/A",

    # ── Chain ─────────────────────────────────────────────
    "chain_stages": [
        "Capture Ingestion",
        "Protocol Dissection",
        "Topology Construction",
        "Risk Surface Report",
    ],

    # ── Runtime ───────────────────────────────────────────
    "cli_commands": ["chain", "ingest", "dissect", "topology", "risk"],
    "default_command": "chain",
    "parameters": [
        {"name": "pcap", "flag": "--pcap", "type": "file",
         "required": True, "default": "",
         "description": "Input PCAP/PCAPNG file"},
        {"name": "subnet_map", "flag": "--subnet-map", "type": "file",
         "required": False, "default": "",
         "description": "JSON file mapping subnets to Purdue levels (auto-inferred if absent)"},
        {"name": "oui_db", "flag": "--oui-db", "type": "file",
         "required": False, "default": "",
         "description": "ICS vendor OUI database"},
        {"name": "grassmarlin", "flag": "--grassmarlin", "type": "string",
         "required": False, "default": "",
         "description": "Path to GrassMarlin binary (auto-detected from PATH if absent)"},
        {"name": "no_grassmarlin", "flag": "--no-grassmarlin", "type": "boolean",
         "required": False, "default": True,
         "description": "Force built-in parser (default: True)"},
        {"name": "conversations", "flag": "--conversations", "type": "file",
         "required": False, "default": "",
         "description": "Pre-parsed conversations JSON (for topology command)"},
        {"name": "topology_file", "flag": "--topology", "type": "file",
         "required": False, "default": "",
         "description": "Pre-built topology JSON (for risk command)"},
        {"name": "output", "flag": "-o", "type": "string",
         "required": False, "default": "marlinspike-report-{ts}.json",
         "description": "Full report output path"},
    ],

    # ── Artifacts ─────────────────────────────────────────
    "artifacts": {
        "ingest": {
            "produces": "indexed_capture",
            "consumes": None,
        },
        "dissect": {
            "produces": "protocol_conversations",
            "consumes": "indexed_capture",
            "consumes_param": "pcap",
        },
        "topology": {
            "produces": "ot_topology",
            "consumes": "protocol_conversations",
            "consumes_param": "conversations",
        },
        "risk": {
            "produces": "risk_surface_report",
            "consumes": "ot_topology",
            "consumes_param": "topology_file",
        },
        "chain": {
            "produces": "marlinspike_report",
            "consumes": None,
        },
    },
}


# ---------------------------------------------------------------------------
# OT Protocol Registry
# ---------------------------------------------------------------------------

OT_PROTOCOLS = {
    502:   "Modbus TCP",
    44818: "EtherNet/IP",
    2222:  "EtherNet/IP (UDP)",
    102:   "S7comm (ISO-TSAP)",
    20000: "DNP3",
    2404:  "IEC 60870-5-104",
    47808: "BACnet/IP",
    4840:  "OPC-UA",
    34964: "Profinet RT",
    34962: "Profinet IO",
    18245: "GE SRTP",
    1911:  "Niagara Fox",
    9600:  "OMRON FINS",
    5007:  "Mitsubishi MELSEC",
    20547: "CODESYS",
}

# Well-known IT/infrastructure ports — fallback after OT_PROTOCOLS
WELL_KNOWN_PORTS = {
    # Remote access
    22:    ("SSH", "IT"),
    23:    ("Telnet", "IT"),
    3389:  ("RDP", "IT"),
    5900:  ("VNC", "IT"),
    5901:  ("VNC", "IT"),
    # Web
    80:    ("HTTP", "IT"),
    443:   ("HTTPS", "IT"),
    8080:  ("HTTP-Alt", "IT"),
    8443:  ("HTTPS-Alt", "IT"),
    # DNS
    53:    ("DNS", "IT/OT"),
    5353:  ("mDNS", "IT/OT"),
    # NTP
    123:   ("NTP", "IT/OT"),
    # DHCP
    67:    ("DHCP Server", "IT/OT"),
    68:    ("DHCP Client", "IT/OT"),
    # SNMP
    161:   ("SNMP", "IT/OT"),
    162:   ("SNMP Trap", "IT/OT"),
    # Email
    25:    ("SMTP", "IT"),
    110:   ("POP3", "IT"),
    143:   ("IMAP", "IT"),
    465:   ("SMTPS", "IT"),
    587:   ("SMTP Submission", "IT"),
    993:   ("IMAPS", "IT"),
    995:   ("POP3S", "IT"),
    # File transfer
    20:    ("FTP Data", "IT"),
    21:    ("FTP", "IT"),
    69:    ("TFTP", "IT/OT"),
    445:   ("SMB", "IT"),
    139:   ("NetBIOS-SSN", "IT"),
    137:   ("NetBIOS-NS", "IT"),
    138:   ("NetBIOS-DGM", "IT"),
    # Directory / Auth
    88:    ("Kerberos", "IT"),
    389:   ("LDAP", "IT"),
    636:   ("LDAPS", "IT"),
    # Logging / monitoring
    514:   ("Syslog", "IT/OT"),
    1514:  ("Syslog TLS", "IT/OT"),
    6514:  ("Syslog TLS", "IT/OT"),
    # Databases
    1433:  ("MSSQL", "IT"),
    1521:  ("Oracle", "IT"),
    3306:  ("MySQL", "IT"),
    5432:  ("PostgreSQL", "IT"),
    6379:  ("Redis", "IT"),
    27017: ("MongoDB", "IT"),
    # Message queues / IoT
    1883:  ("MQTT", "IT/OT"),
    8883:  ("MQTT TLS", "IT/OT"),
    5672:  ("AMQP", "IT"),
    # VoIP
    5060:  ("SIP", "IT"),
    5061:  ("SIP TLS", "IT"),
    # VPN / tunneling
    500:   ("IKE", "IT"),
    4500:  ("IPsec NAT-T", "IT"),
    1194:  ("OpenVPN", "IT"),
    1701:  ("L2TP", "IT"),
    1723:  ("PPTP", "IT"),
    51820: ("WireGuard", "IT"),
    # Misc infrastructure
    853:   ("DNS-over-TLS", "IT"),
    5985:  ("WinRM HTTP", "IT"),
    5986:  ("WinRM HTTPS", "IT"),
    2049:  ("NFS", "IT"),
    111:   ("RPC Portmap", "IT"),
    179:   ("BGP", "IT"),
    1080:  ("SOCKS", "IT"),
    3128:  ("HTTP Proxy", "IT"),
    8088:  ("HTTP-Alt", "IT"),
    9090:  ("Prometheus", "IT"),
    9100:  ("Printer", "IT"),
}

EPHEMERAL_PORT_MIN = 49152

# Tshark protocol name → display name mapping for OT/ICS classification.
# Used by io,phs protocol hierarchy detection (Stage 1).
OT_TSHARK_PROTOCOLS = {
    # SCADA / fieldbus
    "s7comm":       "S7comm",
    "s7comm-plus":  "S7comm Plus",
    "modbus":       "Modbus TCP",
    "mbtcp":        "Modbus TCP",
    "enip":         "EtherNet/IP",
    "cip":          "CIP",
    "cipcm":        "CIP Connection Manager",
    "cipsafety":    "CIP Safety",
    "dnp3":         "DNP3",
    "iec60870_104": "IEC 60870-5-104",
    "iec60870_asdu":"IEC 60870-5 ASDU",
    "bacnet":       "BACnet/IP",
    "opcua":        "OPC-UA",
    "pn_rt":        "PROFINET RT",
    "pn_io":        "PROFINET IO",
    "pn_dcp":       "PROFINET DCP",
    # Power grid
    "synphasor":    "IEEE C37.118 Synchrophasor",
    "goose":        "IEC 61850 GOOSE",
    "sv":           "IEC 61850 Sampled Values",
    "mms":          "MMS (IEC 61850)",
    "r_goose":      "R-GOOSE",
    # Building automation
    "knxnetip":     "KNXnet/IP",
    "lontalk":      "LonTalk",
    # Process / other ICS
    "hartip":       "HART-IP",
    "ff_hse":       "Foundation Fieldbus HSE",
    "gryphon":      "GE SRTP",
    "omron_fins":   "OMRON FINS",
    "codesys":      "CODESYS",
    "ethercat":     "EtherCAT",
    "sercos":       "SERCOS III",
    "opc_da":       "OPC DA (Classic)",
    "epl":          "POWERLINK",
    # Transport layers used by OT (useful context)
    "cotp":         "COTP (ISO 8073)",
    "tpkt":         "TPKT",
    # L2 topology / discovery protocols
    "lldp":         "LLDP",
    "cdp":          "CDP",
    "stp":          "STP",
    "rstp":         "RSTP",
    "mstp":         "MSTP",
    "lacp":         "LACP",
    "edp":          "EDP",
}

# Default BPF filter covering all OT protocol ports
DEFAULT_BPF = " or ".join(f"port {p}" for p in OT_PROTOCOLS)


# ---------------------------------------------------------------------------
# Built-in ICS OUI Database
# ---------------------------------------------------------------------------

ICS_OUI_DB = {
    # Siemens
    "00:00:e3": {"vendor": "Siemens AG", "product_lines": ["S7-300", "S7-400", "ET 200"]},
    "08:00:06": {"vendor": "Siemens AG", "product_lines": ["Legacy Industrial Ethernet"]},
    "00:0e:8c": {"vendor": "Siemens AG", "product_lines": ["SIMATIC", "SCALANCE"]},
    "00:1b:1b": {"vendor": "Siemens AG", "product_lines": ["SIMATIC", "S7-1200", "S7-1500"]},

    # Rockwell / Allen-Bradley
    "00:00:bc": {"vendor": "Allen-Bradley", "product_lines": ["ControlLogix", "CompactLogix"]},
    "b4:e1:02": {"vendor": "Allen-Bradley", "product_lines": ["Stratix", "ArmorBlock"]},
    "00:50:56": {"vendor": "Rockwell Automation", "product_lines": ["EtherNet/IP"]},

    # Schneider Electric
    "00:80:f4": {"vendor": "Schneider Electric", "product_lines": ["Modicon", "Quantum"]},
    "00:06:29": {"vendor": "Schneider Electric", "product_lines": ["Modicon M340", "M580"]},

    # ABB
    "00:16:96": {"vendor": "ABB", "product_lines": ["AC800M", "CI867"]},
    "00:30:11": {"vendor": "ABB", "product_lines": ["Industrial Control"]},

    # Honeywell
    "00:50:c2": {"vendor": "Honeywell", "product_lines": ["C300", "Safety Manager"]},
    "00:e0:63": {"vendor": "Honeywell", "product_lines": ["Process Control"]},

    # Emerson
    "00:a0:bc": {"vendor": "Emerson", "product_lines": ["DeltaV"]},
    "00:d0:bc": {"vendor": "Emerson", "product_lines": ["Ovation"]},

    # Yokogawa
    "00:00:e2": {"vendor": "Yokogawa", "product_lines": ["CENTUM", "ProSafe-RS"]},

    # Mitsubishi
    "00:00:f8": {"vendor": "Mitsubishi Electric", "product_lines": ["MELSEC"]},
    "00:19:d2": {"vendor": "Mitsubishi Electric", "product_lines": ["MELSEC iQ-R", "iQ-F"]},

    # Omron
    "00:00:0e": {"vendor": "Omron", "product_lines": ["CJ", "CS", "NJ"]},


    # Phoenix Contact
    "00:a0:45": {"vendor": "Phoenix Contact", "product_lines": ["ILC", "RFC"]},
}

# Publicly documented CIP Identity Object device-profile values that are
# useful for OT role inference. These are intentionally conservative and can
# be extended as we validate more captures.
CIP_VENDOR_ID_MAP = {
    1: "Allen-Bradley",
    42: "Schneider Electric",
    283: "Hilscher",
}

CIP_DEVICE_TYPE_MAP = {
    0x0C: "Communications Adapter",
    0x0E: "Programmable Logic Controller",
    0x18: "Human-Machine Interface",
    0x2B: "Generic Device",
}

# Public BACnet vendor identifiers from the BACnet Committee assigned-vendor
# list. Keep this focused on commonly observed OT/BMS manufacturers first.
BACNET_VENDOR_ID_MAP = {
    2: "Trane",
    5: "Johnson Controls",
    7: "Siemens",
    8: "Delta Controls",
    10: "Schneider Electric",
    17: "Honeywell",
    18: "Alerton / Honeywell",
    24: "Automated Logic",
    36: "Tridium",
    42: "Acuity Brands",
    61: "Multistack",
}

PROFINET_VENDOR_ID_MAP = {
    0x002A: "Siemens",
    0x00A0: "Wago",
    0x0119: "Phoenix Contact",
    0x011E: "Turck",
    0x0134: "Beckhoff",
}

PROFINET_SWITCH_HINTS = (
    "switch", "scalance", "x208", "x200", "swln",
)

OMRON_SIGNATURES = (
    "sysmac", "cp1", "cp1l", "cp1h", "cj", "cs1", "nj", "nx", "omron",
)

IEC61850_IED_HINTS = (
    "ied_", "relay", "pdis", "protection", "distance", "line diff", "trip",
)

IEC61850_BAY_CONTROLLER_HINTS = (
    "ctrl", "bay", "control",
)

HISTORIAN_SIGNATURES = (
    "historian", "factorytalk historian", "aveva historian",
    "wonderware historian", "proficy historian", "pi server", "pi-system",
)

HMI_SIGNATURES = (
    "wincc", "factorytalk view", "panelview", "intouch",
    "wonderware intouch", "aveva intouch", "ifix", "citect", "zenon",
)

ENGINEERING_SIGNATURES = (
    "studio 5000", "rslogix", "step 7", "tia portal",
    "logix designer", "ccw", "connected components workbench",
)


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------

@dataclass
class CaptureInfo:
    """Stage 1 output — indexed capture metadata."""
    pcap_path: str
    source: str  # "file" or "live"
    packet_count: int
    duration_s: float
    start_ts: str
    end_ts: str
    link_type: str
    unique_macs: int
    unique_ips: int
    protocols_seen: dict


@dataclass
class Conversation:
    """A single protocol conversation extracted from PCAP."""
    src_ip: str
    dst_ip: str
    src_mac: str
    dst_mac: str
    protocol: str
    port: int
    packet_count: int
    bytes_total: int
    first_seen: str
    last_seen: str
    # Protocol-specific fields
    modbus_functions: list = field(default_factory=list)
    modbus_writes: int = 0
    cip_identity: dict = field(default_factory=dict)
    pn_identity: dict = field(default_factory=dict)
    s7_functions: list = field(default_factory=list)
    s7_program_access: bool = False
    dnp3_objects: list = field(default_factory=list)
    opc_sessions: list = field(default_factory=list)
    opc_no_security: bool = False
    bacnet_identity: dict = field(default_factory=dict)
    iec104_typeids: list = field(default_factory=list)
    iec104_causes: list = field(default_factory=list)
    omron_identity: dict = field(default_factory=dict)
    mms_identity: dict = field(default_factory=dict)
    goose_identity: dict = field(default_factory=dict)
    # Five-tuple port analysis
    src_port: int = 0
    transport: str = ""  # "tcp" or "udp"
    src_ports_seen: list = field(default_factory=list)
    beacon_score: float = 0.0
    beacon_interval: float = 0.0
    beacon_jitter: float = 0.0
    dns_queries: list = field(default_factory=list)
    dns_query_types: list = field(default_factory=list)
    dns_entropy: float = 0.0
    operations_seen: list = field(default_factory=list)
    protocol_attributes: dict = field(default_factory=dict)
    protocol_object_refs: list = field(default_factory=list)
    src_asset: dict = field(default_factory=dict)
    dst_asset: dict = field(default_factory=dict)
    # L2 topology discovery fields (LLDP/CDP/STP)
    l2_discovery: dict = field(default_factory=dict)


@dataclass
class TopologyNode:
    """A network node in the OT topology graph."""
    ip: str
    mac: str
    vendor: str = "Unknown"
    product_line: str = ""
    device_type: str = "Unknown"
    purdue_level: int = -1
    protocols: list = field(default_factory=list)
    role: str = "Unknown"  # PLC, RTU, HMI, Engineering Workstation, etc.
    asset_type: str = "local"  # "local", "external", "network" (broadcast/multicast)
    auth_observed: bool = False
    initiates: bool = False
    responds: bool = False
    attack_priority: int = 0
    recommended_modules: list = field(default_factory=list)
    # L2 discovery enrichment
    system_name: str = ""
    system_desc: str = ""
    mgmt_ip: str = ""
    capabilities: list = field(default_factory=list)
    ports: list = field(default_factory=list)  # discovered port descriptions
    vlans: list = field(default_factory=list)
    service_ports: list = field(default_factory=list)  # TCP/UDP services this node listens on


@dataclass
class TopologyEdge:
    """A communication edge in the OT topology graph."""
    src: str
    dst: str
    protocol: str
    conversation_count: int
    bytes_total: int
    first_seen: str
    last_seen: str
    includes_writes: bool = False
    includes_program_access: bool = False
    dst_port: int = 0
    transport: str = ""
    port_label: str = ""
    src_ports_observed: int = 0


@dataclass
class RiskFinding:
    """A risk surface finding."""
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str
    description: str
    affected_nodes: list
    affected_edges: list = field(default_factory=list)
    cvss_impact: float = 0.0
    remediation: str = ""


@dataclass
class MarlinSpikeReport:
    """Full structured report."""
    module: dict = field(default_factory=lambda: MODULE_META)
    timestamp_start: str = ""
    timestamp_end: str = ""

    # Stage 1
    capture_info: Optional[dict] = None

    # Stage 2
    conversations: list = field(default_factory=list)
    protocol_summary: dict = field(default_factory=dict)

    # Stage 3
    topology: dict = field(default_factory=dict)
    nodes: list = field(default_factory=list)
    edges: list = field(default_factory=list)
    purdue_violations: list = field(default_factory=list)

    # Stage 4
    risk_findings: list = field(default_factory=list)
    attack_targets: list = field(default_factory=list)
    port_summary: dict = field(default_factory=dict)
    c2_indicators: list = field(default_factory=list)

    # Recon tables
    mac_table: list = field(default_factory=list)  # [{mac, ip, vendor, system_name, capabilities, source}]

    # Metadata
    grassmarlin_used: bool = False
    dpi_engine: str = "python"
    dpi_engine_version: str = ""
    dpi_schema_version: str = ""
    tshark_version: str = ""
    interrupted: bool = False
    completed_stages: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    def save(self, path: str):
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2, default=str)
        print(f"\n[*] Report saved: {path}")

    def save_yaml_map(self, path: str):
        """Export a YAML relationship map — nodes grouped by Purdue level."""
        purdue_names = {
            0: "Field I/O", 1: "Field Control", 2: "Supervisory",
            3: "Operations", 4: "Enterprise", 5: "DMZ", -1: "Unknown",
        }

        # Group nodes by Purdue level
        levels = defaultdict(list)
        for node in self.nodes:
            levels[node["purdue_level"] if isinstance(node, dict) else node.purdue_level].append(node)

        # Build edge lookup: src → [(dst, proto, bytes)]
        edge_map = defaultdict(list)
        for edge in self.edges:
            e = edge if isinstance(edge, dict) else asdict(edge)
            edge_map[e["src"]].append(e)

        lines = [
            "# MarlinSpike — Passive OT Topology Map",
            f"# Generated: {self.timestamp_end or self.timestamp_start}",
            f"# Source: {self.capture_info.get('pcap_path', 'unknown') if self.capture_info else 'unknown'}",
            f"# tshark: {self.tshark_version}",
            "",
            "topology:",
            f"  nodes: {len(self.nodes)}",
            f"  edges: {len(self.edges)}",
            f"  protocols: [{', '.join(sorted(self.protocol_summary.keys()))}]",
            "",
        ]

        for level in sorted(levels.keys()):
            label = purdue_names.get(level, "Unknown")
            lines.append(f"# ── Purdue Level {level} — {label} ──")
            lines.append(f"level_{level}:")

            for node in sorted(levels[level], key=lambda n: n["ip"] if isinstance(n, dict) else n.ip):
                n = node if isinstance(node, dict) else asdict(node)
                ip = n["ip"]
                role = n["role"]
                protocols = n["protocols"]
                vendor = n["vendor"]

                lines.append(f"  - ip: {ip}")
                lines.append(f"    role: {role}")
                lines.append(f"    vendor: {vendor}")
                lines.append(f"    protocols: [{', '.join(protocols)}]")

                node_edges = edge_map.get(ip, [])
                # Also include edges where this node is dst
                incoming = [e if isinstance(e, dict) else asdict(e)
                            for e in self.edges
                            if (e["dst"] if isinstance(e, dict) else e.dst) == ip]

                if node_edges or incoming:
                    lines.append("    connections:")
                    for e in node_edges:
                        lines.append(f"      - dst: {e['dst']}")
                        lines.append(f"        protocol: {e['protocol']}")
                        lines.append(f"        bytes: {e['bytes_total']}")
                        if e.get("includes_writes"):
                            lines.append(f"        writes: true")
                        if e.get("includes_program_access"):
                            lines.append(f"        program_access: true")
                    for e in incoming:
                        lines.append(f"      - src: {e['src']}")
                        lines.append(f"        protocol: {e['protocol']}")
                        lines.append(f"        bytes: {e['bytes_total']}")
                        lines.append(f"        direction: inbound")
                lines.append("")

        # Risk findings
        if self.risk_findings:
            lines.append("# ── Risk Findings ──")
            lines.append("risk:")
            for finding in self.risk_findings:
                f = finding if isinstance(finding, dict) else asdict(finding)
                lines.append(f"  - severity: {f['severity']}")
                lines.append(f"    category: {f['category']}")
                lines.append(f"    description: \"{f['description']}\"")
                lines.append(f"    affected: {len(f.get('affected_nodes', []))} nodes")
                if f.get("remediation"):
                    lines.append(f"    remediation: \"{f['remediation']}\"")
                lines.append("")

        # Attack targets (top priority)
        if self.attack_targets:
            lines.append("# ── Priority Targets ──")
            lines.append("targets:")
            for target in self.attack_targets:
                t = target if isinstance(target, dict) else asdict(target)
                lines.append(f"  - ip: {t['ip']}")
                lines.append(f"    role: {t['role']}")
                lines.append(f"    priority: {t['priority']}")
                if t.get("recommended_modules"):
                    lines.append(f"    modules: [{', '.join(t['recommended_modules'])}]")
                lines.append("")

        content = "\n".join(lines) + "\n"
        with open(path, "w") as f:
            f.write(content)
        print(f"[*] YAML map saved: {path}")


# ---------------------------------------------------------------------------
# Stage 1: Capture Ingestion
# ---------------------------------------------------------------------------

class CaptureIngestor:
    """Stage 1 — Validate and index PCAP."""

    def __init__(self, pcap: str = "", no_reassembly: bool = True):
        self.pcap = pcap
        self.no_reassembly = no_reassembly
        self.capture_info: Optional[CaptureInfo] = None

    def ingest(self) -> CaptureInfo:
        """Main entry point — validate existing PCAP."""
        print(f"\n{'─'*60}")
        print(f"  STAGE 1 — Capture Ingestion")
        print(f"{'─'*60}")

        if not self.pcap:
            raise ValueError("Must provide --pcap")
        print(f"  Source: File — {self.pcap}")
        return self.validate_pcap(self.pcap)

    def validate_pcap(self, path: str) -> CaptureInfo:
        """Validate and index a PCAP file using capinfos + tshark."""
        if not os.path.exists(path):
            raise FileNotFoundError(f"PCAP not found: {path}")

        print(f"  Validating PCAP...")

        # Get basic stats with capinfos (faster than full tshark parse)
        try:
            result = subprocess.run(
                ["capinfos", "-T", "-M", path],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode != 0:
                # Fall back to tshark if capinfos unavailable
                raise FileNotFoundError("capinfos not found")

            lines = result.stdout.strip().split("\n")
            if len(lines) < 2:
                raise ValueError("Invalid capinfos output")

            fields = dict(zip(lines[0].split("\t"), lines[1].split("\t")))
            packet_count = int(fields.get("Number of packets", 0))
            raw_dur = fields.get("Capture duration (seconds)", "0")
            try:
                duration = float(raw_dur)
            except (ValueError, TypeError):
                duration = 0.0
            start_ts = fields.get("First packet time", "")
            end_ts = fields.get("Last packet time", "")
            link_type = fields.get("Encapsulation", "Unknown")

        except (FileNotFoundError, subprocess.TimeoutExpired):
            # Fall back to tshark-only approach
            stat_cmd = ["tshark", "-r", path, "-q", "-z", "io,stat,0"]
            if self.no_reassembly:
                stat_cmd.extend(["-o", "tcp.desegment_tcp_streams:FALSE",
                                 "-o", "ip.defragment:FALSE"])
            try:
                result = subprocess.run(stat_cmd, capture_output=True, text=True, timeout=30)
                match = re.search(r"(\d+)\s+frames", result.stdout)
                packet_count = int(match.group(1)) if match else 0
                duration = 0.0
                start_ts = ""
                end_ts = ""
                link_type = "Unknown"
            except (FileNotFoundError, subprocess.TimeoutExpired):
                # Minimal fallback for environments that rely on marlinspike-dpi
                # and do not have Wireshark tooling installed.
                packet_count = 0
                duration = 0.0
                start_ts = ""
                end_ts = ""
                link_type = "Unknown"
                print("  [*] capinfos/tshark unavailable — using minimal file validation only")

        # Unique addresses and protocols are deferred to Stage 2 (dissection)
        # to avoid a second full tshark pass. Stage 2 extracts every MAC, IP,
        # and protocol anyway — no reason to read the PCAP twice.

        self.capture_info = CaptureInfo(
            pcap_path=path,
            source="file",
            packet_count=packet_count,
            duration_s=duration,
            start_ts=start_ts,
            end_ts=end_ts,
            link_type=link_type,
            unique_macs=0,  # populated after Stage 2
            unique_ips=0,   # populated after Stage 2
            protocols_seen={},  # populated after Stage 2
        )

        print(f"\n  Capture Summary:")
        print(f"    Packets:        {packet_count:,}")
        print(f"    Duration:       {duration:.1f}s ({duration/60:.1f}m)")
        print(f"    Link Type:      {link_type}")

        return self.capture_info


# ---------------------------------------------------------------------------
# Stage 2: Protocol Dissection
# ---------------------------------------------------------------------------

class OTProtocolDissector:
    """Stage 2 — Built-in PCAP parser using streaming tshark output."""

    # Fields extracted from tshark — order matters (tab-separated output)
    FIELDS = [
        "frame.time", "frame.len", "frame.protocols", "frame.time_epoch",
        "eth.src", "eth.dst", "ip.src", "ip.dst",
        "arp.src.proto_ipv4", "arp.dst.proto_ipv4",
        "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
        # Modbus
        "modbus.func_code", "modbus.reference_num", "modbus.word_cnt",
        "mbtcp.unit_id",
        # EtherNet/IP / CIP
        "enip.cpf.cai.connid", "cip.sc", "cip.class",
        "cip.instance", "cip.id.vendor_id", "cip.id.device_type",
        "cip.id.product_name", "cip.id.product_code",
        "cip.id.serial_number", "cip.class_revision",
        # PROFINET DCP
        "pn_dcp.suboption_device_nameofstation",
        "pn_dcp.suboption_vendor_id",
        "pn_dcp.suboption_device_id",
        "pn_dcp.suboption_device_role",
        "pn_dcp.suboption_ip_ip",
        # S7comm
        "s7comm.param.func", "s7comm.blockinfo.blocktype",
        "s7comm.header.rosctr",
        # DNP3
        "dnp3.al.func", "dnp3.al.obj",
        # IEC 60870-5-104
        "iec60870_asdu.typeid", "iec60870_asdu.causetx",
        # IEC 61850 MMS / GOOSE
        "mms.confirmedServiceRequest", "mms.unconfirmedService",
        "mms.domain", "mms.domainId", "mms.domainName", "mms.namedToken",
        "mms.iec61850.datset", "mms.iec61850.rptid", "mms.iec61850.ctlmodel",
        "goose.gocbRef", "goose.goID", "goose.datSet", "goose.confRev",
        "goose.simulation", "goose.ndsCom",
        # BACnet/IP
        "bacapp.object_name", "bacapp.vendor_identifier",
        "bacapp.objectType", "bacapp.instance_number",
        # OPC-UA
        "opcua.servicenodeid.numeric", "opcua.security.spu",
        # OMRON FINS
        "omron.command", "omron.controller.model", "omron.controller.version",
        # LLDP
        "lldp.chassis.id", "lldp.chassis.subtype",
        "lldp.port.id", "lldp.port.subtype", "lldp.port.desc",
        "lldp.tlv.system.name", "lldp.tlv.system.desc",
        "lldp.mgn.addr.ip4", "lldp.mgn.addr.ip6",
        "lldp.tlv.system_cap", "lldp.tlv.enable_system_cap",
        "lldp.ieee.802_1.port_vlan.id",
        # CDP
        "cdp.deviceid", "cdp.portid", "cdp.platform",
        "cdp.software_version", "cdp.native_vlan",
        # STP
        "stp.root.hw", "stp.bridge.hw",
        "stp.port", "stp.root.cost",
        "stp.flags.tc", "stp.type",
        # LACP
        "lacp.actor.sysid", "lacp.actor.port",
        "lacp.partner.sysid", "lacp.partner.port",
        "lacp.actor.key", "lacp.partner.key",
        # DNS
        "dns.qry.name", "dns.qry.type", "dns.resp.type",
        "dns.a", "dns.txt",
    ]

    SKIP_LAYERS = {"eth", "ethertype", "ip", "ipv6", "tcp", "udp", "frame", "data"}

    def __init__(self, pcap_path: str, chunk_size: int = 0, collapse_threshold: int = 50):
        self.pcap_path = pcap_path
        self.chunk_size = chunk_size
        self.collapse_threshold = collapse_threshold  # 0 = disabled
        self.conversations: list[Conversation] = []

    # Protocols that represent the "real" conversation even when encapsulating
    # other layers (e.g. ICMP error wrapping DNS is still an ICMP conversation)
    ENCAP_PROTOCOLS = {"icmp", "icmpv6", "igmp", "arp", "lldp", "cdp", "stp", "rstp", "mstp", "lacp", "edp"}

    def _classify_protocol(self, proto_stack: str, port: int, transport: str = ""):
        """Classify a packet's protocol from frame.protocols stack or port."""
        if proto_stack:
            layers = proto_stack.split(":")
            # Check for encapsulating protocols first — ICMP wrapping DNS is ICMP
            for layer in layers:
                if layer in self.ENCAP_PROTOCOLS:
                    return layer.upper() if len(layer) <= 5 else layer.capitalize()
            # Walk from most specific (last) to least, match OT names first
            for layer in reversed(layers):
                if layer in OT_TSHARK_PROTOCOLS:
                    return OT_TSHARK_PROTOCOLS[layer]
            # No OT match — use most specific non-transport layer
            for layer in reversed(layers):
                if layer not in self.SKIP_LAYERS:
                    return layer.upper() if len(layer) <= 5 else layer.capitalize()
        # Port-based OT lookup
        if port in OT_PROTOCOLS:
            return OT_PROTOCOLS[port]
        # Well-known IT/infrastructure port lookup
        if port in WELL_KNOWN_PORTS:
            return WELL_KNOWN_PORTS[port][0]
        # Generic transport/port label for unknown services
        if port > 0 and transport:
            return f"{transport.upper()}/{port}"
        return None

    def _run_tshark_pass(self, pcap_path: str, field_args: list, conv_map, ot_names: set,
                         pkt_count: int, skipped: int, pair_ports=None,
                         collapsed_count: int = 0) -> tuple[int, int, int]:
        """Run a single tshark pass over a pcap file, accumulating into conv_map.
        Returns updated (pkt_count, skipped, collapsed_count)."""
        if pair_ports is None:
            pair_ports = defaultdict(set)
        cmd = ["tshark", "-l", "-r", pcap_path,
               "-T", "fields", "-E", "separator=\t", "-E", "occurrence=f",
               "-o", "tcp.desegment_tcp_streams:FALSE",
               "-o", "ip.defragment:FALSE"] + field_args

        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, bufsize=1)
        try:
            for line in proc.stdout:
                line = line.rstrip("\n")
                if not line:
                    continue

                pkt_count += 1
                values = line.split("\t")

                # Parse fields into dict — transient, not stored
                pkt = {}
                for i, fname in enumerate(self.FIELDS):
                    if i < len(values) and values[i]:
                        pkt[fname] = [values[i]]

                src_mac = pkt.get("eth.src", [""])[0]
                dst_mac = pkt.get("eth.dst", [""])[0]
                if not src_mac or not dst_mac:
                    skipped += 1
                    continue

                tcp_sport = pkt.get("tcp.srcport", [""])[0]
                tcp_dport = pkt.get("tcp.dstport", [""])[0]
                udp_sport = pkt.get("udp.srcport", [""])[0]
                udp_dport = pkt.get("udp.dstport", [""])[0]
                port = int(tcp_dport or udp_dport or 0)
                src_port = int(tcp_sport or udp_sport or 0)
                transport = "tcp" if tcp_dport else ("udp" if udp_dport else "")

                proto_stack = pkt.get("frame.protocols", [""])[0]
                protocol = self._classify_protocol(proto_stack, port, transport)
                if not protocol:
                    skipped += 1
                    continue

                # ── Inline port scan collapse ───────────────────────
                # Track unique dest ports per (mac_pair, transport). Once
                # threshold is exceeded, redirect all further packets to a
                # single "Port Scan" conversation instead of creating new entries.
                key = (src_mac, dst_mac, protocol, port)
                if self.collapse_threshold > 0 and port > 0 and transport:
                    pair_key = (src_mac, dst_mac, transport)
                    pair_ports[pair_key].add(port)
                    if len(pair_ports[pair_key]) >= self.collapse_threshold:
                        key = (src_mac, dst_mac, "Port Scan", 0)
                        collapsed_count += 1

                conv = conv_map[key]
                conv["packet_count"] += 1
                conv["bytes"] += int(pkt.get("frame.len", ["0"])[0])

                # Track transport and source ports
                if transport and not conv["transport"]:
                    conv["transport"] = transport
                if src_port and len(conv["src_ports"]) < 100:
                    conv["src_ports"].add(src_port)

                # Track IPs seen on this MAC conversation (optional)
                src_ip = pkt.get("ip.src", [""])[0] or pkt.get("arp.src.proto_ipv4", [""])[0]
                dst_ip = pkt.get("ip.dst", [""])[0] or pkt.get("arp.dst.proto_ipv4", [""])[0]
                if src_ip:
                    conv["src_ips"].add(src_ip)
                if dst_ip:
                    conv["dst_ips"].add(dst_ip)

                timestamp = pkt.get("frame.time", [""])[0]
                if not conv["first_seen"] or timestamp < conv["first_seen"]:
                    conv["first_seen"] = timestamp
                if not conv["last_seen"] or timestamp > conv["last_seen"]:
                    conv["last_seen"] = timestamp

                # Epoch timestamp for IAT analysis (capped at 5000 per conv)
                epoch_str = pkt.get("frame.time_epoch", [""])[0]
                if epoch_str and len(conv["timestamps"]) < 5000:
                    try:
                        conv["timestamps"].append(float(epoch_str))
                    except (ValueError, TypeError):
                        pass

                # DNS metadata extraction
                dns_qname = pkt.get("dns.qry.name", [""])[0]
                if dns_qname:
                    if len(conv["dns_queries"]) < 200:
                        conv["dns_queries"].add(dns_qname)
                    dns_qtype = pkt.get("dns.qry.type", [""])[0]
                    if dns_qtype:
                        conv["dns_query_types"].add(dns_qtype)

                # ── Inline protocol parsing — no packet storage ──
                if "Modbus" in protocol:
                    fc = pkt.get("modbus.func_code", [""])[0]
                    if fc and fc.isdigit():
                        fc_int = int(fc)
                        conv["modbus_functions"].add(fc_int)
                        if fc_int in (5, 6, 15, 16):
                            conv["modbus_writes"] += 1
                elif "EtherNet/IP" in protocol or "CIP" in protocol:
                    vendor = pkt.get("cip.id.vendor_id", [""])[0]
                    device_type = pkt.get("cip.id.device_type", [""])[0]
                    product_name = pkt.get("cip.id.product_name", [""])[0]
                    product_code = pkt.get("cip.id.product_code", [""])[0]
                    serial = pkt.get("cip.id.serial_number", [""])[0]
                    revision = pkt.get("cip.class_revision", [""])[0]
                    if vendor or device_type or product_name:
                        conv["cip_identity"] = {
                            "vendor_id": vendor, "device_type": device_type,
                            "product_name": product_name, "product_code": product_code,
                            "serial_number": serial,
                            "revision": revision,
                        }
                elif "PROFINET" in protocol:
                    station = pkt.get("pn_dcp.suboption_device_nameofstation", [""])[0]
                    pn_vendor = pkt.get("pn_dcp.suboption_vendor_id", [""])[0]
                    pn_device = pkt.get("pn_dcp.suboption_device_id", [""])[0]
                    pn_role = pkt.get("pn_dcp.suboption_device_role", [""])[0]
                    pn_ip = pkt.get("pn_dcp.suboption_ip_ip", [""])[0]
                    if station or pn_vendor or pn_device:
                        conv["pn_identity"] = {
                            "station_name": station, "vendor_id": pn_vendor,
                            "device_id": pn_device, "device_role": pn_role,
                            "ip": pn_ip,
                        }
                elif "S7comm" in protocol:
                    func = pkt.get("s7comm.param.func", [""])[0]
                    rosctr = pkt.get("s7comm.header.rosctr", [""])[0]
                    if func:
                        conv["s7_functions"].add(func)
                    if rosctr == "7":
                        conv["s7_program_access"] = True
                elif "DNP3" in protocol:
                    obj = pkt.get("dnp3.al.obj", [""])[0]
                    if obj:
                        conv["dnp3_objects"].add(obj)
                elif "IEC 60870-5-104" in protocol:
                    typeid = pkt.get("iec60870_asdu.typeid", [""])[0]
                    cause = pkt.get("iec60870_asdu.causetx", [""])[0]
                    if typeid:
                        conv["iec104_typeids"].add(typeid)
                    if cause:
                        conv["iec104_causes"].add(cause)
                elif "MMS (IEC 61850)" in protocol:
                    confirmed = pkt.get("mms.confirmedServiceRequest", [""])[0]
                    unconfirmed = pkt.get("mms.unconfirmedService", [""])[0]
                    if confirmed:
                        conv["mms_identity"]["service_requests"].add(confirmed)
                    if unconfirmed:
                        conv["mms_identity"]["unconfirmed_services"].add(unconfirmed)
                    for field_name in (
                        "mms.domain", "mms.domainId", "mms.domainName",
                        "mms.namedToken", "mms.iec61850.datset", "mms.iec61850.rptid",
                    ):
                        raw = pkt.get(field_name, [""])[0]
                        if raw:
                            for token in raw.split(","):
                                token = token.strip()
                                if token:
                                    if field_name == "mms.iec61850.datset":
                                        conv["mms_identity"]["datasets"].add(token)
                                    elif field_name == "mms.iec61850.rptid":
                                        conv["mms_identity"]["report_ids"].add(token)
                                    else:
                                        conv["mms_identity"]["names"].add(token)
                    ctl_model = pkt.get("mms.iec61850.ctlmodel", [""])[0]
                    if ctl_model:
                        conv["mms_identity"]["ctl_models"].add(ctl_model)
                elif "IEC 61850 GOOSE" in protocol or "R-GOOSE" in protocol:
                    for field_name, bucket in (
                        ("goose.gocbRef", "gocb_refs"),
                        ("goose.goID", "go_ids"),
                        ("goose.datSet", "datasets"),
                        ("goose.confRev", "conf_revs"),
                    ):
                        raw = pkt.get(field_name, [""])[0]
                        if raw:
                            for token in raw.split(","):
                                token = token.strip()
                                if token:
                                    conv["goose_identity"][bucket].add(token)
                    simulation = pkt.get("goose.simulation", [""])[0]
                    nds_com = pkt.get("goose.ndsCom", [""])[0]
                    if simulation and simulation.lower() in ("1", "true"):
                        conv["goose_identity"]["simulation"] = True
                    if nds_com and nds_com.lower() in ("1", "true"):
                        conv["goose_identity"]["nds_com"] = True
                elif "BACnet" in protocol:
                    obj_name = pkt.get("bacapp.object_name", [""])[0]
                    vendor_id = pkt.get("bacapp.vendor_identifier", [""])[0]
                    object_type = pkt.get("bacapp.objectType", [""])[0]
                    if vendor_id:
                        conv["bacnet_identity"]["vendor_ids"].add(vendor_id)
                    if obj_name:
                        conv["bacnet_identity"]["object_names"].add(obj_name)
                    if object_type:
                        conv["bacnet_identity"]["object_types"].add(object_type)
                elif "OPC-UA" in protocol:
                    svc = pkt.get("opcua.servicenodeid.numeric", [""])[0]
                    sec = pkt.get("opcua.security.spu", [""])[0]
                    if svc:
                        conv["opc_sessions"].append(svc)
                    if sec and "none" in sec.lower():
                        conv["opc_no_security"] = True
                elif "OMRON" in protocol:
                    cmd = pkt.get("omron.command", [""])[0]
                    model = pkt.get("omron.controller.model", [""])[0]
                    version = pkt.get("omron.controller.version", [""])[0]
                    if cmd:
                        conv["omron_identity"]["commands"].add(cmd)
                    if model and not conv["omron_identity"]["model"]:
                        conv["omron_identity"]["model"] = model
                    if version and not conv["omron_identity"]["version"]:
                        conv["omron_identity"]["version"] = version
                elif protocol == "LLDP":
                    self._parse_lldp_inline(pkt, conv["l2_discovery"])
                elif protocol == "CDP":
                    self._parse_cdp_inline(pkt, conv["l2_discovery"])
                elif protocol in ("STP", "RSTP", "MSTP"):
                    self._parse_stp_inline(pkt, conv["l2_discovery"])
                elif protocol == "LACP":
                    self._parse_lacp_inline(pkt, conv["l2_discovery"])

                # Progress every 50k packets
                if pkt_count % 50000 == 0:
                    print(f"    {pkt_count:,} packets processed...")

            proc.wait(timeout=30)
        except Exception as e:
            print(f"  [!] tshark stream error: {e}")
            proc.kill()
            proc.wait()

        stderr = proc.stderr.read() if proc.stderr else ""
        if proc.returncode and proc.returncode != 0:
            print(f"  [!] tshark exit code {proc.returncode}: {stderr[:200]}")

        return pkt_count, skipped, collapsed_count

    def dissect(self) -> list[Conversation]:
        """Stream tshark output line-by-line — all parsing inline, zero packet storage."""
        print(f"\n{'─'*60}")
        print(f"  STAGE 2 — Protocol Dissection")
        print(f"  PCAP: {self.pcap_path}")
        print(f"{'─'*60}")

        field_args = []
        for f in self.FIELDS:
            field_args.extend(["-e", f])

        # MAC-keyed conversation map — all parsing done inline, no packet storage
        conv_map = defaultdict(lambda: {
            "packet_count": 0,
            "bytes": 0,
            "first_seen": None,
            "last_seen": None,
            "src_ips": set(),
            "dst_ips": set(),
            "modbus_functions": set(),
            "modbus_writes": 0,
            "cip_identity": {},
            "pn_identity": {},
            "s7_functions": set(),
            "s7_program_access": False,
            "dnp3_objects": set(),
            "opc_sessions": [],
            "opc_no_security": False,
            "bacnet_identity": {"vendor_ids": set(), "object_names": set(), "object_types": set()},
            "iec104_typeids": set(),
            "iec104_causes": set(),
            "omron_identity": {"commands": set(), "model": "", "version": ""},
            "mms_identity": {
                "service_requests": set(),
                "unconfirmed_services": set(),
                "names": set(),
                "datasets": set(),
                "report_ids": set(),
                "ctl_models": set(),
            },
            "goose_identity": {
                "gocb_refs": set(),
                "go_ids": set(),
                "datasets": set(),
                "conf_revs": set(),
                "simulation": False,
                "nds_com": False,
            },
            "l2_discovery": {},
            "src_ports": set(),
            "transport": "",
            "timestamps": [],
            "dns_queries": set(),
            "dns_query_types": set(),
        })
        ot_names = set(OT_TSHARK_PROTOCOLS.values())
        pkt_count = 0
        skipped = 0
        collapsed_count = 0
        # Shared across chunks — tracks unique dest ports per MAC pair for inline collapse
        pair_ports = defaultdict(set)

        if self.chunk_size > 0:
            # Chunked mode — split PCAP with editcap, process each chunk
            print(f"  Chunked mode: {self.chunk_size:,} packets per chunk")
            chunk_num = 0
            while True:
                chunk_num += 1
                start_frame = (chunk_num - 1) * self.chunk_size + 1
                end_frame = chunk_num * self.chunk_size
                chunk_path = f"/tmp/ms-chunk-{os.getpid()}-{chunk_num}.pcap"

                # Extract frame range with editcap
                ec_cmd = ["editcap", "-r", self.pcap_path, chunk_path,
                          f"{start_frame}-{end_frame}"]
                ec = subprocess.run(ec_cmd, capture_output=True, text=True, timeout=300)
                if ec.returncode != 0 or not os.path.isfile(chunk_path):
                    break

                chunk_stat = os.path.getsize(chunk_path)
                if chunk_stat == 0:
                    os.unlink(chunk_path)
                    break

                if chunk_num > 1:
                    print(f"    Chunk {chunk_num}: frames {start_frame:,}–{end_frame:,}...")

                prev_count = pkt_count
                pkt_count, skipped, collapsed_count = self._run_tshark_pass(
                    chunk_path, field_args, conv_map, ot_names, pkt_count, skipped,
                    pair_ports, collapsed_count)

                try:
                    os.unlink(chunk_path)
                except OSError:
                    pass

                if pkt_count == prev_count:
                    break

            print(f"  Packets processed: {pkt_count:,} ({skipped:,} skipped, {chunk_num - 1} chunks)")
        else:
            # Single-pass mode — reassembly disabled keeps memory bounded
            print(f"  Streaming packets from tshark...")
            pkt_count, skipped, collapsed_count = self._run_tshark_pass(
                self.pcap_path, field_args, conv_map, ot_names, pkt_count, skipped,
                pair_ports, collapsed_count)
            print(f"  Packets processed: {pkt_count:,} ({skipped:,} skipped)")

        if collapsed_count > 0:
            print(f"  Reducing to unique conversations: {collapsed_count:,} port-scan packets merged inline")
        print(f"  Unique conversations: {len(conv_map):,}")

        # Build Conversation objects from aggregated data
        for (src_mac, dst_mac, protocol, port), d in conv_map.items():
            # Compute beacon score from timestamps
            b_score, b_interval, b_jitter = self._compute_beacon_score(d["timestamps"])
            # Compute DNS entropy
            d_entropy = self._compute_dns_entropy(d["dns_queries"])
            # Pick most common src_port as representative
            src_port_list = list(d["src_ports"])
            rep_src_port = src_port_list[0] if len(src_port_list) == 1 else 0

            conversation = Conversation(
                src_ip=next(iter(d["src_ips"]), ""),
                dst_ip=next(iter(d["dst_ips"]), ""),
                src_mac=src_mac,
                dst_mac=dst_mac,
                protocol=protocol,
                port=port,
                packet_count=d["packet_count"],
                bytes_total=d["bytes"],
                first_seen=d["first_seen"] or "",
                last_seen=d["last_seen"] or "",
                modbus_functions=list(d["modbus_functions"]),
                modbus_writes=d["modbus_writes"],
                cip_identity=d["cip_identity"],
                pn_identity=d["pn_identity"],
                s7_functions=list(d["s7_functions"]),
                s7_program_access=d["s7_program_access"],
                dnp3_objects=list(d["dnp3_objects"]),
                opc_sessions=d["opc_sessions"],
                opc_no_security=d["opc_no_security"],
                bacnet_identity={
                    "vendor_ids": sorted(d["bacnet_identity"]["vendor_ids"]),
                    "object_names": sorted(d["bacnet_identity"]["object_names"]),
                    "object_types": sorted(d["bacnet_identity"]["object_types"]),
                },
                iec104_typeids=sorted(d["iec104_typeids"]),
                iec104_causes=sorted(d["iec104_causes"]),
                omron_identity={
                    "commands": sorted(d["omron_identity"]["commands"]),
                    "model": d["omron_identity"]["model"],
                    "version": d["omron_identity"]["version"],
                },
                mms_identity={
                    "service_requests": sorted(d["mms_identity"]["service_requests"]),
                    "unconfirmed_services": sorted(d["mms_identity"]["unconfirmed_services"]),
                    "names": sorted(d["mms_identity"]["names"]),
                    "datasets": sorted(d["mms_identity"]["datasets"]),
                    "report_ids": sorted(d["mms_identity"]["report_ids"]),
                    "ctl_models": sorted(d["mms_identity"]["ctl_models"]),
                },
                goose_identity={
                    "gocb_refs": sorted(d["goose_identity"]["gocb_refs"]),
                    "go_ids": sorted(d["goose_identity"]["go_ids"]),
                    "datasets": sorted(d["goose_identity"]["datasets"]),
                    "conf_revs": sorted(d["goose_identity"]["conf_revs"]),
                    "simulation": d["goose_identity"]["simulation"],
                    "nds_com": d["goose_identity"]["nds_com"],
                },
                src_port=rep_src_port,
                transport=d["transport"],
                src_ports_seen=src_port_list[:50],
                beacon_score=b_score,
                beacon_interval=b_interval,
                beacon_jitter=b_jitter,
                dns_queries=list(d["dns_queries"])[:200],
                dns_query_types=list(d["dns_query_types"]),
                dns_entropy=d_entropy,
                l2_discovery=d["l2_discovery"],
            )
            self.conversations.append(conversation)

        # Build port summary
        self.port_summary = self._build_port_summary()

        # Print summary
        l2_names = {"LLDP", "CDP", "STP", "RSTP", "MSTP", "LACP", "EDP"}
        ot_convs = sum(1 for c in self.conversations if c.protocol in ot_names and c.protocol not in l2_names)
        l2_convs = sum(1 for c in self.conversations if c.protocol in l2_names)
        it_convs = len(self.conversations) - ot_convs - l2_convs
        print(f"\n  Protocol Breakdown ({len(self.conversations)} unique conversations, {ot_convs} OT, {it_convs} IT, {l2_convs} L2):")
        proto_counts = defaultdict(int)
        for conv in self.conversations:
            proto_counts[conv.protocol] += 1
        for proto, count in sorted(proto_counts.items(), key=lambda x: -x[1]):
            if proto in l2_names:
                tag = " [L2]"
            elif proto in ot_names:
                tag = " [OT]"
            else:
                tag = ""
            print(f"    {proto:30s} {count:4} conversations{tag}")

        # Print beacon candidates
        beacon_convs = [c for c in self.conversations if c.beacon_score > 0.3]
        if beacon_convs:
            print(f"\n  Beacon Candidates ({len(beacon_convs)}):")
            for c in sorted(beacon_convs, key=lambda x: -x.beacon_score)[:10]:
                print(f"    {c.src_ip:>15} → {c.dst_ip:>15}:{c.port:<6} score={c.beacon_score:.2f} interval={c.beacon_interval:.1f}s jitter={c.beacon_jitter:.2f}")

        return self.conversations

    @staticmethod
    def _compute_beacon_score(timestamps):
        """Jitter-resistant beacon detection via IAT histogram clustering."""
        if len(timestamps) < 10:
            return 0.0, 0.0, 0.0
        ts = sorted(timestamps)
        deltas = [ts[i+1] - ts[i] for i in range(len(ts) - 1)]
        deltas = [d for d in deltas if d > 0.01]  # filter sub-10ms bursts/retransmits
        if len(deltas) < 5:
            return 0.0, 0.0, 0.0

        median_d = sorted(deltas)[len(deltas) // 2]
        if median_d < 0.1:
            return 0.0, 0.0, 0.0  # sub-100ms traffic = not beaconing

        bin_width = max(median_d * 0.1, 0.5)  # adaptive, at least 0.5s bins

        # Build histogram
        bins = defaultdict(int)
        for d in deltas:
            bin_key = round(d / bin_width) * bin_width
            bins[bin_key] += 1

        # Find dominant cluster (tallest bin + neighbors)
        peak_bin = max(bins, key=bins.get)
        cluster_count = sum(
            count for bk, count in bins.items()
            if abs(bk - peak_bin) <= bin_width
        )
        cluster_fraction = cluster_count / len(deltas)

        interval = peak_bin
        cluster_deltas = [d for d in deltas if abs(d - peak_bin) <= bin_width]
        jitter = (max(cluster_deltas) - min(cluster_deltas)) / interval if interval > 0 and cluster_deltas else 1.0

        # Beacon score: high cluster fraction + low jitter = beacon
        score = max(0.0, min(1.0, cluster_fraction * (1 - min(jitter, 1.0))))
        return score, interval, jitter

    @staticmethod
    def _compute_dns_entropy(query_names):
        """Average Shannon entropy of subdomain labels — high entropy = possible encoding."""
        import math
        if not query_names:
            return 0.0
        entropies = []
        for qname in query_names:
            parts = qname.rstrip('.').split('.')
            if len(parts) <= 2:
                continue  # no subdomain
            subdomain = '.'.join(parts[:-2])
            if len(subdomain) < 4:
                continue
            freq = {}
            for c in subdomain.lower():
                freq[c] = freq.get(c, 0) + 1
            entropy = -sum((count/len(subdomain)) * math.log2(count/len(subdomain))
                           for count in freq.values())
            entropies.append(entropy)
        return sum(entropies) / len(entropies) if entropies else 0.0

    def _build_port_summary(self):
        """Build port usage summary from all conversations."""
        port_data = defaultdict(lambda: {"protocol": "", "transport": "", "category": "", "connections": 0, "bytes": 0, "peers": set()})
        for conv in self.conversations:
            if conv.port <= 0:
                continue
            p = port_data[(conv.port, conv.transport)]
            p["protocol"] = conv.protocol
            p["transport"] = conv.transport
            if conv.port in OT_PROTOCOLS:
                p["category"] = "OT"
            elif conv.port in WELL_KNOWN_PORTS:
                p["category"] = WELL_KNOWN_PORTS[conv.port][1]
            elif conv.port >= EPHEMERAL_PORT_MIN:
                p["category"] = "Ephemeral"
            else:
                p["category"] = "Unknown"
            p["connections"] += 1
            p["bytes"] += conv.bytes_total
            if conv.src_ip:
                p["peers"].add(conv.src_ip)
            if conv.dst_ip:
                p["peers"].add(conv.dst_ip)

        summary = {}
        for (port, transport), data in sorted(port_data.items()):
            key = f"{port}/{transport}" if transport else str(port)
            summary[key] = {
                "port": port,
                "transport": transport,
                "protocol": data["protocol"],
                "category": data["category"],
                "connections": data["connections"],
                "bytes": data["bytes"],
                "unique_peers": len(data["peers"]),
            }
        return summary

    # ── Inline L2 Discovery Parsers (operate on plain dicts) ─────

    def _parse_lldp_inline(self, pkt: dict, d: dict):
        """Extract LLDP neighbor discovery data — system name, ports, capabilities."""
        if "source" not in d:
            d["source"] = "lldp"

        chassis_id = pkt.get("lldp.chassis.id", [""])[0]
        if chassis_id:
            d["chassis_id"] = chassis_id

        sys_name = pkt.get("lldp.tlv.system.name", [""])[0]
        if sys_name:
            d["system_name"] = sys_name
        sys_desc = pkt.get("lldp.tlv.system.desc", [""])[0]
        if sys_desc:
            d["system_desc"] = sys_desc

        mgmt_ip = pkt.get("lldp.mgn.addr.ip4", [""])[0] or pkt.get("lldp.mgn.addr.ip6", [""])[0]
        if mgmt_ip:
            d["mgmt_ip"] = mgmt_ip

        port_id = pkt.get("lldp.port.id", [""])[0]
        port_desc = pkt.get("lldp.port.desc", [""])[0]
        if port_id:
            ports = d.setdefault("ports", [])
            port_entry = {"id": port_id, "desc": port_desc}
            if port_entry not in ports:
                ports.append(port_entry)

        cap = pkt.get("lldp.tlv.system_cap", [""])[0]
        cap_enabled = pkt.get("lldp.tlv.enable_system_cap", [""])[0]
        if cap:
            d["capabilities_raw"] = cap
            d["capabilities_enabled"] = cap_enabled or ""
            try:
                cap_int = int(cap, 0)
                caps = []
                if cap_int & 0x04: caps.append("Bridge")
                if cap_int & 0x08: caps.append("WLAN AP")
                if cap_int & 0x10: caps.append("Router")
                if cap_int & 0x20: caps.append("Telephone")
                if cap_int & 0x40: caps.append("DOCSIS Cable")
                if cap_int & 0x80: caps.append("Station Only")
                if caps:
                    d["capabilities"] = caps
            except (ValueError, TypeError):
                pass

        vlan_id = pkt.get("lldp.ieee.802_1.port_vlan.id", [""])[0]
        if vlan_id:
            vlans = d.setdefault("vlans", [])
            if vlan_id not in vlans:
                vlans.append(vlan_id)

    def _parse_cdp_inline(self, pkt: dict, d: dict):
        """Extract CDP neighbor discovery data — device ID, platform, native VLAN."""
        if "source" not in d:
            d["source"] = "cdp"

        device_id = pkt.get("cdp.deviceid", [""])[0]
        if device_id:
            d["system_name"] = device_id

        platform = pkt.get("cdp.platform", [""])[0]
        if platform:
            d["system_desc"] = platform

        sw_version = pkt.get("cdp.software_version", [""])[0]
        if sw_version:
            d["software_version"] = sw_version

        port_id = pkt.get("cdp.portid", [""])[0]
        if port_id:
            ports = d.setdefault("ports", [])
            port_entry = {"id": port_id, "desc": ""}
            if port_entry not in ports:
                ports.append(port_entry)

        native_vlan = pkt.get("cdp.native_vlan", [""])[0]
        if native_vlan:
            vlans = d.setdefault("vlans", [])
            if native_vlan not in vlans:
                vlans.append(native_vlan)

    def _parse_stp_inline(self, pkt: dict, d: dict):
        """Extract STP/RSTP topology data — root bridge, port roles, costs."""
        if "source" not in d:
            d["source"] = "stp"

        root_mac = pkt.get("stp.root.hw", [""])[0]
        bridge_mac = pkt.get("stp.bridge.hw", [""])[0]
        root_cost = pkt.get("stp.root.cost", [""])[0]
        port = pkt.get("stp.port", [""])[0]
        stp_type = pkt.get("stp.type", [""])[0]
        tc_flag = pkt.get("stp.flags.tc", [""])[0]

        if root_mac:
            d["stp_root"] = root_mac
        if bridge_mac:
            d["stp_bridge"] = bridge_mac
        if root_cost:
            d["stp_root_cost"] = root_cost
        if port:
            d["stp_port"] = port
        if stp_type:
            d["stp_type"] = stp_type
        if tc_flag and tc_flag != "0":
            d["stp_topology_change"] = True

    def _parse_lacp_inline(self, pkt: dict, d: dict):
        """Extract LACP link aggregation data — actor/partner system, ports, keys."""
        if "source" not in d:
            d["source"] = "lacp"

        actor_sys = pkt.get("lacp.actor.sysid", [""])[0]
        actor_port = pkt.get("lacp.actor.port", [""])[0]
        actor_key = pkt.get("lacp.actor.key", [""])[0]
        partner_sys = pkt.get("lacp.partner.sysid", [""])[0]
        partner_port = pkt.get("lacp.partner.port", [""])[0]
        partner_key = pkt.get("lacp.partner.key", [""])[0]

        if actor_sys:
            d["lacp_actor"] = {
                "system": actor_sys,
                "port": actor_port,
                "key": actor_key,
            }
        if partner_sys:
            d["lacp_partner"] = {
                "system": partner_sys,
                "port": partner_port,
                "key": partner_key,
            }


# ---------------------------------------------------------------------------
# GrassMarlin Bridge (optional)
# ---------------------------------------------------------------------------

class GrassMarlinBridge:
    """GrassMarlin headless integration — wraps external binary."""

    def __init__(self, binary_path: str, pcap_path: str, output_dir: str):
        self.binary_path = binary_path or self._find_grassmarlin()
        self.pcap_path = pcap_path
        self.output_dir = output_dir

    def is_available(self) -> bool:
        """Check if GrassMarlin binary exists and is executable."""
        if not self.binary_path:
            return False
        return os.path.isfile(self.binary_path) and os.access(self.binary_path, os.X_OK)

    def run(self) -> dict:
        """Execute GrassMarlin headless mode and parse output."""
        print(f"  Running GrassMarlin headless mode...")
        print(f"  Binary: {self.binary_path}")

        os.makedirs(self.output_dir, exist_ok=True)

        result = subprocess.run(
            [self.binary_path, "--headless",
             "--input", self.pcap_path,
             "--output", self.output_dir,
             "--export", "json"],
            capture_output=True, text=True, timeout=600
        )

        if result.returncode != 0:
            print(f"  [!] GrassMarlin failed: {result.stderr[:200]}")
            return {}

        # Parse GrassMarlin output files
        nodes_path = os.path.join(self.output_dir, "nodes.json")
        edges_path = os.path.join(self.output_dir, "edges.json")

        topology = {"nodes": [], "edges": []}

        if os.path.exists(nodes_path):
            with open(nodes_path) as f:
                topology["nodes"] = json.load(f)

        if os.path.exists(edges_path):
            with open(edges_path) as f:
                topology["edges"] = json.load(f)

        print(f"  [+] GrassMarlin analysis complete")
        print(f"      Nodes: {len(topology['nodes'])}")
        print(f"      Edges: {len(topology['edges'])}")

        return topology

    @staticmethod
    def _find_grassmarlin() -> str:
        """Auto-detect GrassMarlin binary in PATH."""
        result = subprocess.run(
            ["which", "grassmarlin"],
            capture_output=True, text=True
        )
        return result.stdout.strip()


# ---------------------------------------------------------------------------
# Stage 3: Topology Construction
# ---------------------------------------------------------------------------

class TopologyBuilder:
    """Stage 3 — Graph construction, Purdue inference, vendor fingerprinting."""

    def __init__(self, conversations: list[Conversation],
                 oui_db: dict = None, subnet_map: dict = None,
                 skip_ephemeral: bool = False):
        self.conversations = conversations
        self.oui_db = self._load_oui_db(oui_db)
        self.subnet_map = subnet_map or {}
        self.skip_ephemeral = skip_ephemeral
        self.nodes: dict[str, TopologyNode] = {}
        self.edges: list[TopologyEdge] = []

    @staticmethod
    def _load_oui_db(override: dict = None) -> dict:
        """Load OUI database: IEEE base + ICS-specific overlay."""
        db = {}
        # Try loading IEEE OUI database — check alongside marlinspike.py, then data/
        base_dir = os.path.dirname(os.path.abspath(__file__))
        oui_path = os.path.join(base_dir, "oui.json")
        if not os.path.isfile(oui_path):
            oui_path = os.path.join(base_dir, "data", "oui.json")
        if os.path.isfile(oui_path):
            try:
                with open(oui_path) as f:
                    ieee_db = json.load(f)
                # Convert flat vendor strings to dict format
                for oui, vendor in ieee_db.items():
                    db[oui] = {"vendor": vendor, "product_lines": []}
                print(f"  [*] Loaded IEEE OUI database: {len(db)} entries")
            except Exception as e:
                print(f"  [!] Failed to load OUI database: {e}")
        # Overlay ICS-specific entries (have product_line detail)
        db.update(ICS_OUI_DB)
        # Apply any user-provided override
        if override:
            db.update(override)
        return db

    def build(self) -> dict:
        """Main entry point — build topology graph."""
        print(f"\n{'─'*60}")
        print(f"  STAGE 3 — Topology Construction")
        print(f"  Unique conversations: {len(self.conversations)}")
        if self.skip_ephemeral:
            print(f"  Mode: Relationship view (ephemeral ports >= {EPHEMERAL_PORT_MIN} skipped)")
        print(f"{'─'*60}")

        # Pre-index conversations by src/dst for O(1) lookups
        self._conv_by_src = defaultdict(list)
        self._conv_by_dst = defaultdict(list)
        for conv in self.conversations:
            src_key = conv.src_ip or conv.src_mac
            dst_key = conv.dst_ip or conv.dst_mac
            self._conv_by_src[src_key].append(conv)
            self._conv_by_dst[dst_key].append(conv)

        # Build node and edge lists
        self._build_graph()

        # Merge L2-only nodes (MAC-keyed) into their IP-keyed counterparts
        self._merge_l2_nodes()

        # Infer Purdue levels
        self._infer_purdue_levels()

        # Fingerprint vendors
        self._fingerprint_vendors()

        # Assign device roles
        self._assign_roles()

        # Rank attack targets
        self._rank_targets()

        print(f"\n  Topology Summary:")
        print(f"    Nodes: {len(self.nodes)}")
        print(f"    Edges: {len(self.edges)}")

        # Print Purdue distribution
        purdue_counts = defaultdict(int)
        for node in self.nodes.values():
            purdue_counts[node.purdue_level] += 1
        print(f"  Purdue Level Distribution:")
        for level in sorted(purdue_counts.keys()):
            level_name = {0: "Field I/O", 1: "Field Control",
                         2: "Supervisory", 3: "Operations/Site",
                         4: "Enterprise", 5: "External/Internet", -1: "Unknown"}
            print(f"    Level {level} ({level_name.get(level, 'Unknown'):15s}): {purdue_counts[level]:3} nodes")

        # Print L2 discovery summary
        l2_nodes = [n for n in self.nodes.values() if n.system_name or n.capabilities]
        if l2_nodes:
            print(f"\n  L2 Discovery (LLDP/CDP/STP):")
            for node in l2_nodes:
                key = node.ip or node.mac
                name = node.system_name or "(unnamed)"
                caps = ", ".join(node.capabilities) if node.capabilities else ""
                mgmt = f" mgmt={node.mgmt_ip}" if node.mgmt_ip else ""
                vlans = f" vlans={node.vlans}" if node.vlans else ""
                print(f"    {key:20s} {name:20s} [{caps}]{mgmt}{vlans}")

        # Build MAC→IP table (after vendor fingerprinting for enrichment)
        mac_table = self._build_mac_table()
        if mac_table:
            print(f"  MAC Table: {len(mac_table)} entries")

        return {
            "producer": MODULE_META["id"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "nodes": [asdict(n) for n in self.nodes.values()],
            "edges": [asdict(e) for e in self.edges],
            "mac_table": mac_table,
        }

    def _build_graph(self):
        """Extract nodes and edges from conversations."""
        # Track service ports per destination node
        service_port_map = defaultdict(lambda: defaultdict(lambda: {"connections": 0, "peers": set()}))
        # Merge edges by (src, dst, protocol, dst_port, transport)
        edge_map = {}

        for conv in self.conversations:
            # Node key: IP if available, else MAC (L2-only devices)
            src_key = conv.src_ip or conv.src_mac
            dst_key = conv.dst_ip or conv.dst_mac

            # Create/update source node
            if src_key not in self.nodes:
                self.nodes[src_key] = TopologyNode(
                    ip=conv.src_ip,
                    mac=conv.src_mac,
                )
            src_node = self.nodes[src_key]
            src_node.initiates = True
            # Collapse generic port labels (TCP/49161) to just the transport
            _proto_display = conv.protocol
            if "/" in _proto_display and _proto_display.split("/")[-1].isdigit():
                _proto_display = _proto_display.split("/")[0]
            if _proto_display not in src_node.protocols:
                src_node.protocols.append(_proto_display)

            # Create/update destination node
            if dst_key not in self.nodes:
                self.nodes[dst_key] = TopologyNode(
                    ip=conv.dst_ip,
                    mac=conv.dst_mac,
                )
            dst_node = self.nodes[dst_key]
            dst_node.responds = True
            if _proto_display not in dst_node.protocols:
                dst_node.protocols.append(_proto_display)

            # Track service ports on destination node
            if conv.port > 0:
                sp_key = (conv.port, conv.transport)
                sp = service_port_map[dst_key][sp_key]
                sp["connections"] += 1
                if src_key:
                    sp["peers"].add(src_key)

            # Enrich nodes from L2 discovery data (LLDP/CDP/STP/LACP)
            if conv.l2_discovery:
                ld = conv.l2_discovery
                # LLDP/CDP source is the sender (src_mac) advertising itself
                if ld.get("source") in ("lldp", "cdp"):
                    node = src_node
                    if ld.get("system_name") and not node.system_name:
                        node.system_name = ld["system_name"]
                    if ld.get("system_desc") and not node.system_desc:
                        node.system_desc = ld["system_desc"]
                    if ld.get("mgmt_ip") and not node.mgmt_ip:
                        node.mgmt_ip = ld["mgmt_ip"]
                    for cap in ld.get("capabilities", []):
                        if cap not in node.capabilities:
                            node.capabilities.append(cap)
                    for port in ld.get("ports", []):
                        if port not in node.ports:
                            node.ports.append(port)
                    for vlan in ld.get("vlans", []):
                        if vlan not in node.vlans:
                            node.vlans.append(vlan)
                # STP — both bridge and root are interesting
                elif ld.get("source") == "stp":
                    if ld.get("stp_bridge"):
                        src_node.system_desc = src_node.system_desc or f"STP Bridge (cost {ld.get('stp_root_cost', '?')})"
                        if "Bridge" not in src_node.capabilities:
                            src_node.capabilities.append("Bridge")
                # LACP — actor is the sender
                elif ld.get("source") == "lacp":
                    actor = ld.get("lacp_actor", {})
                    if actor.get("key"):
                        port_entry = {"id": f"LAG key={actor['key']}", "desc": f"port {actor.get('port', '?')}"}
                        if port_entry not in src_node.ports:
                            src_node.ports.append(port_entry)

            # Skip ephemeral-port edges when in relationship mode
            if self.skip_ephemeral and conv.port >= EPHEMERAL_PORT_MIN:
                continue

            # Build port label for edge
            port_label = ""
            if conv.port > 0:
                transport_str = conv.transport or "tcp"
                if conv.port in OT_PROTOCOLS:
                    port_label = f"{conv.port}/{transport_str} ({OT_PROTOCOLS[conv.port]})"
                elif conv.port in WELL_KNOWN_PORTS:
                    port_label = f"{conv.port}/{transport_str} ({WELL_KNOWN_PORTS[conv.port][0]})"
                else:
                    port_label = f"{conv.port}/{transport_str}"

            # Merge edges by (src, dst, protocol, dst_port, transport)
            edge_key = (src_key, dst_key, conv.protocol, conv.port, conv.transport)
            if edge_key in edge_map:
                e = edge_map[edge_key]
                e.conversation_count += 1
                e.bytes_total += conv.bytes_total
                e.first_seen = min(e.first_seen, conv.first_seen) if e.first_seen and conv.first_seen else (e.first_seen or conv.first_seen)
                e.last_seen = max(e.last_seen, conv.last_seen) if e.last_seen and conv.last_seen else (e.last_seen or conv.last_seen)
                e.includes_writes = e.includes_writes or (conv.modbus_writes > 0)
                e.includes_program_access = e.includes_program_access or conv.s7_program_access
                e.src_ports_observed += len(conv.src_ports_seen)
            else:
                edge_map[edge_key] = TopologyEdge(
                    src=src_key,
                    dst=dst_key,
                    protocol=conv.protocol,
                    conversation_count=1,
                    bytes_total=conv.bytes_total,
                    first_seen=conv.first_seen,
                    last_seen=conv.last_seen,
                    includes_writes=(conv.modbus_writes > 0),
                    includes_program_access=conv.s7_program_access,
                    dst_port=conv.port,
                    transport=conv.transport,
                    port_label=port_label,
                    src_ports_observed=len(conv.src_ports_seen),
                )

        # Flatten merged edges
        self.edges = list(edge_map.values())

        # Populate service_ports on destination nodes
        # Skip ephemeral ports with single connections (client-side, not services)
        for node_key, port_map in service_port_map.items():
            if node_key not in self.nodes:
                continue
            node = self.nodes[node_key]
            for (port, transport), data in sorted(port_map.items()):
                # Skip ephemeral-range ports with only 1 connection (client ephemeral)
                if port >= EPHEMERAL_PORT_MIN and data["connections"] <= 1:
                    continue
                if port in OT_PROTOCOLS:
                    proto_name = OT_PROTOCOLS[port]
                    category = "OT"
                elif port in WELL_KNOWN_PORTS:
                    proto_name = WELL_KNOWN_PORTS[port][0]
                    category = WELL_KNOWN_PORTS[port][1]
                elif port >= EPHEMERAL_PORT_MIN:
                    proto_name = f"{transport.upper()}/{port}" if transport else str(port)
                    category = "Ephemeral"
                else:
                    proto_name = f"{transport.upper()}/{port}" if transport else str(port)
                    category = "Unknown"
                node.service_ports.append({
                    "port": port,
                    "transport": transport or "tcp",
                    "protocol": proto_name,
                    "category": category,
                    "connections": data["connections"],
                    "peers": list(data["peers"])[:20],
                })

        # Print service port summary
        nodes_with_services = [(k, n) for k, n in self.nodes.items() if n.service_ports]
        if nodes_with_services:
            print(f"\n  Service Port Profiles ({len(nodes_with_services)} nodes):")
            for key, node in sorted(nodes_with_services, key=lambda x: -len(x[1].service_ports))[:15]:
                ports_str = ", ".join(f"{sp['port']}/{sp['transport']}({sp['protocol']})" for sp in node.service_ports[:5])
                extra = f" +{len(node.service_ports)-5} more" if len(node.service_ports) > 5 else ""
                print(f"    {key:>15}: {ports_str}{extra}")

    @staticmethod
    def _is_public_ip(ip_str: str) -> bool:
        """Check if an IP address is a public (non-RFC1918, non-link-local) address."""
        try:
            addr = ipaddress.ip_address(ip_str)
            if addr.is_multicast:
                return False  # Multicast (224.0.0.0/4) is not "public internet"
            return addr.is_global
        except ValueError:
            return False  # MAC address or invalid — not public

    # Well-known OT vendor public IP prefixes → service name
    _EXTERNAL_IP_HINTS = [
        ("141.81.",    "Rockwell Automation",  "Cloud/Update Service"),
        ("141.82.",    "Rockwell Automation",  "Cloud/Update Service"),
        ("192.40.56.", "Rockwell Automation",  "FactoryTalk Cloud"),
        ("52.186.",    "Rockwell Automation",  "Azure FactoryTalk"),
        ("23.196.",    "Akamai CDN",           "CDN"),
        ("23.197.",    "Akamai CDN",           "CDN"),
        ("104.16.",    "Cloudflare",           "CDN"),
        ("172.217.",   "Google",               "Cloud Service"),
        ("142.250.",   "Google",               "Cloud Service"),
        ("13.107.",    "Microsoft",            "Azure/O365"),
        ("20.190.",    "Microsoft",            "Azure AD"),
        ("40.126.",    "Microsoft",            "Azure AD"),
    ]

    @classmethod
    def _identify_external_service(cls, ip_str: str) -> str:
        """Identify external IPs by known OT vendor or cloud service ranges."""
        for prefix, vendor, svc in cls._EXTERNAL_IP_HINTS:
            if ip_str.startswith(prefix):
                return f"{vendor} ({svc})"
        return "External Endpoint"

    @staticmethod
    def _is_broadcast_or_multicast(ip_str: str) -> bool:
        """Check if an IP is broadcast (255.255.255.255, x.x.x.255) or multicast (224-239.x.x.x)."""
        try:
            addr = ipaddress.ip_address(ip_str)
            if isinstance(addr, ipaddress.IPv4Address):
                return addr.is_multicast or str(addr) == "255.255.255.255" or str(addr).endswith(".255")
            return addr.is_multicast
        except (ValueError, TypeError):
            return False

    def _merge_l2_nodes(self):
        """Merge MAC-only nodes into their IP-keyed counterparts.

        LLDP/STP packets are L2-only (no IP layer), so _build_graph() creates
        MAC-keyed nodes with 'Bridge' capability.  The same physical switch's
        management traffic creates a *separate* IP-keyed node.  Without merging,
        the IP node falls through Purdue heuristics and gets misclassified
        (e.g. 'Engineering Workstation').
        """
        # 1. Build mac→ip mapping from all conversations where both are present
        mac_to_ip = {}
        for conv in self.conversations:
            if conv.src_mac and conv.src_ip:
                mac_to_ip[conv.src_mac.lower()] = conv.src_ip
            if conv.dst_mac and conv.dst_ip:
                mac_to_ip[conv.dst_mac.lower()] = conv.dst_ip

        merged = 0
        mac_keys = [k for k in self.nodes if ":" in k]

        for mac_key in mac_keys:
            mac_node = self.nodes[mac_key]

            # Resolve target IP: prefer LLDP mgmt_ip, fall back to traffic mapping
            target_ip = mac_node.mgmt_ip or mac_to_ip.get(mac_key.lower())
            if not target_ip or target_ip not in self.nodes:
                continue

            ip_node = self.nodes[target_ip]

            # Merge attributes into IP-keyed node
            for cap in mac_node.capabilities:
                if cap not in ip_node.capabilities:
                    ip_node.capabilities.append(cap)
            if mac_node.system_name and not ip_node.system_name:
                ip_node.system_name = mac_node.system_name
            if mac_node.system_desc and not ip_node.system_desc:
                ip_node.system_desc = mac_node.system_desc
            if mac_node.mgmt_ip and not ip_node.mgmt_ip:
                ip_node.mgmt_ip = mac_node.mgmt_ip
            for port in mac_node.ports:
                if port not in ip_node.ports:
                    ip_node.ports.append(port)
            for vlan in mac_node.vlans:
                if vlan not in ip_node.vlans:
                    ip_node.vlans.append(vlan)
            for proto in mac_node.protocols:
                if proto not in ip_node.protocols:
                    ip_node.protocols.append(proto)
            ip_node.initiates = ip_node.initiates or mac_node.initiates
            ip_node.responds = ip_node.responds or mac_node.responds
            if mac_node.mac and not ip_node.mac:
                ip_node.mac = mac_node.mac

            # Rekey edges: MAC key → IP key
            for edge in self.edges:
                if edge.src == mac_key:
                    edge.src = target_ip
                if edge.dst == mac_key:
                    edge.dst = target_ip

            # Rekey conversation indexes
            if mac_key in self._conv_by_src:
                self._conv_by_src[target_ip].extend(self._conv_by_src.pop(mac_key))
            if mac_key in self._conv_by_dst:
                self._conv_by_dst[target_ip].extend(self._conv_by_dst.pop(mac_key))

            # Remove the MAC-keyed node
            del self.nodes[mac_key]
            merged += 1

        if merged:
            print(f"  Merged {merged} L2 node(s) into IP-keyed counterparts")

    def _build_mac_table(self) -> list:
        """Build MAC→IP mapping table from conversations and node attributes."""
        seen = {}  # mac → entry dict

        for conv in self.conversations:
            for mac, ip, source in [
                (conv.src_mac, conv.src_ip, None),
                (conv.dst_mac, conv.dst_ip, None),
            ]:
                if not mac:
                    continue
                mac_lower = mac.lower()
                if mac_lower not in seen:
                    # Determine source type
                    if conv.l2_discovery:
                        src_type = conv.l2_discovery.get("source", "traffic")
                    elif conv.protocol == "ARP":
                        src_type = "arp"
                    else:
                        src_type = "traffic"
                    seen[mac_lower] = {
                        "mac": mac,
                        "ip": ip or "",
                        "vendor": "Unknown",
                        "system_name": "",
                        "capabilities": [],
                        "source": src_type,
                    }
                elif ip and not seen[mac_lower]["ip"]:
                    seen[mac_lower]["ip"] = ip

        # Enrich from node attributes
        for key, node in self.nodes.items():
            if node.mac:
                mac_lower = node.mac.lower()
                if mac_lower in seen:
                    entry = seen[mac_lower]
                    if node.vendor and node.vendor != "Unknown":
                        entry["vendor"] = node.vendor
                    if node.system_name:
                        entry["system_name"] = node.system_name
                    if node.capabilities:
                        entry["capabilities"] = list(node.capabilities)
                    if node.ip and not entry["ip"]:
                        entry["ip"] = node.ip

        # OUI vendor lookup for entries still Unknown
        for mac_lower, entry in seen.items():
            if entry["vendor"] == "Unknown":
                oui = ":".join(mac_lower.split(":")[:3])
                if oui in self.oui_db:
                    entry["vendor"] = self.oui_db[oui]["vendor"]

        return sorted(seen.values(), key=lambda e: e["ip"] or e["mac"])

    def _infer_purdue_levels(self):
        """Infer Purdue Model levels based on communication patterns."""
        print(f"  Inferring Purdue levels...")

        # If subnet_map provided, use it first
        for ip, node in self.nodes.items():
            for subnet, level in self.subnet_map.items():
                if self._ip_in_subnet(ip, subnet):
                    node.purdue_level = level
                    break

        # Classify broadcast/multicast addresses as network infrastructure
        for ip, node in self.nodes.items():
            if self._is_broadcast_or_multicast(ip):
                node.purdue_level = -1
                node.role = "Broadcast/Multicast"
                node.device_type = "Network Address"
                node.asset_type = "network"
                node.attack_priority = 0

        # Classify public IPs as Level 5 (External/Internet)
        for ip, node in self.nodes.items():
            if node.purdue_level != -1:
                continue
            if self._is_public_ip(ip):
                node.purdue_level = 5
                node.role = "External Host"
                node.asset_type = "external"
                # Identify well-known OT vendor cloud ranges
                node.device_type = self._identify_external_service(ip)

        # Pass 1: Assign OT devices (those speaking OT protocols)
        ot_names = set(OT_TSHARK_PROTOCOLS.values()) | set(OT_PROTOCOLS.values())
        for ip, node in self.nodes.items():
            if node.purdue_level != -1:
                continue  # Already mapped

            has_ot = any(p in ot_names for p in node.protocols)
            if not has_ot:
                continue  # Defer non-OT to pass 2

            if node.responds and not node.initiates:
                node.purdue_level = 1
            elif node.initiates and node.responds:
                node.purdue_level = 2
            elif node.initiates and not node.responds:
                node.purdue_level = 2
            else:
                node.purdue_level = -1

        # Pass 2: Assign non-OT devices based on whether they communicate
        # with OT assets.  Level 3 = IT in the OT zone (talks to L0-L2),
        # Level 4 = enterprise IT (only talks to other IT devices).
        ot_ips = {ip for ip, n in self.nodes.items() if n.purdue_level in (0, 1, 2)}
        for ip, node in self.nodes.items():
            if node.purdue_level != -1:
                continue

            # Check if this node has any conversations with OT devices
            talks_to_ot = False
            for conv in self._conv_by_src.get(ip, []):
                peer = conv.dst_ip or conv.dst_mac
                if peer in ot_ips:
                    talks_to_ot = True
                    break
            if not talks_to_ot:
                for conv in self._conv_by_dst.get(ip, []):
                    peer = conv.src_ip or conv.src_mac
                    if peer in ot_ips:
                        talks_to_ot = True
                        break

            if node.responds and not node.initiates:
                node.purdue_level = 2 if talks_to_ot else 4
            elif node.initiates and node.responds:
                node.purdue_level = 3 if talks_to_ot else 4
            elif node.initiates and not node.responds:
                node.purdue_level = 3 if talks_to_ot else 4
            else:
                node.purdue_level = -1

    def _fingerprint_vendors(self):
        """Fingerprint device vendors from MAC OUI, protocol signatures, and L2 discovery."""
        print(f"  Fingerprinting vendors...")

        for ip, node in self.nodes.items():
            # Extract OUI from MAC (first 3 octets)
            # Skip external hosts — their MAC is the gateway's, not their own
            if node.mac and node.purdue_level != 5 and node.asset_type != "external":
                oui = ":".join(node.mac.split(":")[:3]).lower()
                if oui in self.oui_db:
                    vendor_info = self.oui_db[oui]
                    node.vendor = vendor_info["vendor"]
                    node.product_line = ", ".join(vendor_info.get("product_lines", []))

            # Check CIP Identity Object for more specific info
            for conv in self._conv_by_dst.get(ip, []):
                if conv.cip_identity:
                    product_name = conv.cip_identity.get("product_name", "")
                    if product_name:
                        node.product_line = product_name
                    # Vendor and device-profile mappings from CIP Identity Object
                    vendor_id = conv.cip_identity.get("vendor_id", "")
                    if vendor_id:
                        try:
                            vid = int(vendor_id, 0) if str(vendor_id).startswith("0x") else int(vendor_id)
                        except (TypeError, ValueError):
                            vid = None
                        if vid in CIP_VENDOR_ID_MAP:
                            node.vendor = CIP_VENDOR_ID_MAP[vid]
                    device_type = conv.cip_identity.get("device_type", "")
                    if device_type and node.device_type == "Unknown":
                        try:
                            dt = int(device_type, 0) if str(device_type).startswith("0x") else int(device_type)
                        except (TypeError, ValueError):
                            dt = None
                        if dt in CIP_DEVICE_TYPE_MAP:
                            node.device_type = CIP_DEVICE_TYPE_MAP[dt]

            # BACnet metadata often exposes the vendor identifier and device object
            # name in discovery or I-Am traffic. Use that to enrich BMS assets.
            for conv in self._conv_by_src.get(ip, []) + self._conv_by_dst.get(ip, []):
                if not conv.bacnet_identity:
                    continue
                for vendor_id in conv.bacnet_identity.get("vendor_ids", []):
                    try:
                        vid = int(vendor_id, 0)
                    except (TypeError, ValueError):
                        continue
                    if vid in BACNET_VENDOR_ID_MAP and node.vendor == "Unknown":
                        node.vendor = BACNET_VENDOR_ID_MAP[vid]
                        break
                if node.product_line:
                    break
                object_names = conv.bacnet_identity.get("object_names", [])
                if object_names:
                    node.product_line = object_names[0]
                    if not node.system_name:
                        node.system_name = object_names[0]

            # OMRON FINS can expose controller model/version directly.
            for conv in self._conv_by_dst.get(ip, []) + self._conv_by_src.get(ip, []):
                if not conv.omron_identity:
                    continue
                is_omron_service = any(
                    sp.get("port") == 9600 or "omron" in str(sp.get("protocol", "")).lower()
                    for sp in node.service_ports
                )
                if not is_omron_service:
                    continue
                model = conv.omron_identity.get("model", "")
                version = conv.omron_identity.get("version", "")
                if model:
                    node.vendor = "Omron"
                    node.product_line = model if not version else f"{model} {version}".strip()
                    if node.device_type == "Unknown":
                        node.device_type = "Programmable Logic Controller"
                    break

            # Check PROFINET DCP Identity for device info (src or dst)
            _pn_conv = None
            for conv in self._conv_by_src.get(ip, []):
                if conv.pn_identity:
                    _pn_conv = conv
                    break
            if _pn_conv is None:
                for conv in self._conv_by_dst.get(ip, []):
                    if conv.pn_identity:
                        _pn_conv = conv
                        break
            if _pn_conv is not None:
                conv = _pn_conv
                if conv.pn_identity:
                    pn = conv.pn_identity
                    station = pn.get("station_name", "")
                    if station and not node.system_name:
                        node.system_name = station
                    pn_vendor = pn.get("vendor_id", "")
                    if pn_vendor:
                        pn_vid = int(pn_vendor, 0) if pn_vendor.startswith("0x") else int(pn_vendor) if pn_vendor.isdigit() else 0
                        if pn_vid in PROFINET_VENDOR_ID_MAP:
                            node.vendor = PROFINET_VENDOR_ID_MAP[pn_vid]
                        elif pn_vid and node.vendor == "Unknown":
                            node.vendor = f"PROFINET Vendor 0x{pn_vid:04X}"
                    pn_role = pn.get("device_role", "")
                    if pn_role and node.device_type == "Unknown":
                        if "controller" in pn_role.lower() or pn_role == "2":
                            node.device_type = "IO Controller"
                        elif "device" in pn_role.lower() or pn_role == "1":
                            node.device_type = "IO Device"
                        elif "supervisor" in pn_role.lower() or pn_role == "4":
                            node.device_type = "IO Supervisor"
                    if station and node.device_type == "Unknown":
                        station_lower = station.lower()
                        if any(hint in station_lower for hint in PROFINET_SWITCH_HINTS):
                            node.device_type = "Network Switch"

            # IEC 61850 MMS / GOOSE often exposes stable IED names even when the
            # workstation and IED share generic NIC OUIs.
            iec61850_identity = self._collect_iec61850_identity(ip)
            if iec61850_identity["names"] or iec61850_identity["goose_refs"] or iec61850_identity["goose_ids"]:
                serves_iec61850 = any(sp.get("port") == 102 for sp in node.service_ports) or any(
                    "goose" in str(proto).lower() for proto in node.protocols
                )
                iec_names = sorted(
                    set(iec61850_identity["names"])
                    | set(iec61850_identity["goose_refs"])
                    | set(iec61850_identity["goose_ids"])
                )
                primary_iec_name = min(iec_names, key=len) if iec_names else ""
                if serves_iec61850 and primary_iec_name and not node.system_name:
                    node.system_name = primary_iec_name
                if serves_iec61850 and primary_iec_name and not node.product_line:
                    node.product_line = primary_iec_name
                iec_text = primary_iec_name.lower()
                if serves_iec61850 and any(hint in iec_text for hint in IEC61850_BAY_CONTROLLER_HINTS) and node.device_type == "Unknown":
                    node.device_type = "Bay Controller"
                elif serves_iec61850 and any(hint in iec_text for hint in IEC61850_IED_HINTS) and node.device_type == "Unknown":
                    node.device_type = "Protection IED"

            # Enrich from LLDP/CDP system description (often contains vendor/model)
            if node.system_desc and node.vendor == "Unknown":
                desc_lower = node.system_desc.lower()
                # Common CDP/LLDP platform strings
                if "cisco" in desc_lower:
                    node.vendor = "Cisco"
                elif "juniper" in desc_lower:
                    node.vendor = "Juniper"
                elif "arista" in desc_lower:
                    node.vendor = "Arista"
                elif "hirschmann" in desc_lower:
                    node.vendor = "Hirschmann"
                elif "moxa" in desc_lower:
                    node.vendor = "Moxa"
                elif "siemens" in desc_lower or "scalance" in desc_lower:
                    node.vendor = "Siemens"
                elif "belden" in desc_lower:
                    node.vendor = "Belden"
                elif "phoenix" in desc_lower:
                    node.vendor = "Phoenix Contact"
                elif "westermo" in desc_lower:
                    node.vendor = "Westermo"
                if node.vendor != "Unknown" and not node.product_line:
                    node.product_line = node.system_desc

            # Use system_name as device_type hint for switches
            if "Bridge" in node.capabilities and node.device_type == "Unknown":
                node.device_type = "Network Switch"
            elif "Router" in node.capabilities and node.device_type == "Unknown":
                node.device_type = "Router"

    @staticmethod
    def _node_service_names(node: TopologyNode) -> set[str]:
        names = set()
        for proto in node.protocols:
            if proto:
                names.add(str(proto).strip().lower())
        for sp in node.service_ports:
            proto = str(sp.get("protocol", "")).strip().lower()
            if proto:
                names.add(proto)
        return names

    @staticmethod
    def _node_text(node: TopologyNode) -> str:
        return " ".join(
            filter(
                None,
                [
                    node.vendor,
                    node.product_line,
                    node.device_type,
                    node.system_name,
                    node.system_desc,
                    " ".join(node.protocols),
                    " ".join(str(sp.get("protocol", "")) for sp in node.service_ports),
                ],
            )
        ).lower()

    def _node_peer_count(self, ip: str) -> int:
        peers = set()
        for conv in self._conv_by_src.get(ip, []):
            peer = conv.dst_ip or conv.dst_mac
            if peer and peer != ip:
                peers.add(peer)
        for conv in self._conv_by_dst.get(ip, []):
            peer = conv.src_ip or conv.src_mac
            if peer and peer != ip:
                peers.add(peer)
        return len(peers)

    def _has_engineering_activity(self, ip: str) -> bool:
        for conv in self._conv_by_src.get(ip, []):
            if conv.s7_program_access or conv.modbus_writes > 5:
                return True
        return False

    def _collect_iec61850_identity(self, ip: str) -> dict:
        identity = {
            "names": set(),
            "datasets": set(),
            "report_ids": set(),
            "ctl_models": set(),
            "goose_refs": set(),
            "goose_ids": set(),
            "goose_datasets": set(),
        }
        for conv in self._conv_by_src.get(ip, []) + self._conv_by_dst.get(ip, []):
            if conv.mms_identity:
                identity["names"].update(conv.mms_identity.get("names", []))
                identity["datasets"].update(conv.mms_identity.get("datasets", []))
                identity["report_ids"].update(conv.mms_identity.get("report_ids", []))
                identity["ctl_models"].update(conv.mms_identity.get("ctl_models", []))
            if conv.goose_identity:
                identity["goose_refs"].update(conv.goose_identity.get("gocb_refs", []))
                identity["goose_ids"].update(conv.goose_identity.get("go_ids", []))
                identity["goose_datasets"].update(conv.goose_identity.get("datasets", []))
        return identity

    def _assign_roles(self):
        """Assign device roles based on protocols, L2 discovery, and communication patterns."""
        print(f"  Assigning device roles...")

        for ip, node in self.nodes.items():
            # Skip broadcast/multicast — already classified
            if self._is_broadcast_or_multicast(ip):
                continue

            system_name_lower = (node.system_name or "").strip().lower()
            if node.device_type == "Unknown" and system_name_lower:
                if any(system_name_lower.startswith(prefix) for prefix in ("switch", "sw")):
                    node.device_type = "Network Switch"
                elif any(hint in system_name_lower for hint in PROFINET_SWITCH_HINTS):
                    node.device_type = "Network Switch"

            # L2 infrastructure — identified via LLDP/CDP/STP capabilities
            if node.device_type == "Network Switch" or "Bridge" in node.capabilities:
                node.role = "Network Switch"
                if node.system_name:
                    node.role = f"Network Switch ({node.system_name})"
                continue
            elif node.device_type == "Router" or "Router" in node.capabilities:
                node.role = "Router"
                if node.system_name:
                    node.role = f"Router ({node.system_name})"
                continue

            # Vendor-based network infrastructure — these OEMs primarily make
            # switches, routers, serial servers, firewalls, and gateways.
            # Phoenix Contact and Innominate are included because their devices
            # appearing in IT-protocol-only traffic are almost always FL SWITCH
            # or mGuard appliances, not PLCs (PLCs would show OT protocols and
            # land at purdue_level 0/1 before this check).
            if node.vendor and node.vendor != "Unknown":
                _vl = node.vendor.lower()
                if any(v in _vl for v in (
                    "moxa", "westermo", "ruggedcom", "hirschmann", "belden",
                    "cisco", "juniper", "arista", "allied telesis", "netgear",
                    "ubiquiti", "mikrotik", "d-link", "tp-link", "zyxel",
                    "extreme networks", "huawei", "hewlett packard enterprise",
                    "aruba", "dell networking", "cumulus", "pica8", "edgecore",
                    "phoenix contact", "innominate",
                )):
                    node.role = "Network Infrastructure"
                    node.device_type = node.device_type if node.device_type != "Unknown" else "Switch/Gateway"
                    node.purdue_level = 1
                    node.asset_type = "network"
                    continue

            names = self._node_service_names(node)
            text = self._node_text(node)
            peer_count = self._node_peer_count(ip)
            service_count = len(node.service_ports)
            engineering = self._has_engineering_activity(ip)
            has_db_or_file = any(
                p in names for p in (
                    "mysql", "postgresql", "mssql", "ms-sql-s", "netbios-ssn",
                    "microsoft-ds", "smb", "ftp", "tftp", "rpc portmap",
                )
            )
            has_server_stack = any(
                p in names for p in (
                    "http", "https", "dns", "ntp", "smtp", "smtp submission",
                    "imap", "imaps", "pop3", "pop3s", "snmp", "opc ua",
                )
            )
            has_remote_admin = any(p in names for p in ("ssh", "rdp", "vnc", "telnet"))
            historian_hint = any(
                token in text for token in HISTORIAN_SIGNATURES + (
                    "mes", "ignition", "factorytalk", "proficy",
                )
            )
            hmi_hint = any(token in text for token in HMI_SIGNATURES)
            engineering_signature = any(token in text for token in ENGINEERING_SIGNATURES)
            bacnet_hint = "bacnet" in text
            iec104_hint = "iec 60870-5-104" in text or "iec 60870-5 asdu" in text
            iec61850_hint = "iec 61850" in text or "mms (iec 61850)" in text or "goose" in text
            omron_hint = any(token in text for token in OMRON_SIGNATURES) or "omron fins" in text
            opcua_hint = "opc-ua" in text or "opc ua" in text
            has_omron_service = any(
                sp.get("port") == 9600 or "omron" in str(sp.get("protocol", "")).lower()
                for sp in node.service_ports
            )
            has_iec104_service = any(
                sp.get("port") == 2404 or "iec 60870-5-104" in str(sp.get("protocol", "")).lower()
                for sp in node.service_ports
            )
            has_opcua_service = any(
                sp.get("port") == 4840 or "opc-ua" in str(sp.get("protocol", "")).lower()
                for sp in node.service_ports
            )
            has_mms_service = any(sp.get("port") == 102 for sp in node.service_ports)
            iec61850_name_hint = any(token in text for token in IEC61850_IED_HINTS)
            iec61850_ctrl_hint = any(token in text for token in IEC61850_BAY_CONTROLLER_HINTS)
            camera_hint = any(
                token in text for token in (
                    "axis", "hikvision", "dahua", "avigilon", "mobotix",
                    "bosch security", "camera",
                )
            )
            workstation_hint = any(
                token in text for token in (
                    "apple", "pegatron", "dell", "lenovo", "hewlett packard",
                    "hp ", "asus", "acer", "gigabyte", "microsoft",
                )
            )
            appliance_hint = any(
                token in text for token in (
                    "advantech", "red lion", "digi", "moxa", "westermo",
                    "phoenix contact", "ewon", "hms", "innominate",
                )
            )

            # Strong protocol-native identity beats Purdue heuristics when we have
            # explicit controller/server metadata from the capture itself.
            if node.device_type in ("Programmable Logic Controller", "PLC"):
                node.role = "PLC"
                continue
            if node.device_type == "Human-Machine Interface":
                node.role = "HMI/SCADA"
                continue
            if node.device_type == "Bay Controller":
                node.role = "Supervisory Controller"
                continue
            if node.device_type == "Protection IED":
                node.role = "Protective Relay"
                continue
            if node.device_type == "IO Controller":
                node.role = "Supervisory Controller"
                continue
            if node.device_type == "IO Device":
                node.role = "Field Device"
                continue
            if has_omron_service:
                node.role = "PLC"
                if node.device_type == "Unknown":
                    node.device_type = "Programmable Logic Controller"
                continue
            if iec104_hint and has_iec104_service:
                node.role = "RTU"
                if node.device_type == "Unknown":
                    node.device_type = "Telemetry RTU"
                continue
            if iec61850_hint and has_mms_service:
                if iec61850_ctrl_hint:
                    node.role = "Supervisory Controller"
                    if node.device_type == "Unknown":
                        node.device_type = "Bay Controller"
                else:
                    node.role = "Protective Relay"
                    if node.device_type == "Unknown":
                        node.device_type = "Protection IED"
                continue
            if iec61850_hint and not has_mms_service and node.initiates:
                node.role = "Supervisory Controller"
                if node.device_type == "Unknown":
                    node.device_type = "IEC 61850 Client"
                continue
            if has_opcua_service and node.responds:
                node.role = "Application Server" if node.purdue_level == 3 else "Supervisory Controller"
                if node.device_type == "Unknown":
                    node.device_type = "OPC UA Server"
                continue

            # Default role based on Purdue level and protocols
            if node.purdue_level in (0, 1):
                if "Modbus" in " ".join(node.protocols):
                    node.role = "RTU/PLC"
                    if node.device_type == "Unknown":
                        node.device_type = "RTU/PLC"
                elif "EtherNet/IP" in " ".join(node.protocols):
                    node.role = "PLC"
                    if node.device_type == "Unknown":
                        node.device_type = "PLC"
                elif "S7comm" in " ".join(node.protocols):
                    node.role = "PLC"
                    if node.device_type == "Unknown":
                        node.device_type = "PLC"
                elif "DNP3" in " ".join(node.protocols):
                    node.role = "RTU"
                    if node.device_type == "Unknown":
                        node.device_type = "RTU"
                elif iec104_hint:
                    node.role = "RTU"
                    if node.device_type == "Unknown":
                        node.device_type = "Telemetry RTU"
                elif omron_hint and has_omron_service:
                    node.role = "PLC"
                    if node.device_type == "Unknown":
                        node.device_type = "Programmable Logic Controller"
                elif iec61850_hint:
                    node.role = "Supervisory Controller" if iec61850_ctrl_hint else "Protective Relay"
                    if node.device_type == "Unknown":
                        node.device_type = "Bay Controller" if iec61850_ctrl_hint else "Protection IED"
                elif bacnet_hint:
                    node.role = "Building Controller"
                    if node.device_type == "Unknown":
                        node.device_type = "BACnet Controller"
                else:
                    node.role = "Field Device"
                    if node.device_type == "Unknown":
                        node.device_type = "Field Device"

            elif node.purdue_level == 2:
                if engineering or engineering_signature:
                    node.role = "Engineering Workstation"
                    if node.device_type == "Unknown":
                        node.device_type = "Engineering Workstation"
                elif bacnet_hint and node.initiates and not node.responds:
                    node.role = "HMI/SCADA"
                    if node.device_type == "Unknown":
                        node.device_type = "BMS Workstation"
                elif bacnet_hint and node.responds:
                    node.role = "Supervisory Controller"
                    if node.device_type == "Unknown":
                        node.device_type = "Building Controller"
                elif iec61850_hint and node.responds and has_mms_service:
                    node.role = "Supervisory Controller" if iec61850_ctrl_hint else "Protective Relay"
                    if node.device_type == "Unknown":
                        node.device_type = "Bay Controller" if iec61850_ctrl_hint else "Protection IED"
                elif iec61850_hint and node.initiates and not has_mms_service:
                    node.role = "Supervisory Controller"
                    if node.device_type == "Unknown":
                        node.device_type = "IEC 61850 Client"
                elif omron_hint and has_omron_service:
                    node.role = "PLC"
                    if node.device_type == "Unknown":
                        node.device_type = "Programmable Logic Controller"
                elif opcua_hint and node.responds and not node.initiates:
                    node.role = "Supervisory Controller"
                    if node.device_type == "Unknown":
                        node.device_type = "OPC UA Server"
                elif hmi_hint:
                    node.role = "HMI/SCADA"
                    if node.device_type == "Unknown":
                        node.device_type = "HMI Platform"
                elif node.initiates and not node.responds:
                    node.role = "HMI/SCADA"
                    if node.device_type == "Unknown":
                        node.device_type = "Operator Workstation" if workstation_hint else "HMI Terminal"
                elif workstation_hint:
                    node.role = "HMI/SCADA"
                    if node.device_type == "Unknown":
                        node.device_type = "Operator Workstation"
                elif node.responds and not node.initiates:
                    node.role = "Supervisory Controller"
                    if node.device_type == "Unknown":
                        node.device_type = "SCADA Server" if (service_count >= 2 or has_server_stack) else "Supervisory Controller"
                elif node.initiates and node.responds:
                    if service_count >= 3 or has_db_or_file:
                        node.role = "Supervisory Controller"
                        if node.device_type == "Unknown":
                            node.device_type = "SCADA Server"
                    else:
                        node.role = "HMI/SCADA"
                        if node.device_type == "Unknown":
                            node.device_type = "Supervisory Workstation"
                else:
                    node.role = "Supervisory Controller"
                    if node.device_type == "Unknown":
                        node.device_type = "Supervisory Controller"

            elif node.purdue_level == 3:
                if historian_hint and (has_db_or_file or has_server_stack or service_count >= 2):
                    node.role = "Historian/MES"
                    if node.device_type == "Unknown":
                        node.device_type = "Historian Server"
                elif opcua_hint and node.responds:
                    node.role = "Application Server"
                    if node.device_type == "Unknown":
                        node.device_type = "OPC UA Server"
                elif bacnet_hint and (node.responds or has_server_stack):
                    node.role = "Application Server"
                    if node.device_type == "Unknown":
                        node.device_type = "BMS Server"
                elif hmi_hint:
                    node.role = "HMI/SCADA"
                    if node.device_type == "Unknown":
                        node.device_type = "HMI Platform"
                elif camera_hint:
                    node.role = "Security Appliance"
                    if node.device_type == "Unknown":
                        node.device_type = "IP Camera"
                elif appliance_hint and (has_remote_admin or has_server_stack or service_count >= 2):
                    node.role = "Industrial Appliance"
                    if node.device_type == "Unknown":
                        node.device_type = "Gateway/Appliance"
                elif engineering or engineering_signature:
                    node.role = "Engineering Workstation"
                    if node.device_type == "Unknown":
                        node.device_type = "Engineering Workstation"
                elif iec104_hint and node.responds:
                    node.role = "Application Server"
                    if node.device_type == "Unknown":
                        node.device_type = "Telemetry Server"
                elif workstation_hint or (node.initiates and not node.responds):
                    node.role = "Operations Workstation"
                    if node.device_type == "Unknown":
                        node.device_type = "Workstation"
                elif node.responds and has_db_or_file:
                    node.role = "Data Server"
                    if node.device_type == "Unknown":
                        node.device_type = "Database/File Server"
                elif node.responds and has_server_stack and peer_count >= 3:
                    node.role = "Infrastructure Server"
                    if node.device_type == "Unknown":
                        svc_names = self._node_service_names(node)
                        if svc_names & {"dns", "mdns", "dhcp server", "dhcp client", "ntp"}:
                            node.device_type = "Network Services Host"
                        elif svc_names & {"http", "https", "http-alt", "https-alt"}:
                            node.device_type = "Web Server"
                        elif svc_names & {"smtp", "smtps", "imap", "imaps", "pop3", "pop3s", "smtp submission"}:
                            node.device_type = "Mail Server"
                        elif svc_names & {"syslog", "syslog tls", "snmp", "snmp trap"}:
                            node.device_type = "Monitoring Server"
                        else:
                            node.device_type = "Infrastructure Server"
                elif node.responds:
                    node.role = "Operations Host"
                    if node.device_type == "Unknown":
                        node.device_type = "Server"
                else:
                    node.role = "Operations Host"
                    if node.device_type == "Unknown":
                        node.device_type = "Endpoint"

            elif node.purdue_level == 4:
                if has_db_or_file or (has_server_stack and peer_count >= 3):
                    node.role = "Enterprise Server"
                    if node.device_type == "Unknown":
                        svc_names = self._node_service_names(node)
                        if svc_names & {"dns", "dhcp server", "dhcp client"}:
                            node.device_type = "Enterprise DNS/DHCP"
                        elif svc_names & {"http", "https", "http-alt", "https-alt"}:
                            node.device_type = "Enterprise Web Server"
                        elif svc_names & {"smtp", "smtps", "imap", "imaps", "pop3", "pop3s", "smtp submission"}:
                            node.device_type = "Mail Server"
                        elif svc_names & {"ldap", "ldaps", "kerberos"}:
                            node.device_type = "Directory Server"
                        else:
                            node.device_type = "Enterprise Server"
                elif workstation_hint or (node.initiates and not node.responds):
                    node.role = "Enterprise Workstation"
                    if node.device_type == "Unknown":
                        node.device_type = "Business Workstation"
                else:
                    node.role = "Enterprise Host"
                    if node.device_type == "Unknown":
                        node.device_type = "Enterprise Endpoint"

            elif node.purdue_level == 5:
                node.role = "External Host"
                if node.device_type == "Unknown":
                    node.device_type = "External Endpoint"

            else:
                node.role = "Unknown"

            if (engineering or engineering_signature) and node.role not in ("PLC", "RTU", "RTU/PLC"):
                node.role = "Engineering Workstation"
                if node.device_type in ("Unknown", "Workstation", "Endpoint"):
                    node.device_type = "Engineering Workstation"

    def _rank_targets(self):
        """Rank nodes for attack priority and recommend modules."""
        print(f"  Ranking attack targets...")

        for ip, node in self.nodes.items():
            # Broadcast/multicast are not attack targets
            if self._is_broadcast_or_multicast(ip):
                node.attack_priority = 0
                node.recommended_modules = []
                continue

            score = 0
            recommended = []

            # PLCs and RTUs are high-value targets
            if "PLC" in node.role or "RTU" in node.role:
                score += 10
                recommended.append("VORACITY-MODULE-FACTORYKEYS")
                recommended.append("VORACITY-MODULE-COILTAPPER")

            # Unauthenticated devices
            if not node.auth_observed:
                score += 5

            # Known vendor fingerprint
            if node.vendor != "Unknown":
                score += 3
                if "Siemens" in node.vendor or "Allen-Bradley" in node.vendor:
                    score += 2

            # Multiple protocols = complex device
            if len(node.protocols) > 2:
                score += 2

            node.attack_priority = score
            node.recommended_modules = recommended

    @staticmethod
    def _ip_in_subnet(ip: str, subnet: str) -> bool:
        """Check if IP is in subnet (simple prefix match)."""
        # Simplified — production would use ipaddress module
        return ip.startswith(subnet.split("/")[0].rsplit(".", 1)[0])


# ---------------------------------------------------------------------------
# Stage 4: Risk Surface
# ---------------------------------------------------------------------------

class RiskSurface:
    """Stage 4 — Score topology and produce target recommendations."""

    FINDINGS = {
        "CROSS_PURDUE": ("HIGH", "Direct communication bypasses zone boundary"),
        "CLEARTEXT_ENG": ("HIGH", "Engineering traffic without authentication/encryption"),
        "MODBUS_WRITE_ANON": ("HIGH", "Modbus write commands from unexpected source"),
        "NO_AUTH_OBSERVED": ("MEDIUM", "Device has no observed authentication exchanges"),
        "BROADCAST_STORM": ("MEDIUM", "Excessive broadcast/multicast volume"),
        "CIP_IDENTITY_OPEN": ("INFO", "CIP Identity Object responds — full device info exposed"),
        "OPC_NO_SECURITY": ("HIGH", "OPC-UA session established with SecurityMode=None"),
        "S7_PROGRAM_ACCESS": ("CRITICAL", "S7comm program upload/download observed — logic exposed"),
    }

    def __init__(self, topology: dict, conversations: list[Conversation], skip_c2: bool = False):
        self.topology = topology
        self.conversations = conversations
        self.nodes = {n["ip"]: n for n in topology["nodes"]}
        self.edges = topology["edges"]
        self.skip_c2 = skip_c2
        self.findings: list[RiskFinding] = []

    def score(self) -> dict:
        """Main entry point — score topology and generate findings."""
        print(f"\n{'─'*60}")
        print(f"  STAGE 4 — Risk Surface Report")
        print(f"{'─'*60}")

        self._check_external_comms()
        self._check_cross_purdue()
        self._check_cleartext_engineering()
        self._check_write_sources()
        self._check_no_auth()
        self._check_opc_security()
        self._check_program_access()
        self._check_port_analysis()
        c2_indicators = [] if self.skip_c2 else self._check_c2_indicators()

        print(f"\n  Risk Summary:")
        severity_counts = defaultdict(int)
        for finding in self.findings:
            severity_counts[finding.severity] += 1

        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = severity_counts[severity]
            if count > 0:
                print(f"    {severity:10s} {count:3} findings")

        if c2_indicators:
            print(f"\n  C2 Indicators: {len(c2_indicators)}")

        # Rank targets
        targets = self._rank_targets()

        return {
            "findings": [asdict(f) for f in self.findings],
            "attack_targets": targets,
            "c2_indicators": c2_indicators,
        }

    def _check_external_comms(self):
        """Flag ICS/OT assets communicating with public internet addresses."""
        ot_names = set(OT_TSHARK_PROTOCOLS.values()) | set(OT_PROTOCOLS.values())

        # Find nodes that speak OT protocols
        ot_nodes = set()
        for key, node in self.nodes.items():
            if any(p in ot_names for p in node.get("protocols", [])):
                ot_nodes.add(key)

        # Find conversations between OT nodes and public IPs
        external_convs = []
        external_ips = set()
        ot_assets_exposed = set()
        for conv in self.conversations:
            src_key = conv.src_ip or conv.src_mac
            dst_key = conv.dst_ip or conv.dst_mac

            src_public = self._is_public_ip(conv.src_ip) if conv.src_ip else False
            dst_public = self._is_public_ip(conv.dst_ip) if conv.dst_ip else False

            # OT asset talking to public IP
            if src_key in ot_nodes and dst_public:
                external_convs.append(conv)
                external_ips.add(conv.dst_ip)
                ot_assets_exposed.add(src_key)
            elif dst_key in ot_nodes and src_public:
                external_convs.append(conv)
                external_ips.add(conv.src_ip)
                ot_assets_exposed.add(dst_key)

        if external_convs:
            # Build detail lines
            details = []
            for conv in external_convs:
                src_key = conv.src_ip or conv.src_mac
                dst_key = conv.dst_ip or conv.dst_mac
                details.append(f"{src_key} → {dst_key} ({conv.protocol}, {conv.packet_count} pkts)")

            finding = RiskFinding(
                severity="CRITICAL",
                category="ICS_EXTERNAL_COMMS",
                description=(
                    f"{len(ot_assets_exposed)} OT asset(s) communicating with {len(external_ips)} "
                    f"public internet address(es): {', '.join(sorted(external_ips))}. "
                    f"ICS assets should not have direct internet connectivity."
                ),
                affected_nodes=list(ot_assets_exposed | external_ips),
                affected_edges=details,
                remediation=(
                    "Isolate ICS network from internet. Implement DMZ architecture with "
                    "data diodes or proxies for any required external data flows. "
                    "Investigate why OT assets are reaching public addresses — "
                    "potential data exfiltration, misconfigured NAT, or unauthorized connectivity."
                ),
            )
            self.findings.append(finding)
            print(f"  [CRITICAL] OT assets with external comms: {len(ot_assets_exposed)} assets → {len(external_ips)} public IPs")

        # Also flag public IPs that talk to any internal node (even non-OT)
        # as informational — they exist in the capture
        all_public = set()
        for key, node in self.nodes.items():
            if node.get("purdue_level") == 5:
                all_public.add(key)

        if all_public and not external_convs:
            finding = RiskFinding(
                severity="INFO",
                category="EXTERNAL_IPS_OBSERVED",
                description=f"Public internet addresses observed in capture: {', '.join(sorted(all_public))}",
                affected_nodes=list(all_public),
                remediation="Verify expected external communications. ICS networks should minimize internet exposure.",
            )
            self.findings.append(finding)
            print(f"  [INFO] External IPs in capture: {len(all_public)}")

    def _check_cross_purdue(self):
        """Flag cross-Purdue-level communications."""
        violations = []
        for edge in self.edges:
            src = self.nodes.get(edge["src"])
            dst = self.nodes.get(edge["dst"])

            if not src or not dst:
                continue

            src_level = src.get("purdue_level", -1)
            dst_level = dst.get("purdue_level", -1)

            # Level 0/1 should never directly talk to Level 3+
            if src_level in (0, 1) and dst_level >= 3:
                violations.append((edge["src"], edge["dst"]))
            elif src_level >= 3 and dst_level in (0, 1):
                violations.append((edge["src"], edge["dst"]))

        if violations:
            finding = RiskFinding(
                severity="HIGH",
                category="CROSS_PURDUE",
                description=f"Detected {len(violations)} cross-Purdue-level communications bypassing supervisory layer",
                affected_nodes=list(set([ip for pair in violations for ip in pair])),
                affected_edges=[f"{src} → {dst}" for src, dst in violations],
                remediation="Implement zone segmentation with firewall rules enforcing Purdue model boundaries",
            )
            self.findings.append(finding)
            print(f"  [HIGH] Cross-Purdue violations: {len(violations)}")

    def _check_cleartext_engineering(self):
        """Flag cleartext engineering protocols."""
        cleartext_convs = []
        for conv in self.conversations:
            # S7comm without TLS, Modbus TCP, etc.
            if "S7comm" in conv.protocol or "Modbus" in conv.protocol:
                if conv.s7_program_access or conv.modbus_writes > 0:
                    cleartext_convs.append(conv)

        if cleartext_convs:
            affected = list(set([(c.src_ip or c.src_mac) for c in cleartext_convs] + [(c.dst_ip or c.dst_mac) for c in cleartext_convs]))
            finding = RiskFinding(
                severity="HIGH",
                category="CLEARTEXT_ENG",
                description=f"Engineering operations conducted over cleartext protocols",
                affected_nodes=affected,
                remediation="Enable TLS for S7comm, use VPN for engineering access, implement MFA",
            )
            self.findings.append(finding)
            print(f"  [HIGH] Cleartext engineering: {len(cleartext_convs)} conversations")

    def _check_write_sources(self):
        """Flag unexpected Modbus write sources."""
        write_sources = defaultdict(int)
        for conv in self.conversations:
            if conv.modbus_writes > 0:
                write_sources[conv.src_ip or conv.src_mac] += conv.modbus_writes

        # More than 2 sources writing = potential issue
        if len(write_sources) > 2:
            finding = RiskFinding(
                severity="MEDIUM",
                category="MODBUS_WRITE_ANON",
                description=f"Multiple sources ({len(write_sources)}) performing Modbus write operations",
                affected_nodes=list(write_sources.keys()),
                remediation="Restrict write access to authorized engineering workstations only",
            )
            self.findings.append(finding)
            print(f"  [MEDIUM] Multiple Modbus write sources: {len(write_sources)}")

    # Protocols that inherently lack authentication — suppress NO_AUTH_OBSERVED
    _AUTH_EXEMPT_PROTOCOLS = frozenset({
        "arp", "rarp",
        "mdns", "llmnr", "ssdp", "igmp",
        "dhcp server", "dhcp client", "dhcp",
        "icmp", "icmpv6",
        "ntp",
        "lldp", "cdp", "stp",
        "profinet dcp", "pn_dcp",
        "goose", "sv",           # IEC 61850 L2 multicast
        "broadcast/multicast",
    })

    # Protocols where authentication IS possible and its absence is notable
    _AUTH_CAPABLE_PROTOCOLS = frozenset({
        "ssh", "rdp", "vnc", "telnet",
        "http", "https", "http-alt", "https-alt",
        "smb", "ftp", "tftp",
        "snmp", "snmp trap",
        "ldap", "ldaps", "kerberos",
        "modbus tcp", "ethernet/ip", "cip", "opc-ua", "s7comm",
        "dnp3", "iec 60870-5-104",
        "mqtt", "mqtt tls", "amqp",
        "mssql", "oracle", "mysql", "postgresql",
        "winrm http", "winrm https",
        "sip", "sip tls",
    })

    def _check_no_auth(self):
        """Flag devices with no observed authentication, filtered by protocol context."""
        unauth_nodes = []
        for ip, node in self.nodes.items():
            if node.get("auth_observed", False):
                continue
            # Skip broadcast/multicast addresses
            if node.get("asset_type") == "network" or node.get("purdue_level") == -1:
                continue
            # Skip external hosts — auth is between the gateway and the host
            if node.get("asset_type") == "external" or node.get("purdue_level") == 5:
                continue
            # Check if this node uses ONLY auth-exempt protocols
            protos = {p.strip().lower() for p in node.get("protocols", []) if p}
            for sp in node.get("service_ports", []):
                p = str(sp.get("protocol", "")).strip().lower()
                if p:
                    protos.add(p)
            if not protos:
                continue  # No protocol info at all — skip
            has_auth_capable = bool(protos & self._AUTH_CAPABLE_PROTOCOLS)
            if not has_auth_capable:
                # All protocols are exempt or unrecognized — not a meaningful finding
                continue
            unauth_nodes.append(ip)

        if len(unauth_nodes) > 0:
            internal_count = sum(
                1 for n in self.nodes.values()
                if n.get("asset_type") not in ("external", "network")
                and n.get("purdue_level", -1) not in (-1, 5)
            )
            pct = (len(unauth_nodes) / internal_count * 100) if internal_count else 0
            finding = RiskFinding(
                severity="MEDIUM",
                category="NO_AUTH_OBSERVED",
                description=(
                    f"{len(unauth_nodes)} device(s) using auth-capable protocols show "
                    f"no authentication exchanges ({pct:.0f}% of internal assets)"
                ),
                affected_nodes=unauth_nodes[:20],
                remediation="Implement authentication for all OT protocols where supported",
            )
            self.findings.append(finding)
            print(f"  [MEDIUM] No auth observed: {len(unauth_nodes)} nodes ({pct:.0f}% of internal)")

    def _check_opc_security(self):
        """Flag OPC-UA sessions without security."""
        insecure_opc = []
        for conv in self.conversations:
            if "OPC-UA" in conv.protocol and conv.opc_no_security:
                insecure_opc.append(conv)

        if insecure_opc:
            affected = list(set([(c.src_ip or c.src_mac) for c in insecure_opc] + [(c.dst_ip or c.dst_mac) for c in insecure_opc]))
            finding = RiskFinding(
                severity="HIGH",
                category="OPC_NO_SECURITY",
                description=f"OPC-UA sessions established with SecurityMode=None",
                affected_nodes=affected,
                remediation="Enable OPC-UA security policies (Basic256Sha256 minimum)",
            )
            self.findings.append(finding)
            print(f"  [HIGH] Insecure OPC-UA: {len(insecure_opc)} sessions")

    def _check_program_access(self):
        """Flag S7comm program upload/download operations."""
        program_access = []
        for conv in self.conversations:
            if conv.s7_program_access:
                program_access.append(conv)

        if program_access:
            affected = list(set([(c.src_ip or c.src_mac) for c in program_access] + [(c.dst_ip or c.dst_mac) for c in program_access]))
            finding = RiskFinding(
                severity="CRITICAL",
                category="S7_PROGRAM_ACCESS",
                description=f"S7comm program upload/download detected — PLC logic exposed",
                affected_nodes=affected,
                remediation="Disable remote program access, require physical key switch for programming mode",
            )
            self.findings.append(finding)
            print(f"  [CRITICAL] S7 program access: {len(program_access)} operations")

    @staticmethod
    def _is_public_ip(ip_str: str) -> bool:
        """Return True if the IP address is publicly routable."""
        try:
            import ipaddress
            addr = ipaddress.ip_address(ip_str)
            return addr.is_global
        except (ValueError, TypeError):
            return False

    def _rank_targets(self) -> list[dict]:
        """Rank all nodes for attack priority."""
        targets = []
        for ip, node in self.nodes.items():
            # Skip broadcast/multicast — not real targets
            try:
                addr = ipaddress.ip_address(ip)
                if addr.is_multicast or str(addr) == "255.255.255.255" or str(addr).endswith(".255"):
                    continue
            except (ValueError, TypeError):
                pass
            priority = node.get("attack_priority", 0)
            if priority <= 0:
                continue
            targets.append({
                "ip": ip,
                "role": node.get("role", "Unknown"),
                "vendor": node.get("vendor", "Unknown"),
                "priority": priority,
                "recommended_modules": node.get("recommended_modules", []),
            })

        targets.sort(key=lambda x: -x["priority"])
        return targets[:20]  # Top 20

    def _check_port_analysis(self):
        """Flag suspicious port usage patterns — aggregated per-node."""
        # Allowed IT services on OT devices (NTP, DNS, DHCP, Syslog, SNMP)
        allowed_it_on_ot = {53, 67, 68, 123, 161, 162, 514, 5353}
        # Port scan threshold — if a node has more unknown ports than this,
        # emit a single "port scan target" finding instead of per-port findings
        SCAN_THRESHOLD = 20

        for ip, node in self.nodes.items():
            if not isinstance(node, dict):
                node = node if hasattr(node, 'purdue_level') else None
                if node is None:
                    continue
                level = node.get("purdue_level", -1) if isinstance(node, dict) else -1
                service_ports = node.get("service_ports", []) if isinstance(node, dict) else []
            else:
                level = node.get("purdue_level", -1)
                service_ports = node.get("service_ports", [])

            # Collect per-node aggregations before emitting findings
            cleartext_ports = []
            unknown_ports = []
            it_on_ot_ports = []
            high_ports = []

            for sp in service_ports:
                port = sp.get("port", 0)
                category = sp.get("category", "")
                proto_name = sp.get("protocol", "")
                conns = sp.get("connections", 0)
                transport = sp.get("transport", "tcp")

                # Cleartext remote access — always flag individually (these are specific and actionable)
                if port in (23, 21, 5900, 5901):
                    cleartext_ports.append((port, proto_name))

                # Unknown service on OT device
                if category == "Unknown" and level in (0, 1, 2, 3):
                    unknown_ports.append((port, transport))

                # IT service on Level 0/1 field device (excluding allowed)
                if category == "IT" and level in (0, 1) and port not in allowed_it_on_ot:
                    it_on_ot_ports.append((port, proto_name))

                # High-port unknown service (skip ephemeral with few connections)
                if port > 10000 and category == "Unknown" and (port < EPHEMERAL_PORT_MIN or conns >= 3):
                    high_ports.append((port, transport, conns))

            # Emit cleartext findings individually
            for port, proto_name in cleartext_ports:
                self.findings.append(RiskFinding(
                    severity="HIGH",
                    category="CLEARTEXT_REMOTE_ACCESS",
                    description=f"Cleartext remote access service ({proto_name}) on {ip}:{port}",
                    affected_nodes=[ip],
                    remediation=f"Replace {proto_name} with encrypted alternative (SSH, SFTP, VPN)",
                ))
                print(f"  [HIGH] Cleartext remote access: {ip}:{port} ({proto_name})")

            # Emit unknown ports — aggregated if above scan threshold
            if unknown_ports:
                if len(unknown_ports) > SCAN_THRESHOLD:
                    sample = [f"{p}/{t}" for p, t in unknown_ports[:10]]
                    self.findings.append(RiskFinding(
                        severity="HIGH",
                        category="PORT_SCAN_TARGET",
                        description=f"Possible port scan target: {ip} has {len(unknown_ports)} unknown service ports (sample: {', '.join(sample)}, ...)",
                        affected_nodes=[ip],
                        remediation="Investigate scanning activity — review firewall logs and IDS alerts for this host",
                    ))
                    print(f"  [HIGH] Port scan target: {ip} ({len(unknown_ports)} unknown ports)")
                else:
                    for port, transport in unknown_ports:
                        self.findings.append(RiskFinding(
                            severity="MEDIUM",
                            category="UNKNOWN_SERVICE_PORT",
                            description=f"Unknown service on OT device {ip}:{port}/{transport}",
                            affected_nodes=[ip],
                            remediation="Investigate unknown services — may indicate unauthorized software or backdoor",
                        ))

            # Emit IT-on-OT individually (typically small count)
            for port, proto_name in it_on_ot_ports:
                self.findings.append(RiskFinding(
                    severity="MEDIUM",
                    category="IT_SERVICE_ON_OT_DEVICE",
                    description=f"IT service ({proto_name}) on field device {ip}:{port}",
                    affected_nodes=[ip],
                    remediation="Field devices should not run IT services — restrict to OT protocols only",
                ))

            # Emit high-port findings — aggregated if above scan threshold
            if high_ports:
                if len(high_ports) > SCAN_THRESHOLD:
                    sample = [f"{p}/{t}" for p, t, _ in high_ports[:10]]
                    # Already covered by PORT_SCAN_TARGET if unknown_ports > threshold too
                    if len(unknown_ports) <= SCAN_THRESHOLD:
                        self.findings.append(RiskFinding(
                            severity="HIGH",
                            category="PORT_SCAN_TARGET",
                            description=f"Possible port scan target: {ip} has {len(high_ports)} unknown high-port services (sample: {', '.join(sample)}, ...)",
                            affected_nodes=[ip],
                            remediation="Investigate scanning activity — review firewall logs and IDS alerts for this host",
                        ))
                        print(f"  [HIGH] Port scan target (high ports): {ip} ({len(high_ports)} ports)")
                else:
                    for port, transport, conns in high_ports:
                        self.findings.append(RiskFinding(
                            severity="MEDIUM",
                            category="HIGH_PORT_SERVICE",
                            description=f"Unknown high-port service on {ip}:{port}/{transport} ({conns} connections)",
                            affected_nodes=[ip],
                            remediation="Investigate high-port services — may indicate C2 channel, tunneling, or unauthorized application",
                        ))

    def _check_c2_indicators(self) -> list:
        """Detect command & control indicators: beaconing, DNS exfil, data staging."""
        c2_indicators = []

        for conv in self.conversations:
            src_key = conv.src_ip or conv.src_mac
            dst_key = conv.dst_ip or conv.dst_mac
            dst_public = self._is_public_ip(conv.dst_ip) if conv.dst_ip else False
            is_ot_port = conv.port in OT_PROTOCOLS
            is_known_port = conv.port in WELL_KNOWN_PORTS

            # ── A. Beaconing Detection ──
            if conv.beacon_score > 0.5:
                if dst_public:
                    severity = "CRITICAL" if conv.beacon_score > 0.7 else "HIGH"
                    indicator = {
                        "type": "C2_BEACONING",
                        "severity": severity,
                        "src": src_key,
                        "dst": dst_key,
                        "port": conv.port,
                        "transport": conv.transport,
                        "beacon_score": round(conv.beacon_score, 3),
                        "interval": round(conv.beacon_interval, 1),
                        "jitter": round(conv.beacon_jitter, 3),
                        "packets": conv.packet_count,
                        "description": (
                            f"Possible C2 beaconing: {src_key} -> {dst_key}:{conv.port} "
                            f"every ~{conv.beacon_interval:.1f}s "
                            f"(jitter {conv.beacon_jitter:.0%}, confidence {conv.beacon_score:.0%})"
                        ),
                    }
                    c2_indicators.append(indicator)
                    self.findings.append(RiskFinding(
                        severity=severity,
                        category="C2_BEACONING",
                        description=indicator["description"],
                        affected_nodes=[src_key, dst_key],
                        remediation="Investigate periodic outbound traffic — block external IP, check for malware on source host",
                    ))
                    print(f"  [{severity}] C2 beaconing: {src_key} -> {dst_key}:{conv.port} interval={conv.beacon_interval:.1f}s score={conv.beacon_score:.2f}")

                elif conv.beacon_score > 0.7 and not is_ot_port and not is_known_port:
                    # Internal beaconing on unknown port — lateral movement
                    indicator = {
                        "type": "C2_BEACONING",
                        "severity": "HIGH",
                        "src": src_key,
                        "dst": dst_key,
                        "port": conv.port,
                        "transport": conv.transport,
                        "beacon_score": round(conv.beacon_score, 3),
                        "interval": round(conv.beacon_interval, 1),
                        "jitter": round(conv.beacon_jitter, 3),
                        "packets": conv.packet_count,
                        "description": (
                            f"Internal beaconing on unknown port: {src_key} -> {dst_key}:{conv.port} "
                            f"every ~{conv.beacon_interval:.1f}s (possible lateral movement)"
                        ),
                    }
                    c2_indicators.append(indicator)
                    self.findings.append(RiskFinding(
                        severity="HIGH",
                        category="C2_BEACONING",
                        description=indicator["description"],
                        affected_nodes=[src_key, dst_key],
                        remediation="Investigate internal beaconing — check both endpoints for compromise",
                    ))

            # ── B. DNS Data Exfiltration ──
            if conv.dns_queries:
                # Extract base domains and unique subdomains
                base_domains = defaultdict(set)
                for qname in conv.dns_queries:
                    parts = qname.rstrip('.').split('.')
                    if len(parts) >= 3:
                        base = '.'.join(parts[-2:])
                        subdomain = '.'.join(parts[:-2])
                        base_domains[base].add(subdomain)

                for base, subdomains in base_domains.items():
                    unique_count = len(subdomains)
                    sample_queries = list(conv.dns_queries)[:5]

                    # Critical: high entropy + high fanout
                    if conv.dns_entropy > 4.0 and unique_count > 50:
                        indicator = {
                            "type": "C2_DNS_EXFIL",
                            "severity": "CRITICAL",
                            "src": src_key,
                            "dst": dst_key,
                            "base_domain": base,
                            "unique_subdomains": unique_count,
                            "entropy": round(conv.dns_entropy, 2),
                            "bytes": conv.bytes_total,
                            "sample_queries": sample_queries,
                            "description": (
                                f"DNS data exfiltration suspected: {src_key} -> {base} "
                                f"({unique_count} unique subdomains, entropy {conv.dns_entropy:.2f})"
                            ),
                        }
                        c2_indicators.append(indicator)
                        self.findings.append(RiskFinding(
                            severity="CRITICAL",
                            category="C2_DNS_EXFIL",
                            description=indicator["description"],
                            affected_nodes=[src_key, dst_key],
                            remediation=f"Block DNS queries to {base} — investigate for DNS tunneling malware",
                        ))
                        print(f"  [CRITICAL] DNS exfil: {src_key} -> {base} ({unique_count} subdomains, entropy {conv.dns_entropy:.2f})")

                    # High: moderate entropy + high volume
                    elif conv.dns_entropy > 3.5 and (conv.packet_count > 500 or conv.bytes_total > 102400):
                        indicator = {
                            "type": "C2_DNS_TUNNEL_SUSPECT",
                            "severity": "HIGH",
                            "src": src_key,
                            "dst": dst_key,
                            "base_domain": base,
                            "unique_subdomains": unique_count,
                            "entropy": round(conv.dns_entropy, 2),
                            "bytes": conv.bytes_total,
                            "packets": conv.packet_count,
                            "sample_queries": sample_queries,
                            "description": (
                                f"DNS tunneling suspected: {src_key} -> {base} "
                                f"({conv.packet_count} pkts, {conv.bytes_total} bytes, entropy {conv.dns_entropy:.2f})"
                            ),
                        }
                        c2_indicators.append(indicator)
                        self.findings.append(RiskFinding(
                            severity="HIGH",
                            category="C2_DNS_TUNNEL_SUSPECT",
                            description=indicator["description"],
                            affected_nodes=[src_key, dst_key],
                            remediation=f"Investigate high-volume DNS traffic to {base} — possible tunneling",
                        ))

                # Medium: high entropy even at low volume
                if conv.dns_entropy > 4.0 and not any(i["type"] == "C2_DNS_EXFIL" and i["src"] == src_key for i in c2_indicators):
                    indicator = {
                        "type": "C2_DNS_HIGH_ENTROPY",
                        "severity": "MEDIUM",
                        "src": src_key,
                        "dst": dst_key,
                        "entropy": round(conv.dns_entropy, 2),
                        "query_count": len(conv.dns_queries),
                        "sample_queries": list(conv.dns_queries)[:5],
                        "description": (
                            f"High-entropy DNS queries from {src_key} "
                            f"(entropy {conv.dns_entropy:.2f}, {len(conv.dns_queries)} queries)"
                        ),
                    }
                    c2_indicators.append(indicator)
                    self.findings.append(RiskFinding(
                        severity="MEDIUM",
                        category="C2_DNS_HIGH_ENTROPY",
                        description=indicator["description"],
                        affected_nodes=[src_key],
                        remediation="Investigate encoded DNS queries — potential data exfiltration channel",
                    ))

            # ── D. Suspect C2 Channel (OT device -> external on unknown high port) ──
            src_node = self.nodes.get(src_key, {})
            src_level = src_node.get("purdue_level", -1) if isinstance(src_node, dict) else -1
            if (src_level in (0, 1, 2)
                    and dst_public
                    and not is_ot_port and not is_known_port
                    and conv.port > 1024):
                indicator = {
                    "type": "C2_SUSPECT_CHANNEL",
                    "severity": "HIGH",
                    "src": src_key,
                    "dst": dst_key,
                    "port": conv.port,
                    "transport": conv.transport,
                    "packets": conv.packet_count,
                    "bytes": conv.bytes_total,
                    "description": (
                        f"OT device {src_key} (L{src_level}) communicating with external {dst_key}:{conv.port} "
                        f"on unknown port ({conv.packet_count} pkts, {conv.bytes_total} bytes)"
                    ),
                }
                c2_indicators.append(indicator)
                self.findings.append(RiskFinding(
                    severity="HIGH",
                    category="C2_SUSPECT_CHANNEL",
                    description=indicator["description"],
                    affected_nodes=[src_key, dst_key],
                    remediation="Block unauthorized external connections from OT devices — investigate for compromise",
                ))
                print(f"  [HIGH] Suspect C2 channel: {src_key}(L{src_level}) -> {dst_key}:{conv.port}")

        # ── C. Data Exfiltration (Asymmetric Flows) ──
        flow_pairs = defaultdict(lambda: {"outbound": 0, "inbound": 0})
        for conv in self.conversations:
            src_key = conv.src_ip or conv.src_mac
            dst_key = conv.dst_ip or conv.dst_mac
            pair_key = (src_key, dst_key) if src_key < dst_key else (dst_key, src_key)
            if src_key < dst_key:
                flow_pairs[pair_key]["outbound"] += conv.bytes_total
            else:
                flow_pairs[pair_key]["inbound"] += conv.bytes_total

        for (a, b), flows in flow_pairs.items():
            # Check both directions for asymmetry to external
            for src, dst, out_bytes, in_bytes in [
                (a, b, flows["outbound"], flows["inbound"]),
                (b, a, flows["inbound"], flows["outbound"]),
            ]:
                if out_bytes <= 0 or in_bytes <= 0:
                    continue
                dst_public = self._is_public_ip(dst) if dst else False
                src_node = self.nodes.get(src, {})
                src_level = src_node.get("purdue_level", -1) if isinstance(src_node, dict) else -1
                if (dst_public and src_level in (0, 1, 2)
                        and out_bytes > 10 * in_bytes
                        and out_bytes > 10240):
                    indicator = {
                        "type": "C2_DATA_EXFIL",
                        "severity": "HIGH",
                        "src": src,
                        "dst": dst,
                        "outbound_bytes": out_bytes,
                        "inbound_bytes": in_bytes,
                        "ratio": round(out_bytes / max(in_bytes, 1), 1),
                        "description": (
                            f"Asymmetric data flow: {src}(L{src_level}) -> {dst} "
                            f"({out_bytes} bytes out vs {in_bytes} bytes in, {out_bytes/max(in_bytes,1):.1f}x ratio)"
                        ),
                    }
                    c2_indicators.append(indicator)
                    self.findings.append(RiskFinding(
                        severity="HIGH",
                        category="C2_DATA_EXFIL",
                        description=indicator["description"],
                        affected_nodes=[src, dst],
                        remediation="Investigate large outbound data transfers from OT devices — possible data exfiltration",
                    ))
                    print(f"  [HIGH] Data exfil: {src} -> {dst} ({out_bytes/max(in_bytes,1):.1f}x asymmetry)")

        # ── E. Connection Persistence ──
        capture_duration = 0.0
        if hasattr(self, '_capture_duration'):
            capture_duration = self._capture_duration
        if capture_duration > 0:
            for conv in self.conversations:
                dst_public = self._is_public_ip(conv.dst_ip) if conv.dst_ip else False
                is_known = conv.port in OT_PROTOCOLS or conv.port in WELL_KNOWN_PORTS
                if not dst_public or is_known:
                    continue
                # Estimate conversation duration from first/last timestamps
                # Use beacon timestamps if available
                if conv.beacon_interval > 0 and conv.packet_count > 2:
                    est_duration = conv.beacon_interval * conv.packet_count
                    if est_duration > 0.8 * capture_duration:
                        src_key = conv.src_ip or conv.src_mac
                        dst_key = conv.dst_ip or conv.dst_mac
                        indicator = {
                            "type": "C2_PERSISTENCE",
                            "severity": "MEDIUM",
                            "src": src_key,
                            "dst": dst_key,
                            "port": conv.port,
                            "est_duration": round(est_duration, 1),
                            "capture_duration": round(capture_duration, 1),
                            "description": (
                                f"Persistent connection: {src_key} -> {dst_key}:{conv.port} "
                                f"(~{est_duration:.0f}s of {capture_duration:.0f}s capture)"
                            ),
                        }
                        c2_indicators.append(indicator)
                        self.findings.append(RiskFinding(
                            severity="MEDIUM",
                            category="C2_PERSISTENCE",
                            description=indicator["description"],
                            affected_nodes=[src_key, dst_key],
                            remediation="Investigate persistent connections to external hosts on non-standard ports",
                        ))

        return c2_indicators


# ---------------------------------------------------------------------------
# CLI / Chain Orchestrator
# ---------------------------------------------------------------------------

BANNER = r"""
 ╔══════════════════════════════════════════════════╗
 ║   ███╗   ███╗ █████╗ ██████╗ ██╗     ██╗███╗  ██╗ ║
 ║   ████╗ ████║██╔══██╗██╔══██╗██║     ██║████╗ ██║ ║
 ║   ██╔████╔██║███████║██████╔╝██║     ██║██╔██╗██║ ║
 ║   ██║╚██╔╝██║██╔══██║██╔══██╗██║     ██║██║╚████║ ║
 ║   ██║ ╚═╝ ██║██║  ██║██║  ██║███████╗██║██║ ╚███║ ║
 ║   ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝╚═╝  ╚══╝ ║
 ║                                          SPIKE    ║
 ║   RiverFlow Voracity — VORACITY-MODULE-MARLINSPIKE║
 ║   Passive OT Topology Mapping — Zero Transmission ║
 ║   CWE-200 │ MITRE T1040 │ IEC 62443 SR 2.8       ║
 ║                                                   ║
 ║   [!] AUTHORIZED ENGAGEMENT ONLY                  ║
 ╚═══════════════════════════════════════════════════╝
"""


def _save_intermediate(report, path, stage_name):
    """Save intermediate report after completing a stage."""
    report.completed_stages.append(stage_name)
    report.timestamp_end = datetime.now(timezone.utc).isoformat()
    try:
        report.save(path)
    except Exception as e:
        print(f"  [!] Failed to save intermediate report: {e}")


def run_chain(args):
    """Full attack chain: ingest → dissect → topology → risk.

    Registers SIGTERM/SIGINT handlers for graceful shutdown. Saves
    intermediate report after each stage so progress is never lost
    when stopped from the UI.
    """
    global _active_report, _active_report_path, _shutdown_requested

    # Register signal handlers
    signal.signal(signal.SIGTERM, _shutdown_handler)
    signal.signal(signal.SIGINT, _shutdown_handler)
    _apply_fast_profile(args)

    print(BANNER)
    report = MarlinSpikeReport(
        timestamp_start=datetime.now(timezone.utc).isoformat(),
    )
    _active_report = report
    _active_report_path = args.output

    # Check for tshark — try common paths if bare name fails
    tshark_found = False
    for tshark_candidate in ["tshark", "/usr/bin/tshark", "/usr/local/bin/tshark"]:
        try:
            result = subprocess.run([tshark_candidate, "--version"],
                                  capture_output=True, text=True, timeout=5)
            version_match = re.search(r"TShark.*(\d+\.\d+\.\d+)", result.stdout)
            if version_match:
                report.tshark_version = version_match.group(1)
                print(f"[*] tshark version: {report.tshark_version}")
                tshark_found = True
                break
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    if not tshark_found:
        print("[!] WARNING: tshark not found — capture analysis will fail")
        print("    Install Wireshark/tshark: apt-get install tshark")

    # ── Stage 1: Ingest ──────────────────────────────────────────
    ingestor = CaptureIngestor(
        pcap=args.pcap,
        no_reassembly=not getattr(args, 'reassembly', False),
    )
    capture_info = ingestor.ingest()
    report.capture_info = asdict(capture_info)
    _save_intermediate(report, args.output, "Capture Ingestion")

    if _shutdown_requested:
        print("[*] Stopped after Stage 1 — partial report saved")
        return report

    # ── Stage 2: Dissect ─────────────────────────────────────────
    conversations = []
    if not args.no_grassmarlin:
        bridge = GrassMarlinBridge(
            binary_path=args.grassmarlin,
            pcap_path=capture_info.pcap_path,
            output_dir="/tmp/marlinspike-grassmarlin"
        )
        if bridge.is_available():
            print(f"\n[*] GrassMarlin detected — using headless mode")
            gm_topology = bridge.run()
            report.grassmarlin_used = True
            report.topology = gm_topology
            report.nodes = gm_topology.get("nodes", [])
            report.edges = gm_topology.get("edges", [])
        else:
            print(f"\n[*] GrassMarlin not available — using built-in parser")
            report.grassmarlin_used = False

    if not report.grassmarlin_used:
        capture_id = os.path.splitext(os.path.basename(capture_info.pcap_path))[0] or "capture"
        conversations, port_summary, dpi_metadata = _dissect_with_selected_engine(
            capture_info.pcap_path,
            args,
            capture_id,
        )
        report.conversations = [asdict(c) for c in conversations]
        report.dpi_engine = dpi_metadata.get("engine", "python")
        report.dpi_engine_version = dpi_metadata.get("version", "")
        report.dpi_schema_version = dpi_metadata.get("schema_version", "")

        proto_counts = defaultdict(int)
        for conv in conversations:
            proto_counts[conv.protocol] += 1
        report.protocol_summary = dict(proto_counts)

        # Backfill capture_info with address/protocol data from dissection
        # (deferred from Stage 1 to avoid a redundant full tshark pass)
        all_macs = set()
        all_ips = set()
        for c in conversations:
            if c.src_mac: all_macs.add(c.src_mac)
            if c.dst_mac: all_macs.add(c.dst_mac)
            if c.src_ip: all_ips.add(c.src_ip)
            if c.dst_ip: all_ips.add(c.dst_ip)
        capture_info.unique_macs = len(all_macs)
        capture_info.unique_ips = len(all_ips)
        capture_info.protocols_seen = dict(proto_counts)
        report.capture_info = asdict(capture_info)
        report.port_summary = port_summary

    _save_intermediate(report, args.output, "Protocol Dissection")

    if _shutdown_requested:
        print("[*] Stopped after Stage 2 — partial report saved")
        return report

    # ── Stage 3: Topology ────────────────────────────────────────
    if not report.grassmarlin_used:
        builder = TopologyBuilder(
            conversations=conversations,
            subnet_map=_load_subnet_map(args.subnet_map),
            skip_ephemeral=args.skip_ephemeral,
        )
        topology = builder.build()
        report.topology = topology
        report.nodes = topology["nodes"]
        report.edges = topology["edges"]
        report.mac_table = topology.get("mac_table", [])

    _save_intermediate(report, args.output, "Topology Construction")

    if _shutdown_requested:
        print("[*] Stopped after Stage 3 — partial report saved")
        return report

    # ── Stage 4: Risk ────────────────────────────────────────────
    risk_analyzer = RiskSurface(
        topology=report.topology,
        conversations=conversations if not report.grassmarlin_used else [],
        skip_c2=getattr(args, "fast", False),
    )
    # Pass capture duration for persistence detection
    if report.capture_info:
        risk_analyzer._capture_duration = report.capture_info.get("duration_s", 0.0)
    risk_report = risk_analyzer.score()
    report.risk_findings = risk_report["findings"]
    report.attack_targets = risk_report["attack_targets"]
    report.c2_indicators = risk_report.get("c2_indicators", [])

    # Port summary from dissector
    _save_intermediate(report, args.output, "Risk Surface Report")

    report.timestamp_end = datetime.now(timezone.utc).isoformat()
    report.interrupted = False
    report.save(args.output)

    # YAML relationship map
    yaml_path = args.yaml_map
    if yaml_path == "":
        yaml_path = args.output.replace(".json", "-map.yaml")
    if yaml_path:
        report.save_yaml_map(yaml_path)

    _active_report = None
    _active_report_path = None
    return report


def run_ingest(args):
    """Stage 1 only: ingest and validate PCAP."""
    global _active_report, _active_report_path
    signal.signal(signal.SIGTERM, _shutdown_handler)
    signal.signal(signal.SIGINT, _shutdown_handler)

    print(BANNER)
    ingestor = CaptureIngestor(pcap=args.pcap)
    report = MarlinSpikeReport(
        timestamp_start=datetime.now(timezone.utc).isoformat(),
    )
    _active_report = report
    _active_report_path = args.output

    capture_info = ingestor.ingest()
    report.capture_info = asdict(capture_info)
    report.completed_stages.append("Capture Ingestion")
    report.timestamp_end = datetime.now(timezone.utc).isoformat()
    report.save(args.output)

    _active_report = None
    _active_report_path = None

    # Save artifact for dissect command
    reports_dir = os.path.dirname(os.path.abspath(args.output))
    run_id = os.path.basename(args.output).replace(".json", "").split("-")[-1][:8]
    artifact_path = os.path.join(reports_dir, f"{MODULE_META['id']}-ingest-{run_id}.json")
    artifact = {
        "artifact_type": "indexed_capture",
        "module_id": MODULE_META["id"],
        "command": "ingest",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": {
            "pcap_path": capture_info.pcap_path,
        },
    }
    with open(artifact_path, "w") as f:
        json.dump(artifact, f, indent=2)
    print(f"[*] Artifact saved: {artifact_path}")

    return report


def run_dissect(args):
    """Stage 2 only: protocol dissection."""
    print(BANNER)
    _apply_fast_profile(args)

    # Auto-discover PCAP from ingest artifact if not provided
    pcap_path = args.pcap
    if not pcap_path:
        reports_dir = os.path.dirname(os.path.abspath(args.output))
        print("[*] No --pcap specified, looking for ingest artifact...")
        artifact_path = _find_recent_artifact(reports_dir, MODULE_META["id"], "ingest")
        if artifact_path:
            with open(artifact_path) as f:
                artifact = json.load(f)
            pcap_path = artifact["data"]["pcap_path"]
            print(f"[*] Using PCAP from artifact: {pcap_path}")
        else:
            print("[!] No ingest artifact found and no --pcap provided")
            sys.exit(1)

    capture_id = os.path.splitext(os.path.basename(pcap_path))[0] or "capture"
    conversations, port_summary, dpi_metadata = _dissect_with_selected_engine(
        pcap_path,
        args,
        capture_id,
    )

    report = MarlinSpikeReport(
        timestamp_start=datetime.now(timezone.utc).isoformat(),
        conversations=[asdict(c) for c in conversations],
        protocol_summary=dict(defaultdict(int)),
        port_summary=port_summary,
        dpi_engine=dpi_metadata.get("engine", "python"),
        dpi_engine_version=dpi_metadata.get("version", ""),
        dpi_schema_version=dpi_metadata.get("schema_version", ""),
    )
    proto_counts = defaultdict(int)
    for conv in conversations:
        proto_counts[conv.protocol] += 1
    report.protocol_summary = dict(proto_counts)
    report.timestamp_end = datetime.now(timezone.utc).isoformat()
    report.save(args.output)

    # Save artifact for topology command
    reports_dir = os.path.dirname(os.path.abspath(args.output))
    run_id = os.path.basename(args.output).replace(".json", "").split("-")[-1][:8]
    artifact_path = os.path.join(reports_dir, f"{MODULE_META['id']}-dissect-{run_id}.json")
    artifact = {
        "artifact_type": "protocol_conversations",
        "module_id": MODULE_META["id"],
        "command": "dissect",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "engine": report.dpi_engine,
        "engine_version": report.dpi_engine_version,
        "schema_version": report.dpi_schema_version,
        "data": {
            "conversations": [asdict(c) for c in conversations],
            "protocol_summary": report.protocol_summary,
            "port_summary": port_summary,
        },
    }
    with open(artifact_path, "w") as f:
        json.dump(artifact, f, indent=2, default=str)
    print(f"[*] Artifact saved: {artifact_path}")

    return report


def run_topology(args):
    """Stage 3 only: topology construction."""
    print(BANNER)
    _apply_fast_profile(args)

    # Auto-discover conversations from dissect artifact if not provided
    conversations_data = []
    if args.conversations:
        with open(args.conversations) as f:
            data = json.load(f)
            conversations_data = data.get("conversations", data.get("data", {}).get("conversations", []))
    else:
        reports_dir = os.path.dirname(os.path.abspath(args.output))
        print("[*] No --conversations specified, looking for dissect artifact...")
        artifact_path = _find_recent_artifact(reports_dir, MODULE_META["id"], "dissect")
        if artifact_path:
            with open(artifact_path) as f:
                artifact = json.load(f)
            conversations_data = artifact["data"]["conversations"]
            print(f"[*] Using conversations from artifact: {os.path.basename(artifact_path)}")
        else:
            print("[!] No dissect artifact found and no --conversations provided")
            sys.exit(1)

    # Convert dict conversations back to Conversation objects
    conversations = []
    for c_dict in conversations_data:
        conversations.append(Conversation(**c_dict))

    builder = TopologyBuilder(
        conversations=conversations,
        subnet_map=_load_subnet_map(args.subnet_map),
        skip_ephemeral=args.skip_ephemeral,
    )
    topology = builder.build()

    report = MarlinSpikeReport(
        timestamp_start=datetime.now(timezone.utc).isoformat(),
        topology=topology,
        nodes=topology["nodes"],
        edges=topology["edges"],
        mac_table=topology.get("mac_table", []),
    )
    report.timestamp_end = datetime.now(timezone.utc).isoformat()
    report.save(args.output)

    # YAML relationship map
    yaml_path = args.yaml_map
    if yaml_path == "":
        yaml_path = args.output.replace(".json", "-map.yaml")
    if yaml_path:
        report.save_yaml_map(yaml_path)

    # Save artifact for risk command
    reports_dir = os.path.dirname(os.path.abspath(args.output))
    run_id = os.path.basename(args.output).replace(".json", "").split("-")[-1][:8]
    artifact_path = os.path.join(reports_dir, f"{MODULE_META['id']}-topology-{run_id}.json")
    artifact = {
        "artifact_type": "ot_topology",
        "module_id": MODULE_META["id"],
        "command": "topology",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": topology,
    }
    with open(artifact_path, "w") as f:
        json.dump(artifact, f, indent=2, default=str)
    print(f"[*] Artifact saved: {artifact_path}")

    return report


def run_risk(args):
    """Stage 4 only: risk surface analysis."""
    print(BANNER)
    _apply_fast_profile(args)

    # Auto-discover topology from topology artifact if not provided
    topology_data = None
    if args.topology_file:
        with open(args.topology_file) as f:
            data = json.load(f)
            topology_data = data.get("topology", data.get("data", {}))
    else:
        reports_dir = os.path.dirname(os.path.abspath(args.output))
        print("[*] No --topology specified, looking for topology artifact...")
        artifact_path = _find_recent_artifact(reports_dir, MODULE_META["id"], "topology")
        if artifact_path:
            with open(artifact_path) as f:
                artifact = json.load(f)
            topology_data = artifact["data"]
            print(f"[*] Using topology from artifact: {os.path.basename(artifact_path)}")
        else:
            print("[!] No topology artifact found and no --topology provided")
            sys.exit(1)

    # Run risk analysis
    risk_analyzer = RiskSurface(
        topology=topology_data,
        conversations=[],  # Risk analysis doesn't need full conversations
        skip_c2=getattr(args, "fast", False),
    )
    risk_report = risk_analyzer.score()

    report = MarlinSpikeReport(
        timestamp_start=datetime.now(timezone.utc).isoformat(),
        topology=topology_data,
        nodes=topology_data.get("nodes", []),
        edges=topology_data.get("edges", []),
        risk_findings=risk_report["findings"],
        attack_targets=risk_report["attack_targets"],
    )
    report.timestamp_end = datetime.now(timezone.utc).isoformat()
    report.save(args.output)

    return report


def run_chain_from_conversations(args):
    """Topology + risk from a merged conversations artifact."""
    global _active_report, _active_report_path, _shutdown_requested

    signal.signal(signal.SIGTERM, _shutdown_handler)
    signal.signal(signal.SIGINT, _shutdown_handler)
    _apply_fast_profile(args)

    print(BANNER)
    report = MarlinSpikeReport(
        timestamp_start=datetime.now(timezone.utc).isoformat(),
    )
    _active_report = report
    _active_report_path = args.output

    if not args.conversations:
        print("[!] --conversations is required for chain-from-conversations")
        sys.exit(1)

    with open(args.conversations) as f:
        data = json.load(f)

    conversations_data = data.get("conversations", data.get("data", {}).get("conversations", []))
    capture_info_data = data.get("capture_info", data.get("data", {}).get("capture_info", {})) or {}
    conversations = [Conversation(**c_dict) for c_dict in conversations_data]

    print(f"[*] Loaded {len(conversations):,} merged conversations")

    report.conversations = conversations_data
    report.capture_info = dict(capture_info_data)
    report.dpi_engine = data.get("engine", report.dpi_engine)
    report.dpi_engine_version = data.get("engine_version", report.dpi_engine_version)
    report.dpi_schema_version = data.get("schema_version", report.dpi_schema_version)

    proto_counts = defaultdict(int)
    all_macs = set()
    all_ips = set()
    for conv in conversations:
        proto_counts[conv.protocol] += 1
        if conv.src_mac:
            all_macs.add(conv.src_mac)
        if conv.dst_mac:
            all_macs.add(conv.dst_mac)
        if conv.src_ip:
            all_ips.add(conv.src_ip)
        if conv.dst_ip:
            all_ips.add(conv.dst_ip)
    report.protocol_summary = dict(proto_counts)
    report.port_summary = _build_port_summary_from_conversations(conversations)
    report.capture_info["unique_macs"] = len(all_macs)
    report.capture_info["unique_ips"] = len(all_ips)
    report.capture_info["protocols_seen"] = dict(proto_counts)

    if _shutdown_requested:
        print("[*] Stopped before topology — partial report saved")
        report.save(args.output)
        return report

    builder = TopologyBuilder(
        conversations=conversations,
        subnet_map=_load_subnet_map(args.subnet_map),
        skip_ephemeral=args.skip_ephemeral,
    )
    topology = builder.build()
    report.topology = topology
    report.nodes = topology["nodes"]
    report.edges = topology["edges"]
    report.mac_table = topology.get("mac_table", [])
    _save_intermediate(report, args.output, "Topology Construction")

    if _shutdown_requested:
        print("[*] Stopped after Stage 3 — partial report saved")
        return report

    risk_analyzer = RiskSurface(
        topology=report.topology,
        conversations=conversations,
        skip_c2=getattr(args, "fast", False),
    )
    if report.capture_info:
        risk_analyzer._capture_duration = report.capture_info.get("duration_s", 0.0)
    risk_report = risk_analyzer.score()
    report.risk_findings = risk_report["findings"]
    report.attack_targets = risk_report["attack_targets"]
    report.c2_indicators = risk_report.get("c2_indicators", [])
    _save_intermediate(report, args.output, "Risk Surface Report")

    report.timestamp_end = datetime.now(timezone.utc).isoformat()
    report.interrupted = False
    report.save(args.output)

    _active_report = None
    _active_report_path = None
    return report


def _load_subnet_map(path: str) -> dict:
    """Load subnet-to-Purdue-level mapping from JSON file."""
    if not path or not os.path.exists(path):
        return {}
    with open(path) as f:
        return json.load(f)


def _apply_fast_profile(args) -> None:
    """Apply low-cost defaults for triage-first, time-bounded scans."""
    if not getattr(args, "fast", False):
        return
    args.skip_ephemeral = True
    if getattr(args, "collapse_threshold", 50) == 50:
        args.collapse_threshold = 25


def main():
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    parser = argparse.ArgumentParser(
        prog="marlinspike",
        description="RiverFlow Voracity — MarlinSpike (Passive OT Topology Mapping)",
    )

    # All arguments on parent parser
    parser.add_argument("--pcap", default="",
                       help="Input PCAP/PCAPNG file")
    parser.add_argument("--subnet-map", default="",
                       help="JSON file mapping subnets to Purdue levels")
    parser.add_argument("--oui-db", default="",
                       help="ICS vendor OUI database")
    parser.add_argument("--grassmarlin", default="",
                       help="Path to GrassMarlin binary")
    parser.add_argument("--no-grassmarlin", action="store_true", default=True,
                       help="Force built-in parser (default: True)")
    parser.add_argument("--conversations", default="",
                       help="Pre-parsed conversations JSON (for topology command)")
    parser.add_argument("--topology", dest="topology_file", default="",
                       help="Pre-built topology JSON (for risk command)")
    parser.add_argument("-o", "--output",
                       default=f"marlinspike-report-{ts}.json",
                       help="Report output path")
    parser.add_argument("--yaml-map", default="",
                       help="Export YAML relationship map to this path (auto-named if empty)")
    parser.add_argument("--skip-ephemeral", action="store_true", default=False,
                       help="Skip ephemeral-port (>=49152) edges for cleaner relationship view")
    parser.add_argument("--chunk-size", type=int, default=0,
                       help="Process PCAP in chunks of N packets (0 = single pass, default: 0)")
    parser.add_argument("--collapse-threshold", type=int, default=50,
                       help="Collapse port scan conversations when MAC pair has >N unique dest ports (0 = disabled, default: 50)")
    parser.add_argument("--reassembly", action="store_true", default=False,
                       help="Enable TCP reassembly (default: disabled for lower memory usage)")
    parser.add_argument("--fast", action="store_true", default=False,
                       help="Fast scan: skip ephemeral edges, lower collapse threshold, and skip C2 heuristics")
    parser.add_argument("--dpi-engine", default="auto",
                       choices=["auto", "python", "marlinspike-dpi"],
                       help="Stage 2 DPI engine to use (default: auto)")
    parser.add_argument("--dpi-binary", default="",
                       help="Path to marlinspike-dpi binary (default: PATH or MARLINSPIKE_DPI_BIN)")

    # Subcommands
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("chain", help="Full chain: ingest → dissect → topology → risk").set_defaults(func=run_chain)
    sub.add_parser("ingest", help="Stage 1: capture ingestion").set_defaults(func=run_ingest)
    sub.add_parser("dissect", help="Stage 2: protocol dissection").set_defaults(func=run_dissect)
    sub.add_parser("topology", help="Stage 3: topology construction").set_defaults(func=run_topology)
    sub.add_parser("risk", help="Stage 4: risk surface analysis").set_defaults(func=run_risk)
    sub.add_parser("chain-from-conversations", help="Topology + risk from merged conversations").set_defaults(func=run_chain_from_conversations)
    sub.add_parser("analyze", help="Legacy alias for dissect").set_defaults(func=run_dissect)
    sub.add_parser("classify", help="Legacy alias for topology").set_defaults(func=run_topology)
    sub.add_parser("report", help="Legacy alias for risk").set_defaults(func=run_risk)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Normalize empty strings
    args.pcap = args.pcap or ""
    args.subnet_map = args.subnet_map or ""
    args.oui_db = args.oui_db or ""
    args.grassmarlin = args.grassmarlin or ""
    args.conversations = args.conversations or ""
    args.topology_file = getattr(args, "topology_file", getattr(args, "topology", "")) or ""
    args.dpi_engine = args.dpi_engine or "auto"
    args.dpi_binary = args.dpi_binary or ""
    if not hasattr(args, "yaml_map"):
        args.yaml_map = ""

    args.func(args)


if __name__ == "__main__":
    main()
