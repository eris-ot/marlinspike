"""MarlinSpike — Standalone passive OT network topology mapper.

Flask web application with database-backed auth and scan history.
"""

import glob
import hashlib
import io
import json
import logging
import math
import os
import platform
import re
import secrets
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

import yaml
from flask import (
    Flask,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from limits.storage import storage_from_string

from marlinspike import config
from marlinspike import enrich as _enrich
from marlinspike.aggregate import aggregate_reports
from marlinspike.baselines import compute_asset_baseline
from marlinspike.audit import audit
from marlinspike.auth import (
    admin_required,
    bootstrap_admin,
    change_password,
    cleanup_expired_tokens,
    create_reset_token,
    create_user,
    csrf_exempt,
    login_required,
    use_reset_token,
    validate_reset_token,
    verify_user,
)
from marlinspike.csrf import csrf_token, rotate_csrf, validate_csrf
from marlinspike.i18n import (
    DEFAULT_LOCALE,
    LOCALE_LABELS,
    SUPPORTED_LOCALES,
    load_translations,
    merged_for_locale,
    normalise_locale,
    resolve_locale,
    t as _translate,
)
from marlinspike.iocs import (
    VALID_IOC_TYPES,
    VALID_SEVERITIES,
    parse_ioc_paste,
    scan_ioc_list_against_reports,
)
from marlinspike.models import (
    AssetTag,
    AuditLog,
    FindingNote,
    IocEntry,
    IocList,
    PasswordResetToken,
    Project,
    ProjectMember,
    ScanHistory,
    User,
    db,
)

APP_VERSION = "3.6.0"

log = logging.getLogger("marlinspike")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")

# PCAP magic bytes for validation
PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1",  # pcap LE
    b"\xa1\xb2\xc3\xd4",  # pcap BE
    b"\x0a\x0d\x0d\x0a",  # pcapng
}


# ═══════════════════════════════════════════════════════════════
# Timeline helpers — module-level so they are importable from tests
# ═══════════════════════════════════════════════════════════════

def _ts_to_epoch(value):
    """Convert a timestamp value to a Unix epoch float, or None."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError):
        return None


def _compute_timeline_buckets(conversations: list) -> dict:
    """Build adaptive timeline buckets from a list of conversation dicts.

    Returns a dict with keys: first_seen, last_seen, bucket_seconds, buckets.
    Each bucket: {t, packets, bytes, conv_count}.
    """
    entries = []
    for conv in conversations:
        fs = _ts_to_epoch(conv.get("first_seen"))
        ls = _ts_to_epoch(conv.get("last_seen"))
        pkts = int(conv.get("packet_count") or 0)
        bts = int(conv.get("bytes_total") or 0)
        if fs is None:
            continue
        if ls is None or ls < fs:
            ls = fs
        entries.append((fs, ls, pkts, bts))

    if not entries:
        return {
            "first_seen": None,
            "last_seen": None,
            "bucket_seconds": 1,
            "buckets": [],
        }

    global_first = min(e[0] for e in entries)
    global_last = max(e[1] for e in entries)
    span = global_last - global_first

    # ~120 buckets max; minimum 1 second per bucket
    bucket_seconds = max(1, math.ceil(span / 120)) if span > 0 else 1
    n_buckets = math.ceil(span / bucket_seconds) + 1 if span > 0 else 1

    pkt_arr = [0] * n_buckets
    byte_arr = [0] * n_buckets
    conv_arr = [0] * n_buckets

    for (fs, ls, pkts, bts) in entries:
        b_start = int((fs - global_first) / bucket_seconds)
        b_end = int((ls - global_first) / bucket_seconds)
        b_start = max(0, min(b_start, n_buckets - 1))
        b_end = max(0, min(b_end, n_buckets - 1))
        n_span = b_end - b_start + 1
        # Distribute packets/bytes uniformly; spread remainder across leading buckets
        pkt_each, pkt_rem = divmod(pkts, n_span)
        byte_each, byte_rem = divmod(bts, n_span)
        for offset in range(n_span):
            i = b_start + offset
            conv_arr[i] += 1
            pkt_arr[i] += pkt_each + (1 if offset < pkt_rem else 0)
            byte_arr[i] += byte_each + (1 if offset < byte_rem else 0)

    buckets = []
    for i in range(n_buckets):
        t = global_first + i * bucket_seconds
        if pkt_arr[i] or byte_arr[i] or conv_arr[i]:
            buckets.append({
                "t": t,
                "packets": pkt_arr[i],
                "bytes": byte_arr[i],
                "conv_count": conv_arr[i],
            })

    return {
        "first_seen": global_first,
        "last_seen": global_last,
        "bucket_seconds": bucket_seconds,
        "buckets": buckets,
    }


# LRU cache keyed by (path, mtime), max 32 entries
_timeline_cache: dict = {}
_TIMELINE_CACHE_MAX = 32


def _get_timeline_for_report(path: str, conversations: list) -> dict:
    """Return cached timeline dict; keyed by (path, mtime) to invalidate on file change."""
    try:
        mtime = os.stat(path).st_mtime
    except OSError:
        mtime = 0.0
    cache_key = (path, mtime)
    if cache_key in _timeline_cache:
        return _timeline_cache[cache_key]
    result = _compute_timeline_buckets(conversations)
    if len(_timeline_cache) >= _TIMELINE_CACHE_MAX:
        # Evict oldest inserted key
        oldest = next(iter(_timeline_cache))
        del _timeline_cache[oldest]
    _timeline_cache[cache_key] = result
    return result


# ═══════════════════════════════════════════════════════════════
# Run registry — in-memory subprocess tracking
# ═══════════════════════════════════════════════════════════════

_run_registry = {}  # run_id -> {process, output, status, ...}
_runs_lock = threading.Lock()
_stage_re = re.compile(r"^\s*STAGE\s+(\d+)\s*[—–-]\s*(.+)")
_error_re = re.compile(r"\[!\].*(?:FAILED|ERROR)", re.IGNORECASE)


REPORT_FINDING_COVERAGE = [
    {
        "id": "ICS_EXTERNAL_COMMS",
        "title": "OT asset direct internet communications",
        "type": "finding",
        "family": "network exposure",
        "severity": "CRITICAL",
        "detail": "Flags OT or ICS assets observed talking directly to public internet addresses.",
    },
    {
        "id": "EXTERNAL_IPS_OBSERVED",
        "title": "Public internet addresses observed",
        "type": "finding",
        "family": "network exposure",
        "severity": "INFO",
        "detail": "Records public internet addresses present in the capture even when direct OT exposure is not established.",
    },
    {
        "id": "CROSS_PURDUE",
        "title": "Cross-Purdue communication violations",
        "type": "finding",
        "family": "segmentation",
        "severity": "HIGH",
        "detail": "Detects direct communications that bypass expected Purdue supervisory boundaries.",
    },
    {
        "id": "CLEARTEXT_ENG",
        "title": "Cleartext engineering operations",
        "type": "finding",
        "family": "engineering access",
        "severity": "HIGH",
        "detail": "Highlights engineering actions carried over cleartext industrial protocols.",
    },
    {
        "id": "MODBUS_WRITE_ANON",
        "title": "Multiple Modbus write sources",
        "type": "finding",
        "family": "control-path risk",
        "severity": "MEDIUM",
        "detail": "Flags unexpected or overly broad sources issuing Modbus write operations.",
    },
    {
        "id": "NO_AUTH_OBSERVED",
        "title": "No authentication observed",
        "type": "finding",
        "family": "authentication gap",
        "severity": "MEDIUM",
        "detail": "Calls out devices with no observed authentication exchanges in the capture surface.",
    },
    {
        "id": "OPC_NO_SECURITY",
        "title": "OPC UA SecurityMode=None",
        "type": "finding",
        "family": "protocol security",
        "severity": "HIGH",
        "detail": "Detects OPC UA sessions established without transport or message security.",
    },
    {
        "id": "S7_PROGRAM_ACCESS",
        "title": "S7 program upload or download activity",
        "type": "finding",
        "family": "control-path risk",
        "severity": "CRITICAL",
        "detail": "Highlights Siemens S7 programming access that may expose PLC logic or allow engineering changes.",
    },
    {
        "id": "CLEARTEXT_REMOTE_ACCESS",
        "title": "Cleartext remote access services",
        "type": "finding",
        "family": "service exposure",
        "severity": "HIGH",
        "detail": "Flags cleartext remote administration services such as Telnet, FTP, and VNC.",
    },
    {
        "id": "PORT_SCAN_TARGET",
        "title": "Possible port-scan target surface",
        "type": "finding",
        "family": "service exposure",
        "severity": "HIGH",
        "detail": "Aggregates unusually broad unknown port exposure that resembles port-scan target behavior.",
    },
    {
        "id": "UNKNOWN_SERVICE_PORT",
        "title": "Unknown service on OT device",
        "type": "finding",
        "family": "service exposure",
        "severity": "MEDIUM",
        "detail": "Flags unknown or unexplained listener ports on OT assets.",
    },
    {
        "id": "IT_SERVICE_ON_OT_DEVICE",
        "title": "IT service on field OT device",
        "type": "finding",
        "family": "service exposure",
        "severity": "MEDIUM",
        "detail": "Highlights non-allowed IT services exposed by Level 0 or Level 1 devices.",
    },
    {
        "id": "HIGH_PORT_SERVICE",
        "title": "High-port unknown service",
        "type": "finding",
        "family": "service exposure",
        "severity": "MEDIUM",
        "detail": "Flags stable unknown services running on high ports outside the normal ephemeral pattern.",
    },
    {
        "id": "C2_BEACONING",
        "title": "Beaconing and periodic command channel indicators",
        "type": "indicator",
        "family": "command and control",
        "severity": "HIGH",
        "detail": "Uses interval clustering and timing analysis to flag recurring beacon-like communications.",
    },
    {
        "id": "C2_DNS_EXFIL",
        "title": "DNS exfiltration indicators",
        "type": "indicator",
        "family": "exfiltration",
        "severity": "CRITICAL",
        "detail": "Identifies high-volume or asymmetrical DNS activity suggestive of exfiltration over DNS.",
    },
    {
        "id": "C2_DNS_TUNNEL_SUSPECT",
        "title": "DNS tunneling suspects",
        "type": "indicator",
        "family": "command and control",
        "severity": "HIGH",
        "detail": "Flags suspicious DNS behavior consistent with covert tunneling or staged command channels.",
    },
    {
        "id": "C2_DNS_HIGH_ENTROPY",
        "title": "High-entropy DNS labels",
        "type": "indicator",
        "family": "exfiltration",
        "severity": "MEDIUM",
        "detail": "Surfaces high-entropy DNS labels that may indicate encoded payloads or tunneled data.",
    },
    {
        "id": "C2_SUSPECT_CHANNEL",
        "title": "Suspicious external channels",
        "type": "indicator",
        "family": "command and control",
        "severity": "HIGH",
        "detail": "Highlights unexplained external connections on unusual ports or protocols.",
    },
    {
        "id": "C2_DATA_EXFIL",
        "title": "Asymmetric outbound data transfer",
        "type": "indicator",
        "family": "exfiltration",
        "severity": "HIGH",
        "detail": "Flags strongly asymmetric outbound flows from OT assets toward external destinations.",
    },
    {
        "id": "C2_PERSISTENCE",
        "title": "Persistent long-lived suspicious channel",
        "type": "indicator",
        "family": "command and control",
        "severity": "MEDIUM",
        "detail": "Surfaces persistent external communications that remain active for most of the capture duration.",
    },
    {
        "id": "MALWARE_IOC_MATCH",
        "title": "Malware IOC match",
        "type": "indicator",
        "family": "malware",
        "severity": "HIGH",
        "detail": "Stage 4b IOC or signature hit produced by the marlinspike-malware engine and published rule packs.",
    },
    {
        "id": "ARP_DUPLICATE_IP_CLAIM",
        "title": "ARP duplicate IP claim",
        "type": "finding",
        "family": "arp poisoning",
        "severity": "HIGH",
        "detail": "Same IP address claimed by two or more distinct source MACs in ARP traffic — a primary indicator of ARP poisoning. ATT&CK: T0830, T1557.002.",
    },
    {
        "id": "ARP_GATEWAY_MAC_CHANGE",
        "title": "ARP gateway MAC change",
        "type": "finding",
        "family": "arp poisoning",
        "severity": "CRITICAL",
        "detail": "Configured gateway IP is bound to a MAC that differs from its expected primary binding — possible gateway spoofing. ATT&CK: T0830.",
    },
    {
        "id": "ARP_MAC_CLAIMS_MANY_IPS",
        "title": "ARP MAC claiming many IPs",
        "type": "finding",
        "family": "arp poisoning",
        "severity": "HIGH",
        "detail": "Single source MAC announces more than the threshold number of distinct IPs in ARP traffic, consistent with ARP spoofing. ATT&CK: T0830.",
    },
    {
        "id": "ARP_SCAN_BEHAVIOR",
        "title": "ARP scan or reconnaissance behavior",
        "type": "finding",
        "family": "arp reconnaissance",
        "severity": "MEDIUM",
        "detail": "One source MAC sends ARP toward many distinct destination IPs with a low response rate, consistent with ARP-based host discovery. ATT&CK: T0842.",
    },
    {
        "id": "ARP_BROADCAST_STORM",
        "title": "ARP broadcast storm",
        "type": "finding",
        "family": "arp flooding",
        "severity": "HIGH",
        "detail": "ARP broadcast rate from a single source exceeds the configured threshold per minute — possible ARP flood or denial-of-service condition. ATT&CK: T0814.",
    },
    {
        "id": "ARP_GRATUITOUS_REPLY",
        "title": "Gratuitous ARP reply",
        "type": "finding",
        "family": "arp poisoning",
        "severity": "MEDIUM",
        "detail": "Unsolicited ARP reply (opcode 2 with src_ip == dst_ip), or a bilgepump-flagged gratuitous announcement — frequently used to seed downstream caches during ARP poisoning. ATT&CK: T0830, T1557.002.",
    },
    {
        "id": "APT_LATERAL_MOVEMENT_SMB",
        "title": "APT lateral movement via SMB",
        "type": "finding",
        "family": "apt lateral movement",
        "severity": "HIGH",
        "detail": "One source IP initiated SMB (445/139) traffic to a threshold number of distinct destination hosts in the capture — consistent with SMB-based lateral movement (PsExec, SMB tasking, share access enumeration). ATT&CK: T1021.002, T1570.",
    },
    {
        "id": "APT_LATERAL_MOVEMENT_RDP",
        "title": "APT lateral movement via RDP",
        "type": "finding",
        "family": "apt lateral movement",
        "severity": "HIGH",
        "detail": "RDP (3389) fan-out from a non-jump-host source. RDP fan-out across multiple hosts is rare in legitimate operation; this pattern is consistent with interactive lateral movement. ATT&CK: T1021.001.",
    },
    {
        "id": "APT_LATERAL_MOVEMENT_WINRM",
        "title": "APT lateral movement via WinRM",
        "type": "finding",
        "family": "apt lateral movement",
        "severity": "HIGH",
        "detail": "WSMAN/WinRM (5985/5986) fan-out from a non-jump-host source. WinRM is a common APT lateral-movement vector via PowerShell remoting and Invoke-Command. ATT&CK: T1021.006.",
    },
    {
        "id": "APT_OT_RECONNAISSANCE",
        "title": "APT reconnaissance of OT assets",
        "type": "finding",
        "family": "apt reconnaissance",
        "severity": "HIGH",
        "detail": "A non-polling source initiated OT-protocol traffic (Modbus, CIP, S7, DNP3, OPC-UA, BACnet, IEC-60870, PROFINET) to a threshold number of distinct destinations. Suppressed for HMI/Historian/Engineering Workstation roles and for hosts in the polling allowlist. ATT&CK: T0842, T0840, T0888.",
    },
    {
        "id": "APT_NEW_HOST_PROTOCOL",
        "title": "Unexpected protocol from host",
        "type": "finding",
        "family": "apt behavioral",
        "severity": "MEDIUM",
        "detail": "A host initiated a protocol family inconsistent with its inferred role (e.g. HMI doing SMB outbound, PLC initiating HTTPS). Behavioral baseline signal — may indicate compromise, unauthorized tooling, or a misclassified asset. ATT&CK: T1018, T1046.",
    },
    {
        "id": "APT_C2_BEACON",
        "title": "APT C2 beacon to external host",
        "type": "finding",
        "family": "apt c2",
        "severity": "HIGH",
        "detail": "A host produced a high-regularity periodic outbound conversation to a publicly-routable destination over a non-control protocol. Consistent with command-and-control beaconing. ATT&CK: T1071, T1102, T1573.",
    },
]

MALWARE_OBSERVABLE_COVERAGE = [
    ("dns_query", "DNS query domain"),
    ("dns_answer", "DNS response value"),
    ("http_host", "HTTP host header"),
    ("http_uri", "HTTP request URI"),
    ("tls_sni", "TLS SNI value"),
    ("artifact_sha256", "SHA-256 extracted artifact hash"),
    ("artifact_key", "Artifact key, file path, mutex, or registry path"),
    ("src_ip", "Source IP address"),
    ("dst_ip", "Destination IP address"),
    ("src_mac", "Source MAC address"),
    ("dst_mac", "Destination MAC address"),
    ("hostname", "Observed hostname"),
    ("protocol", "Protocol identifier"),
    ("any_text", "Catch-all text observable"),
]

DPI_EXTRA_COVERAGE = [
    ("protocol family", "Bronze protocol_transaction events", "event family", "transaction stream"),
    ("asset family", "Bronze asset_observation events", "event family", "asset observation"),
    ("topology family", "Bronze topology_observation events", "event family", "topology observation"),
    ("anomaly family", "Bronze parse_anomaly events", "event family", "parser anomaly"),
    ("artifact family", "Bronze extracted_artifact events", "event family", "artifact extraction"),
    ("stovetop", "Frame integrity inspection", "anomaly", "frame integrity"),
    ("icmpeeker", "ICMP anomaly inspection", "anomaly", "icmp anomaly"),
    ("bilgepump", "Stateful L2 anomaly analysis", "anomaly", "l2 anomaly"),
]


def _cleanup_runs():
    """Remove completed/failed runs older than RUN_CLEANUP_SECONDS."""
    now = datetime.now(timezone.utc)
    to_remove = []
    for run_id, run in _run_registry.items():
        if run["status"] in ("completed", "failed", "stopped") and run.get("finished_at"):
            try:
                finished = datetime.fromisoformat(run["finished_at"])
                if (now - finished).total_seconds() > config.RUN_CLEANUP_SECONDS:
                    to_remove.append(run_id)
            except (ValueError, TypeError):
                pass
    for run_id in to_remove:
        del _run_registry[run_id]


def _slug_to_label(value):
    return str(value or "").replace("_", " ").replace("-", " ").strip().title()


def _find_malware_rules_catalog_paths():
    candidates = []
    env_rules = os.environ.get("MARLINSPIKE_MALWARE_RULES", "").strip()
    if env_rules:
        candidates.append(Path(env_rules))
    candidates.extend([
        Path("/usr/share/marlinspike-malware/rules/packs"),
        Path.home() / "marlinspike-malware-rules" / "packs",
        Path.home() / "marlinspike-malware" / "rules",
    ])
    for packs_dir in candidates:
        if packs_dir and packs_dir.is_dir():
            root_dir = packs_dir.parent if packs_dir.name == "packs" else packs_dir
            manifest_path = root_dir / "manifests" / "index.yaml"
            return root_dir, packs_dir, manifest_path
    return None, None, None


def _append_catalog_entry(entries, **entry):
    raw = dict(entry)
    raw["source"] = str(raw.get("source", "") or "").strip().lower()
    raw["type"] = str(raw.get("type", "") or "").strip().lower()
    raw["family"] = str(raw.get("family", "") or "").strip()
    raw["severity"] = str(raw.get("severity", "") or "").strip().upper()
    raw["title"] = str(raw.get("title", "") or "").strip()
    raw["subtitle"] = str(raw.get("subtitle", "") or "").strip()
    raw["detail"] = str(raw.get("detail", "") or "").strip()
    raw["meta"] = str(raw.get("meta", "") or "").strip()
    raw["search_blob"] = " ".join(
        part for part in [
            raw.get("source", ""),
            raw.get("type", ""),
            raw.get("family", ""),
            raw.get("severity", ""),
            raw.get("title", ""),
            raw.get("subtitle", ""),
            raw.get("detail", ""),
            raw.get("meta", ""),
        ] if part
    ).lower()
    entries.append(raw)


@lru_cache(maxsize=1)
def _build_findings_catalog():
    entries = []
    source_meta = {}

    for item in REPORT_FINDING_COVERAGE:
        _append_catalog_entry(
            entries,
            source="report",
            type=item["type"],
            family=item["family"],
            severity=item["severity"],
            title=item["title"],
            subtitle=item["id"],
            detail=item["detail"],
            meta="Current engine-emitted finding or indicator class",
        )
    source_meta["report"] = {
        "label": "Report Findings",
        "summary": f"{len(REPORT_FINDING_COVERAGE)} current finding and indicator classes emitted by the engine",
    }

    dpi_protocols = sorted({
        (_slug_to_label(name), key.replace("_", "-"))
        for key, name in getattr(__import__("_ms_engine"), "RUST_PROTOCOL_DISPLAY_NAMES", {}).items()
    }, key=lambda item: item[0].lower())
    for title, proto_key in dpi_protocols:
        _append_catalog_entry(
            entries,
            source="dpi",
            type="protocol",
            family="protocol dissector",
            severity="",
            title=title,
            subtitle=proto_key,
            detail="Protocol coverage exposed through the Stage 2 DPI substrate.",
            meta="marlinspike-dpi parser surface",
        )
    for slug, title, coverage_type, family in DPI_EXTRA_COVERAGE:
        _append_catalog_entry(
            entries,
            source="dpi",
            type=coverage_type,
            family=family,
            severity="",
            title=title,
            subtitle=slug,
            detail="Additional parser-adjacent coverage published by the DPI substrate.",
            meta="Bronze v2 event or parser-adjacent inspection surface",
        )
    source_meta["dpi"] = {
        "label": "DPI Coverage",
        "summary": f"{len(dpi_protocols)} protocol dissectors plus Bronze event families and parser-adjacent anomaly surfaces",
    }

    for field_name, description in MALWARE_OBSERVABLE_COVERAGE:
        _append_catalog_entry(
            entries,
            source="malware",
            type="observable",
            family="observable field",
            severity="",
            title=field_name,
            subtitle=_slug_to_label(field_name),
            detail=description,
            meta="Accepted by marlinspike-malware during Stage 4b evaluation",
        )

    malware_root, packs_dir, manifest_path = _find_malware_rules_catalog_paths()
    malware_manifest = {}
    if manifest_path and manifest_path.is_file():
        try:
            malware_manifest = yaml.safe_load(manifest_path.read_text()) or {}
        except Exception:
            malware_manifest = {}
    malware_pack_count = int(malware_manifest.get("pack_count") or 0)
    malware_rule_count = int(malware_manifest.get("rule_count") or 0)
    manifest_pack_map = {}
    for pack in malware_manifest.get("packs") or []:
        path_value = str(pack.get("path") or "").strip()
        if path_value:
            manifest_pack_map[path_value] = pack

    if packs_dir and packs_dir.is_dir():
        for rule_file in sorted(packs_dir.rglob("*.y*ml")):
            try:
                payload = yaml.safe_load(rule_file.read_text()) or {}
            except Exception:
                continue
            rules = payload.get("rules") or []
            relative_path = ""
            try:
                relative_path = str(rule_file.relative_to(malware_root)).replace(os.sep, "/")
            except Exception:
                relative_path = str(rule_file)
            pack_meta = manifest_pack_map.get(relative_path, {})
            pack_label = pack_meta.get("name") or payload.get("name") or rule_file.stem
            for rule in rules:
                conditions = rule.get("conditions") or []
                matched_fields = sorted({str(condition.get("field") or "").strip() for condition in conditions if condition.get("field")})
                references = rule.get("references") or []
                _append_catalog_entry(
                    entries,
                    source="malware",
                    type="rule",
                    family=rule.get("family") or pack_label,
                    severity=rule.get("severity") or "",
                    title=rule.get("name") or rule.get("id") or "Unnamed malware rule",
                    subtitle=rule.get("id") or pack_label,
                    detail=(rule.get("description") or "").strip() or f"Pack: {pack_label}",
                    meta="Fields: " + ", ".join(matched_fields[:6]) + (f" | Ref: {references[0]}" if references else ""),
                )
    source_meta["malware"] = {
        "label": "Malware Coverage",
        "summary": (
            f"{len(MALWARE_OBSERVABLE_COVERAGE)} observable fields, "
            f"{malware_pack_count or 'unknown'} packs, {malware_rule_count or 'unknown'} rules"
        ),
    }

    mitre_rule_count = 0
    mitre_technique_ids = set()
    mitre_attack_version = ""
    mitre_rules_dir = Path("rules/mitre")
    mitre_catalog_path = Path("plugins/marlinspike_mitre/catalog/attack_catalog.json")
    mitre_catalog = {}
    try:
        mitre_catalog = json.loads(mitre_catalog_path.read_text())
    except Exception:
        mitre_catalog = {}
    enterprise_domain = ((mitre_catalog.get("domains") or {}).get("enterprise-attack") or {})
    ics_domain = ((mitre_catalog.get("domains") or {}).get("ics-attack") or {})
    mitre_attack_version = str(enterprise_domain.get("attack_version") or "").strip()
    ics_attack_version = str(ics_domain.get("attack_version") or "").strip()
    mitre_packs: list[dict] = []
    if mitre_rules_dir.is_dir():
        for pack_path in sorted(mitre_rules_dir.glob("*.yaml")):
            try:
                mitre_packs.append(yaml.safe_load(pack_path.read_text()) or {})
            except Exception:
                pass
    for pack in mitre_packs:
        pack_domain = str(pack.get("default_domain") or "enterprise-attack")
        technique_map = (
            ics_domain.get("techniques") or {}
            if pack_domain == "ics-attack"
            else enterprise_domain.get("techniques") or {}
        )
        for rule in pack.get("rules") or []:
            technique_id = str(rule.get("technique_id") or "").strip().upper()
            rule_domain = str(rule.get("domain") or pack_domain)
            if rule_domain == "ics-attack":
                technique = (ics_domain.get("techniques") or {}).get(technique_id) or {}
            else:
                technique = technique_map.get(technique_id) or {}
            mitre_rule_count += 1
            if technique_id:
                mitre_technique_ids.add(technique_id)
            tactic_shortnames = technique.get("tactic_shortnames") or []
            if not tactic_shortnames:
                tactic_shortnames = [
                    str(t.get("shortname") or "")
                    for t in (technique.get("tactics") or [])
                    if str(t.get("shortname") or "").strip()
                ]
            tactics = ", ".join(tactic_shortnames)
            domain_label = "ICS ATT&CK" if rule_domain == "ics-attack" else "Enterprise ATT&CK"
            _append_catalog_entry(
                entries,
                source="mitre",
                type=str(rule.get("kind") or "mapping"),
                family=rule.get("family") or "ATT&CK mapping",
                severity="",
                title=f"{technique_id} {rule.get('title') or technique.get('name') or 'ATT&CK mapping'}".strip(),
                subtitle=rule.get("id") or technique_id,
                detail=rule.get("rationale") or "Rule-backed ATT&CK mapping for the report workflow.",
                meta=f"Domain: {domain_label} | Publication: {rule.get('publication') or ''}"
                + (f" | Tactics: {tactics}" if tactics else ""),
            )
    version_label = f"Enterprise {mitre_attack_version}" + (f" / ICS {ics_attack_version}" if ics_attack_version else "")
    source_meta["mitre"] = {
        "label": "ATT&CK Coverage",
        "summary": (
            f"{mitre_rule_count} mapping rules, {len(mitre_technique_ids)} techniques"
            + (f", ATT&CK {version_label}" if version_label.strip(' /') else "")
        ),
    }

    entries.sort(key=lambda item: (
        item.get("source", ""),
        item.get("family", "").lower(),
        item.get("severity", ""),
        item.get("title", "").lower(),
    ))

    return {
        "entries": entries,
        "source_meta": source_meta,
        "summary": {
            "total_entries": len(entries),
            "report_classes": len(REPORT_FINDING_COVERAGE),
            "dpi_protocols": len(dpi_protocols),
            "malware_packs": malware_pack_count,
            "malware_rules": malware_rule_count,
            "mitre_rules": mitre_rule_count,
            "mitre_techniques": len(mitre_technique_ids),
            "mitre_attack_version": mitre_attack_version,
        },
    }


MAX_CONCURRENT_SCANS = 1


# ── Password policy (v3.5.4) ────────────────────────────────────────────────
#
# Pre-v3.5.4 only enforced len >= 8. Now enforces a policy that's strict
# enough to reject the worst common passwords (length + multi-class), but
# loose enough that it doesn't break real-world admin passphrases.
# Reject common predictable passwords explicitly — the bar is "not in the
# top-100 most common", not a full HIBP integration.

_MEMBER_ROLE_RANK: dict[str, int] = {"viewer": 1, "editor": 2, "owner": 3}
_VALID_MEMBER_ROLES = frozenset(_MEMBER_ROLE_RANK)

_PASSWORD_MIN_LENGTH = 12
_PASSWORD_REJECT = {
    "password", "password1", "password123", "passw0rd",
    "marlinspike", "marlinspike1", "admin", "admin123",
    "letmein", "qwerty", "12345678", "123456789",
    "changeme", "change-me", "secret", "default",
}


def _password_meets_policy(password: str) -> bool:
    """Strict-enough policy: length + multi-class + not in deny-list.

    Length 12+ (was 8+ pre-v3.5.4 — accommodate cloudmarlin's tier
    requirements while remaining usable for real admins).
    Two of: uppercase, lowercase, digit, symbol.
    Not in the explicit reject list (covers the worst common picks).
    """
    if not password or len(password) < _PASSWORD_MIN_LENGTH:
        return False
    if password.lower() in _PASSWORD_REJECT:
        return False
    classes = 0
    if any(c.isupper() for c in password):
        classes += 1
    if any(c.islower() for c in password):
        classes += 1
    if any(c.isdigit() for c in password):
        classes += 1
    if any(not c.isalnum() for c in password):
        classes += 1
    return classes >= 2


def _password_policy_message() -> str:
    return (
        f"Password must be at least {_PASSWORD_MIN_LENGTH} characters and "
        f"include at least two of: uppercase, lowercase, digits, symbols. "
        f"Common predictable passwords are rejected."
    )


def _get_project_for_user(pid: int, min_role: str = "viewer") -> "Project | None":
    """Return the project if the current session user can access it.

    Access is granted when the user is the project creator (always owner)
    OR has a ProjectMember row whose role rank >= min_role.
    Returns None when the project doesn't exist or the user lacks access.
    """
    from flask import session as _session
    uid = _session.get("user_id")
    if not uid:
        return None
    proj = db.session.get(Project, pid)
    if proj is None:
        return None
    if proj.user_id == uid:
        return proj
    member = ProjectMember.query.filter_by(project_id=pid, user_id=uid).first()
    if member and _MEMBER_ROLE_RANK.get(member.role, 0) >= _MEMBER_ROLE_RANK.get(min_role, 1):
        return proj
    return None


def _get_active_runs(user_id=None):
    """Return list of (run_id, run_state) for active runs.

    Default ``memory`` backend reads ``_run_registry`` (host-local).
    With ``MARLINSPIKE_RUN_STORE=db`` set, reads from ``scan_history``
    so multiple Gunicorn workers share a consistent active-run view —
    required for cross-worker per-tier concurrency limits.

    The ``run_state`` returned in ``db`` mode is a degraded dict
    (no Popen handle, no live output) — sufficient for the
    concurrency hook and admin diagnostics, not for live tail.
    """
    if config.MARLINSPIKE_RUN_STORE == "db":
        from marlinspike import run_store as _run_store
        active = []
        for rec in ScanHistory.query.filter_by(status="running").all():
            if user_id is not None and rec.user_id != user_id:
                continue
            # Build a minimal run_state shaped like the in-memory one.
            run_state = {
                "status": rec.status,
                "user_id": rec.user_id,
                "project_id": rec.project_id,
                "command": rec.command,
                "scan_profile": rec.scan_profile,
                "started_at": rec.started_at.isoformat() if rec.started_at else None,
                "finished_at": rec.completed_at.isoformat() if rec.completed_at else None,
                "report_path": rec.report_path,
                "report_filename": os.path.basename(rec.report_path or ""),
                "stage": 0,
                "stage_name": "",
                "stages": [],
                "output": [],
                "return_code": None,
                "artifacts_produced": {},
            }
            active.append((rec.run_id, run_state))
        return active

    active = []
    for run_id, run in _run_registry.items():
        if run["status"] not in ("pending", "running"):
            continue
        if user_id is not None and run.get("user_id") != user_id:
            continue
        active.append((run_id, run))
    return active


# ── Concurrency policy hook ─────────────────────────────────────────────────
# Wrappers (e.g. cloudmarlin) override this to apply per-user / per-tier
# concurrency limits. The hook receives the requesting user's id and returns
# a (active_count, limit) tuple. When unset, marlinspike falls back to the
# legacy global limit (``MAX_CONCURRENT_SCANS`` runs across all users).

_concurrent_check_fn = None


def set_concurrent_check_fn(fn):
    """Install a callable that decides whether a scan request may proceed.

    ``fn(user_id) -> (active_count, limit)``. Marlinspike rejects the request
    with HTTP 409 when ``active_count >= limit``. Pass ``None`` to restore the
    default global behaviour.
    """
    global _concurrent_check_fn
    _concurrent_check_fn = fn


def _resolve_concurrency(user_id):
    if _concurrent_check_fn is not None:
        return _concurrent_check_fn(user_id)
    # Legacy default: one scan globally.
    return len(_get_active_runs()), MAX_CONCURRENT_SCANS


def _scan_artifacts(run_state):
    """Scan reports dir for artifact files produced by this run."""
    command = run_state["command"]
    reports_dir = os.path.dirname(run_state.get("report_path", "")) or config.REPORTS_DIR
    pattern = os.path.join(reports_dir, f"marlinspike-{command}-*.json")
    try:
        started = datetime.fromisoformat(run_state["started_at"]).timestamp()
    except (ValueError, TypeError):
        started = 0
    for path in glob.glob(pattern):
        try:
            if os.path.getmtime(path) >= started:
                with open(path) as f:
                    artifact = json.load(f)
                art_type = artifact.get("artifact_type", command)
                run_state["artifacts_produced"][art_type] = path
        except Exception:
            pass


def _set_run_stage(run_state, stage_num, stage_name=""):
    """Update run stage progress for UI polling."""
    run_state["stage"] = stage_num
    if stage_name:
        run_state["stage_name"] = stage_name
    for stage in run_state.get("stages", []):
        if stage["number"] < stage_num:
            if stage["state"] not in ("failed", "stopped"):
                stage["state"] = "complete"
        elif stage["number"] == stage_num:
            if stage["state"] not in ("failed", "stopped"):
                stage["state"] = "running"


def _mark_active_stage(run_state, state):
    """Mark the currently running stage as failed/stopped."""
    for stage in run_state.get("stages", []):
        if stage["state"] == "running":
            stage["state"] = state
            return


def _apply_stage_marker(run_state, line, stage_map=None):
    """Parse engine STAGE lines into UI stage progress."""
    match = _stage_re.match(line)
    if not match:
        return
    stage_num = int(match.group(1))
    if stage_map:
        stage_num = stage_map.get(stage_num, stage_num)
    if stage_num < 1:
        return
    stage_name = match.group(2).strip()
    _set_run_stage(run_state, stage_num, stage_name)


def _merge_nested(existing, incoming):
    """Merge protocol identity dicts without dropping values from prior chunks."""
    if not isinstance(existing, dict):
        existing = {}
    if not isinstance(incoming, dict):
        incoming = {}
    merged = dict(existing)
    for key, value in incoming.items():
        current = merged.get(key)
        if isinstance(current, dict) and isinstance(value, dict):
            merged[key] = _merge_nested(current, value)
        elif isinstance(current, list) and isinstance(value, list):
            seen = {json.dumps(item, sort_keys=True, default=str) for item in current}
            combined = list(current)
            for item in value:
                marker = json.dumps(item, sort_keys=True, default=str)
                if marker not in seen:
                    combined.append(item)
                    seen.add(marker)
            merged[key] = combined
        elif isinstance(current, bool) and isinstance(value, bool):
            merged[key] = current or value
        elif current in (None, "", [], {}):
            merged[key] = value
    return merged


def _merge_chunk_conversations(chunk_reports, capture_info_seed=None):
    """Merge conversations from chunk-level dissect reports into one artifact."""
    conv_map = {}
    merged_capture_info = dict(capture_info_seed or {})

    list_fields = (
        "modbus_functions",
        "s7_functions",
        "dnp3_objects",
        "opc_sessions",
        "iec104_typeids",
        "iec104_causes",
        "src_ports_seen",
        "dns_queries",
        "dns_query_types",
    )
    nested_fields = (
        "cip_identity",
        "pn_identity",
        "bacnet_identity",
        "omron_identity",
        "mms_identity",
        "goose_identity",
        "l2_discovery",
    )
    numeric_sum_fields = ("packet_count", "bytes_total", "modbus_writes")
    bool_fields = ("s7_program_access", "opc_no_security")

    for report_path in chunk_reports:
        with open(report_path) as handle:
            data = json.load(handle)

        conversations = data.get("conversations", data.get("data", {}).get("conversations", [])) or []
        capture_info = data.get("capture_info", data.get("data", {}).get("capture_info", {})) or {}

        if capture_info:
            if not merged_capture_info:
                merged_capture_info = dict(capture_info)
            else:
                for field in ("total_packets", "total_bytes"):
                    if field in capture_info:
                        merged_capture_info[field] = merged_capture_info.get(field, 0) + capture_info[field]
                if capture_info.get("duration_s", 0) > merged_capture_info.get("duration_s", 0):
                    merged_capture_info["duration_s"] = capture_info["duration_s"]
                    merged_capture_info["duration_seconds"] = capture_info.get(
                        "duration_seconds",
                        capture_info["duration_s"],
                    )
                for field in ("pcap_path", "capture_source", "capture_type"):
                    if not merged_capture_info.get(field) and capture_info.get(field):
                        merged_capture_info[field] = capture_info[field]

        for conv in conversations:
            key = (
                conv.get("src_mac", ""),
                conv.get("dst_mac", ""),
                conv.get("protocol", ""),
                int(conv.get("port", 0) or 0),
            )
            if key not in conv_map:
                conv_map[key] = dict(conv)
                continue

            existing = conv_map[key]

            for field in numeric_sum_fields:
                existing[field] = int(existing.get(field, 0) or 0) + int(conv.get(field, 0) or 0)

            if conv.get("first_seen") and (
                not existing.get("first_seen") or conv["first_seen"] < existing["first_seen"]
            ):
                existing["first_seen"] = conv["first_seen"]
            if conv.get("last_seen") and (
                not existing.get("last_seen") or conv["last_seen"] > existing["last_seen"]
            ):
                existing["last_seen"] = conv["last_seen"]

            for field in ("src_ip", "dst_ip", "transport"):
                if not existing.get(field) and conv.get(field):
                    existing[field] = conv[field]
            if not existing.get("src_port") and conv.get("src_port"):
                existing["src_port"] = conv["src_port"]

            for field in list_fields:
                current = list(existing.get(field) or [])
                seen = {json.dumps(item, sort_keys=True, default=str) for item in current}
                for item in conv.get(field) or []:
                    marker = json.dumps(item, sort_keys=True, default=str)
                    if marker not in seen:
                        current.append(item)
                        seen.add(marker)
                existing[field] = current

            for field in nested_fields:
                existing[field] = _merge_nested(existing.get(field), conv.get(field))

            for field in bool_fields:
                if conv.get(field):
                    existing[field] = True

            if float(conv.get("beacon_score", 0.0) or 0.0) > float(existing.get("beacon_score", 0.0) or 0.0):
                existing["beacon_score"] = conv.get("beacon_score", 0.0)
                existing["beacon_interval"] = conv.get("beacon_interval", 0.0)
                existing["beacon_jitter"] = conv.get("beacon_jitter", 0.0)
            if float(conv.get("dns_entropy", 0.0) or 0.0) > float(existing.get("dns_entropy", 0.0) or 0.0):
                existing["dns_entropy"] = conv.get("dns_entropy", 0.0)

    return list(conv_map.values()), merged_capture_info


def _finalize_scan_history(app, run_id, run_state, report_path):
    """Persist final scan status and summary metadata."""
    try:
        with app.app_context():
            rec = ScanHistory.query.filter_by(run_id=run_id).first()
            if rec:
                rec.status = run_state["status"]
                rec.completed_at = datetime.now(timezone.utc)
                if run_state["status"] in ("failed", "stopped"):
                    tail = run_state["output"][-10:]
                    rec.error_tail = "\n".join(tail) if tail else None
                if os.path.isfile(report_path):
                    try:
                        with open(report_path) as rf:
                            rdata = json.load(rf)
                        topo = rdata.get("results", {}).get("topology", rdata.get("topology", {}))
                        rec.node_count = len(topo.get("nodes", []))
                        rec.edge_count = len(topo.get("edges", []))
                    except Exception:
                        pass
                db.session.commit()
    except Exception as exc:
        log.warning("Failed to update scan_history: %s", exc)


def _finalize_run(app, run_id, run_state, report_path):
    """Apply final run status, optional ATT&CK plugin, and DB persistence."""
    run_state["finished_at"] = datetime.now(timezone.utc).isoformat()

    if run_state.get("stop_requested"):
        run_state["status"] = "stopped"
        _mark_active_stage(run_state, "stopped")
    elif run_state.get("return_code", 1) == 0:
        if config.MARLINSPIKE_MITRE_ENABLED and run_state.get("command") == "chain":
            plugin_stage_num = len(run_state["stages"])
            _set_run_stage(run_state, plugin_stage_num, "MITRE ATT&CK")
            if os.path.isfile(report_path):
                run_state["output"].append("[*] Running marlinspike-mitre...")
                try:
                    artifact_path, plugin_output = _run_mitre_plugin(report_path)
                    if artifact_path:
                        run_state["artifacts_produced"]["marlinspike-mitre"] = artifact_path
                    run_state["output"].extend(plugin_output)
                    if artifact_path:
                        run_state["output"].append(
                            f"[+] MITRE artifact saved: {os.path.basename(artifact_path)}"
                        )
                except Exception as exc:
                    run_state["output"].append(f"[!] marlinspike-mitre skipped: {exc}")
            else:
                run_state["output"].append("[!] marlinspike-mitre skipped: report file missing")
            for stage in run_state["stages"]:
                if stage["number"] == plugin_stage_num and stage["state"] == "running":
                    stage["state"] = "complete"

        if config.MARLINSPIKE_ARP_ENABLED and run_state.get("command") == "chain":
            arp_stage_num = len(run_state["stages"])
            _set_run_stage(run_state, arp_stage_num, "ARP Analysis")
            if os.path.isfile(report_path):
                run_state["output"].append("[*] Running marlinspike-arp...")
                try:
                    artifact_path, plugin_output = _run_arp_plugin(report_path)
                    if artifact_path:
                        run_state["artifacts_produced"]["marlinspike-arp"] = artifact_path
                    run_state["output"].extend(plugin_output)
                    if artifact_path:
                        run_state["output"].append(
                            f"[+] ARP artifact saved: {os.path.basename(artifact_path)}"
                        )
                except Exception as exc:
                    run_state["output"].append(f"[!] marlinspike-arp skipped: {exc}")
            else:
                run_state["output"].append("[!] marlinspike-arp skipped: report file missing")
            for stage in run_state["stages"]:
                if stage["number"] == arp_stage_num and stage["state"] == "running":
                    stage["state"] = "complete"

        if config.MARLINSPIKE_APT_ENABLED and run_state.get("command") == "chain":
            apt_stage_num = len(run_state["stages"])
            _set_run_stage(run_state, apt_stage_num, "APT Analysis")
            if os.path.isfile(report_path):
                run_state["output"].append("[*] Running marlinspike-apt...")
                try:
                    artifact_path, plugin_output = _run_apt_plugin(report_path)
                    if artifact_path:
                        run_state["artifacts_produced"]["marlinspike-apt"] = artifact_path
                    run_state["output"].extend(plugin_output)
                    if artifact_path:
                        run_state["output"].append(
                            f"[+] APT artifact saved: {os.path.basename(artifact_path)}"
                        )
                except Exception as exc:
                    run_state["output"].append(f"[!] marlinspike-apt skipped: {exc}")
            else:
                run_state["output"].append("[!] marlinspike-apt skipped: report file missing")
            for stage in run_state["stages"]:
                if stage["number"] == apt_stage_num and stage["state"] == "running":
                    stage["state"] = "complete"

        if config.MARLINSPIKE_CISA_ENABLED and run_state.get("command") == "chain":
            cisa_stage_num = len(run_state["stages"])
            _set_run_stage(run_state, cisa_stage_num, "CISA Advisories")
            if os.path.isfile(report_path):
                run_state["output"].append("[*] Running marlinspike-cisa...")
                try:
                    artifact_path, plugin_output = _run_cisa_plugin(report_path)
                    if artifact_path:
                        run_state["artifacts_produced"]["marlinspike-cisa"] = artifact_path
                    run_state["output"].extend(plugin_output)
                    if artifact_path:
                        run_state["output"].append(
                            f"[+] CISA artifact saved: {os.path.basename(artifact_path)}"
                        )
                except Exception as exc:
                    run_state["output"].append(f"[!] marlinspike-cisa skipped: {exc}")
            else:
                run_state["output"].append("[!] marlinspike-cisa skipped: report file missing")
            for stage in run_state["stages"]:
                if stage["number"] == cisa_stage_num and stage["state"] == "running":
                    stage["state"] = "complete"

        run_state["status"] = "completed"
        for stage in run_state["stages"]:
            if stage["state"] in ("running", "complete"):
                stage["state"] = "complete"
    else:
        run_state["status"] = "failed"
        _mark_active_stage(run_state, "failed")

    _scan_artifacts(run_state)
    _finalize_scan_history(app, run_id, run_state, report_path)


# ═══════════════════════════════════════════════════════════════
# Submission archival helpers
# ═══════════════════════════════════════════════════════════════

def _archive_submission(src_path, user_id, username, original_filename):
    """Archive uploaded PCAP to submissions dir (background, TOS compliance)."""
    try:
        os.makedirs(os.path.join(config.SUBMISSIONS_DIR, str(user_id)), exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe_fn = re.sub(r'[^a-zA-Z0-9._-]', '_', original_filename)[:120]
        base_name = f"{username}_{ts}_{safe_fn}"

        try:
            import zstandard as zstd
            dest = os.path.join(config.SUBMISSIONS_DIR, str(user_id), base_name + ".zst")
            cctx = zstd.ZstdCompressor(level=3)
            with open(src_path, "rb") as fin, open(dest, "wb") as fout:
                cctx.copy_stream(fin, fout)
        except ImportError:
            import gzip as gz
            dest = os.path.join(config.SUBMISSIONS_DIR, str(user_id), base_name + ".gz")
            with open(src_path, "rb") as fin, gz.open(dest, "wb", compresslevel=6) as fout:
                shutil.copyfileobj(fin, fout)
        log.info("Archived submission: %s (%s)", dest, original_filename)
    except Exception as e:
        log.warning("Failed to archive submission: %s", e)


# ═══════════════════════════════════════════════════════════════
# Flask app factory
# ═══════════════════════════════════════════════════════════════


def _sanitize_report(report: dict) -> dict:
    """Strip internal details from report before sending to browser."""
    r = report.copy()
    r.pop("tshark_version", None)
    if "capture_info" in r and isinstance(r["capture_info"], dict):
        ci = r["capture_info"] = r["capture_info"].copy()
        if "pcap_path" in ci:
            # Keep only filename, not full path
            ci["pcap_path"] = os.path.basename(ci["pcap_path"])
        ci.pop("tshark_path", None)
    return r


def _localize_finding(finding: dict, locale: str) -> dict:
    """Overlay localized category label, description, and remediation on an
    engine-emitted risk finding. Falls back to the engine's English values
    when no translation is registered for the category. Description templates
    receive ``count`` (= len(affected_nodes)) and ``ips`` (= sorted distinct
    IP/MAC string) as substitution params, so categories whose engine prose
    is templated by exactly those fields get a clean FR rendering."""
    if locale == DEFAULT_LOCALE:
        return finding
    cat = str(finding.get("category") or "").strip().upper()
    if not cat:
        return finding
    out = dict(finding)
    affected = list(finding.get("affected_nodes") or [])
    params = {
        "count": len(affected),
        "ips": ", ".join(sorted({str(x) for x in affected})),
    }
    label = _translate(f"viewer.finding.cat.{cat}", locale=locale)
    if label and label != f"viewer.finding.cat.{cat}":
        out["category_label"] = label
    rem = _translate(f"viewer.finding.rem.{cat}", locale=locale)
    if rem and rem != f"viewer.finding.rem.{cat}":
        out["remediation"] = rem
    desc = _translate(f"viewer.finding.desc.{cat}", locale=locale, **params)
    if desc and desc != f"viewer.finding.desc.{cat}":
        out["description"] = desc
    return out


def _localize_indicator(indicator: dict, locale: str) -> dict:
    """C2 indicators carry ``type`` rather than ``category`` — same overlay,
    keyed under ``viewer.indicator.*``."""
    if locale == DEFAULT_LOCALE:
        return indicator
    cat = str(indicator.get("type") or "").strip().upper()
    if not cat:
        return indicator
    out = dict(indicator)
    rem = _translate(f"viewer.indicator.rem.{cat}", locale=locale)
    if rem and rem != f"viewer.indicator.rem.{cat}":
        out["remediation"] = rem
    label = _translate(f"viewer.indicator.cat.{cat}", locale=locale)
    if label and label != f"viewer.indicator.cat.{cat}":
        out["type_label"] = label
    desc = _translate(f"viewer.indicator.desc.{cat}", locale=locale)
    if desc and desc != f"viewer.indicator.desc.{cat}":
        out["description"] = desc
    return out


def _localize_report(report: dict, locale: str) -> dict:
    """Apply locale overlays to a sanitized report's finding lists.

    Keeps the structure intact; only swaps in localized strings where a
    translation key exists. Engine-emitted English remains the fallback so
    nothing goes blank if a category lacks a translation."""
    if locale == DEFAULT_LOCALE:
        return report
    r = dict(report)
    risk_findings = list(r.get("risk_findings") or [])
    if risk_findings:
        r["risk_findings"] = [_localize_finding(f, locale) for f in risk_findings]
    c2_indicators = list(r.get("c2_indicators") or [])
    if c2_indicators:
        r["c2_indicators"] = [_localize_indicator(i, locale) for i in c2_indicators]
    return r


def _is_primary_report_filename(filename: str) -> bool:
    safe_name = os.path.basename(str(filename or ""))
    return bool(
        safe_name.endswith(".json")
        and not safe_name.endswith("-mitre.json")
        and not safe_name.endswith("-arp.json")
        and not safe_name.endswith("-apt.json")
    )


def _mitre_sidecar_path(report_path: str) -> str:
    return _enrich.sidecar_path(report_path, "-mitre.json")


def _arp_sidecar_path(report_path: str) -> str:
    return _enrich.sidecar_path(report_path, "-arp.json")


def _apt_sidecar_path(report_path: str) -> str:
    return _enrich.sidecar_path(report_path, "-apt.json")


def _cisa_sidecar_path(report_path: str) -> str:
    return _enrich.sidecar_path(report_path, "-cisa.json")


# Enrichment now lives in marlinspike/enrich.py so the headless engine and the
# web app share one implementation. These thin wrappers preserve the names /
# signatures the rest of app.py (and _finalize_run) already call.
def _run_mitre_plugin(report_path: str) -> tuple[str, list[str]]:
    return _enrich.run_one("marlinspike-mitre", report_path)


def _run_arp_plugin(report_path: str) -> tuple[str, list[str]]:
    return _enrich.run_one("marlinspike-arp", report_path)


def _run_apt_plugin(report_path: str) -> tuple[str, list[str]]:
    return _enrich.run_one("marlinspike-apt", report_path)


def _run_cisa_plugin(report_path: str) -> tuple[str, list[str]]:
    return _enrich.run_one("marlinspike-cisa", report_path)


def _load_report_with_extensions(path: str, ensure_mitre: bool = False) -> dict:
    return _enrich.load_report_with_extensions(path, ensure_mitre=ensure_mitre)


def _collect_plugin_risk_findings(extensions: dict) -> list[dict]:
    return _enrich.collect_plugin_risk_findings(extensions)


def _plugin_finding_to_risk_finding(plugin_id: str, finding: dict):
    return _enrich.plugin_finding_to_risk_finding(plugin_id, finding)


def _viewer_anchor(value: str) -> str:
    value = str(value or "").strip()
    return re.sub(r"[^a-zA-Z0-9_-]+", "-", value).strip("-") or "asset"


def _severity_rank(severity: str) -> int:
    return {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "INFO": 4,
    }.get((severity or "").upper(), 5)


def _finding_signature(finding: dict) -> str:
    payload = {
        "category": str(finding.get("category") or ""),
        "nodes": sorted(str(n) for n in (finding.get("affected_nodes") or [])),
        "edges": sorted(str(e) for e in (finding.get("affected_edges") or [])),
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:32]


_DPI_LABELS = {
    "app_name": "App Name",
    "called_station_id": "Called Station",
    "calling_station_id": "Calling Station",
    "client_id": "Client ID",
    "facility": "Facility",
    "firmware": "Firmware",
    "framed_ip_address": "Framed IP",
    "identifier": "Identifier",
    "ip": "IP",
    "nas_identifier": "NAS Identifier",
    "nas_ip_address": "NAS IP",
    "nas_port_type": "NAS Port Type",
    "protocol_name": "Protocol Name",
    "protocol_version": "Protocol Version",
    "qos": "QoS",
    "service_type": "Service Type",
    "severity": "Severity",
    "transaction_id": "Transaction ID",
    "username": "Username",
}

_DPI_IDENTITY_KEYS = {
    "app_name",
    "called_station_id",
    "calling_station_id",
    "client_id",
    "firmware",
    "framed_ip_address",
    "ip",
    "nas_identifier",
    "nas_ip_address",
    "username",
}

_DPI_PRIORITY_KEYS = {
    "username": 0,
    "client_id": 1,
    "nas_identifier": 2,
    "nas_ip_address": 3,
    "calling_station_id": 4,
    "called_station_id": 5,
    "app_name": 6,
    "firmware": 7,
}

_WORKBENCH_VIEW_LOCATIONS = {
    "dashboard",
    "map",
    "findings",
    "evidence",
    "assets",
    "intel",
    "risk",
    "reports",
}

_WORKBENCH_BLOCK_TYPES = {
    "metric_strip",
    "key_value",
    "chip_list",
    "table",
    "records",
    "markdown",
}


def _dpi_label(key: str) -> str:
    key = str(key or "").strip()
    return _DPI_LABELS.get(key, key.replace("_", " ").title())


def _dpi_values(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        items = list(value)
    else:
        items = [value]

    out = []
    for item in items:
        if item is None:
            continue
        if isinstance(item, dict):
            for subkey, subvalue in item.items():
                for text in _dpi_values(subvalue):
                    merged = f"{_dpi_label(subkey)}: {text}"
                    if merged not in out:
                        out.append(merged)
            continue
        text = str(item).strip()
        if text and text not in out:
            out.append(text[:240])
    return out


def _append_unique_text(values: list[str], value: str, limit: int = 8) -> None:
    text = str(value or "").strip()
    if text and text not in values and len(values) < limit:
        values.append(text)


def _append_unique_pair(values: list[dict], label: str, value: str, limit: int = 8) -> None:
    label = str(label or "").strip()
    text = str(value or "").strip()
    if not label or not text or len(values) >= limit:
        return
    candidate = {"label": label, "value": text}
    if candidate not in values:
        values.append(candidate)


def _workbench_text(value, *, limit: int = 240) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    return text[:limit]


def _sanitize_workbench_block(block: dict) -> dict | None:
    if not isinstance(block, dict):
        return None
    block_type = _workbench_text(block.get("type"), limit=32).lower()
    if block_type not in _WORKBENCH_BLOCK_TYPES:
        return None

    title = _workbench_text(block.get("title"), limit=120)
    note = _workbench_text(block.get("note"), limit=240)
    sanitized = {"type": block_type}
    if title:
        sanitized["title"] = title
    if note:
        sanitized["note"] = note

    if block_type == "metric_strip":
        items = []
        for item in list(block.get("items") or [])[:8]:
            if not isinstance(item, dict):
                continue
            label = _workbench_text(item.get("label"), limit=64)
            value = _workbench_text(item.get("value"), limit=48)
            if not label or not value:
                continue
            entry = {"label": label, "value": value}
            tone = _workbench_text(item.get("tone"), limit=24).lower()
            if tone:
                entry["tone"] = tone
            items.append(entry)
        if not items:
            return None
        sanitized["items"] = items
        return sanitized

    if block_type == "key_value":
        items = []
        for item in list(block.get("items") or [])[:16]:
            if not isinstance(item, dict):
                continue
            label = _workbench_text(item.get("label"), limit=96)
            value = _workbench_text(item.get("value"), limit=240)
            if label and value:
                items.append({"label": label, "value": value})
        if not items:
            return None
        sanitized["items"] = items
        return sanitized

    if block_type == "chip_list":
        items = []
        for item in list(block.get("items") or [])[:24]:
            text = _workbench_text(item, limit=120)
            if text:
                items.append(text)
        if not items:
            return None
        sanitized["items"] = items
        return sanitized

    if block_type == "table":
        columns = []
        for column in list(block.get("columns") or [])[:8]:
            text = _workbench_text(column, limit=64)
            if text:
                columns.append(text)
        rows = []
        for row in list(block.get("rows") or [])[:24]:
            if not isinstance(row, (list, tuple)):
                continue
            cleaned = [_workbench_text(cell, limit=160) for cell in list(row)[: len(columns) or 8]]
            if any(cleaned):
                rows.append(cleaned)
        if not columns or not rows:
            return None
        sanitized["columns"] = columns
        sanitized["rows"] = rows
        return sanitized

    if block_type == "records":
        items = []
        for item in list(block.get("items") or [])[:16]:
            if not isinstance(item, dict):
                continue
            title = _workbench_text(item.get("title"), limit=120)
            if not title:
                continue
            record = {"title": title}
            subtitle = _workbench_text(item.get("subtitle"), limit=180)
            body = _workbench_text(item.get("body"), limit=360)
            chips = [_workbench_text(chip, limit=80) for chip in list(item.get("chips") or [])[:8]]
            chips = [chip for chip in chips if chip]
            if subtitle:
                record["subtitle"] = subtitle
            if body:
                record["body"] = body
            if chips:
                record["chips"] = chips
            items.append(record)
        if not items:
            return None
        sanitized["items"] = items
        return sanitized

    if block_type == "markdown":
        text = _workbench_text(block.get("text"), limit=4000)
        if not text:
            return None
        sanitized["text"] = text
        return sanitized

    return None


def _collect_workbench_views(report: dict) -> list[dict]:
    extensions = dict(report.get("extensions") or {})
    views = []
    for extension_id, artifact in extensions.items():
        if not isinstance(artifact, dict):
            continue
        for raw_view in list(artifact.get("workbench_views") or [])[:12]:
            if not isinstance(raw_view, dict):
                continue
            title = _workbench_text(raw_view.get("title"), limit=120)
            if not title:
                continue
            view_id = _viewer_anchor(raw_view.get("view_id") or title)
            location = _workbench_text(raw_view.get("location") or "intel", limit=24).lower()
            if location not in _WORKBENCH_VIEW_LOCATIONS:
                location = "intel"
            blocks = []
            for block in list(raw_view.get("blocks") or [])[:12]:
                sanitized = _sanitize_workbench_block(block)
                if sanitized:
                    blocks.append(sanitized)
            if not blocks:
                continue

            view = {
                "view_id": view_id,
                "title": title,
                "location": location,
                "source_extension": extension_id,
                "order": int(raw_view.get("order") or 100),
                "blocks": blocks,
            }
            summary = _workbench_text(raw_view.get("summary"), limit=240)
            badge = _workbench_text(raw_view.get("badge"), limit=48)
            nav_label = _workbench_text(raw_view.get("nav_label"), limit=32)
            if summary:
                view["summary"] = summary
            if badge:
                view["badge"] = badge
            if nav_label:
                view["nav_label"] = nav_label
            views.append(view)

    views.sort(key=lambda item: (item.get("location", ""), int(item.get("order") or 100), item.get("title", "")))
    return views


def _build_dpi_context(report: dict, nodes: list[dict]) -> tuple[dict, dict]:
    conversations = list(report.get("conversations") or [])
    known_ips = {
        str(node.get("ip") or node.get("address") or "").strip()
        for node in nodes
        if str(node.get("ip") or node.get("address") or "").strip()
    }
    asset_state = {}
    protocol_counts = Counter()
    identity_counts = Counter()
    hunt_term_counts = Counter()
    highlight_candidates = []

    def get_asset_state(ip: str) -> dict:
        if ip not in asset_state:
            asset_state[ip] = {
                "conversation_count": 0,
                "protocol_counts": Counter(),
                "operations": [],
                "identity_pairs": [],
                "attribute_pairs": [],
                "objects": [],
                "asset_hints": [],
                "hunt_terms": [],
                "peers": defaultdict(
                    lambda: {
                        "conversation_count": 0,
                        "protocol_counts": Counter(),
                        "operations": [],
                        "objects": [],
                        "notes": [],
                    }
                ),
            }
        return asset_state[ip]

    def collect_asset_hints(asset: dict, prefix: str) -> tuple[list[dict], list[str]]:
        hints = []
        hunt_terms = []
        if not isinstance(asset, dict):
            return hints, hunt_terms

        for key, value in dict(asset.get("identifiers") or {}).items():
            for text in _dpi_values(value):
                _append_unique_pair(hints, f"{prefix} {_dpi_label(key)}", text, limit=8)
                _append_unique_text(hunt_terms, text, limit=12)

        for key, value in asset.items():
            if key in {"asset_key", "identifiers", "protocols"}:
                continue
            for text in _dpi_values(value):
                _append_unique_pair(hints, f"{prefix} {_dpi_label(key)}", text, limit=8)
                _append_unique_text(hunt_terms, text, limit=12)

        return hints, hunt_terms

    for conversation in conversations:
        protocol = str(conversation.get("protocol") or "Unknown").strip() or "Unknown"
        src_ip = str(conversation.get("src_ip") or "").strip()
        dst_ip = str(conversation.get("dst_ip") or "").strip()
        operations = _dpi_values(conversation.get("operations_seen"))
        object_refs = _dpi_values(conversation.get("protocol_object_refs"))
        protocol_attributes = dict(conversation.get("protocol_attributes") or {})
        src_asset = dict(conversation.get("src_asset") or {})
        dst_asset = dict(conversation.get("dst_asset") or {})
        src_hints, src_terms = collect_asset_hints(src_asset, "Source")
        dst_hints, dst_terms = collect_asset_hints(dst_asset, "Target")

        attribute_pairs = []
        identity_pairs = []
        hunt_terms = []
        for key in sorted(protocol_attributes, key=lambda item: (_DPI_PRIORITY_KEYS.get(item, 99), _dpi_label(item))):
            for text in _dpi_values(protocol_attributes.get(key)):
                label = _dpi_label(key)
                _append_unique_pair(attribute_pairs, label, text, limit=10)
                _append_unique_text(hunt_terms, text, limit=16)
                if key in _DPI_IDENTITY_KEYS:
                    _append_unique_pair(identity_pairs, label, text, limit=8)

        for value in object_refs:
            _append_unique_text(hunt_terms, value, limit=16)
        for value in src_terms + dst_terms:
            _append_unique_text(hunt_terms, value, limit=16)

        has_enrichment = bool(operations or object_refs or attribute_pairs or src_hints or dst_hints)
        if not has_enrichment:
            continue

        protocol_counts[protocol] += 1
        for pair in identity_pairs:
            identity_counts[f"{pair['label']}: {pair['value']}"] += 1
        for term in hunt_terms:
            hunt_term_counts[term] += 1

        conversation_score = (
            len(identity_pairs) * 4
            + len(object_refs) * 3
            + (len(src_hints) + len(dst_hints)) * 2
            + len(operations)
        )
        highlight_candidates.append(
            {
                "protocol": protocol,
                "src": src_ip or "Unknown",
                "dst": dst_ip or "Unknown",
                "operations": operations[:6],
                "identities": identity_pairs[:5],
                "attributes": attribute_pairs[:6],
                "object_refs": object_refs[:5],
                "asset_hints": (src_hints + dst_hints)[:6],
                "hunt_terms": hunt_terms[:6],
                "packet_count": int(conversation.get("packet_count") or 0),
                "bytes_total": int(conversation.get("bytes_total") or 0),
                "_score": conversation_score,
            }
        )

        endpoints = [
            (src_ip, dst_ip, src_hints, "source"),
            (dst_ip, src_ip, dst_hints, "target"),
        ]
        for ip, peer_ip, asset_hints, side in endpoints:
            if ip not in known_ips:
                continue
            entry = get_asset_state(ip)
            entry["conversation_count"] += 1
            entry["protocol_counts"][protocol] += 1

            for op in operations:
                _append_unique_text(entry["operations"], op, limit=10)
            for pair in identity_pairs:
                _append_unique_pair(entry["identity_pairs"], pair["label"], pair["value"], limit=8)
            for pair in attribute_pairs:
                _append_unique_pair(entry["attribute_pairs"], pair["label"], pair["value"], limit=10)
            for value in object_refs:
                _append_unique_text(entry["objects"], value, limit=8)
            for pair in asset_hints:
                _append_unique_pair(entry["asset_hints"], pair["label"], pair["value"], limit=8)
            for term in hunt_terms:
                _append_unique_text(entry["hunt_terms"], term, limit=12)

            if peer_ip:
                peer_entry = entry["peers"][peer_ip]
                peer_entry["conversation_count"] += 1
                peer_entry["protocol_counts"][protocol] += 1
                for op in operations:
                    _append_unique_text(peer_entry["operations"], op, limit=6)
                for value in object_refs:
                    _append_unique_text(peer_entry["objects"], value, limit=4)
                for pair in identity_pairs[:4]:
                    _append_unique_text(peer_entry["notes"], f"{pair['label']}: {pair['value']}", limit=5)
                for pair in asset_hints[:4]:
                    _append_unique_text(peer_entry["notes"], f"{pair['label']}: {pair['value']}", limit=5)

    asset_evidence = {}
    for ip, state in asset_state.items():
        peer_items = []
        for peer_ip, peer in sorted(
            state["peers"].items(),
            key=lambda item: (
                -int(item[1].get("conversation_count") or 0),
                -sum(item[1]["protocol_counts"].values()),
                item[0],
            ),
        )[:5]:
            peer_items.append(
                {
                    "peer": peer_ip,
                    "conversation_count": int(peer.get("conversation_count") or 0),
                    "protocols": [
                        name
                        for name, _count in peer["protocol_counts"].most_common(3)
                    ],
                    "operations": peer["operations"][:5],
                    "objects": peer["objects"][:4],
                    "notes": peer["notes"][:4],
                }
            )

        asset_evidence[ip] = {
            "conversation_count": int(state["conversation_count"] or 0),
            "protocols": [name for name, _count in state["protocol_counts"].most_common(4)],
            "operations": state["operations"][:8],
            "identities": state["identity_pairs"][:6],
            "attributes": state["attribute_pairs"][:8],
            "objects": state["objects"][:6],
            "asset_hints": state["asset_hints"][:6],
            "hunt_terms": state["hunt_terms"][:10],
            "peers": peer_items,
        }

    highlight_candidates.sort(
        key=lambda item: (
            -int(item["_score"] or 0),
            -int(item.get("packet_count") or 0),
            item.get("protocol", ""),
            item.get("src", ""),
            item.get("dst", ""),
        )
    )
    highlights = [
        {key: value for key, value in item.items() if key != "_score"}
        for item in highlight_candidates[:8]
    ]

    summary = {
        "engine": str(report.get("dpi_engine") or "").strip(),
        "engine_version": str(report.get("dpi_engine_version") or "").strip(),
        "schema_version": str(report.get("dpi_schema_version") or "").strip(),
        "enriched_conversation_count": len(highlight_candidates),
        "asset_count": len(asset_evidence),
        "identity_count": len(identity_counts),
        "hunt_term_count": len(hunt_term_counts),
        "top_protocols": [
            {"name": name, "count": count}
            for name, count in protocol_counts.most_common(6)
        ],
        "top_identities": [
            {"label": label, "count": count}
            for label, count in identity_counts.most_common(6)
        ],
    }
    return summary, {"asset_evidence": asset_evidence, "dpi_highlights": highlights}


_DISSECTOR_FAMILY_KEYS = (
    ("modbus", ("modbus_functions", "modbus_writes")),
    ("s7", ("s7_functions", "s7_program_access")),
    ("dnp3", ("dnp3_objects",)),
    ("iec104", ("iec104_typeids", "iec104_causes")),
    ("cip", ("cip_identity",)),
    ("mms", ("mms_identity",)),
    ("goose", ("goose_identity",)),
    ("bacnet", ("bacnet_identity",)),
    ("omron", ("omron_identity",)),
    ("profinet", ("pn_identity",)),
    ("opc", ("opc_no_security", "opc_sessions")),
    ("dns", ("dns_queries", "dns_query_types")),
)


def _count_active_dissector_families(conversations: list) -> int:
    """Count how many DPI dissector families produced any per-conversation evidence."""
    active = 0
    for _, keys in _DISSECTOR_FAMILY_KEYS:
        for conv in conversations or ():
            for key in keys:
                value = conv.get(key) if isinstance(conv, dict) else None
                if value in (None, "", False):
                    continue
                if isinstance(value, (list, tuple, dict)) and not value:
                    continue
                active += 1
                break
            else:
                continue
            break
    return active


_SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _apply_contextual_severity(
    findings: list,
    asset_tags_by_key: dict,
    notes_by_sig: dict,
) -> list:
    """Return enriched copies of each finding with contextual severity fields."""
    result = []
    for finding in findings:
        item = dict(finding)
        base_sev = str(item.get("severity") or "").upper()
        affected = [str(n) for n in (item.get("affected_nodes") or [])]

        # Build per-finding asset_tags map: node_key -> tag dict
        node_tag_map = {}
        for node_key in affected:
            tag = asset_tags_by_key.get(node_key)
            if tag is not None:
                node_tag_map[node_key] = tag

        ctx_sev = base_sev
        reason = "unchanged"

        if base_sev in _SEVERITY_ORDER:
            base_idx = _SEVERITY_ORDER.index(base_sev)
            tagged_criticalities = [
                tag.get("criticality") for tag in node_tag_map.values() if tag.get("criticality")
            ]
            has_critical_asset = any(c == "critical" for c in tagged_criticalities)
            # "all low": every affected node must be present in tags AND tagged low
            all_low = (
                bool(affected)
                and len(node_tag_map) == len(affected)
                and all(
                    node_tag_map.get(n, {}).get("criticality") == "low" for n in affected
                )
            )

            if has_critical_asset and base_idx < len(_SEVERITY_ORDER) - 1:
                ctx_sev = _SEVERITY_ORDER[base_idx + 1]
                reason = "bumped: affected node tagged critical"
            elif all_low and base_idx > 0:
                ctx_sev = _SEVERITY_ORDER[base_idx - 1]
                reason = "reduced: all affected nodes tagged low"

        sig = _finding_signature(item)
        note = notes_by_sig.get(sig)

        item["contextual_severity"] = ctx_sev
        item["contextual_severity_reason"] = reason
        item["note"] = note
        item["asset_tags"] = node_tag_map
        item["signature"] = sig
        result.append(item)
    return result


def _build_viewer_context(report: dict, project_id: int = None, report_filename: str = None) -> dict:
    """Prepare server-rendered triage context for the viewer."""
    nodes = list(report.get("nodes") or [])
    edges = list(report.get("edges") or [])
    risk_findings = list(report.get("risk_findings") or [])
    c2_indicators = list(report.get("c2_indicators") or [])
    protocol_summary = dict(report.get("protocol_summary") or {})
    port_summary = dict(report.get("port_summary") or {})
    purdue_violations = list(report.get("purdue_violations") or [])
    mac_table = list(report.get("mac_table") or [])
    mitre_extension = dict(((report.get("extensions") or {}).get("marlinspike-mitre") or {}))
    mitre_data = dict(mitre_extension.get("data") or {})
    mitre_summary = dict(mitre_extension.get("summary") or {})
    mitre_attack_metadata = dict(mitre_extension.get("attack_metadata") or {})
    mitre_matrix = dict(mitre_data.get("matrix") or {})
    mitre_classifications = sorted(
        list(mitre_data.get("classifications") or []),
        key=lambda item: (
            {"observed": 0, "inferred": 1, "platform": 2}.get(str(item.get("basis") or "inferred"), 9),
            -float(item.get("confidence") or 0.0),
            str(item.get("technique_id") or ""),
        ),
    )
    mitre_platform_coverage = sorted(
        list(mitre_data.get("platform_coverage") or []),
        key=lambda item: (str(item.get("domain") or ""), str(item.get("family") or ""), str(item.get("technique_id") or "")),
    )
    mitre_domains = sorted(
        list((mitre_attack_metadata.get("domains") or {}).values()),
        key=lambda item: (str(item.get("name") or ""), str(item.get("domain") or "")),
    )
    mitre_matrix_domains = sorted(
        list(mitre_matrix.get("domains") or []),
        key=lambda item: (str(item.get("name") or ""), str(item.get("domain") or "")),
    )

    signal_attack_ids = defaultdict(list)
    for item in mitre_classifications:
        technique_id = str(item.get("technique_id") or "").strip().upper()
        if not technique_id:
            continue
        for signal in item.get("mapped_from") or []:
            signal_key = str(signal or "").strip().upper()
            if signal_key and technique_id not in signal_attack_ids[signal_key]:
                signal_attack_ids[signal_key].append(technique_id)

    enriched_findings = []
    for finding in risk_findings:
        item = dict(finding or {})
        mapped = signal_attack_ids.get(str(item.get("category") or "").strip().upper(), [])
        existing = [str(value).strip().upper() for value in (item.get("attack_ids") or []) if str(value).strip()]
        item["attack_ids"] = sorted(set(existing + mapped))
        enriched_findings.append(item)
    risk_findings = enriched_findings

    # ── Contextual severity overlay (Bet 2) ──────────────────────────────────
    # Load AssetTags and FindingNotes for this project when project_id is given.
    _ctx_asset_tags_by_key: dict = {}
    _ctx_notes_by_sig: dict = {}
    if project_id is not None:
        for tag in AssetTag.query.filter_by(project_id=project_id).all():
            _ctx_asset_tags_by_key[tag.asset_key] = {
                "id": tag.id,
                "asset_key": tag.asset_key,
                "owner": tag.owner,
                "criticality": tag.criticality,
                "zone": tag.zone,
                "business_function": tag.business_function,
                "free_text": tag.free_text,
            }
        _fn_query = FindingNote.query.filter_by(project_id=project_id)
        if report_filename:
            _fn_query = _fn_query.filter_by(report_filename=report_filename)
        for note in _fn_query.all():
            _ctx_notes_by_sig[note.finding_signature] = {
                "id": note.id,
                "status": note.status,
                "body": note.body,
                "author_id": note.author_id,
                "report_filename": note.report_filename,
                "created_at": note.created_at.isoformat() if note.created_at else None,
                "updated_at": note.updated_at.isoformat() if note.updated_at else None,
            }
        risk_findings = _apply_contextual_severity(
            risk_findings, _ctx_asset_tags_by_key, _ctx_notes_by_sig
        )

    enriched_indicators = []
    for indicator in c2_indicators:
        item = dict(indicator or {})
        mapped = signal_attack_ids.get(str(item.get("type") or "").strip().upper(), [])
        existing = [str(value).strip().upper() for value in (item.get("attack_ids") or []) if str(value).strip()]
        item["attack_ids"] = sorted(set(existing + mapped))
        enriched_indicators.append(item)
    c2_indicators = sorted(
        enriched_indicators,
        key=lambda item: (_severity_rank(item.get("severity")), item.get("type", ""), item.get("src", "")),
    )

    node_risks = defaultdict(list)
    for finding in risk_findings:
        if finding.get("category") == "NO_AUTH_OBSERVED":
            continue
        for ip in finding.get("affected_nodes") or []:
            node_risks[str(ip)].append(finding)
    for items in node_risks.values():
        items.sort(key=lambda item: (_severity_rank(item.get("severity")), item.get("category", "")))

    dpi_summary, dpi_context = _build_dpi_context(report, nodes)
    asset_evidence = dict(dpi_context.get("asset_evidence") or {})
    module_views = _collect_workbench_views(report)
    module_views_by_location = {location: [] for location in sorted(_WORKBENCH_VIEW_LOCATIONS)}
    for view in module_views:
        location = str(view.get("location") or "intel")
        module_views_by_location.setdefault(location, []).append(view)

    def classify_score(node: dict) -> int:
        score = 0
        if node.get("vendor") and node.get("vendor") != "Unknown":
            score += 1
        if node.get("device_type") and node.get("device_type") != "Unknown":
            score += 1
        if node.get("product_line"):
            score += 1
        if node.get("system_name") or node.get("system_desc"):
            score += 1
        return score

    def node_priority_key(node: dict):
        ip = str(node.get("ip") or node.get("address") or "")
        risk_count = len(node_risks.get(ip, []))
        service_count = len(node.get("service_ports") or [])
        protocol_count = len(node.get("protocols") or [])
        return (
            int(node.get("attack_priority") or 0),
            risk_count,
            service_count,
            protocol_count,
            ip,
        )

    assets_sorted = []
    write_nodes = set()
    for edge in edges:
        if edge.get("includes_writes") or edge.get("includes_program_access"):
            if edge.get("src"):
                write_nodes.add(str(edge["src"]))
            if edge.get("dst"):
                write_nodes.add(str(edge["dst"]))

    for node in sorted(nodes, key=node_priority_key, reverse=True):
        ip = str(node.get("ip") or node.get("address") or "")
        related_risks = node_risks.get(ip, [])
        dpi_evidence = asset_evidence.get(ip, {})
        assets_sorted.append({
            **node,
            "_ip": ip,
            "_anchor": _viewer_anchor(ip),
            "_risk_count": len(related_risks),
            "_top_risk": related_risks[0] if related_risks else None,
            "_risk_findings": related_risks,
            "_classification_score": classify_score(node),
            "_has_writes": ip in write_nodes,
            "_dpi": dpi_evidence,
        })

    priority_nodes = [node for node in assets_sorted if int(node.get("attack_priority") or 0) > 0][:8]
    auth_gap_nodes = [node for node in assets_sorted if not node.get("auth_observed", False)][:8]
    unclassified_nodes = [node for node in assets_sorted if node["_classification_score"] == 0][:8]
    write_paths = [
        {
            **edge,
            "_anchor_src": _viewer_anchor(edge.get("src", "")),
            "_anchor_dst": _viewer_anchor(edge.get("dst", "")),
        }
        for edge in edges
        if edge.get("includes_writes") or edge.get("includes_program_access")
    ]
    write_paths.sort(key=lambda edge: (int(bool(edge.get("includes_program_access"))), int(bool(edge.get("includes_writes"))), int(edge.get("conversation_count") or 0)), reverse=True)

    external_types = {
        "C2_BEACONING",
        "C2_DNS_EXFIL",
        "C2_DNS_TUNNEL_SUSPECT",
        "C2_DNS_HIGH_ENTROPY",
        "C2_SUSPECT_CHANNEL",
        "C2_DATA_EXFIL",
        "C2_PERSISTENCE",
    }
    external_indicators = [item for item in c2_indicators if item.get("type") in external_types][:8]
    top_findings = sorted(
        risk_findings,
        key=lambda item: (_severity_rank(item.get("severity")), item.get("category", ""), item.get("description", "")),
    )[:8]

    protocol_items = [
        {"name": name, "count": count}
        for name, count in sorted(protocol_summary.items(), key=lambda item: (-int(item[1]), item[0]))
    ]
    port_items = [
        {"label": label, **details}
        for label, details in sorted(
            port_summary.items(),
            key=lambda item: (-int((item[1] or {}).get("connections") or 0), item[0]),
        )
    ]

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for finding in risk_findings:
        sev = str(finding.get("severity") or "").upper()
        if sev in severity_counts:
            severity_counts[sev] += 1

    capture_info = report.get("capture_info") or {}
    # Engine reports use ``packet_count`` / ``duration_s``; some older artefacts use
    # ``total_packets`` / ``duration_seconds``. Accept either so the header is never
    # silently empty when a real value is on disk.
    cap_packets = capture_info.get("packet_count") or capture_info.get("total_packets")
    cap_duration = capture_info.get("duration_s") or capture_info.get("duration_seconds")
    l2_anomalies = report.get("l2_anomalies") or []
    arp_observations = report.get("arp_observations") or []

    summary = {
        "asset_count": len(nodes),
        "edge_count": len(edges),
        "protocol_count": len(protocol_items),
        "classified_count": sum(1 for node in assets_sorted if node["_classification_score"] > 0),
        "auth_gap_count": sum(1 for node in assets_sorted if not node.get("auth_observed", False)),
        "write_node_count": len(write_nodes),
        "write_edge_count": len(write_paths),
        "priority_count": len([node for node in assets_sorted if int(node.get("attack_priority") or 0) > 0]),
        "external_count": len([node for node in assets_sorted if node.get("purdue_level") == 5 or node.get("role") == "External Host"]),
        "critical_high_count": severity_counts["CRITICAL"] + severity_counts["HIGH"],
        "severity_counts": severity_counts,
        "packet_count": cap_packets,
        "duration_seconds": cap_duration,
        "capture_source": capture_info.get("source"),
        "capture_link_type": capture_info.get("link_type"),
        "capture_unique_macs": capture_info.get("unique_macs"),
        "capture_unique_ips": capture_info.get("unique_ips"),
        "conversation_count": len(report.get("conversations") or []),
        "dissector_family_count": _count_active_dissector_families(report.get("conversations") or []),
        "l2_anomaly_count": len(l2_anomalies),
        "arp_observation_count": len(arp_observations),
        "dpi_enriched_conversation_count": int(dpi_summary.get("enriched_conversation_count") or 0),
        "dpi_asset_count": int(dpi_summary.get("asset_count") or 0),
        "dpi_identity_count": int(dpi_summary.get("identity_count") or 0),
    }
    summary["unclassified_count"] = max(0, summary["asset_count"] - summary["classified_count"])
    summary["mitre_classification_total"] = len(mitre_classifications)
    summary["mitre_platform_total"] = len(mitre_platform_coverage)
    summary["mitre_tactic_total"] = int(mitre_summary.get("tactic_total") or 0)
    summary["mitre_subtechnique_total"] = int(mitre_summary.get("subtechnique_total") or 0)
    summary["mitre_matrix_domain_total"] = int(mitre_summary.get("matrix_domain_total") or len(mitre_matrix_domains))
    summary["module_view_total"] = len(module_views)
    summary["module_location_total"] = sum(1 for items in module_views_by_location.values() if items)

    # Compact L2 anomaly digest — group by anomaly_type so the sidebar can
    # show "{count} of {type}" without each entry leaking into context.
    l2_anomaly_buckets: dict[str, dict] = {}
    for entry in l2_anomalies[:5000]:
        atype = str(entry.get("anomaly_type") or "unknown")
        bucket = l2_anomaly_buckets.setdefault(
            atype,
            {"anomaly_type": atype, "count": 0, "severities": {}, "sample": None},
        )
        bucket["count"] += 1
        sev = str((entry.get("details") or {}).get("severity") or "").lower() or "unknown"
        bucket["severities"][sev] = bucket["severities"].get(sev, 0) + 1
        if bucket["sample"] is None:
            reason = (entry.get("details") or {}).get("reason")
            bucket["sample"] = {
                "src_mac": entry.get("src_mac"),
                "dst_mac": entry.get("dst_mac"),
                "src_ip": entry.get("src_ip"),
                "dst_ip": entry.get("dst_ip"),
                "reason": reason,
                "decoder": entry.get("decoder"),
                "timestamp": entry.get("timestamp"),
            }
    l2_anomaly_digest = sorted(l2_anomaly_buckets.values(), key=lambda b: -int(b["count"] or 0))[:8]

    return {
        "summary": summary,
        "assets_sorted": assets_sorted,
        "priority_nodes": priority_nodes,
        "auth_gap_nodes": auth_gap_nodes,
        "unclassified_nodes": unclassified_nodes,
        "write_paths": write_paths[:10],
        "top_findings": top_findings,
        "external_indicators": external_indicators,
        "protocol_items": protocol_items[:10],
        "port_items": port_items[:12],
        "purdue_violations": purdue_violations,
        "c2_indicators": c2_indicators,
        "mac_table": mac_table,
        "l2_anomaly_digest": l2_anomaly_digest,
        "arp_observations": arp_observations[:10],
        "mitre_summary": mitre_summary,
        "mitre_attack_metadata": mitre_attack_metadata,
        "mitre_domains": mitre_domains,
        "mitre_matrix": mitre_matrix,
        "mitre_matrix_domains": mitre_matrix_domains,
        "mitre_classifications": mitre_classifications,
        "mitre_platform_coverage": mitre_platform_coverage,
        "dpi_summary": dpi_summary,
        "dpi_highlights": dpi_context.get("dpi_highlights") or [],
        "asset_evidence": asset_evidence,
        "module_views": module_views,
        "module_views_by_location": module_views_by_location,
        "project_id": project_id,
        "asset_tags_by_key": _ctx_asset_tags_by_key,
        "finding_notes_by_sig": _ctx_notes_by_sig,
    }


SCAN_COMMAND_ALIASES = {
    "analyze": "dissect",
    "classify": "topology",
    "report": "risk",
}

VALID_SCAN_COMMANDS = {"chain", "ingest", "dissect", "topology", "risk"}
VALID_SCAN_PROFILES = {"full", "fast"}


def _normalize_scan_command(command: str) -> str:
    """Map legacy UI labels onto canonical engine subcommands."""
    normalized = (command or "chain").strip().lower()
    normalized = SCAN_COMMAND_ALIASES.get(normalized, normalized)
    return normalized if normalized in VALID_SCAN_COMMANDS else "chain"


def _normalize_scan_profile(profile: str) -> str:
    normalized = (profile or "full").strip().lower()
    return normalized if normalized in VALID_SCAN_PROFILES else "full"


def _scan_stage_names(command: str) -> list[str]:
    if command == "chain":
        return ["Ingest", "Analyze", "Classify", "Report"]
    if command == "ingest":
        return ["Ingest"]
    if command == "dissect":
        return ["Analyze"]
    if command == "topology":
        return ["Classify"]
    if command == "risk":
        return ["Report"]
    return ["Run"]


def _run_schema_init(app) -> None:
    """Apply Alembic migrations (preferred) or db.create_all() (fallback).

    Priority order:
      1. If the ``migrations/`` directory is present, ``flask-migrate`` is
         installed, and the database URL is not an in-memory SQLite URI, run
         ``flask_migrate.upgrade()`` to bring the DB to head.  This is the
         standard path for all persistent-DB installs (Docker, production,
         editable installs with DATABASE_URL pointing at a file or Postgres).
      2. In-memory SQLite (``sqlite:///:memory:``): Alembic opens connections
         via NullPool; each connection is a fresh empty DB.  Fall back to
         ``db.create_all()`` which uses the app's shared connection pool.
      3. If ``migrations/`` is missing (bare ``pip install marlinspike``
         without the source tree) or flask-migrate is not installed, fall
         back to ``db.create_all()``.  No version tracking is performed.
      4. If ``MARLINSPIKE_ALLOW_NO_DATABASE_URL=true`` is set (test mode),
         skip the Alembic path only — still run ``db.create_all()`` so that
         the in-process schema is initialised for the bootstrap_admin() call
         that follows immediately inside create_app().  Test fixtures may call
         ``db.create_all()`` again after reconfiguring the URI; that is safe.
    """
    import pathlib

    _migrations_dir = pathlib.Path(__file__).parent.parent / "migrations"
    _have_migrations = _migrations_dir.is_dir()

    try:
        import flask_migrate as _fm  # noqa: F401
        _have_flask_migrate = True
    except ImportError:
        _have_flask_migrate = False

    # Detect in-memory SQLite — Alembic's NullPool makes every statement open
    # a fresh connection, giving each one an empty database.  Use create_all()
    # instead so the schema lives in the app's shared connection pool.
    _db_url = app.config.get("SQLALCHEMY_DATABASE_URI", "")
    _is_memory_sqlite = _db_url in ("sqlite:///:memory:", "sqlite://")

    # Skip the Alembic path in test mode (ALLOW_NO_DATABASE_URL) or for
    # in-memory SQLite; always fall through to db.create_all().
    _skip_alembic = config.ALLOW_NO_DATABASE_URL or _is_memory_sqlite

    if _have_migrations and _have_flask_migrate and not _skip_alembic:
        from flask_migrate import Migrate, upgrade as _alembic_upgrade

        # Attach Migrate to the app so upgrade() can locate the migrations dir.
        # render_as_batch=True is required for SQLite ALTER TABLE support.
        Migrate(app, db, directory=str(_migrations_dir), render_as_batch=True)
        with app.app_context():
            try:
                _alembic_upgrade()
                log.info("Alembic upgrade to head completed successfully.")
                return  # Alembic handled it; skip the create_all() below.
            except Exception as exc:
                log.error(
                    "Alembic migration failed: %s — falling back to db.create_all(). "
                    "Manual intervention may be required for production databases.",
                    exc,
                    exc_info=True,
                )
    else:
        if _is_memory_sqlite:
            log.debug("In-memory SQLite detected — using db.create_all() (Alembic skipped).")
        elif config.ALLOW_NO_DATABASE_URL:
            log.debug("MARLINSPIKE_ALLOW_NO_DATABASE_URL=true — using db.create_all() (test mode).")
        elif not _have_migrations:
            log.info(
                "migrations/ directory not found at %s — using db.create_all() fallback.",
                _migrations_dir,
            )
        elif not _have_flask_migrate:
            log.info(
                "flask-migrate not installed — using db.create_all() fallback. "
                "Install marlinspike[migrations] to enable Alembic tracking."
            )

    # Fallback (and test-mode) path: create all tables using SQLAlchemy metadata.
    with app.app_context():
        db.create_all()


def create_app():
    app = Flask(__name__)

    # ── Fail-closed config (v3.5.2) ─────────────────────────────────
    # Refuse to boot when sensitive config is missing. Prior versions
    # silently generated a random SECRET_KEY (sessions invalidated on
    # restart, no operator-controlled rotation) and shipped a
    # predictable default DATABASE_URL ("marlinspike:marlinspike").
    # Both are footguns in production. The escape hatches below are
    # for tests / dev only.

    secret = config.SECRET_KEY
    allow_dev_secret = config._env_bool("MARLINSPIKE_ALLOW_GENERATED_SECRET", default=False)
    if not secret:
        if not allow_dev_secret:
            raise RuntimeError(
                "SECRET_KEY is not set. Refusing to start with a generated "
                "ephemeral key in production: sessions would invalidate on "
                "every restart and any cookie/CSRF state would be unstable. "
                "Set SECRET_KEY env var to a strong random value (e.g. "
                "`python -c \"import secrets; print(secrets.token_hex(32))\"`). "
                "For tests / dev, set MARLINSPIKE_ALLOW_GENERATED_SECRET=true "
                "to opt back into the legacy generated-key behaviour."
            )
        secret = secrets.token_hex(32)
        log.warning(
            "MARLINSPIKE_ALLOW_GENERATED_SECRET=true — using ephemeral "
            "session SECRET_KEY. Sessions will invalidate on restart. "
            "DO NOT USE IN PRODUCTION."
        )
    app.secret_key = secret

    if not config.DATABASE_URL and not config.ALLOW_NO_DATABASE_URL:
        raise RuntimeError(
            "DATABASE_URL is not set. The previous v3.5.1 default "
            "('postgresql://marlinspike:marlinspike@localhost:5432/marlinspike') "
            "shipped predictable credentials — refusing to default to it now. "
            "Set DATABASE_URL explicitly. Examples: "
            "'postgresql://user:STRONG_PASS@host/db' (production), "
            "'sqlite:///./data/dev.db' (dev). "
            "For tests, set MARLINSPIKE_ALLOW_NO_DATABASE_URL=true."
        )

    app.config["SQLALCHEMY_DATABASE_URI"] = config.DATABASE_URL or "sqlite:///:memory:"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config.update(
        SESSION_COOKIE_SECURE=config.SESSION_COOKIE_SECURE,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        PERMANENT_SESSION_LIFETIME=86400,
    )

    # Rate limiter. Production deployments should use a shared backend so
    # auth and upload throttles survive restarts and span workers.
    rate_limit_storage_uri = config.RATELIMIT_STORAGE_URI or "memory://"
    if config.RATELIMIT_STORAGE_URI:
        try:
            if not storage_from_string(config.RATELIMIT_STORAGE_URI).check():
                raise RuntimeError("health check failed")
        except Exception as exc:
            raise RuntimeError(
                "RATELIMIT_STORAGE_URI is configured but unavailable. "
                "Refusing to start with ineffective shared rate limiting."
            ) from exc
    else:
        log.warning(
            "RATELIMIT_STORAGE_URI not set — using in-memory rate limits. "
            "Suitable only for single-process dev/test deployments."
        )

    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=[],
        storage_uri=rate_limit_storage_uri,
    )

    # Ensure writable paths exist before database initialization.
    os.makedirs(config.DATA_DIR, exist_ok=True)
    os.makedirs(config.REPORTS_DIR, exist_ok=True)
    os.makedirs(config.UPLOADS_DIR, exist_ok=True)
    os.makedirs(config.SUBMISSIONS_DIR, exist_ok=True)
    os.makedirs(config.PRESETS_DIR, exist_ok=True)

    # Init DB
    db.init_app(app)
    _run_schema_init(app)

    # Cleanup expired reset tokens
    with app.app_context():
        try:
            cleanup_expired_tokens()
        except Exception:
            pass

    # Bootstrap admin
    bootstrap_admin(app)

    # Mid-scan recovery — reconcile any scan_history rows still 'running'
    # from a previous boot. Engine subprocesses are reparented to init
    # when Flask dies and usually keep running; the reaper finds them via
    # saved PID + argv (PID-reuse defense), then re-attaches a watcher
    # for live ones, or marks failed/completed for dead ones.
    # See marlinspike.recovery and docs/run-store-and-recovery.md.
    from marlinspike import recovery as _recovery
    try:
        _recovery.reap_orphan_runs(app)
    except Exception as exc:
        log.warning("Mid-scan recovery encountered an error: %s", exc, exc_info=True)

    # One-time migration: copy baked-in presets to data volume
    if os.path.isdir(config.PRESETS_BAKED_DIR) and config.PRESETS_BAKED_DIR != config.PRESETS_DIR:
        if not os.listdir(config.PRESETS_DIR):
            try:
                shutil.copytree(config.PRESETS_BAKED_DIR, config.PRESETS_DIR, dirs_exist_ok=True)
                log.info("Migrated baked-in presets to data volume: %s", config.PRESETS_DIR)
            except Exception as e:
                log.warning("Preset migration failed: %s", e)

    # ── Project migration (idempotent) ────────────────────
    def _migrate_projects():
        """Create Default project for each user and move flat files into project dirs."""
        users = User.query.all()
        for u in users:
            # Ensure Default project exists
            default = Project.query.filter_by(user_id=u.id, name="Default").first()
            if not default:
                default = Project(user_id=u.id, name="Default")
                db.session.add(default)
                db.session.flush()
                log.info("Created Default project for user %s (id=%d)", u.username, default.id)

            # Move flat uploads into project subdir
            user_up = os.path.join(config.UPLOADS_DIR, str(u.id))
            proj_up = os.path.join(user_up, str(default.id))
            if os.path.isdir(user_up):
                os.makedirs(proj_up, exist_ok=True)
                for fn in os.listdir(user_up):
                    src = os.path.join(user_up, fn)
                    if os.path.isfile(src) and fn.lower().endswith((".pcap", ".pcapng", ".cap")):
                        dst = os.path.join(proj_up, fn)
                        if not os.path.exists(dst):
                            shutil.move(src, dst)
                            log.info("Migrated upload %s -> project %d", fn, default.id)

            # Move flat reports into project subdir
            user_rp = os.path.join(config.REPORTS_DIR, str(u.id))
            proj_rp = os.path.join(user_rp, str(default.id))
            if os.path.isdir(user_rp):
                os.makedirs(proj_rp, exist_ok=True)
                for fn in os.listdir(user_rp):
                    src = os.path.join(user_rp, fn)
                    if os.path.isfile(src) and fn.lower().endswith(".json"):
                        dst = os.path.join(proj_rp, fn)
                        if not os.path.exists(dst):
                            shutil.move(src, dst)
                            log.info("Migrated report %s -> project %d", fn, default.id)

            # Update scan history records that have no project_id
            ScanHistory.query.filter_by(user_id=u.id, project_id=None).update(
                {"project_id": default.id}
            )

        db.session.commit()

    with app.app_context():
        try:
            _migrate_projects()
        except Exception as e:
            log.warning("Project migration error (may be first run): %s", e)
            db.session.rollback()

    # ── Per-user directory helpers (project-aware) ────────
    def _ensure_default_project(user_id):
        """Get or create the Default project for a user."""
        proj = Project.query.filter_by(user_id=user_id, name="Default").first()
        if not proj:
            proj = Project(user_id=user_id, name="Default")
            db.session.add(proj)
            db.session.commit()
        return proj

    def user_uploads_dir(project_id=None):
        uid = str(session["user_id"])
        if project_id is None:
            default = _ensure_default_project(session["user_id"])
            project_id = default.id
        d = os.path.join(config.UPLOADS_DIR, uid, str(project_id))
        os.makedirs(d, exist_ok=True)
        return d

    def user_reports_dir(project_id=None):
        uid = str(session["user_id"])
        if project_id is None:
            default = _ensure_default_project(session["user_id"])
            project_id = default.id
        d = os.path.join(config.REPORTS_DIR, uid, str(project_id))
        os.makedirs(d, exist_ok=True)
        return d

    # ── i18n ──────────────────────────────────────────────────
    load_translations()

    @app.before_request
    def resolve_request_locale():
        accept = request.headers.get("Accept-Language")
        g.locale = resolve_locale(session.get("locale"), accept)

    def _t(key, **kwargs):
        return _translate(key, locale=getattr(g, "locale", DEFAULT_LOCALE), **kwargs)

    def _i18n_dict():
        return merged_for_locale(getattr(g, "locale", DEFAULT_LOCALE))

    app.jinja_env.globals["t"] = _t
    app.jinja_env.globals["i18n_dict"] = _i18n_dict

    @app.route("/i18n/set/<locale>", methods=["GET", "POST"])
    def i18n_set(locale):
        picked = normalise_locale(locale)
        session["locale"] = picked
        nxt = request.args.get("next") or request.referrer or url_for("dashboard")
        # Same-host redirect only.
        if urlparse(nxt).netloc and urlparse(nxt).netloc != request.host:
            nxt = url_for("dashboard")
        return redirect(nxt)

    # Expose feature flags + locale state to templates
    @app.context_processor
    def inject_features():
        return {
            "app_version": APP_VERSION,
            "locale": getattr(g, "locale", DEFAULT_LOCALE),
            "supported_locales": SUPPORTED_LOCALES,
            "locale_labels": LOCALE_LABELS,
        }

    # ── Taxonomy context processor ────────────────────────────
    @app.context_processor
    def inject_taxonomy():
        from marlinspike import taxonomy as _tax
        return {
            "taxonomy_entities": _tax.taxonomy_export()["entity_types"],
            "taxonomy_chip": _tax.chip_for,
            "severity_chip_class": _tax.severity_chip_class,
        }

    # Jinja filter: severity string → chip CSS class
    @app.template_filter("severity_chip_class")
    def _sev_chip_filter(value):
        from marlinspike import taxonomy as _tax
        return _tax.severity_chip_class(value)

    # ── /api/taxonomy ─────────────────────────────────────────
    @app.route("/api/taxonomy")
    def api_taxonomy():
        from marlinspike import taxonomy as _tax
        return jsonify(_tax.taxonomy_export())

    # ── CSRF defense (v3.5.4: token primary + origin belt-and-suspenders) ───
    #
    # v3.5.4 adds a proper per-session CSRF token as the *primary* defense.
    # The origin/referer check introduced in v3.5.2 is kept unchanged as
    # defense-in-depth (SOP bypasses, browser bugs).
    #
    # Validation order for state-changing methods (POST/PUT/DELETE/PATCH):
    #   1. If view is @csrf_exempt → skip all checks and return.
    #   2. Check per-session token:
    #        - X-CSRF-Token header (all content types)
    #        - _csrf form field   (multipart/form-data only)
    #      If the token is valid, the request is accepted and origin checks
    #      are skipped (token is strictly stronger).
    #   3. Fall back to origin/referer check (legacy belt-and-suspenders).
    #      A request that passes *either* the token check OR the origin
    #      check is allowed through; both failing returns 403.
    #
    # GET/HEAD/OPTIONS are never checked.

    @app.before_request
    def csrf_check():
        if request.method not in ('POST', 'PUT', 'DELETE', 'PATCH'):
            return
        view = app.view_functions.get(request.endpoint)
        if view is not None and getattr(view, "_csrf_exempt", False):
            return

        # ── Token check (primary, v3.5.4) ──────────────────────────
        candidate = request.headers.get('X-CSRF-Token')
        if candidate is None and request.content_type and 'multipart/form-data' in request.content_type:
            candidate = request.form.get('_csrf')
        if validate_csrf(candidate):
            return  # token valid — no need to also check origin

        # ── Origin/referer check (belt-and-suspenders, v3.5.2) ─────
        origin = request.headers.get('Origin') or ''
        referer = request.headers.get('Referer') or ''
        # Build the allowed-origin set: request's own URL root
        # (full scheme://host:port), plus any explicit allowlist.
        expected_origin = (request.url_root or '').rstrip('/')
        allowed_origins = {expected_origin}
        for extra in config.MARLINSPIKE_ALLOWED_ORIGINS:
            allowed_origins.add(extra)
        origin_full = origin.rstrip('/') if origin else None
        # For Referer, reduce to scheme://host:port for comparison.
        referer_origin = None
        if referer:
            p = urlparse(referer)
            if p.scheme and p.netloc:
                referer_origin = f"{p.scheme}://{p.netloc}"
        if origin_full is None and referer_origin is None:
            # No token, no Origin, no Referer — reject.
            return jsonify({"error": "CSRF token missing or invalid"}), 403
        if origin_full and origin_full not in allowed_origins:
            return jsonify({"error": "Origin check failed"}), 403
        if referer_origin and referer_origin not in allowed_origins:
            return jsonify({"error": "Referer check failed"}), 403

    # ── Browser security headers + per-request CSP nonce (v3.5.2) ────
    #
    # Templates have carried `nonce="{{ csp_nonce }}"` since v3.2.1 but
    # nothing was generating the nonce server-side or emitting a CSP
    # header. v3.5.2 closes that:
    #  * Generate a fresh CSP nonce per request, expose it as `csp_nonce`
    #    in the Jinja context.
    #  * Emit Content-Security-Policy with the nonce on script-src and
    #    style-src. `'unsafe-inline'` retained for now because templates
    #    still carry inline event handlers (onclick=) and inline style=
    #    attributes (a removal pass is tracked for v3.6+ — UPGRADING.md
    #    documents the gap).
    #  * X-Content-Type-Options: nosniff
    #  * X-Frame-Options: DENY  (and frame-ancestors 'none' in CSP for
    #    consistency with older browsers)
    #  * Referrer-Policy: strict-origin-when-cross-origin
    #  * Strict-Transport-Security when SESSION_COOKIE_SECURE (TLS site)

    @app.before_request
    def issue_csp_nonce():
        g.csp_nonce = secrets.token_urlsafe(16)

    @app.context_processor
    def inject_csp_nonce():
        return {"csp_nonce": getattr(g, "csp_nonce", "")}

    @app.context_processor
    def inject_csrf_token():
        """Expose csrf_token() callable in every Jinja template context."""
        return {"csrf_token": csrf_token}

    @app.after_request
    def security_headers(resp):
        nonce = getattr(g, "csp_nonce", "")
        # CSP — keep 'unsafe-inline' on script/style-src until templates
        # are scrubbed of inline handlers + style attributes. The nonce
        # is the future-proofing path; once inline-everywhere is gone,
        # drop 'unsafe-inline' (UPGRADING.md tracks this).
        nonce_token = f"'nonce-{nonce}'" if nonce else ""
        csp_parts = [
            "default-src 'self'",
            f"script-src 'self' {nonce_token} 'unsafe-inline'".strip(),
            f"style-src 'self' {nonce_token} 'unsafe-inline'".strip(),
            "img-src 'self' data: blob:",
            "font-src 'self' data:",
            "connect-src 'self'",
            "frame-ancestors 'none'",
            "base-uri 'self'",
            "form-action 'self'",
            "object-src 'none'",
        ]
        resp.headers.setdefault("Content-Security-Policy", "; ".join(csp_parts))
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        resp.headers.setdefault("Permissions-Policy",
                                "geolocation=(), microphone=(), camera=()")
        if config.SESSION_COOKIE_SECURE:
            # HSTS — only emit when we're confident the deployment is TLS.
            # 1 year, includeSubDomains, preload-eligible.
            resp.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains; preload",
            )
        return resp

    # ── Auth routes ──────────────────────────────────────────

    @app.route("/login", methods=["GET"])
    def login_page():
        if "user" in session:
            return redirect(url_for("dashboard"))
        return render_template("login.html")

    @app.route("/login", methods=["POST"])
    @limiter.limit("5 per minute")
    @csrf_exempt  # no session token exists before login; rate-limiting is the guard here
    def login_submit():
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = verify_user(username, password)
        if not user:
            log.warning("Failed login for '%s' from %s", username, request.remote_addr)
            audit("auth.login_failed", status="failure",
                  target_type="user", target_id=username,
                  ip_address=request.remote_addr)
            return render_template("login.html", error=_t("login.invalid_credentials"))
        log.info("Login: %s from %s", username, request.remote_addr)
        session["user"] = user.username
        session["user_id"] = user.id
        session["role"] = user.role
        session["session_version"] = user.session_version or 1
        rotate_csrf()  # session fixation: ensure a fresh CSRF token post-login
        audit("auth.login", target_type="user", target_id=username)
        return redirect(url_for("dashboard"))

    @app.route("/logout")
    def logout():
        audit("auth.logout")
        session.clear()
        return redirect(url_for("login_page"))

    # ── Password reset ──────────────────────────────────────

    @app.route("/api/auth/reset-request", methods=["POST"])
    @limiter.limit("5 per minute")
    def api_reset_request():
        """Request a password reset.

        v3.5.2 security fix: the reset token is NEVER returned in the
        HTTP response (the previous behaviour made this an unauthenticated
        account takeover — anyone who knew a username could reset that
        account). Token delivery is configurable via
        MARLINSPIKE_RESET_TOKEN_DELIVERY:
          * 'disabled' (default) — endpoint returns 503
          * 'file' — token written to data/instance/reset-tokens/<user>-<ts>.txt
          * 'log' — token written to server stderr only
        Cloudmarlin / wrappers can register an alternate ``deliver_reset_token``
        hook (see marlinspike.auth.set_reset_token_delivery).
        """
        delivery = config.MARLINSPIKE_RESET_TOKEN_DELIVERY
        if delivery == "disabled":
            return jsonify({
                "ok": False,
                "error": "Password reset is disabled on this deployment. "
                         "Contact your administrator."
            }), 503

        body = request.get_json(silent=True) or {}
        username = body.get("username", "").strip()
        if not username:
            return jsonify({"ok": False, "error": "Username required"}), 400
        user = User.query.filter_by(username=username).first()
        # Always return the same response shape regardless of whether the user
        # exists (no enumeration). Generate the token only when the user does
        # exist; deliver it via the configured side channel.
        if user:
            token = create_reset_token(user, ip_address=request.remote_addr)
            try:
                from marlinspike.auth import deliver_reset_token
                deliver_reset_token(user, token, delivery)
            except Exception as exc:
                log.error("Reset token delivery failed for %s: %s", username, exc)
                # Still return the same generic message — don't leak
                # delivery-channel state to the caller either.
            audit("auth.reset_requested", target_type="user", target_id=username)
        return jsonify({
            "ok": True,
            "message": "If the account exists, a reset token has been delivered "
                       "via the configured channel."
        })

    @app.route("/api/auth/reset-confirm", methods=["POST"])
    @limiter.limit("5 per minute")
    def api_reset_confirm():
        body = request.get_json(silent=True) or {}
        raw_token = body.get("token", "").strip()
        new_password = body.get("new_password", "")
        if not raw_token or not new_password:
            return jsonify({"ok": False, "error": "Token and new_password required"}), 400
        if not _password_meets_policy(new_password):
            return jsonify({"ok": False, "error": _password_policy_message()}), 400
        token = validate_reset_token(raw_token)
        if not token:
            return jsonify({"ok": False, "error": "Invalid or expired token"}), 400
        user = use_reset_token(token, new_password)
        return jsonify({"ok": True, "message": f"Password reset for {user.username}"})

    # ── Root redirects ────────────────────────────────────────

    @app.route("/")
    def landing_page():
        if "user" in session:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login_page"))

    @app.route("/about")
    def about_page():
        return redirect(url_for("login_page"))

    # ── Dashboard ────────────────────────────────────────────

    @app.route("/dashboard")
    @login_required
    def dashboard():
        return render_template("dashboard.html")

    @app.route("/reports")
    @login_required
    def reports_page():
        return render_template("reports.html")

    @app.route("/scans")
    @login_required
    def scans_page():
        return render_template("scans.html")

    # ── Projects page ────────────────────────────────────────

    @app.route("/projects")
    @login_required
    def projects_page():
        return render_template("projects.html")

    @app.route("/iocs")
    @login_required
    def iocs_page():
        return render_template("iocs.html")

    @app.route("/capture")
    @login_required
    def capture_page():
        return render_template("capture.html",
                               live_capture_enabled=config.LIVE_CAPTURE_ENABLED,
                               live_capture_socket=config.LIVE_CAPTURE_SOCKET)

    @app.route("/capabilities")
    @login_required
    def capabilities_page():
        catalog = _build_findings_catalog()
        entries = list(catalog["entries"])

        selected = {
            "q": request.args.get("q", "").strip(),
            "source": request.args.get("source", "").strip().lower(),
            "type": request.args.get("type", "").strip().lower(),
            "family": request.args.get("family", "").strip(),
            "severity": request.args.get("severity", "").strip().upper(),
        }

        filtered = []
        query = selected["q"].lower()
        for entry in entries:
            if selected["source"] and entry["source"] != selected["source"]:
                continue
            if selected["type"] and entry["type"] != selected["type"]:
                continue
            if selected["family"] and entry["family"] != selected["family"]:
                continue
            if selected["severity"] and entry["severity"] != selected["severity"]:
                continue
            if query and query not in entry["search_blob"]:
                continue
            filtered.append(entry)

        options = {
            "sources": sorted({entry["source"] for entry in entries if entry["source"]}),
            "types": sorted({entry["type"] for entry in entries if entry["type"]}),
            "families": sorted({entry["family"] for entry in entries if entry["family"]}),
            "severities": [sev for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") if any(entry["severity"] == sev for entry in entries)],
        }

        filtered_counts = Counter(entry["source"] for entry in filtered)
        return render_template(
            "findings.html",
            summary=catalog["summary"],
            source_meta=catalog["source_meta"],
            entries=filtered,
            options=options,
            selected=selected,
            filtered_counts=dict(filtered_counts),
            total_count=len(entries),
            filtered_count=len(filtered),
        )

    # ── Project CRUD API ─────────────────────────────────────

    @app.route("/api/projects")
    @login_required
    def api_projects_list():
        from sqlalchemy import or_
        uid = session["user_id"]
        shared_pids = db.session.query(ProjectMember.project_id).filter_by(user_id=uid)
        projects = Project.query.filter(
            or_(Project.user_id == uid, Project.id.in_(shared_pids))
        ).order_by(Project.created_at).all()
        # Build a role lookup for shared projects
        memberships = {
            m.project_id: m.role
            for m in ProjectMember.query.filter_by(user_id=uid).all()
        }
        result = []
        for p in projects:
            is_owner = p.user_id == uid
            member_role = "owner" if is_owner else memberships.get(p.id, "viewer")
            up_dir = os.path.join(config.UPLOADS_DIR, str(p.user_id), str(p.id))
            rp_dir = os.path.join(config.REPORTS_DIR, str(p.user_id), str(p.id))
            pcap_count = 0
            report_count = 0
            if os.path.isdir(up_dir):
                pcap_count = sum(1 for f in os.listdir(up_dir)
                                 if f.lower().endswith((".pcap", ".pcapng", ".cap")))
            if os.path.isdir(rp_dir):
                report_count = sum(1 for f in os.listdir(rp_dir) if _is_primary_report_filename(f))
            result.append({
                "id": p.id,
                "name": p.name,
                "pcap_count": pcap_count,
                "report_count": report_count,
                "created_at": p.created_at.isoformat() if p.created_at else None,
                "is_owner": is_owner,
                "member_role": member_role,
            })
        return jsonify({"projects": result})

    @app.route("/api/projects", methods=["POST"])
    @login_required
    def api_projects_create():
        body = request.get_json(silent=True) or {}
        name = body.get("name", "").strip()
        if not name:
            return jsonify({"ok": False, "error": "Project name required"}), 400
        if len(name) > 200:
            return jsonify({"ok": False, "error": "Name too long (max 200 chars)"}), 400
        existing = Project.query.filter_by(user_id=session["user_id"], name=name).first()
        if existing:
            return jsonify({"ok": False, "error": "Project name already exists"}), 409
        proj = Project(user_id=session["user_id"], name=name)
        db.session.add(proj)
        db.session.commit()
        return jsonify({"ok": True, "id": proj.id, "name": proj.name})

    @app.route("/api/projects/<int:pid>", methods=["PUT"])
    @login_required
    def api_projects_rename(pid):
        proj = _get_project_for_user(pid, "owner")
        if not proj:
            return jsonify({"ok": False, "error": "Project not found"}), 404
        if proj.name == "Default":
            return jsonify({"ok": False, "error": "Cannot rename the Default project"}), 400
        body = request.get_json(silent=True) or {}
        name = body.get("name", "").strip()
        if not name:
            return jsonify({"ok": False, "error": "Project name required"}), 400
        if len(name) > 200:
            return jsonify({"ok": False, "error": "Name too long (max 200 chars)"}), 400
        dup = Project.query.filter_by(user_id=session["user_id"], name=name).first()
        if dup and dup.id != pid:
            return jsonify({"ok": False, "error": "Project name already exists"}), 409
        proj.name = name
        db.session.commit()
        return jsonify({"ok": True})

    @app.route("/api/projects/<int:pid>", methods=["DELETE"])
    @login_required
    def api_projects_delete(pid):
        if request.args.get("confirm") != "true":
            return jsonify({"ok": False, "error": "Add ?confirm=true to delete"}), 400
        proj = _get_project_for_user(pid, "owner")
        if not proj:
            return jsonify({"ok": False, "error": "Project not found"}), 404
        if proj.name == "Default":
            return jsonify({"ok": False, "error": "Cannot delete the Default project"}), 400

        # Delete files on disk
        uid = str(session["user_id"])
        up_dir = os.path.join(config.UPLOADS_DIR, uid, str(pid))
        rp_dir = os.path.join(config.REPORTS_DIR, uid, str(pid))
        if os.path.isdir(up_dir):
            shutil.rmtree(up_dir, ignore_errors=True)
        if os.path.isdir(rp_dir):
            shutil.rmtree(rp_dir, ignore_errors=True)

        # SET NULL on scans (handled by FK ondelete, but be explicit)
        ScanHistory.query.filter_by(project_id=pid, user_id=session["user_id"]).update(
            {"project_id": None}
        )
        db.session.delete(proj)
        db.session.commit()
        return jsonify({"ok": True})

    # ── Project membership ───────────────────────────────────────

    @app.route("/api/projects/<int:pid>/members")
    @login_required
    def api_project_members_list(pid):
        proj = _get_project_for_user(pid)
        if not proj:
            return jsonify({"error": "Project not found"}), 404
        creator = db.session.get(User, proj.user_id)
        members = [{
            "user_id": proj.user_id,
            "username": creator.username if creator else "unknown",
            "role": "owner",
            "is_creator": True,
            "invited_by": None,
            "created_at": None,
        }]
        for m in ProjectMember.query.filter_by(project_id=pid).all():
            u = db.session.get(User, m.user_id)
            members.append({
                "user_id": m.user_id,
                "username": u.username if u else "unknown",
                "role": m.role,
                "is_creator": False,
                "invited_by": m.invited_by,
                "created_at": m.created_at.isoformat() if m.created_at else None,
            })
        return jsonify({"members": members})

    @app.route("/api/projects/<int:pid>/members", methods=["POST"])
    @login_required
    def api_project_members_add(pid):
        proj = _get_project_for_user(pid, "owner")
        if not proj:
            return jsonify({"error": "Project not found"}), 404
        body = request.get_json(silent=True) or {}
        username = (body.get("username") or "").strip()
        role = body.get("role", "viewer")
        if role not in _VALID_MEMBER_ROLES:
            return jsonify({"error": f"role must be one of: {sorted(_VALID_MEMBER_ROLES)}"}), 400
        target = User.query.filter_by(username=username).first()
        if not target:
            return jsonify({"error": "User not found"}), 404
        if target.id == proj.user_id:
            return jsonify({"error": "Project creator is already an owner"}), 409
        existing = ProjectMember.query.filter_by(project_id=pid, user_id=target.id).first()
        if existing:
            existing.role = role
        else:
            existing = ProjectMember(
                project_id=pid,
                user_id=target.id,
                role=role,
                invited_by=session["user_id"],
            )
            db.session.add(existing)
        db.session.commit()
        return jsonify({"ok": True, "user_id": target.id, "username": target.username, "role": role})

    @app.route("/api/projects/<int:pid>/members/<int:uid>", methods=["PUT"])
    @login_required
    def api_project_members_update(pid, uid):
        proj = _get_project_for_user(pid, "owner")
        if not proj:
            return jsonify({"error": "Project not found"}), 404
        if uid == proj.user_id:
            return jsonify({"error": "Cannot change the project creator's role"}), 400
        body = request.get_json(silent=True) or {}
        role = body.get("role")
        if role not in _VALID_MEMBER_ROLES:
            return jsonify({"error": f"role must be one of: {sorted(_VALID_MEMBER_ROLES)}"}), 400
        member = ProjectMember.query.filter_by(project_id=pid, user_id=uid).first()
        if not member:
            return jsonify({"error": "Member not found"}), 404
        member.role = role
        db.session.commit()
        return jsonify({"ok": True})

    @app.route("/api/projects/<int:pid>/members/<int:uid>", methods=["DELETE"])
    @login_required
    def api_project_members_remove(pid, uid):
        proj = _get_project_for_user(pid, "owner")
        if not proj:
            return jsonify({"error": "Project not found"}), 404
        if uid == proj.user_id:
            return jsonify({"error": "Cannot remove the project creator"}), 400
        member = ProjectMember.query.filter_by(project_id=pid, user_id=uid).first()
        if member:
            db.session.delete(member)
            db.session.commit()
        return jsonify({"ok": True})

    # ── Asset tags (Bet 2) ───────────────────────────────────────

    _VALID_CRITICALITIES = {"low", "medium", "high", "critical"}
    _VALID_NOTE_STATUSES = {"open", "resolved", "accepted", "false_positive"}
    _ASSET_KEY_RE = re.compile(r"[\x00-\x1f\x7f]")

    def _validate_asset_key(key: str):
        """Return error string if key is invalid, else None."""
        if not key or len(key) > 64:
            return "asset_key must be 1–64 characters"
        if _ASSET_KEY_RE.search(key):
            return "asset_key must not contain control characters"
        return None

    def _asset_tag_dict(tag: "AssetTag") -> dict:
        return {
            "id": tag.id,
            "project_id": tag.project_id,
            "asset_key": tag.asset_key,
            "owner": tag.owner,
            "criticality": tag.criticality,
            "zone": tag.zone,
            "business_function": tag.business_function,
            "free_text": tag.free_text,
            "updated_by": tag.updated_by,
            "created_at": tag.created_at.isoformat() if tag.created_at else None,
            "updated_at": tag.updated_at.isoformat() if tag.updated_at else None,
        }

    def _finding_note_dict(note: "FindingNote") -> dict:
        return {
            "id": note.id,
            "project_id": note.project_id,
            "report_filename": note.report_filename,
            "finding_signature": note.finding_signature,
            "status": note.status,
            "body": note.body,
            "author_id": note.author_id,
            "created_at": note.created_at.isoformat() if note.created_at else None,
            "updated_at": note.updated_at.isoformat() if note.updated_at else None,
        }

    @app.route("/api/projects/<int:pid>/asset-tags")
    @login_required
    def api_asset_tags_list(pid):
        proj = _get_project_for_user(pid)
        if not proj:
            return jsonify({"error": "Project not found"}), 404
        tags = AssetTag.query.filter_by(project_id=pid).order_by(AssetTag.asset_key).all()
        return jsonify({"asset_tags": [_asset_tag_dict(t) for t in tags]})

    @app.route("/api/projects/<int:pid>/asset-tags/<path:asset_key>", methods=["PUT"])
    @login_required
    def api_asset_tags_upsert(pid, asset_key):
        proj = _get_project_for_user(pid, "editor")
        if not proj:
            return jsonify({"error": "Project not found"}), 404
        err = _validate_asset_key(asset_key)
        if err:
            return jsonify({"error": err}), 400
        body = request.get_json(silent=True) or {}
        criticality = body.get("criticality")
        if criticality is not None and criticality not in _VALID_CRITICALITIES:
            return jsonify({"error": f"criticality must be one of {sorted(_VALID_CRITICALITIES)}"}), 400
        tag = AssetTag.query.filter_by(project_id=pid, asset_key=asset_key).first()
        now = datetime.utcnow()
        if tag is None:
            tag = AssetTag(
                project_id=pid,
                asset_key=asset_key,
                created_at=now,
            )
            db.session.add(tag)
        tag.owner = body.get("owner", tag.owner)
        tag.criticality = criticality if criticality is not None else tag.criticality
        tag.zone = body.get("zone", tag.zone)
        tag.business_function = body.get("business_function", tag.business_function)
        tag.free_text = body.get("free_text", tag.free_text)
        tag.updated_by = session["user_id"]
        tag.updated_at = now
        db.session.commit()
        return jsonify(_asset_tag_dict(tag))

    @app.route("/api/projects/<int:pid>/asset-tags/<path:asset_key>", methods=["DELETE"])
    @login_required
    def api_asset_tags_delete(pid, asset_key):
        proj = _get_project_for_user(pid, "editor")
        if not proj:
            return jsonify({"error": "Project not found"}), 404
        tag = AssetTag.query.filter_by(project_id=pid, asset_key=asset_key).first()
        if tag:
            db.session.delete(tag)
            db.session.commit()
        return "", 204

    # ── Finding notes (Bet 2) ────────────────────────────────────

    @app.route("/api/projects/<int:pid>/notes")
    @login_required
    def api_notes_list(pid):
        proj = _get_project_for_user(pid)
        if not proj:
            return jsonify({"error": "Project not found"}), 404
        q = FindingNote.query.filter_by(project_id=pid)
        report_filter = request.args.get("report")
        if report_filter:
            q = q.filter_by(report_filename=report_filter)
        notes = q.order_by(FindingNote.updated_at.desc()).all()
        return jsonify({"notes": [_finding_note_dict(n) for n in notes]})

    @app.route("/api/projects/<int:pid>/notes/<finding_signature>", methods=["PUT"])
    @login_required
    def api_notes_upsert(pid, finding_signature):
        proj = _get_project_for_user(pid, "editor")
        if not proj:
            return jsonify({"error": "Project not found"}), 404
        err = _validate_asset_key(finding_signature)  # same constraints: no control chars, ≤64
        if err:
            return jsonify({"error": f"finding_signature invalid: {err}"}), 400
        body = request.get_json(silent=True) or {}
        status = body.get("status", "open")
        if status not in _VALID_NOTE_STATUSES:
            return jsonify({"error": f"status must be one of {sorted(_VALID_NOTE_STATUSES)}"}), 400
        report_filename = body.get("report_filename", "")
        note = FindingNote.query.filter_by(
            project_id=pid, finding_signature=finding_signature
        ).first()
        now = datetime.utcnow()
        if note is None:
            note = FindingNote(
                project_id=pid,
                finding_signature=finding_signature,
                report_filename=report_filename,
                created_at=now,
            )
            db.session.add(note)
        if report_filename:
            note.report_filename = report_filename
        note.status = status
        note.body = body.get("body", note.body)
        note.author_id = session["user_id"]
        note.updated_at = now
        db.session.commit()
        return jsonify(_finding_note_dict(note))

    @app.route("/api/projects/<int:pid>/notes/<finding_signature>", methods=["DELETE"])
    @login_required
    def api_notes_delete(pid, finding_signature):
        proj = _get_project_for_user(pid, "editor")
        if not proj:
            return jsonify({"error": "Project not found"}), 404
        note = FindingNote.query.filter_by(
            project_id=pid, finding_signature=finding_signature
        ).first()
        if note:
            db.session.delete(note)
            db.session.commit()
        return "", 204

    @app.route("/api/projects/<int:pid>/files")
    @login_required
    def api_project_files(pid):
        proj = _get_project_for_user(pid)
        if not proj:
            return jsonify({"error": "Project not found"}), 404
        files = []
        udir = os.path.join(config.UPLOADS_DIR, str(proj.user_id), str(pid))
        if os.path.isdir(udir):
            for fn in os.listdir(udir):
                if not fn.lower().endswith((".pcap", ".pcapng", ".cap")):
                    continue
                path = os.path.join(udir, fn)
                try:
                    stat = os.stat(path)
                    files.append({
                        "name": fn,
                        "size": stat.st_size,
                        "modified": datetime.fromtimestamp(
                            stat.st_mtime, tz=timezone.utc
                        ).isoformat(),
                    })
                except Exception:
                    pass
        files.sort(key=lambda f: f["modified"], reverse=True)
        return jsonify({"files": files})

    @app.route("/api/projects/<int:pid>/reports")
    @login_required
    def api_project_reports(pid):
        proj = _get_project_for_user(pid)
        if not proj:
            return jsonify({"error": "Project not found"}), 404
        reports = []
        rdir = os.path.join(config.REPORTS_DIR, str(proj.user_id), str(pid))
        if os.path.isdir(rdir):
            for fn in os.listdir(rdir):
                if _is_primary_report_filename(fn):
                    path = os.path.join(rdir, fn)
                    try:
                        stat = os.stat(path)
                        reports.append({
                            "filename": fn,
                            "size": stat.st_size,
                            "modified": datetime.fromtimestamp(
                                stat.st_mtime, tz=timezone.utc
                            ).isoformat(),
                        })
                    except Exception:
                        pass
        reports.sort(key=lambda r: r["modified"], reverse=True)
        return jsonify({"reports": reports})

    @app.route("/projects/<int:pid>/assets/<path:asset_key>")
    @login_required
    def asset_baseline_page(pid, asset_key):
        proj = _get_project_for_user(pid)
        if not proj:
            return "Project not found", 404
        return render_template(
            "asset_baseline.html",
            pid=pid,
            project_name=proj.name,
            asset_key=asset_key,
        )

    @app.route("/api/projects/<int:pid>/assets/<path:asset_key>/baseline")
    @login_required
    def api_asset_baseline(pid, asset_key):
        proj = _get_project_for_user(pid)
        if not proj:
            return jsonify({"error": "Project not found"}), 404

        # Default cap so the page doesn't sit on "Loading…" for projects with hundreds of
        # reports — defenders mostly care about recent drift. Pass ?limit_reports= to widen.
        limit = request.args.get("limit_reports", type=int)
        if limit is None:
            limit = 30
        limit = max(1, min(500, limit))

        rdir = os.path.join(config.REPORTS_DIR, str(proj.user_id), str(pid))
        candidates: list[tuple[str, str]] = []  # (sort_key, path) — pre-sort by mtime descending
        if os.path.isdir(rdir):
            for fn in os.listdir(rdir):
                if not _is_primary_report_filename(fn):
                    continue
                path = os.path.join(rdir, fn)
                try:
                    mtime = os.path.getmtime(path)
                except OSError:
                    continue
                candidates.append((mtime, path, fn))
        # Take the newest *limit* by mtime (cheap proxy for capture order; we re-sort by
        # capture timestamp once loaded). This caps how many JSONs we open.
        candidates.sort(key=lambda c: c[0], reverse=True)
        candidates = candidates[:limit]

        loaded: list[dict] = []
        for _, path, fn in candidates:
            try:
                # Plain load — baselines only reads top-level fields; sidecar merge is wasted I/O.
                with open(path) as fh:
                    report = json.load(fh)
            except Exception:
                continue
            if not isinstance(report, dict):
                continue
            report["_report_filename"] = fn
            loaded.append(report)

        # Final sort oldest → newest by best-available capture timestamp.
        def _sort_key(r: dict) -> tuple[str, str]:
            ts = r.get("timestamp_start") or (r.get("capture_info") or {}).get("start_ts") or ""
            return (str(ts), str(r.get("_report_filename") or ""))

        loaded.sort(key=_sort_key)

        baseline = compute_asset_baseline(loaded, asset_key, limit_reports=None)
        if baseline is None:
            return jsonify({
                "error": "asset not found in any report in this project",
                "asset_key": asset_key,
                "scanned_reports": len(loaded),
                "limit_reports_applied": limit,
            }), 404
        baseline["limit_reports_applied"] = limit
        baseline["scanned_reports"] = len(loaded)
        return jsonify(baseline)

    @app.route("/api/projects/<int:pid>/aggregate")
    @login_required
    def api_project_aggregate(pid):
        proj = _get_project_for_user(pid)
        if not proj:
            return jsonify({"error": "Project not found"}), 404

        rdir = os.path.join(config.REPORTS_DIR, str(proj.user_id), str(pid))
        report_paths: list[str] = []
        report_meta: dict[str, dict] = {}
        if os.path.isdir(rdir):
            for fn in os.listdir(rdir):
                if not _is_primary_report_filename(fn):
                    continue
                path = os.path.join(rdir, fn)
                try:
                    stat = os.stat(path)
                except OSError:
                    continue
                report_paths.append(path)
                report_meta[path] = {
                    "filename": fn,
                    "modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                }

        # Backfill scan_profile from ScanHistory (matched by report filename basename).
        if report_paths:
            scans = ScanHistory.query.filter_by(
                user_id=session["user_id"], project_id=pid
            ).all()
            profile_by_basename: dict[str, str] = {}
            for s in scans:
                if s.report_path and s.scan_profile:
                    profile_by_basename[os.path.basename(s.report_path)] = s.scan_profile
            for path, meta in report_meta.items():
                if meta["filename"] in profile_by_basename:
                    meta["scan_profile"] = profile_by_basename[meta["filename"]]

        aggregate = aggregate_reports(
            report_paths,
            loader=_load_report_with_extensions,
            report_meta=report_meta,
        )
        aggregate["project"] = {
            "id": proj.id,
            "name": proj.name,
            "created_at": proj.created_at.isoformat() if proj.created_at else None,
        }
        return jsonify(aggregate)

    def _project_report_paths(pid: int, owner_uid: int) -> list[str]:
        """Return primary report.json paths for every report in this project."""
        rdir = os.path.join(config.REPORTS_DIR, str(owner_uid), str(pid))
        if not os.path.isdir(rdir):
            return []
        paths = []
        for fn in os.listdir(rdir):
            if not _is_primary_report_filename(fn):
                continue
            path = os.path.join(rdir, fn)
            if os.path.isfile(path):
                paths.append(path)
        return sorted(paths)

    @app.route("/api/projects/<int:pid>/ocsf")
    @login_required
    def api_project_ocsf(pid):
        """Concatenate every report's OCSF NDJSON in the project into one stream.

        Each report's sibling ``.ocsf.ndjson`` is preferred when present;
        on-the-fly application-layer rendering happens otherwise.
        """
        proj = _get_project_for_user(pid)
        if not proj:
            return jsonify({"error": "Project not found"}), 404
        from marlinspike.emit import ocsf as _ocsf_emit
        from flask import Response
        paths = _project_report_paths(pid, proj.user_id)
        if not paths:
            return jsonify({"error": "No reports in project"}), 404

        def stream():
            for json_path in paths:
                ocsf_path = json_path.replace(".json", ".ocsf.ndjson")
                if os.path.isfile(ocsf_path):
                    with open(ocsf_path) as f:
                        chunk = f.read()
                    if chunk:
                        yield chunk if chunk.endswith("\n") else (chunk + "\n")
                    continue
                try:
                    with open(json_path) as f:
                        report = json.load(f)
                    chunk = _ocsf_emit.render_ndjson(report)
                except Exception as exc:
                    log.warning("project OCSF chunk skipped %s: %s", json_path, exc)
                    continue
                if chunk:
                    yield chunk + "\n"

        return Response(
            stream(),
            mimetype="application/x-ndjson",
            headers={
                "Content-Disposition": f'attachment; filename="{proj.name}.ocsf.ndjson"',
            },
        )

    @app.route("/api/projects/<int:pid>/navigator")
    @login_required
    def api_project_navigator(pid):
        """Merge per-domain Navigator layers across every report in the project.

        Per technique, the highest score across all reports wins. Comments
        + metadata are union-merged with the report filename appended so
        defenders can see which capture(s) drove each technique.
        """
        proj = _get_project_for_user(pid)
        if not proj:
            return jsonify({"error": "Project not found"}), 404
        domain = request.args.get("domain", "ics-attack").lower()
        from marlinspike.emit import navigator as _nav_emit
        from flask import Response
        paths = _project_report_paths(pid, proj.user_id)
        if not paths:
            return jsonify({"error": "No reports in project"}), 404

        merged: dict[str, dict] = {}
        layer_template = None
        attack_version = None
        for json_path in paths:
            try:
                with open(json_path) as f:
                    report = json.load(f)
            except Exception:
                continue
            layer = _nav_emit.render_layer_for_domain(report, domain)
            if layer is None:
                continue
            if layer_template is None:
                layer_template = layer  # remember versions / gradient / legend
                attack_version = layer.get("versions", {}).get("attack")
            for tech in layer.get("techniques") or []:
                tid = tech.get("techniqueID")
                if not tid:
                    continue
                existing = merged.get(tid)
                if existing is None or (tech.get("score", 0) > existing.get("score", 0)):
                    merged[tid] = dict(tech)  # copy
                # Annotate with report filename (best-effort)
                fname = os.path.basename(json_path)
                comment = merged[tid].get("comment", "")
                if fname and fname not in comment:
                    merged[tid]["comment"] = (comment + f"\n\nseen in: {fname}").strip()
        if not merged or layer_template is None:
            return jsonify({"error": f"No {domain} techniques across project reports"}), 404
        out = {
            "name": f"MarlinSpike — project '{proj.name}' — {domain}",
            "versions": layer_template["versions"],
            "domain": domain,
            "description": (
                f"Aggregated ATT&CK technique coverage across {len(paths)} report(s) "
                f"in project '{proj.name}'. Per technique, the highest score across "
                f"all reports wins."
            ),
            "filters": {"platforms": []},
            "sorting": 3,
            "layout": layer_template.get("layout"),
            "hideDisabled": False,
            "techniques": sorted(merged.values(), key=lambda t: -t.get("score", 0)),
            "gradient": layer_template["gradient"],
            "legendItems": layer_template.get("legendItems"),
            "metadata": [
                {"name": "project", "value": proj.name},
                {"name": "report_count", "value": str(len(paths))},
                {"name": "produced_by", "value": "MarlinSpike"},
            ],
        }
        return Response(
            json.dumps(out, indent=2),
            mimetype="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="{proj.name}.navigator.{("ics" if domain == "ics-attack" else "enterprise")}.json"',
            },
        )

    @app.route("/api/projects/<int:pid>/stix")
    @login_required
    def api_project_stix(pid):
        """Merge every report's STIX bundle into one project-level bundle.

        Identity object is deduplicated; all other objects are
        concatenated. Stable IDs mean the same finding across reports
        appears once.
        """
        proj = _get_project_for_user(pid)
        if not proj:
            return jsonify({"error": "Project not found"}), 404
        from marlinspike.emit import stix as _stix_emit
        paths = _project_report_paths(pid, proj.user_id)
        if not paths:
            return jsonify({"error": "No reports in project"}), 404

        all_objects: dict[str, dict] = {}  # by stix id, dedupe
        for json_path in paths:
            try:
                with open(json_path) as f:
                    report = json.load(f)
            except Exception:
                continue
            bundle = _stix_emit.render_bundle(report)
            for obj in bundle.get("objects") or []:
                oid = obj.get("id")
                if oid and oid not in all_objects:
                    all_objects[oid] = obj

        if not all_objects:
            return jsonify({"error": "No STIX objects across project reports"}), 404

        merged_bundle = {
            "type": "bundle",
            "id": _stix_emit._stable_id("bundle", f"project:{pid}:{proj.name}"),
            "objects": list(all_objects.values()),
        }
        from flask import Response
        return Response(
            json.dumps(merged_bundle, indent=2),
            mimetype="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="{proj.name}.stix.json"',
            },
        )

    @app.route("/api/projects/<int:pid>/sigma")
    @login_required
    def api_project_sigma(pid):
        """Concatenate every report's Sigma rules into one multi-document YAML stream.

        Rules are deduplicated by their stable ``id`` field — same finding
        across reports appears once in the output.
        """
        proj = _get_project_for_user(pid)
        if not proj:
            return jsonify({"error": "Project not found"}), 404
        from marlinspike.emit import sigma as _sigma_emit
        from flask import Response
        paths = _project_report_paths(pid, proj.user_id)
        if not paths:
            return jsonify({"error": "No reports in project"}), 404

        seen_ids: set[str] = set()
        rules_yaml: list[str] = []
        for json_path in paths:
            try:
                with open(json_path) as f:
                    report = json.load(f)
            except Exception:
                continue
            for filename, rule in _sigma_emit.render_rules(report):
                rid = rule.get("id")
                if not rid or rid in seen_ids:
                    continue
                seen_ids.add(rid)
                rules_yaml.append(_sigma_emit._yaml_dump(rule))

        if not rules_yaml:
            return jsonify({"error": "No Sigma-emittable findings across project reports"}), 404

        body = "\n---\n".join(rules_yaml) + "\n"
        return Response(
            body,
            mimetype="application/x-yaml",
            headers={
                "Content-Disposition": f'attachment; filename="{proj.name}.sigma.yml"',
            },
        )

    @app.route("/api/projects/<int:pid>/upload", methods=["POST"])
    @login_required
    @limiter.limit("10 per minute")
    def api_project_upload(pid):
        proj = _get_project_for_user(pid, "editor")
        if not proj:
            return jsonify({"ok": False, "error": "Project not found"}), 404
        return _handle_upload(pid)

    @app.route("/api/projects/<int:pid>/files/<filename>", methods=["DELETE"])
    @login_required
    def api_project_file_delete(pid, filename):
        proj = _get_project_for_user(pid, "editor")
        if not proj:
            return jsonify({"ok": False, "error": "Project not found"}), 404
        safe_name = os.path.basename(filename)
        path = os.path.join(config.UPLOADS_DIR, str(proj.user_id), str(pid), safe_name)
        if os.path.isfile(path):
            os.unlink(path)
        return jsonify({"ok": True})

    # ── Upload pipeline (shared logic) ───────────────────────

    def _handle_upload(project_id=None):
        """Core upload handler with magic-byte validation, size limits, auto-slice, and archival."""
        if "file" not in request.files:
            return jsonify({"ok": False, "error": "No file part"}), 400
        f = request.files["file"]
        if not f.filename:
            return jsonify({"ok": False, "error": "No file selected"}), 400

        # Per-user upload limit (falls back to global default)
        _uploader = User.query.get(session["user_id"])
        _limit_mb = (_uploader.upload_limit_mb if _uploader and _uploader.upload_limit_mb else 200)
        user_max_size = _limit_mb * 1024 * 1024

        # Check content length hint
        content_length = request.content_length or 0
        if content_length > user_max_size:
            return jsonify({
                "ok": False,
                "error": f"File too large (max {_limit_mb} MB)",
            }), 413

        safe_name = os.path.basename(f.filename)

        # Resolve project
        if project_id is None:
            project_id_str = request.form.get("project_id", "")
            if project_id_str:
                try:
                    project_id = int(project_id_str)
                    proj = Project.query.filter_by(id=project_id, user_id=session["user_id"]).first()
                    if not proj:
                        return jsonify({"ok": False, "error": "Project not found"}), 404
                except (ValueError, TypeError):
                    project_id = None

        if project_id is None:
            default = _ensure_default_project(session["user_id"])
            project_id = default.id

        dest_dir = user_uploads_dir(project_id)

        # Stream to temp file with magic-byte check and size enforcement
        import tempfile
        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".pcap", dir=dest_dir)
        written = 0
        magic_checked = False
        try:
            with os.fdopen(tmp_fd, "wb") as out:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    # Check magic bytes after first chunk
                    if not magic_checked:
                        if len(chunk) < 4:
                            # Read more to get at least 4 bytes
                            chunk += f.read(4 - len(chunk))
                        if len(chunk) < 4 or chunk[:4] not in PCAP_MAGIC:
                            os.unlink(tmp_path)
                            return jsonify({
                                "ok": False,
                                "error": "Not a valid PCAP file",
                            }), 400
                        magic_checked = True

                    written += len(chunk)
                    if written > user_max_size:
                        os.unlink(tmp_path)
                        return jsonify({
                            "ok": False,
                            "error": f"File too large (max {_limit_mb} MB)",
                        }), 413
                    out.write(chunk)
        except Exception:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise

        if written == 0:
            os.unlink(tmp_path)
            return jsonify({"ok": False, "error": "Empty file"}), 400

        # Save the full PCAP — no auto-slice (chunked pipeline handles large files)
        user_id = session["user_id"]
        username = session.get("user", "unknown")
        final_path = os.path.join(dest_dir, safe_name)
        os.rename(tmp_path, final_path)

        # Background archive (TOS compliance)
        threading.Thread(
            target=_archive_submission,
            args=(final_path, user_id, username, safe_name),
            daemon=True,
            name="archive-submission",
        ).start()

        log.info("Upload: %s by %s (%d bytes)", safe_name, session.get("user", "?"), written)
        return jsonify({
            "ok": True,
            "filename": safe_name,
            "size": written,
            "project_id": project_id,
        })

    # ── Scan start ───────────────────────────────────────────

    @app.route("/api/scans/start", methods=["POST"])
    @login_required
    @limiter.limit("10 per minute")
    def api_scan_start():
        body = request.get_json(silent=True) or {}
        command = _normalize_scan_command(body.get("command", "chain"))
        # Accept pcap_file (bare filename) with pcap_path backward compat
        pcap_file = body.get("pcap_file", "") or body.get("pcap_path", "")
        skip_ephemeral = body.get("skip_ephemeral", False)
        capture_filter = body.get("capture_filter", "")
        chunk_size = body.get("chunk_size", 300000)
        collapse_threshold = body.get("collapse_threshold", 50)
        scan_profile = _normalize_scan_profile(body.get("scan_profile", body.get("profile", "full")))
        project_id = body.get("project_id")

        # Resolve project
        if project_id is not None:
            try:
                project_id = int(project_id)
                proj = Project.query.filter_by(id=project_id, user_id=session["user_id"]).first()
                if not proj:
                    return jsonify({"ok": False, "error": "Project not found"}), 404
            except (ValueError, TypeError):
                project_id = None

        if project_id is None:
            default = _ensure_default_project(session["user_id"])
            project_id = default.id

        # Resolve pcap_file to full path
        pcap_path = ""
        if pcap_file:
            if pcap_file.startswith("preset:"):
                # Preset file — resolve from presets directory (category/filename)
                preset_rel = pcap_file[7:]
                try:
                    presets_root = Path(config.PRESETS_DIR).resolve()
                    requested = (presets_root / preset_rel).resolve()
                    if not str(requested).startswith(str(presets_root) + os.sep) and requested != presets_root:
                        return jsonify({"ok": False, "error": "Invalid preset"}), 400
                    pcap_path = str(requested)
                except (ValueError, OSError):
                    return jsonify({"ok": False, "error": "Invalid preset"}), 400
            else:
                # User file — resolve from uploads directory
                pcap_path = os.path.join(user_uploads_dir(project_id), os.path.basename(pcap_file))
                # Fallback: search presets subdirs for bare filename (retry support)
                if not os.path.isfile(pcap_path) and os.path.isdir(config.PRESETS_DIR):
                    bare = os.path.basename(pcap_file)
                    presets_root = Path(config.PRESETS_DIR).resolve()
                    for cat in os.listdir(config.PRESETS_DIR):
                        candidate = (presets_root / cat / bare).resolve()
                        if str(candidate).startswith(str(presets_root) + os.sep) and candidate.is_file():
                            pcap_path = str(candidate)
                            break
            if not os.path.isfile(pcap_path):
                return jsonify({"ok": False, "error": "File not found"}), 404

        with _runs_lock:
            active_count, scan_limit = _resolve_concurrency(session.get("user_id"))
            if active_count >= scan_limit:
                # The active_run_ids list still reflects the GLOBAL set so the
                # admin diagnostic surface is unchanged.
                return jsonify({
                    "ok": False,
                    "error": f"Maximum {scan_limit} concurrent scans reached",
                    "active_run_ids": [r[0] for r in _get_active_runs()],
                }), 409
            _cleanup_runs()

        if not pcap_path:
            return jsonify({"ok": False, "error": "PCAP file required"}), 400

        run_id = str(uuid.uuid4())
        # Prefix report with original PCAP filename (sanitised)
        pcap_stem = os.path.splitext(os.path.basename(pcap_path))[0]
        pcap_stem = re.sub(r'[^a-zA-Z0-9._-]', '_', pcap_stem)[:60]
        prefix = f"{pcap_stem}-" if pcap_stem else ""
        report_filename = f"{prefix}marlinspike-{run_id[:8]}.json"
        report_path = os.path.join(user_reports_dir(project_id), report_filename)

        chunk_val = 0
        try:
            chunk_val = max(0, int(chunk_size))
        except (ValueError, TypeError):
            chunk_val = 0

        collapse_val = 50
        try:
            collapse_val = int(collapse_threshold)
        except (ValueError, TypeError):
            collapse_val = 50

        pcap_size = os.path.getsize(pcap_path) if os.path.isfile(pcap_path) else 0
        use_chunked_chain = bool(
            command == "chain"
            and chunk_val > 0
            and pcap_size > config.PCAP_PROCESS_SIZE
        )

        # Build CLI args
        args = list(config.MARLINSPIKE_ENGINE_CMD)
        args.extend(["--pcap", pcap_path])
        if config.MARLINSPIKE_DPI_ENGINE:
            args.extend(["--dpi-engine", config.MARLINSPIKE_DPI_ENGINE])
        if config.MARLINSPIKE_DPI_BIN:
            args.extend(["--dpi-binary", config.MARLINSPIKE_DPI_BIN])
        if skip_ephemeral:
            args.append("--skip-ephemeral")
        if capture_filter:
            args.extend(["--capture-filter", capture_filter])
        if scan_profile == "fast":
            args.append("--fast")
        if chunk_val > 0 and not use_chunked_chain:
            args.extend(["--chunk-size", str(chunk_val)])
        if collapse_val > 0:
            args.extend(["--collapse-threshold", str(collapse_val)])
        else:
            args.extend(["--collapse-threshold", "0"])
        args.append("--no-grassmarlin")
        args.extend(["-o", report_path])
        args.append(command)

        # MarlinSpike chain stages
        chain_stages = _scan_stage_names(command)
        if command == "chain" and config.MARLINSPIKE_MITRE_ENABLED:
            chain_stages.append("ATT&CK")
        stages = []
        for i, stage_name in enumerate(chain_stages):
            stages.append({
                "number": i + 1,
                "name": stage_name,
                "state": "pending",
            })

        proc = None
        if not use_chunked_chain:
            try:
                proc = subprocess.Popen(
                    args,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    cwd=config.REPORTS_DIR,
                )
            except Exception as e:
                log.error("Failed to start scan: %s", e)
                return jsonify({"ok": False, "error": "Failed to start scan"}), 500

        # Compute PCAP hash
        pcap_hash = None
        pcap_source = os.path.basename(pcap_path)
        if os.path.isfile(pcap_path):
            try:
                h = hashlib.sha256()
                with open(pcap_path, "rb") as pf:
                    for chunk in iter(lambda: pf.read(65536), b""):
                        h.update(chunk)
                pcap_hash = h.hexdigest()
            except Exception:
                pass

        log.info(
            "Scan start: %s by %s (command=%s, file=%s, mode=%s)",
            run_id,
            session.get("user", "?"),
            command,
            pcap_source or "live",
            "chunked" if use_chunked_chain else "single",
        )

        run_state = {
            "process": proc,
            "output": [],
            "status": "running",
            "stage": 0,
            "stage_name": "",
            "stages": stages,
            "command": command,
            "scan_profile": scan_profile,
            "report_path": report_path,
            "report_filename": report_filename,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "finished_at": None,
            "return_code": None,
            "artifacts_produced": {},
            "project_id": project_id,
            "user_id": session.get("user_id"),
            "stop_requested": False,
            "pcap_path": pcap_path,
            "pcap_size": pcap_size,
            "chunk_size": chunk_val,
            "collapse_threshold": collapse_val,
            "chunked": use_chunked_chain,
        }

        with _runs_lock:
            _run_registry[run_id] = run_state

        # Persist to scan_history with recovery essentials (engine_pid,
        # engine_argv, timeout_at). For chunked scans, proc is None here;
        # the chunked supervisor calls run_store.update_pid as it spawns
        # each child so recovery sees the currently-running subprocess.
        from marlinspike import run_store as _run_store
        _run_store.record_start(
            run_id,
            user_id=session["user_id"],
            project_id=project_id,
            command=command,
            scan_profile=scan_profile,
            pcap_source=pcap_source,
            pcap_hash=pcap_hash,
            pcap_path=pcap_path,
            report_path=report_path,
            engine_pid=(proc.pid if proc is not None else None),
            engine_argv=args,
        )

        def _reader():
            for line in proc.stdout:
                line = line.rstrip()
                run_state["output"].append(line)
                _apply_stage_marker(run_state, line)
                if _error_re.search(line):
                    _mark_active_stage(run_state, "failed")
            proc.wait()
            run_state["return_code"] = proc.returncode
            _finalize_run(app, run_id, run_state, report_path)

        def _chunked_reader():
            chunk_dir = ""
            merged_path = ""
            chunk_reports = []

            def _run_child(child_args, cwd=None, prefix="", stage_map=None):
                child = subprocess.Popen(
                    child_args,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    cwd=cwd or config.REPORTS_DIR,
                )
                run_state["process"] = child
                # Surface the currently-running child's PID + argv to
                # scan_history so the recovery reaper finds the right
                # process if Flask dies mid-chunk.
                try:
                    from marlinspike import run_store as _run_store
                    with app.app_context():
                        _run_store.update_pid(run_id, child.pid, child_args)
                except Exception:
                    pass
                try:
                    for raw_line in child.stdout:
                        raw_line = raw_line.rstrip()
                        display_line = f"{prefix}{raw_line}" if prefix else raw_line
                        run_state["output"].append(display_line)
                        if stage_map is not None:
                            _apply_stage_marker(run_state, raw_line, stage_map=stage_map)
                        if _error_re.search(raw_line):
                            _mark_active_stage(run_state, "failed")
                    child.wait()
                    return child.returncode
                finally:
                    run_state["process"] = None

            try:
                temp_root = os.path.join(tempfile.gettempdir(), "ms-chunks")
                os.makedirs(temp_root, exist_ok=True)
                chunk_dir = tempfile.mkdtemp(prefix=f"{run_id[:8]}-", dir=temp_root)

                run_state["output"].append("[*] Large capture detected — using chunked chain pipeline")
                _set_run_stage(run_state, 1, "Ingest")
                run_state["output"].append(
                    f"[*] Splitting {os.path.basename(pcap_path)} into chunks of {chunk_val:,} packets"
                )

                split_args = [
                    "editcap",
                    "-c",
                    str(chunk_val),
                    pcap_path,
                    os.path.join(chunk_dir, "chunk.pcap"),
                ]
                split_rc = _run_child(split_args, cwd=chunk_dir)
                if run_state["stop_requested"]:
                    run_state["return_code"] = -15
                    return
                if split_rc != 0:
                    run_state["output"].append(f"[!] FAILED: editcap split failed (rc={split_rc})")
                    run_state["return_code"] = split_rc
                    return

                chunk_files = sorted(
                    name for name in os.listdir(chunk_dir)
                    if name.startswith("chunk") and (name.endswith(".pcap") or name.endswith(".pcapng"))
                )
                if not chunk_files:
                    run_state["output"].append("[!] FAILED: chunk split produced no chunk files")
                    run_state["return_code"] = 1
                    return

                total_chunks = len(chunk_files)
                run_state["output"].append(f"[*] Split into {total_chunks} chunks")
                _set_run_stage(run_state, 2, f"Analyze (1/{total_chunks})")

                for idx, chunk_file in enumerate(chunk_files, start=1):
                    if run_state["stop_requested"]:
                        run_state["return_code"] = -15
                        return
                    chunk_path = os.path.join(chunk_dir, chunk_file)
                    chunk_report = os.path.join(chunk_dir, f"chunk-dissect-{idx:05d}.json")
                    chunk_reports.append(chunk_report)
                    run_state["stage_name"] = f"Analyze ({idx}/{total_chunks})"
                    run_state["output"].append(f"[*] Dissecting chunk {idx}/{total_chunks}: {chunk_file}")

                    dissect_args = list(config.MARLINSPIKE_ENGINE_CMD) + [
                        "--pcap",
                        chunk_path,
                        "--no-grassmarlin",
                        "-o",
                        chunk_report,
                    ]
                    if config.MARLINSPIKE_DPI_ENGINE:
                        dissect_args.extend(["--dpi-engine", config.MARLINSPIKE_DPI_ENGINE])
                    if config.MARLINSPIKE_DPI_BIN:
                        dissect_args.extend(["--dpi-binary", config.MARLINSPIKE_DPI_BIN])
                    if scan_profile == "fast":
                        dissect_args.append("--fast")
                    if collapse_val > 0:
                        dissect_args.extend(["--collapse-threshold", str(collapse_val)])
                    else:
                        dissect_args.extend(["--collapse-threshold", "0"])
                    dissect_args.append("dissect")

                    dissect_rc = _run_child(
                        dissect_args,
                        prefix=f"[chunk {idx}/{total_chunks}] ",
                    )
                    if run_state["stop_requested"]:
                        run_state["return_code"] = -15
                        return
                    if dissect_rc != 0:
                        run_state["output"].append(
                            f"[!] FAILED: chunk {idx}/{total_chunks} dissection failed (rc={dissect_rc})"
                        )
                        run_state["return_code"] = dissect_rc
                        return
                    if not os.path.isfile(chunk_report):
                        run_state["output"].append(
                            f"[!] FAILED: chunk {idx}/{total_chunks} produced no dissect report"
                        )
                        run_state["return_code"] = 1
                        return
                    try:
                        os.unlink(chunk_path)
                    except OSError:
                        pass

                if run_state["stop_requested"]:
                    run_state["return_code"] = -15
                    return

                run_state["stage_name"] = "Analyze (merge)"
                run_state["output"].append("[*] Merging conversations from chunk reports")
                merged_conversations, merged_capture_info = _merge_chunk_conversations(
                    chunk_reports,
                    capture_info_seed={
                        "pcap_path": pcap_path,
                        "capture_source": os.path.basename(pcap_path),
                        "total_bytes": pcap_size,
                    },
                )
                run_state["output"].append(
                    f"[*] Merged {len(merged_conversations):,} unique conversations"
                )
                merged_path = os.path.join(chunk_dir, "merged-conversations.json")
                with open(merged_path, "w") as handle:
                    json.dump(
                        {
                            "conversations": merged_conversations,
                            "capture_info": merged_capture_info,
                        },
                        handle,
                        indent=2,
                        default=str,
                    )

                if run_state["stop_requested"]:
                    run_state["return_code"] = -15
                    return

                run_state["output"].append("[*] Running topology + risk from merged conversations")
                chain_args = list(config.MARLINSPIKE_ENGINE_CMD) + [
                    "--conversations",
                    merged_path,
                    "--no-grassmarlin",
                    "-o",
                    report_path,
                ]
                if skip_ephemeral:
                    chain_args.append("--skip-ephemeral")
                if scan_profile == "fast":
                    chain_args.append("--fast")
                chain_args.append("chain-from-conversations")

                run_state["return_code"] = _run_child(
                    chain_args,
                    stage_map={3: 3, 4: 4},
                )
            except FileNotFoundError as exc:
                run_state["output"].append(f"[!] FAILED: required tool missing: {exc}")
                run_state["return_code"] = 127
            except Exception as exc:
                log.exception("Chunked scan %s failed", run_id)
                run_state["output"].append(f"[!] FAILED: chunked pipeline error: {exc}")
                run_state["return_code"] = 1
            finally:
                if chunk_dir:
                    shutil.rmtree(chunk_dir, ignore_errors=True)
                _finalize_run(app, run_id, run_state, report_path)

        worker = _chunked_reader if use_chunked_chain else _reader
        threading.Thread(target=worker, daemon=True, name=f"ms-run-{run_id[:8]}").start()

        return jsonify({"ok": True, "run_id": run_id})

    # ── Run status/output/stop/list ──────────────────────────

    @app.route("/api/runs")
    @login_required
    def api_runs_list():
        with _runs_lock:
            _cleanup_runs()
            active = []
            recent = []
            for run_id, run in _run_registry.items():
                entry = {
                    "run_id": run_id,
                    "command": run["command"],
                    "scan_profile": run.get("scan_profile", "full"),
                    "status": run["status"],
                    "stage": run["stage"],
                    "stage_name": run["stage_name"],
                    "stages": run.get("stages", []),
                    "started_at": run["started_at"],
                    "finished_at": run["finished_at"],
                    "output_lines": len(run["output"]),
                    "report_filename": run["report_filename"],
                }
                if run["status"] in ("pending", "running"):
                    active.append(entry)
                else:
                    recent.append(entry)
        return jsonify({"active": active, "recent": recent})

    @app.route("/api/runs/<run_id>/status")
    @login_required
    def api_run_status(run_id):
        with _runs_lock:
            run = _run_registry.get(run_id)
        # Fall back to ScanHistory when the run isn't in the in-memory
        # registry — typically after Flask restart where the engine was
        # re-attached but the live state is gone.
        if not run:
            from marlinspike import run_store as _run_store
            durable = _run_store.get(run_id)
            if not durable:
                return jsonify({"error": "Run not found"}), 404
            return jsonify({
                "run_id": run_id,
                "status": durable["status"],
                "stage": 0,
                "stage_name": "",
                "stages": [],
                "command": durable["command"],
                "scan_profile": durable["scan_profile"],
                "started_at": durable["started_at"],
                "finished_at": durable["finished_at"],
                "return_code": None,
                "output_lines": 0,
                "report_filename": os.path.basename(durable["report_path"] or ""),
                "project_id": durable["project_id"],
                "artifacts_produced": {},
                "recovered": True,
                "recovery_state": durable["recovery_state"],
            })
        artifacts = {
            str(key): os.path.basename(str(path))
            for key, path in (run.get("artifacts_produced", {}) or {}).items()
            if path
        }
        return jsonify({
            "run_id": run_id,
            "status": run["status"],
            "stage": run["stage"],
            "stage_name": run["stage_name"],
            "stages": run.get("stages", []),
            "command": run["command"],
            "scan_profile": run.get("scan_profile", "full"),
            "started_at": run["started_at"],
            "finished_at": run["finished_at"],
            "return_code": run["return_code"],
            "output_lines": len(run["output"]),
            "report_filename": run["report_filename"],
            "project_id": run.get("project_id"),
            "artifacts_produced": artifacts,
        })

    @app.route("/api/runs/<run_id>/output")
    @login_required
    def api_run_output(run_id):
        with _runs_lock:
            run = _run_registry.get(run_id)
        if not run:
            return jsonify({"error": "Run not found"}), 404
        from_idx = request.args.get("from", None, type=int)
        if from_idx is None:
            from_idx = request.args.get("since", 0, type=int)
        raw_lines = run["output"][from_idx:]
        total = len(run["output"])
        # Sanitize output — strip paths, tool names, internal details
        sanitized = []
        for line in raw_lines:
            line = re.sub(r"/[\w/.-]+/([^/\s]+)", r"\1", line)  # strip directory paths
            line = re.sub(r"\btshark\b", "analyzer", line, flags=re.IGNORECASE)
            line = re.sub(r"\bcapinfos?\b", "analyzer", line, flags=re.IGNORECASE)
            line = re.sub(r"\beditcap\b", "preprocessor", line, flags=re.IGNORECASE)
            sanitized.append(line)
        return jsonify({
            "lines": sanitized,
            "next_from": total,
            "total": total,
            "status": run["status"],
        })

    @app.route("/api/runs/<run_id>/stop", methods=["POST"])
    @login_required
    def api_run_stop(run_id):
        with _runs_lock:
            run = _run_registry.get(run_id)
        if not run:
            return jsonify({"error": "Run not found"}), 404
        run["stop_requested"] = True
        proc = run.get("process")
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                proc.kill()
        if run["status"] in ("pending", "running"):
            _mark_active_stage(run, "stopped")
            run["stage_name"] = "Stopping"
        return jsonify({"ok": True})

    # ── Run topology + live viewer ───────────────────────────

    @app.route("/api/runs/<run_id>/topology")
    @login_required
    def api_run_topology(run_id):
        with _runs_lock:
            run = _run_registry.get(run_id)
        if not run:
            return jsonify({"error": "Run not found"}), 404
        report_path = run.get("report_path", "")
        if not os.path.isfile(report_path):
            return jsonify({
                "status": run["status"],
                "stage": run["stage"],
                "report_filename": run.get("report_filename", ""),
                "topology": {"nodes": [], "edges": []},
                "has_data": False,
            })
        try:
            with open(report_path) as f:
                report = json.load(f)
            topo = report.get("topology", {})
            nodes = topo.get("nodes", report.get("nodes", []))
            edges = topo.get("edges", report.get("edges", []))
            return jsonify({
                "status": run["status"],
                "stage": run["stage"],
                "stage_name": run["stage_name"],
                "stages": run.get("stages", []),
                "report_filename": run.get("report_filename", ""),
                "capture_info": report.get("capture_info"),
                "protocol_summary": report.get("protocol_summary", {}),
                "risk_findings": report.get("risk_findings", []),
                "topology": {"nodes": nodes, "edges": edges},
                "node_count": len(nodes),
                "edge_count": len(edges),
                "has_data": len(nodes) > 0,
                "completed_stages": report.get("completed_stages", []),
            })
        except Exception as e:
            log.error("Failed to read report: %s", e)
            return jsonify({"error": "Failed to read report"}), 500

    @app.route("/api/runs/<run_id>/live")
    @login_required
    def api_run_live_viewer(run_id):
        with _runs_lock:
            run = _run_registry.get(run_id)
        if not run:
            # Fall back to durable store — covers re-attached / reaped runs
            # whose in-memory state was lost across a Flask restart.
            from marlinspike import run_store as _run_store
            durable = _run_store.get(run_id)
            if not durable:
                return "Run not found", 404
            return render_template(
                "scan_progress.html",
                run_id=run_id,
                recovered=True,
                recovery_state=durable.get("recovery_state") or "",
            )
        return render_template(
            "scan_progress.html",
            run_id=run_id,
            recovered=False,
            recovery_state="",
        )

    # ── Reports ──────────────────────────────────────────────

    @app.route("/api/reports")
    @login_required
    def api_reports_list():
        project_id = request.args.get("project_id", None, type=int)
        limit = request.args.get("limit", None, type=int)
        reports = []
        rdir = user_reports_dir(project_id)
        if os.path.isdir(rdir):
            for fn in os.listdir(rdir):
                if _is_primary_report_filename(fn):
                    path = os.path.join(rdir, fn)
                    try:
                        stat = os.stat(path)
                        size = stat.st_size
                        mtime_ts = stat.st_mtime
                        mtime = datetime.fromtimestamp(
                            mtime_ts, tz=timezone.utc
                        ).isoformat()
                    except Exception:
                        size = 0
                        mtime_ts = 0
                        mtime = ""
                    reports.append({"filename": fn, "size": size, "modified": mtime, "_sort": mtime_ts})
            reports.sort(key=lambda r: r.pop("_sort"), reverse=True)
        total = len(reports)
        if limit and limit > 0:
            reports = reports[:limit]
        return jsonify({"reports": reports, "total": total})

    @app.route("/api/reports/diff")
    @login_required
    def api_report_diff():
        a_name = os.path.basename(request.args.get("a", ""))
        b_name = os.path.basename(request.args.get("b", ""))
        project_id = request.args.get("project_id", None, type=int)
        if not a_name or not b_name:
            return "Missing ?a= and ?b= parameters", 400
        rdir = user_reports_dir(project_id)
        a_path = os.path.join(rdir, a_name)
        b_path = os.path.join(rdir, b_name)
        if not os.path.isfile(a_path):
            return f"Report A not found: {a_name}", 404
        if not os.path.isfile(b_path):
            return f"Report B not found: {b_name}", 404

        with open(a_path) as f:
            report_a = json.load(f)
        with open(b_path) as f:
            report_b = json.load(f)

        topo_a = report_a.get("results", {}).get("topology", report_a.get("topology", {}))
        topo_b = report_b.get("results", {}).get("topology", report_b.get("topology", {}))
        nodes_a = {n["ip"]: n for n in topo_a.get("nodes", []) if n.get("ip")}
        nodes_b = {n["ip"]: n for n in topo_b.get("nodes", []) if n.get("ip")}
        edges_a = topo_a.get("edges", [])
        edges_b = topo_b.get("edges", [])

        # Node diff
        all_ips = set(nodes_a.keys()) | set(nodes_b.keys())
        node_diffs = []
        for ip in sorted(all_ips):
            a_node = nodes_a.get(ip)
            b_node = nodes_b.get(ip)
            if a_node and not b_node:
                node_diffs.append({"ip": ip, "diff": "removed", "a": a_node, "b": None, "changes": []})
            elif b_node and not a_node:
                node_diffs.append({"ip": ip, "diff": "added", "a": None, "b": b_node, "changes": []})
            else:
                changes = []
                for field in ("role", "vendor", "purdue_level"):
                    va = a_node.get(field)
                    vb = b_node.get(field)
                    if va != vb:
                        changes.append({"field": field, "from": va, "to": vb})
                pa = set(a_node.get("protocols", []))
                pb = set(b_node.get("protocols", []))
                if pa != pb:
                    changes.append({
                        "field": "protocols",
                        "added": sorted(pb - pa),
                        "removed": sorted(pa - pb),
                    })
                diff_type = "changed" if changes else "unchanged"
                node_diffs.append({"ip": ip, "diff": diff_type, "a": a_node, "b": b_node, "changes": changes})

        # Edge diff
        def edge_key(e):
            return (e.get("src", ""), e.get("dst", ""), e.get("protocol", ""))

        ea_set = {edge_key(e): e for e in edges_a}
        eb_set = {edge_key(e): e for e in edges_b}
        all_edges = set(ea_set.keys()) | set(eb_set.keys())
        edge_diffs = []
        for ek in sorted(all_edges):
            a_e = ea_set.get(ek)
            b_e = eb_set.get(ek)
            if a_e and not b_e:
                edge_diffs.append({"key": list(ek), "diff": "removed", "a": a_e, "b": None})
            elif b_e and not a_e:
                edge_diffs.append({"key": list(ek), "diff": "added", "a": None, "b": b_e})
            else:
                edge_diffs.append({"key": list(ek), "diff": "unchanged", "a": a_e, "b": b_e})

        summary = {
            "nodes_added": sum(1 for n in node_diffs if n["diff"] == "added"),
            "nodes_removed": sum(1 for n in node_diffs if n["diff"] == "removed"),
            "nodes_changed": sum(1 for n in node_diffs if n["diff"] == "changed"),
            "nodes_unchanged": sum(1 for n in node_diffs if n["diff"] == "unchanged"),
            "edges_added": sum(1 for e in edge_diffs if e["diff"] == "added"),
            "edges_removed": sum(1 for e in edge_diffs if e["diff"] == "removed"),
            "edges_unchanged": sum(1 for e in edge_diffs if e["diff"] == "unchanged"),
        }

        diff_data = {
            "a_name": a_name,
            "b_name": b_name,
            "a_time": report_a.get("timestamp", ""),
            "b_time": report_b.get("timestamp", ""),
            "summary": summary,
            "nodes": node_diffs,
            "edges": edge_diffs,
        }

        return render_template("diff.html", diff=diff_data, diff_json=diff_data)

    @app.route("/api/reports/<filename>")
    @login_required
    def api_report_download(filename):
        safe_name = os.path.basename(filename)
        project_id = request.args.get("project_id", None, type=int)
        path = os.path.join(user_reports_dir(project_id), safe_name)
        if not os.path.isfile(path):
            return jsonify({"error": "Report not found"}), 404
        return send_file(path, as_attachment=True, download_name=safe_name)

    @app.route("/api/reports/<filename>/ocsf")
    @login_required
    def api_report_ocsf(filename):
        """Stream the OCSF NDJSON sibling next to the report (or generate
        on-the-fly for the application-layer slice if the sibling file
        doesn't exist on disk — older report or
        MARLINSPIKE_EMIT_OCSF=false)."""
        safe_name = os.path.basename(filename)
        project_id = request.args.get("project_id", None, type=int)
        json_path = os.path.join(user_reports_dir(project_id), safe_name)
        if not os.path.isfile(json_path):
            return jsonify({"error": "Report not found"}), 404
        ocsf_path = json_path.replace(".json", ".ocsf.ndjson")
        if os.path.isfile(ocsf_path):
            return send_file(
                ocsf_path,
                as_attachment=True,
                download_name=safe_name.replace(".json", ".ocsf.ndjson"),
                mimetype="application/x-ndjson",
            )
        # Fallback: generate the application-layer slice from the report.
        try:
            from marlinspike.emit import ocsf as _ocsf_emit
            with open(json_path) as f:
                report = json.load(f)
            ndjson = _ocsf_emit.render_ndjson(report)
        except Exception as exc:
            log.warning("OCSF on-demand render failed for %s: %s", safe_name, exc)
            return jsonify({"error": "OCSF emit failed"}), 500
        from flask import Response
        return Response(
            (ndjson + "\n") if ndjson else "",
            mimetype="application/x-ndjson",
            headers={
                "Content-Disposition": f'attachment; filename="{safe_name.replace(".json", ".ocsf.ndjson")}"',
            },
        )

    @app.route("/api/reports/<filename>/navigator")
    @login_required
    def api_report_navigator(filename):
        """Return a MITRE ATT&CK Navigator v4.5 layer for one domain.
        Query string: ?domain=ics-attack|enterprise-attack (default ics)."""
        safe_name = os.path.basename(filename)
        project_id = request.args.get("project_id", None, type=int)
        domain = request.args.get("domain", "ics-attack").lower()
        json_path = os.path.join(user_reports_dir(project_id), safe_name)
        if not os.path.isfile(json_path):
            return jsonify({"error": "Report not found"}), 404
        # Prefer the on-disk sibling if it exists.
        short = "ics" if domain == "ics-attack" else "enterprise"
        nav_path = json_path.replace(".json", f".navigator.{short}.json")
        if os.path.isfile(nav_path):
            return send_file(
                nav_path,
                as_attachment=True,
                download_name=safe_name.replace(".json", f".navigator.{short}.json"),
                mimetype="application/json",
            )
        # Fallback: generate from report.
        try:
            from marlinspike.emit import navigator as _nav_emit
            with open(json_path) as f:
                report = json.load(f)
            layer = _nav_emit.render_layer_for_domain(report, domain)
        except Exception as exc:
            log.warning("Navigator on-demand render failed for %s: %s", safe_name, exc)
            return jsonify({"error": "Navigator emit failed"}), 500
        if layer is None:
            return jsonify({"error": f"No {domain} techniques in report"}), 404
        from flask import Response
        return Response(
            json.dumps(layer, indent=2),
            mimetype="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="{safe_name.replace(".json", f".navigator.{short}.json")}"',
            },
        )

    @app.route("/api/reports/<filename>/stix")
    @login_required
    def api_report_stix(filename):
        """Stream the STIX 2.1 bundle sibling, or generate on-the-fly."""
        safe_name = os.path.basename(filename)
        project_id = request.args.get("project_id", None, type=int)
        json_path = os.path.join(user_reports_dir(project_id), safe_name)
        if not os.path.isfile(json_path):
            return jsonify({"error": "Report not found"}), 404
        stix_path = json_path.replace(".json", ".stix.json")
        if os.path.isfile(stix_path):
            return send_file(
                stix_path,
                as_attachment=True,
                download_name=safe_name.replace(".json", ".stix.json"),
                mimetype="application/json",
            )
        try:
            from marlinspike.emit import stix as _stix_emit
            with open(json_path) as f:
                report = json.load(f)
            bundle_json = _stix_emit.render_json(report)
        except Exception as exc:
            log.warning("STIX on-demand render failed for %s: %s", safe_name, exc)
            return jsonify({"error": "STIX emit failed"}), 500
        from flask import Response
        return Response(
            bundle_json,
            mimetype="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="{safe_name.replace(".json", ".stix.json")}"',
            },
        )

    @app.route("/api/reports/<filename>/sigma")
    @login_required
    def api_report_sigma(filename):
        """Stream the Sigma YAML sibling, or generate on-the-fly."""
        safe_name = os.path.basename(filename)
        project_id = request.args.get("project_id", None, type=int)
        json_path = os.path.join(user_reports_dir(project_id), safe_name)
        if not os.path.isfile(json_path):
            return jsonify({"error": "Report not found"}), 404
        sigma_path = json_path.replace(".json", ".sigma.yml")
        if os.path.isfile(sigma_path):
            return send_file(
                sigma_path,
                as_attachment=True,
                download_name=safe_name.replace(".json", ".sigma.yml"),
                mimetype="application/x-yaml",
            )
        try:
            from marlinspike.emit import sigma as _sigma_emit
            with open(json_path) as f:
                report = json.load(f)
            yaml_text = _sigma_emit.render_yaml_concat(report)
        except Exception as exc:
            log.warning("Sigma on-demand render failed for %s: %s", safe_name, exc)
            return jsonify({"error": "Sigma emit failed"}), 500
        if not yaml_text:
            return jsonify({"error": "No Sigma-emittable findings in report"}), 404
        from flask import Response
        return Response(
            yaml_text + "\n",
            mimetype="application/x-yaml",
            headers={
                "Content-Disposition": f'attachment; filename="{safe_name.replace(".json", ".sigma.yml")}"',
            },
        )

    @app.route("/api/reports/<filename>/viewer")
    @login_required
    def api_report_viewer(filename):
        safe_name = os.path.basename(filename)
        project_id = request.args.get("project_id", None, type=int)
        path = os.path.join(user_reports_dir(project_id), safe_name)
        if not os.path.isfile(path):
            return "Report not found", 404
        report = _load_report_with_extensions(path, ensure_mitre=True)
        sanitized_report = _sanitize_report(report)
        # Localize finding/indicator strings per the request locale BEFORE the
        # viewer context is built so the JS-rendered surfaces and the
        # server-rendered report tab both see the same translated copy.
        locale = getattr(g, "locale", DEFAULT_LOCALE)
        sanitized_report = _localize_report(sanitized_report, locale)
        return render_template(
            "viewer.html",
            report=sanitized_report,
            report_json=sanitized_report,
            viewer_context=_build_viewer_context(
                sanitized_report,
                project_id=project_id,
                report_filename=safe_name,
            ),
            filename=safe_name,
        )

    @app.route("/api/reports/<filename>/assets")
    @login_required
    def api_report_assets(filename):
        safe_name = os.path.basename(filename)
        project_id = request.args.get("project_id", None, type=int)
        path = os.path.join(user_reports_dir(project_id), safe_name)
        if not os.path.isfile(path):
            return "Report not found", 404
        report = _load_report_with_extensions(path, ensure_mitre=True)
        return render_template(
            "assets.html",
            report_json=_sanitize_report(report),
            filename=safe_name,
        )

    @app.route("/api/reports/<filename>/timeline")
    @login_required
    def api_report_timeline(filename):
        """GET — time-bucketed packet+byte counts from report.conversations[].

        Query params:
            project_id  (int, optional)

        Response JSON:
            {first_seen, last_seen, bucket_seconds,
             buckets: [{t, packets, bytes, conv_count}]}
        """
        safe_name = os.path.basename(filename)
        project_id = request.args.get("project_id", None, type=int)
        path = os.path.join(user_reports_dir(project_id), safe_name)
        if not os.path.isfile(path):
            return jsonify({"error": "Report not found"}), 404
        try:
            with open(path) as fh:
                report = json.load(fh)
        except Exception as exc:
            log.warning("timeline: failed to parse report %s: %s", path, exc)
            return jsonify({"error": "Failed to parse report"}), 500
        conversations = report.get("conversations") or []
        result = _get_timeline_for_report(path, conversations)
        return jsonify(result)

    @app.route("/api/reports/<filename>/extract", methods=["POST"])
    @login_required
    def api_report_extract(filename):
        """POST — extract a sub-PCAP for a specific conversation or time window.

        Request JSON (all fields optional):
            src, dst, port, protocol, time_start, time_end, max_packets

        Returns the resulting .pcap as application/vnd.tcpdump.pcap.
        Hard timeout: 60 s (returns 504 on TimeoutExpired).
        Max packets: min(request.max_packets, 500_000).
        """
        EXTRACT_TIMEOUT = 60
        MAX_PACKETS_HARD = 500_000

        safe_name = os.path.basename(filename)
        project_id = request.args.get("project_id", None, type=int)
        report_path = os.path.join(user_reports_dir(project_id), safe_name)
        if not os.path.isfile(report_path):
            return jsonify({"error": "Report not found"}), 404

        body = request.get_json(silent=True) or {}
        src = body.get("src")
        dst = body.get("dst")
        port = body.get("port")
        protocol = body.get("protocol")
        time_start = body.get("time_start")
        time_end = body.get("time_end")
        max_packets_req = body.get("max_packets")

        max_packets = MAX_PACKETS_HARD
        if max_packets_req is not None:
            try:
                max_packets = min(int(max_packets_req), MAX_PACKETS_HARD)
            except (TypeError, ValueError):
                pass

        # Resolve PCAP path from report capture_info
        try:
            with open(report_path) as fh:
                report = json.load(fh)
        except Exception as exc:
            log.warning("extract: failed to parse report %s: %s", report_path, exc)
            return jsonify({"error": "Failed to parse report"}), 500

        capture_info = report.get("capture_info") or {}
        pcap_basename = os.path.basename(capture_info.get("pcap_path") or "")
        if not pcap_basename:
            return jsonify({"error": "No PCAP path recorded in report"}), 404

        pid_for_path = project_id
        if pid_for_path is None:
            pid_for_path = _ensure_default_project(session["user_id"]).id
        pcap_path = os.path.join(
            config.UPLOADS_DIR,
            str(session["user_id"]),
            str(pid_for_path),
            pcap_basename,
        )
        if not os.path.isfile(pcap_path):
            return jsonify({"error": "Original PCAP not found"}), 404

        # Build tshark display filter
        filter_parts = []
        if src and dst:
            filter_parts.append(
                f"(ip.src=={src} and ip.dst=={dst})"
                f" or (ip.src=={dst} and ip.dst=={src})"
            )
        elif src:
            filter_parts.append(f"ip.src=={src} or ip.dst=={src}")
        elif dst:
            filter_parts.append(f"ip.src=={dst} or ip.dst=={dst}")
        if port is not None:
            try:
                port_int = int(port)
                filter_parts.append(f"tcp.port=={port_int} or udp.port=={port_int}")
            except (TypeError, ValueError):
                pass
        if protocol:
            filter_parts.append(protocol.lower())

        display_filter = (
            " and ".join(f"({p})" for p in filter_parts) if filter_parts else ""
        )

        # v3.5.2: extraction fails closed. Previous behaviour fell back
        # to the original PCAP if tshark or editcap failed, which meant
        # a "give me just this slice" request could silently hand back
        # the entire capture — exactly the opposite of what the user
        # asked for. Now: any stage failure → HTTP 500, no data
        # returned. The only success path is when the requested filter
        # actually produced an output PCAP.
        tmp_dir = tempfile.mkdtemp(prefix="ms_extract_")
        try:
            stage1_out = os.path.join(tmp_dir, "stage1.pcap")
            stage2_out = os.path.join(tmp_dir, "stage2.pcap")

            # Stage 1: tshark filter (IP / port / protocol)
            tshark_cmd = [
                "tshark", "-r", pcap_path,
                "-w", stage1_out,
                "-c", str(max_packets),
            ]
            if display_filter:
                tshark_cmd = [
                    "tshark", "-r", pcap_path,
                    "-Y", display_filter,
                    "-w", stage1_out,
                    "-c", str(max_packets),
                ]

            try:
                subprocess.run(
                    tshark_cmd,
                    capture_output=True,
                    timeout=EXTRACT_TIMEOUT,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                return jsonify({"error": "Extract timed out"}), 504

            # Fail closed: if tshark didn't produce stage1_out, refuse
            # to return the unfiltered original PCAP.
            if not os.path.isfile(stage1_out):
                log.warning("extract: tshark stage1 produced no output for %s", safe_name)
                return jsonify({"error": "Extract failed: tshark filter stage produced no output"}), 500
            intermediate = stage1_out

            # Stage 2: editcap time window
            if time_start is not None or time_end is not None:
                editcap_cmd = ["editcap"]
                if time_start is not None:
                    try:
                        start_iso = datetime.fromtimestamp(
                            float(time_start), tz=timezone.utc
                        ).strftime("%Y-%m-%d %H:%M:%S")
                        editcap_cmd += ["-A", start_iso]
                    except (TypeError, ValueError, OSError):
                        pass
                if time_end is not None:
                    try:
                        end_iso = datetime.fromtimestamp(
                            float(time_end), tz=timezone.utc
                        ).strftime("%Y-%m-%d %H:%M:%S")
                        editcap_cmd += ["-B", end_iso]
                    except (TypeError, ValueError, OSError):
                        pass
                editcap_cmd += [intermediate, stage2_out]
                try:
                    subprocess.run(
                        editcap_cmd,
                        capture_output=True,
                        timeout=EXTRACT_TIMEOUT,
                        check=False,
                    )
                except subprocess.TimeoutExpired:
                    return jsonify({"error": "Extract timed out"}), 504
                # Fail closed on stage 2: if editcap was supposed to
                # narrow the window and didn't produce an output, refuse.
                if not os.path.isfile(stage2_out):
                    log.warning("extract: editcap stage2 produced no output for %s", safe_name)
                    return jsonify({"error": "Extract failed: editcap time-window stage produced no output"}), 500
                final_path = stage2_out
            else:
                final_path = intermediate

            if not os.path.isfile(final_path):
                return jsonify({"error": "Extract produced no output"}), 500

            stem = safe_name.replace(".json", "")
            dl_name = f"{stem}-extract.pcap"
            with open(final_path, "rb") as fh:
                data = fh.read()
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

        return app.response_class(
            response=data,
            status=200,
            mimetype="application/vnd.tcpdump.pcap",
            headers={"Content-Disposition": f'attachment; filename="{dl_name}"'},
        )

    @app.route("/api/reports/<filename>", methods=["DELETE"])
    @login_required
    def api_report_delete(filename):
        safe_name = os.path.basename(filename)
        project_id = request.args.get("project_id", None, type=int)
        path = os.path.join(user_reports_dir(project_id), safe_name)
        if os.path.isfile(path):
            os.unlink(path)
        mitre_path = _mitre_sidecar_path(path)
        if os.path.isfile(mitre_path):
            os.unlink(mitre_path)
        arp_path = _arp_sidecar_path(path)
        if os.path.isfile(arp_path):
            os.unlink(arp_path)
        apt_path = _apt_sidecar_path(path)
        if os.path.isfile(apt_path):
            os.unlink(apt_path)
        return jsonify({"ok": True})

    # ── PCAP file browser ─────────────────────────────────────

    @app.route("/api/files")
    @login_required
    def api_files_list():
        project_id = request.args.get("project_id", None, type=int)
        files = []
        udir = user_uploads_dir(project_id)
        if os.path.isdir(udir):
            for fn in os.listdir(udir):
                if not fn.lower().endswith((".pcap", ".pcapng", ".cap")):
                    continue
                path = os.path.join(udir, fn)
                try:
                    stat = os.stat(path)
                    files.append({
                        "name": fn,
                        "size": stat.st_size,
                        "modified": datetime.fromtimestamp(
                            stat.st_mtime, tz=timezone.utc
                        ).isoformat(),
                    })
                except Exception:
                    pass
        files.sort(key=lambda f: f["modified"], reverse=True)

        # Merge preset PCAPs (read-only, baked into image, nested by category)
        presets = []
        if os.path.isdir(config.PRESETS_DIR):
            for cat_name in sorted(os.listdir(config.PRESETS_DIR)):
                cat_dir = os.path.join(config.PRESETS_DIR, cat_name)
                if not os.path.isdir(cat_dir):
                    continue
                cat_files = []
                for fn in sorted(os.listdir(cat_dir)):
                    if not fn.lower().endswith((".pcap", ".pcapng", ".cap")):
                        continue
                    path = os.path.join(cat_dir, fn)
                    try:
                        stat = os.stat(path)
                        cat_files.append({
                            "name": fn,
                            "size": stat.st_size,
                            "path": f"{cat_name}/{fn}",
                        })
                    except Exception:
                        pass
                if cat_files:
                    presets.append({"category": cat_name, "files": cat_files})

        return jsonify({"files": files, "presets": presets})

    # ── PCAP upload ──────────────────────────────────────────

    @app.route("/api/upload", methods=["POST"])
    @login_required
    @limiter.limit("10 per minute")
    def api_upload():
        return _handle_upload()

    # ── Scan history ─────────────────────────────────────────

    @app.route("/api/history")
    @login_required
    def api_scan_history():
        query = ScanHistory.query
        # Admins see all scans; regular users see only their own
        if session.get("role") != "admin":
            query = query.filter_by(user_id=session["user_id"])
        project_id = request.args.get("project_id", None, type=int)
        if project_id is not None:
            query = query.filter_by(project_id=project_id)
        limit = request.args.get("limit", 100, type=int)
        scans = query.order_by(ScanHistory.started_at.desc()).limit(limit).all()
        return jsonify({"scans": [
            {
                "run_id": s.run_id,
                "user": s.user.username if s.user else "?",
                "command": s.command,
                "scan_profile": s.scan_profile or "full",
                "pcap_source": os.path.basename(s.pcap_source) if s.pcap_source else None,
                "status": s.status,
                "started_at": s.started_at.isoformat() if s.started_at else None,
                "completed_at": s.completed_at.isoformat() if s.completed_at else None,
                "report_filename": os.path.basename(s.report_path) if s.report_path else None,
                "node_count": s.node_count,
                "edge_count": s.edge_count,
                "error_tail": s.error_tail,
                "project_id": s.project_id,
                "project_name": s.project.name if s.project else None,
                "recovery_state": s.recovery_state,
            }
            for s in scans
        ]})

    # ── System stats (admin) ────────────────────────────────

    @app.route("/system")
    @admin_required
    def system_page():
        return render_template("system.html")

    @app.route("/api/admin/stats")
    @admin_required
    def api_admin_stats():
        stats = {}

        # Uptime & platform
        try:
            with open("/proc/uptime") as f:
                uptime_secs = float(f.read().split()[0])
            stats["uptime_seconds"] = int(uptime_secs)
        except Exception:
            stats["uptime_seconds"] = None
        # platform and python version intentionally omitted

        # Memory (from /proc/meminfo)
        try:
            meminfo = {}
            with open("/proc/meminfo") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2:
                        meminfo[parts[0].rstrip(":")] = int(parts[1]) * 1024  # kB -> bytes
            stats["memory"] = {
                "total": meminfo.get("MemTotal", 0),
                "available": meminfo.get("MemAvailable", 0),
                "used": meminfo.get("MemTotal", 0) - meminfo.get("MemAvailable", 0),
            }
        except Exception:
            stats["memory"] = None

        # Disk usage for data directory
        try:
            usage = shutil.disk_usage(config.DATA_DIR)
            stats["disk"] = {
                "total": usage.total,
                "used": usage.used,
                "free": usage.free,
            }
        except Exception:
            stats["disk"] = None

        # Data directory sizes
        def dir_size(path):
            total = 0
            try:
                for dirpath, _dirnames, filenames in os.walk(path):
                    for fn in filenames:
                        try:
                            total += os.path.getsize(os.path.join(dirpath, fn))
                        except OSError:
                            pass
            except Exception:
                pass
            return total

        def file_count(path, extensions=None):
            count = 0
            try:
                for dirpath, _dirnames, filenames in os.walk(path):
                    for fn in filenames:
                        if extensions is None or any(fn.lower().endswith(e) for e in extensions):
                            count += 1
            except Exception:
                pass
            return count

        stats["data"] = {
            "uploads_size": dir_size(config.UPLOADS_DIR),
            "uploads_count": file_count(config.UPLOADS_DIR, (".pcap", ".pcapng", ".cap")),
            "reports_size": dir_size(config.REPORTS_DIR),
            "reports_count": file_count(config.REPORTS_DIR, (".json",)),
        }

        # Submissions stats
        stats["submissions"] = {
            "total_size": dir_size(config.SUBMISSIONS_DIR),
            "total_count": file_count(config.SUBMISSIONS_DIR),
        }

        # Database stats
        stats["db"] = {
            "users": User.query.count(),
            "scans_total": ScanHistory.query.count(),
            "scans_completed": ScanHistory.query.filter_by(status="completed").count(),
            "scans_failed": ScanHistory.query.filter_by(status="failed").count(),
            "scans_running": ScanHistory.query.filter_by(status="running").count(),
        }

        # Active in-memory runs
        with _runs_lock:
            active = _get_active_runs()
            stats["active_scans"] = len(active)

        # CPU load
        try:
            load1, load5, load15 = os.getloadavg()
            stats["load"] = {"1m": round(load1, 2), "5m": round(load5, 2), "15m": round(load15, 2)}
        except Exception:
            stats["load"] = None

        # CPU count
        try:
            stats["cpu_count"] = os.cpu_count()
        except Exception:
            stats["cpu_count"] = None

        # Per-user storage breakdown
        user_storage = []
        users = User.query.all()
        for u in users:
            u_uploads = os.path.join(config.UPLOADS_DIR, str(u.id))
            u_reports = os.path.join(config.REPORTS_DIR, str(u.id))
            user_storage.append({
                "username": u.username,
                "user_id": u.id,
                "uploads_size": dir_size(u_uploads),
                "uploads_count": file_count(u_uploads, (".pcap", ".pcapng", ".cap")),
                "reports_size": dir_size(u_reports),
                "reports_count": file_count(u_reports, (".json",)),
            })
        stats["user_storage"] = user_storage

        return jsonify(stats)

    # ── Admin preset (sample library) management ────────────

    _SAFE_NAME_RE = re.compile(r'^[a-zA-Z0-9._-]+$')

    def _safe_preset_name(name):
        """Validate and sanitise a preset name (category or filename)."""
        name = os.path.basename(name).strip()
        if not name or not _SAFE_NAME_RE.match(name):
            return None
        return name

    @app.route("/api/admin/presets")
    @admin_required
    def api_admin_presets_list():
        categories = []
        if os.path.isdir(config.PRESETS_DIR):
            for cat_name in sorted(os.listdir(config.PRESETS_DIR)):
                cat_dir = os.path.join(config.PRESETS_DIR, cat_name)
                if not os.path.isdir(cat_dir):
                    continue
                files = []
                total_size = 0
                for fn in sorted(os.listdir(cat_dir)):
                    path = os.path.join(cat_dir, fn)
                    if not os.path.isfile(path):
                        continue
                    try:
                        sz = os.path.getsize(path)
                    except OSError:
                        sz = 0
                    files.append({"name": fn, "size": sz})
                    total_size += sz
                categories.append({
                    "name": cat_name,
                    "files": files,
                    "file_count": len(files),
                    "total_size": total_size,
                })
        return jsonify({"categories": categories})

    @app.route("/api/admin/presets/upload", methods=["POST"])
    @admin_required
    @limiter.limit("20 per minute")
    def api_admin_presets_upload():
        if "file" not in request.files:
            return jsonify({"ok": False, "error": "No file part"}), 400
        f = request.files["file"]
        if not f.filename:
            return jsonify({"ok": False, "error": "No file selected"}), 400

        category = _safe_preset_name(request.form.get("category", ""))
        if not category:
            return jsonify({"ok": False, "error": "Invalid category name"}), 400

        safe_name = _safe_preset_name(f.filename)
        if not safe_name:
            return jsonify({"ok": False, "error": "Invalid filename (alphanumeric, dots, hyphens, underscores only)"}), 400

        # Stream to temp, validate magic bytes, enforce size limit
        cat_dir = os.path.join(config.PRESETS_DIR, category)
        os.makedirs(cat_dir, exist_ok=True)

        import tempfile
        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".pcap", dir=cat_dir)
        written = 0
        magic_checked = False
        try:
            with os.fdopen(tmp_fd, "wb") as out:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    if not magic_checked:
                        if len(chunk) < 4:
                            chunk += f.read(4 - len(chunk))
                        if len(chunk) < 4 or chunk[:4] not in PCAP_MAGIC:
                            os.unlink(tmp_path)
                            return jsonify({"ok": False, "error": "Not a valid PCAP file"}), 400
                        magic_checked = True
                    written += len(chunk)
                    if written > config.PCAP_MAX_SIZE:
                        os.unlink(tmp_path)
                        return jsonify({"ok": False, "error": f"File too large (max {config.PCAP_MAX_SIZE // (1024*1024)} MB)"}), 413
                    out.write(chunk)
        except Exception:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise

        if written == 0:
            os.unlink(tmp_path)
            return jsonify({"ok": False, "error": "Empty file"}), 400

        final_path = os.path.join(cat_dir, safe_name)
        os.rename(tmp_path, final_path)
        log.info("Preset upload: %s/%s by %s (%d bytes)", category, safe_name, session.get("user", "?"), written)
        return jsonify({"ok": True, "category": category, "filename": safe_name, "size": written})

    @app.route("/api/admin/presets/category", methods=["POST"])
    @admin_required
    def api_admin_presets_create_category():
        body = request.get_json(silent=True) or {}
        name = _safe_preset_name(body.get("name", ""))
        if not name:
            return jsonify({"ok": False, "error": "Invalid category name (alphanumeric, dots, hyphens, underscores only)"}), 400
        cat_dir = os.path.join(config.PRESETS_DIR, name)
        if os.path.exists(cat_dir):
            return jsonify({"ok": False, "error": "Category already exists"}), 409
        os.makedirs(cat_dir, exist_ok=True)
        log.info("Preset category created: %s by %s", name, session.get("user", "?"))
        return jsonify({"ok": True, "name": name})

    @app.route("/api/admin/presets/category/<name>", methods=["PUT"])
    @admin_required
    def api_admin_presets_rename_category(name):
        old_name = _safe_preset_name(name)
        if not old_name:
            return jsonify({"ok": False, "error": "Invalid category name"}), 400
        body = request.get_json(silent=True) or {}
        new_name = _safe_preset_name(body.get("name", ""))
        if not new_name:
            return jsonify({"ok": False, "error": "Invalid new name"}), 400
        old_dir = os.path.join(config.PRESETS_DIR, old_name)
        new_dir = os.path.join(config.PRESETS_DIR, new_name)
        if not os.path.isdir(old_dir):
            return jsonify({"ok": False, "error": "Category not found"}), 404
        if os.path.exists(new_dir):
            return jsonify({"ok": False, "error": "Target name already exists"}), 409
        os.rename(old_dir, new_dir)
        log.info("Preset category renamed: %s -> %s by %s", old_name, new_name, session.get("user", "?"))
        return jsonify({"ok": True})

    @app.route("/api/admin/presets/<category>/<filename>", methods=["DELETE"])
    @admin_required
    def api_admin_presets_delete_file(category, filename):
        if request.args.get("confirm") != "true":
            return jsonify({"ok": False, "error": "Add ?confirm=true to delete"}), 400
        cat = _safe_preset_name(category)
        fn = _safe_preset_name(filename)
        if not cat or not fn:
            return jsonify({"ok": False, "error": "Invalid name"}), 400
        path = os.path.join(config.PRESETS_DIR, cat, fn)
        if not os.path.isfile(path):
            return jsonify({"ok": False, "error": "File not found"}), 404
        os.unlink(path)
        log.info("Preset deleted: %s/%s by %s", cat, fn, session.get("user", "?"))
        return jsonify({"ok": True})

    @app.route("/api/admin/presets/category/<name>", methods=["DELETE"])
    @admin_required
    def api_admin_presets_delete_category(name):
        if request.args.get("confirm") != "true":
            return jsonify({"ok": False, "error": "Add ?confirm=true to delete"}), 400
        cat = _safe_preset_name(name)
        if not cat:
            return jsonify({"ok": False, "error": "Invalid category name"}), 400
        cat_dir = os.path.join(config.PRESETS_DIR, cat)
        if not os.path.isdir(cat_dir):
            return jsonify({"ok": False, "error": "Category not found"}), 404
        shutil.rmtree(cat_dir)
        log.info("Preset category deleted: %s by %s", cat, session.get("user", "?"))
        return jsonify({"ok": True})

    # ── User management (admin) ──────────────────────────────

    @app.route("/users")
    @admin_required
    def users_page():
        return render_template("users.html")

    @app.route("/api/users")
    @admin_required
    def api_users_list():
        users = User.query.order_by(User.created_at).all()
        return jsonify({"users": [
            {
                "id": u.id,
                "username": u.username,
                "role": u.role,
                "created_at": u.created_at.isoformat() if u.created_at else None,
                "upload_limit_mb": u.upload_limit_mb if u.upload_limit_mb else 200,
            }
            for u in users
        ]})

    @app.route("/api/users", methods=["POST"])
    @admin_required
    @limiter.limit("3 per minute")
    def api_users_create():
        body = request.get_json(silent=True) or {}
        username = body.get("username", "").strip()
        password = body.get("password", "")
        role = body.get("role", "user")
        if not username or not password:
            return jsonify({"ok": False, "error": "Username and password required"}), 400
        if not _password_meets_policy(password):
            return jsonify({"ok": False, "error": _password_policy_message()}), 400
        if role not in ("admin", "user"):
            return jsonify({"ok": False, "error": "Invalid role"}), 400
        if User.query.filter_by(username=username).first():
            return jsonify({"ok": False, "error": "Username already exists"}), 409
        upload_limit = 200
        if "upload_limit_mb" in body:
            try:
                upload_limit = int(body["upload_limit_mb"])
                if upload_limit < 1 or upload_limit > 10000:
                    raise ValueError
            except (TypeError, ValueError):
                return jsonify({"ok": False, "error": "upload_limit_mb must be 1-10000"}), 400
        create_user(username, password, role, upload_limit_mb=upload_limit)
        log.info("User created: %s (role=%s, limit=%dMB) by %s", username, role, upload_limit, session.get("user", "?"))
        return jsonify({"ok": True})

    @app.route("/api/users/<username>", methods=["DELETE"])
    @admin_required
    def api_users_delete(username):
        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({"ok": False, "error": "User not found"}), 404
        if user.username == session.get("user"):
            return jsonify({"ok": False, "error": "Cannot delete yourself"}), 400
        log.info("User deleted: %s by %s", username, session.get("user", "?"))
        db.session.delete(user)
        db.session.commit()
        return jsonify({"ok": True})

    @app.route("/api/users/<username>/password", methods=["POST"])
    @admin_required
    @limiter.limit("10 per hour")
    def api_users_change_password(username):
        body = request.get_json(silent=True) or {}
        new_pass = body.get("password", "")
        if not new_pass:
            return jsonify({"ok": False, "error": "Password required"}), 400
        if not _password_meets_policy(new_pass):
            return jsonify({"ok": False, "error": _password_policy_message()}), 400
        user = User.query.filter_by(username=username).first()
        if not user:
            audit("auth.password_change_failed",
                  target_type="user", target_id=username,
                  status="not_found")
            return jsonify({"ok": False, "error": "User not found"}), 404
        change_password(user, new_pass)
        audit("auth.password_change_admin",
              target_type="user", target_id=username,
              status="success")
        return jsonify({"ok": True})

    @app.route("/api/account/password", methods=["POST"])
    @login_required
    @limiter.limit("5 per hour")
    def api_account_change_password():
        body = request.get_json(silent=True) or {}
        current = body.get("current_password", "")
        new_pass = body.get("new_password", "")
        if not current or not new_pass:
            return jsonify({"ok": False, "error": "Current and new password required"}), 400
        if not _password_meets_policy(new_pass):
            return jsonify({"ok": False, "error": _password_policy_message()}), 400
        user = User.query.filter_by(username=session["user"]).first()
        if not verify_user(user.username, current):
            audit("auth.password_change_failed",
                  target_type="user", target_id=user.username if user else session.get("user"),
                  status="wrong_current_password")
            return jsonify({"ok": False, "error": "Current password is incorrect"}), 403
        change_password(user, new_pass)
        audit("auth.password_change",
              target_type="user", target_id=user.username,
              status="success")
        return jsonify({"ok": True})

    # ── Profile ───────────────────────────────────────────────

    @app.route("/profile")
    @login_required
    def profile_page():
        return render_template("profile.html")

    @app.route("/api/profile", methods=["GET"])
    @login_required
    def api_profile_get():
        user = User.query.get(session["user_id"])
        scan_count = ScanHistory.query.filter_by(user_id=user.id).count()
        project_count = Project.query.filter_by(user_id=user.id).count()
        return jsonify({
            "username": user.username,
            "role": user.role,
            "email": user.email or "",
            "full_name": user.full_name or "",
            "company": user.company or "",
            "phone": user.phone or "",
            "birthday": user.birthday.isoformat() if user.birthday else "",
            "address": user.address or "",
            "upload_limit_mb": user.upload_limit_mb if user.upload_limit_mb else 200,
            "joined": user.created_at.isoformat() if user.created_at else "",
            "scan_count": scan_count,
            "project_count": project_count,
        })

    @app.route("/api/profile", methods=["POST"])
    @login_required
    def api_profile_update():
        body = request.get_json(silent=True) or {}
        user = User.query.get(session["user_id"])
        for field in ("full_name", "company", "phone", "address"):
            if field in body:
                val = body[field].strip() if body[field] else None
                setattr(user, field, val or None)
        if "email" in body:
            email_val = body["email"].strip() if body["email"] else None
            if email_val and User.query.filter(User.email == email_val, User.id != user.id).first():
                return jsonify({"ok": False, "error": "Email already in use"}), 409
            user.email = email_val or None
        if "birthday" in body:
            try:
                from datetime import date as _date
                user.birthday = _date.fromisoformat(body["birthday"]) if body["birthday"] else None
            except ValueError:
                return jsonify({"ok": False, "error": "Invalid birthday format (YYYY-MM-DD)"}), 400
        db.session.commit()
        return jsonify({"ok": True})

    @app.route("/api/users/<username>/limits", methods=["POST"])
    @admin_required
    def api_users_set_limits(username):
        body = request.get_json(silent=True) or {}
        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({"ok": False, "error": "User not found"}), 404
        if "upload_limit_mb" in body:
            try:
                limit = int(body["upload_limit_mb"])
                if limit < 1 or limit > 10000:
                    raise ValueError
                user.upload_limit_mb = limit
            except (ValueError, TypeError):
                return jsonify({"ok": False, "error": "upload_limit_mb must be 1–10000"}), 400
        db.session.commit()
        log.info(
            "Upload limit updated for %s by %s: %s MB",
            username,
            session.get("user", "?"),
            user.upload_limit_mb,
        )
        return jsonify({"ok": True})

    # ── Audit log (admin) ────────────────────────────────────

    @app.route("/audit")
    @admin_required
    def audit_page():
        return render_template("audit.html")

    @app.route("/api/audit")
    @admin_required
    def api_audit_list():
        limit = min(int(request.args.get("limit", 100)), 500)
        offset = int(request.args.get("offset", 0))
        event_type = request.args.get("event_type", "").strip()
        username = request.args.get("username", "").strip()
        status_filter = request.args.get("status", "").strip()

        q = AuditLog.query.order_by(AuditLog.created_at.desc())
        if event_type:
            q = q.filter(AuditLog.event_type.ilike(f"%{event_type}%"))
        if username:
            q = q.filter(AuditLog.actor_username.ilike(f"%{username}%"))
        if status_filter:
            q = q.filter(AuditLog.status == status_filter)

        total = q.count()
        entries = q.offset(offset).limit(limit).all()

        return jsonify({
            "total": total,
            "offset": offset,
            "limit": limit,
            "entries": [
                {
                    "id": e.id,
                    "event_type": e.event_type,
                    "category": e.category,
                    "actor_username": e.actor_username,
                    "actor_role": e.actor_role,
                    "target_type": e.target_type,
                    "target_id": e.target_id,
                    "status": e.status,
                    "ip_address": e.ip_address,
                    "detail": e.detail,
                    "created_at": e.created_at.isoformat() if e.created_at else None,
                }
                for e in entries
            ],
        })

    # ── IOC Threat Hunting ─────────────────────────────────────

    def _ioc_entry_to_dict(e: IocEntry) -> dict:
        return {
            "id": e.id,
            "ioc_type": e.ioc_type,
            "value": e.value,
            "label": e.label,
            "severity": e.severity,
        }

    def _ioc_list_to_dict(lst: IocList, include_entries: bool = False) -> dict:
        d = {
            "id": lst.id,
            "project_id": lst.project_id,
            "name": lst.name,
            "description": lst.description,
            "source": lst.source,
            "created_at": lst.created_at.isoformat() if lst.created_at else None,
            "updated_at": lst.updated_at.isoformat() if lst.updated_at else None,
            "created_by": lst.created_by,
            "entry_count": IocEntry.query.filter_by(list_id=lst.id).count(),
        }
        if include_entries:
            d["entries"] = [_ioc_entry_to_dict(e) for e in lst.entries]
        return d

    def _get_ioc_list_or_404(pid: int, list_id: int, min_role: str = "viewer"):
        proj = _get_project_for_user(pid, min_role)
        if not proj:
            return None, None
        lst = IocList.query.filter_by(id=list_id, project_id=pid).first()
        return proj, lst

    @app.route("/api/projects/<int:pid>/iocs")
    @login_required
    def api_ioc_lists(pid):
        proj = _get_project_for_user(pid)
        if not proj:
            return jsonify({"error": "Project not found"}), 404
        lists = IocList.query.filter_by(project_id=pid).order_by(IocList.created_at).all()
        return jsonify({"lists": [_ioc_list_to_dict(lst) for lst in lists]})

    @app.route("/api/projects/<int:pid>/iocs", methods=["POST"])
    @login_required
    def api_ioc_lists_create(pid):
        proj = _get_project_for_user(pid, "editor")
        if not proj:
            return jsonify({"error": "Project not found"}), 404

        body = request.get_json(silent=True) or {}
        name = (body.get("name") or "").strip()
        if not name:
            return jsonify({"error": "name required"}), 400
        if len(name) > 120:
            return jsonify({"error": "name too long (max 120)"}), 400

        if IocList.query.filter_by(project_id=pid, name=name).first():
            return jsonify({"error": "IOC list name already exists in this project"}), 409

        raw_entries = body.get("entries") or []
        errors: list[dict] = []
        validated: list[dict] = []
        for idx, e in enumerate(raw_entries):
            if not isinstance(e, dict):
                errors.append({"index": idx, "reason": "entry must be an object"})
                continue
            ioc_type = (e.get("ioc_type") or "").strip().lower()
            value = (e.get("value") or "").strip()
            if ioc_type not in VALID_IOC_TYPES:
                errors.append({"index": idx, "reason": f"invalid ioc_type '{ioc_type}'"})
                continue
            if not value:
                errors.append({"index": idx, "reason": "value required"})
                continue
            sev = (e.get("severity") or "").strip().lower() or None
            if sev and sev not in VALID_SEVERITIES:
                errors.append({"index": idx, "reason": f"invalid severity '{sev}'"})
                continue
            validated.append({
                "ioc_type": ioc_type,
                "value": value,
                "label": (e.get("label") or "").strip() or None,
                "severity": sev,
            })

        lst = IocList(
            project_id=pid,
            name=name,
            description=(body.get("description") or "").strip() or None,
            source=(body.get("source") or "").strip() or None,
            created_by=session.get("user_id"),
        )
        db.session.add(lst)
        db.session.flush()

        for e in validated:
            db.session.add(IocEntry(list_id=lst.id, **e))

        db.session.commit()
        return jsonify({"ok": True, "list": _ioc_list_to_dict(lst, include_entries=True), "errors": errors}), 201

    @app.route("/api/projects/<int:pid>/iocs/<int:list_id>")
    @login_required
    def api_ioc_list_get(pid, list_id):
        proj, lst = _get_ioc_list_or_404(pid, list_id)
        if proj is None:
            return jsonify({"error": "Project not found"}), 404
        if lst is None:
            return jsonify({"error": "IOC list not found"}), 404
        return jsonify({"list": _ioc_list_to_dict(lst, include_entries=True)})

    @app.route("/api/projects/<int:pid>/iocs/<int:list_id>", methods=["PUT"])
    @login_required
    def api_ioc_list_replace(pid, list_id):
        proj, lst = _get_ioc_list_or_404(pid, list_id, "editor")
        if proj is None:
            return jsonify({"error": "Project not found"}), 404
        if lst is None:
            return jsonify({"error": "IOC list not found"}), 404

        body = request.get_json(silent=True) or {}

        if "name" in body:
            name = (body["name"] or "").strip()
            if not name:
                return jsonify({"error": "name required"}), 400
            if len(name) > 120:
                return jsonify({"error": "name too long (max 120)"}), 400
            dup = IocList.query.filter_by(project_id=pid, name=name).first()
            if dup and dup.id != list_id:
                return jsonify({"error": "IOC list name already exists in this project"}), 409
            lst.name = name

        if "description" in body:
            lst.description = (body["description"] or "").strip() or None
        if "source" in body:
            lst.source = (body["source"] or "").strip() or None

        # Full replace of entries
        raw_entries = body.get("entries")
        errors: list[dict] = []
        if raw_entries is not None:
            IocEntry.query.filter_by(list_id=lst.id).delete()
            for idx, e in enumerate(raw_entries):
                if not isinstance(e, dict):
                    errors.append({"index": idx, "reason": "entry must be an object"})
                    continue
                ioc_type = (e.get("ioc_type") or "").strip().lower()
                value = (e.get("value") or "").strip()
                if ioc_type not in VALID_IOC_TYPES:
                    errors.append({"index": idx, "reason": f"invalid ioc_type '{ioc_type}'"})
                    continue
                if not value:
                    errors.append({"index": idx, "reason": "value required"})
                    continue
                sev = (e.get("severity") or "").strip().lower() or None
                if sev and sev not in VALID_SEVERITIES:
                    errors.append({"index": idx, "reason": f"invalid severity '{sev}'"})
                    continue
                db.session.add(IocEntry(
                    list_id=lst.id,
                    ioc_type=ioc_type,
                    value=value,
                    label=(e.get("label") or "").strip() or None,
                    severity=sev,
                ))

        db.session.commit()
        return jsonify({"ok": True, "list": _ioc_list_to_dict(lst, include_entries=True), "errors": errors})

    @app.route("/api/projects/<int:pid>/iocs/<int:list_id>", methods=["DELETE"])
    @login_required
    def api_ioc_list_delete(pid, list_id):
        proj, lst = _get_ioc_list_or_404(pid, list_id, "editor")
        if proj is None:
            return jsonify({"error": "Project not found"}), 404
        if lst is None:
            return jsonify({"error": "IOC list not found"}), 404
        db.session.delete(lst)  # cascade deletes entries via relationship
        db.session.commit()
        return jsonify({"ok": True})

    @app.route("/api/projects/<int:pid>/iocs/<int:list_id>/import", methods=["POST"])
    @login_required
    def api_ioc_list_import(pid, list_id):
        proj, lst = _get_ioc_list_or_404(pid, list_id, "editor")
        if proj is None:
            return jsonify({"error": "Project not found"}), 404
        if lst is None:
            return jsonify({"error": "IOC list not found"}), 404

        body = request.get_json(silent=True) or {}
        text = body.get("text") or ""
        default_type = (body.get("default_type") or "ip").strip().lower()
        if default_type not in VALID_IOC_TYPES:
            return jsonify({"error": f"invalid default_type '{default_type}'"}), 400

        parsed = parse_ioc_paste(text, default_type=default_type)
        added = 0
        skipped = 0

        for e in parsed["entries"]:
            existing = IocEntry.query.filter_by(
                list_id=lst.id,
                ioc_type=e["ioc_type"],
                value=e["value"],
            ).first()
            if existing:
                skipped += 1
                continue
            db.session.add(IocEntry(
                list_id=lst.id,
                ioc_type=e["ioc_type"],
                value=e["value"],
            ))
            added += 1

        db.session.commit()
        return jsonify({"added": added, "skipped": skipped, "errors": parsed["errors"]})

    @app.route("/api/projects/<int:pid>/iocs/<int:list_id>/scan", methods=["POST"])
    @login_required
    def api_ioc_list_scan(pid, list_id):
        proj, lst = _get_ioc_list_or_404(pid, list_id)
        if proj is None:
            return jsonify({"error": "Project not found"}), 404
        if lst is None:
            return jsonify({"error": "IOC list not found"}), 404

        entries = [
            {
                "id": e.id,
                "ioc_type": e.ioc_type,
                "value": e.value,
                "label": e.label,
                "severity": e.severity,
            }
            for e in IocEntry.query.filter_by(list_id=lst.id).all()
        ]

        # Collect all report paths for this project
        rdir = os.path.join(config.REPORTS_DIR, str(proj.user_id), str(pid))
        report_paths: list[str] = []
        if os.path.isdir(rdir):
            for fn in sorted(os.listdir(rdir)):
                if _is_primary_report_filename(fn):
                    report_paths.append(os.path.join(rdir, fn))

        result = scan_ioc_list_against_reports(
            entries=entries,
            report_paths=report_paths,
            loader=_load_report_with_extensions,
        )
        result["list"] = {
            "id": lst.id,
            "name": lst.name,
            "entry_count": len(entries),
        }
        return jsonify(result)

    # ── Live capture (capd) ──────────────────────────────────
    # Blueprint mounts at /api/capture/* and degrades gracefully when
    # LIVE_CAPTURE_ENABLED is false or capd is unreachable.
    from marlinspike.capture.api import bp as capture_bp
    app.register_blueprint(capture_bp)

    return app


# ═══════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    app = create_app()
    print(f"[marlinspike] Starting on http://{config.HOST}:{config.PORT}")
    app.run(host=config.HOST, port=config.PORT, debug=False)
