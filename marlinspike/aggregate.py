"""Project-level aggregation across reports.

Walks every report in a project, deduplicates assets and findings across
captures, and returns a single roll-up document the Project Overview UI
consumes. No schema migration: pure compute over the existing report JSON
plus loaded plugin sidecars.

Identity policy:
  - Asset key: MAC if present (stable across DHCP renewals), else IP.
  - Finding key: (category, sorted(affected_nodes), sorted(affected_edges)).

Temporal policy: every aggregated record carries first_seen / last_seen
report metadata (timestamp + filename). The UI decides what counts as
"active" — Phase 3 territory.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Callable, Iterable


_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def _norm_severity(value) -> str:
    s = str(value or "").upper().strip()
    return s if s in _SEVERITIES else "MEDIUM"


def _coerce_int(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _asset_key(node: dict) -> tuple[str, str] | None:
    """Return (key, key_type) for a node, or None if neither MAC nor IP."""
    mac = (node.get("mac") or "").strip().lower()
    if mac:
        return mac, "mac"
    ip = (node.get("ip") or "").strip()
    if ip:
        return ip, "ip"
    return None


def _finding_key(finding: dict) -> tuple:
    cat = str(finding.get("category") or "").strip().upper()
    nodes = tuple(sorted(str(n) for n in (finding.get("affected_nodes") or [])))
    edges = tuple(sorted(str(e) for e in (finding.get("affected_edges") or [])))
    return cat, nodes, edges


def aggregate_reports(
    report_paths: Iterable[str],
    loader: Callable[[str], dict],
    *,
    report_meta: dict[str, dict] | None = None,
) -> dict:
    """Walk reports via `loader(path) -> report_dict` and return a roll-up.

    `report_meta[path]` may carry `{"filename", "modified", "scan_profile"}` —
    used for first/last seen attribution and the scan-profile breakdown.
    """
    report_meta = report_meta or {}

    assets: dict[str, dict] = {}
    findings: dict[tuple, dict] = {}
    protocols: dict[str, dict] = defaultdict(lambda: {"report_count": 0, "packet_count": 0})
    severity_counts: dict[str, int] = {s: 0 for s in _SEVERITIES}
    scan_profiles: dict[str, int] = defaultdict(int)
    capture_starts: list[str] = []
    capture_ends: list[str] = []
    report_timestamps: list[str] = []
    report_count = 0

    for path in report_paths:
        try:
            report = loader(path)
        except Exception:
            continue
        if not isinstance(report, dict):
            continue
        report_count += 1
        meta = report_meta.get(path, {})
        filename = meta.get("filename") or path.rsplit("/", 1)[-1]
        modified = meta.get("modified") or report.get("timestamp_end") or ""
        profile = (meta.get("scan_profile") or "").strip().lower()
        if profile:
            scan_profiles[profile] += 1

        if report.get("timestamp_start"):
            report_timestamps.append(report["timestamp_start"])
        cap = report.get("capture_info") or {}
        if cap.get("start_ts"):
            capture_starts.append(cap["start_ts"])
        if cap.get("end_ts"):
            capture_ends.append(cap["end_ts"])

        seen_protos_in_report: set[str] = set()
        for proto, count in (cap.get("protocols_seen") or {}).items():
            name = str(proto).strip()
            if not name:
                continue
            entry = protocols[name]
            if name not in seen_protos_in_report:
                entry["report_count"] += 1
                seen_protos_in_report.add(name)
            entry["packet_count"] += _coerce_int(count)

        seen_asset_keys_in_report: set[str] = set()
        for node in report.get("nodes") or []:
            keyed = _asset_key(node)
            if not keyed:
                continue
            key, key_type = keyed
            asset = assets.get(key)
            if not asset:
                asset = {
                    "key": key,
                    "key_type": key_type,
                    "macs": set(),
                    "ips": set(),
                    "roles": set(),
                    "vendors": set(),
                    "device_types": set(),
                    "purdue_levels": set(),
                    "protocols": set(),
                    "report_count": 0,
                    "first_seen_report": filename,
                    "first_seen_modified": modified,
                    "last_seen_report": filename,
                    "last_seen_modified": modified,
                }
                assets[key] = asset
            else:
                if modified > asset["last_seen_modified"]:
                    asset["last_seen_modified"] = modified
                    asset["last_seen_report"] = filename
                if modified and (not asset["first_seen_modified"] or modified < asset["first_seen_modified"]):
                    asset["first_seen_modified"] = modified
                    asset["first_seen_report"] = filename
            if key not in seen_asset_keys_in_report:
                asset["report_count"] += 1
                seen_asset_keys_in_report.add(key)
            if node.get("mac"):
                asset["macs"].add(node["mac"].lower())
            if node.get("ip"):
                asset["ips"].add(node["ip"])
            if node.get("role"):
                asset["roles"].add(str(node["role"]))
            if node.get("vendor"):
                asset["vendors"].add(str(node["vendor"]))
            if node.get("device_type"):
                asset["device_types"].add(str(node["device_type"]))
            if node.get("purdue_level") is not None:
                asset["purdue_levels"].add(_coerce_int(node["purdue_level"]))
            for proto in node.get("protocols") or []:
                asset["protocols"].add(str(proto))

        seen_finding_keys_in_report: set[tuple] = set()
        for finding in report.get("risk_findings") or []:
            if not isinstance(finding, dict):
                continue
            key = _finding_key(finding)
            sev = _norm_severity(finding.get("severity"))
            entry = findings.get(key)
            if not entry:
                entry = {
                    "category": key[0],
                    "severity": sev,
                    "description": str(finding.get("description") or ""),
                    "remediation": str(finding.get("remediation") or ""),
                    "affected_nodes": list(key[1]),
                    "affected_edges": list(key[2]),
                    "attack_ids": [],
                    "source": str(finding.get("source") or "engine"),
                    "occurrences": 0,
                    "first_seen_report": filename,
                    "first_seen_modified": modified,
                    "last_seen_report": filename,
                    "last_seen_modified": modified,
                    "max_cvss_impact": float(finding.get("cvss_impact") or 0.0),
                }
                findings[key] = entry
            else:
                if modified > entry["last_seen_modified"]:
                    entry["last_seen_modified"] = modified
                    entry["last_seen_report"] = filename
                    # Latest report wins for description/remediation (most current view)
                    if finding.get("description"):
                        entry["description"] = str(finding["description"])
                    if finding.get("remediation"):
                        entry["remediation"] = str(finding["remediation"])
                if modified and (not entry["first_seen_modified"] or modified < entry["first_seen_modified"]):
                    entry["first_seen_modified"] = modified
                    entry["first_seen_report"] = filename
                # Promote severity if newer report is more severe
                if _sev_rank(sev) < _sev_rank(entry["severity"]):
                    entry["severity"] = sev
                cvss = float(finding.get("cvss_impact") or 0.0)
                if cvss > entry["max_cvss_impact"]:
                    entry["max_cvss_impact"] = cvss
            if key not in seen_finding_keys_in_report:
                entry["occurrences"] += 1
                seen_finding_keys_in_report.add(key)
                severity_counts[sev] += 1
            for tid in finding.get("attack_ids") or finding.get("attack_techniques") or []:
                tid_norm = str(tid).strip().upper()
                if tid_norm and tid_norm not in entry["attack_ids"]:
                    entry["attack_ids"].append(tid_norm)

    asset_list = sorted(
        (_asset_to_dict(a) for a in assets.values()),
        key=lambda a: (a.get("purdue_level") if a.get("purdue_level") is not None else 99,
                       -a["report_count"], a["key"]),
    )
    finding_list = sorted(
        findings.values(),
        key=lambda f: (_sev_rank(f["severity"]), -f["occurrences"], f["category"]),
    )
    proto_list = sorted(
        ({"name": k, **v} for k, v in protocols.items()),
        key=lambda p: (-p["report_count"], -p["packet_count"], p["name"]),
    )
    attack_index: dict[str, dict] = {}
    for f in finding_list:
        for tid in f["attack_ids"]:
            entry = attack_index.setdefault(tid, {"id": tid, "report_count": 0, "categories": []})
            entry["report_count"] += f["occurrences"]
            if f["category"] not in entry["categories"]:
                entry["categories"].append(f["category"])

    window = {
        "earliest_report": min(report_timestamps) if report_timestamps else None,
        "latest_report": max(report_timestamps) if report_timestamps else None,
        "earliest_capture": min(capture_starts) if capture_starts else None,
        "latest_capture": max(capture_ends) if capture_ends else None,
    }

    return {
        "report_count": report_count,
        "totals": {
            "assets": len(asset_list),
            "findings": len(finding_list),
            "finding_occurrences": sum(f["occurrences"] for f in finding_list),
            "protocols": len(proto_list),
            "attack_techniques": len(attack_index),
        },
        "severity_counts": severity_counts,
        "window": window,
        "scan_profiles": dict(scan_profiles),
        "assets": asset_list,
        "findings": finding_list,
        "protocols": proto_list,
        "attack_coverage": sorted(attack_index.values(), key=lambda a: (-a["report_count"], a["id"])),
    }


def _sev_rank(sev: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(sev, 5)


def _asset_to_dict(asset: dict) -> dict:
    purdue = sorted(asset["purdue_levels"]) if asset["purdue_levels"] else []
    return {
        "key": asset["key"],
        "key_type": asset["key_type"],
        "macs": sorted(asset["macs"]),
        "ips": sorted(asset["ips"]),
        "roles": sorted(asset["roles"]),
        "vendors": sorted(asset["vendors"]),
        "device_types": sorted(asset["device_types"]),
        "purdue_level": purdue[0] if purdue else None,
        "purdue_levels": purdue,
        "protocols": sorted(asset["protocols"]),
        "report_count": asset["report_count"],
        "first_seen_report": asset["first_seen_report"],
        "first_seen_modified": asset["first_seen_modified"],
        "last_seen_report": asset["last_seen_report"],
        "last_seen_modified": asset["last_seen_modified"],
    }
