"""OCSF v1.4.0 emit for MarlinSpike application-layer findings.

Maps the Python engine's ``risk_findings``, ``c2_indicators``,
``malware_findings``, and ``mitre_classifications`` onto OCSF
Detection Finding records (class 2004). Output is NDJSON suitable for
SIEM ingestion (Splunk, Sentinel, AWS Security Lake, etc.) or
concatenation with ``marlinspike-dpi``'s native OCSF emit (for the
Bronze families: ProtocolTransaction, AssetObservation, ParseAnomaly).

This module covers what ``marlinspike-dpi``'s OCSF renderer does NOT —
the application-layer findings computed in Python on top of aggregated
Bronze events. Together the two surfaces produce a complete OCSF view
of one capture.

CLI::

    python -m marlinspike.emit.ocsf path/to/report.json -o report.ocsf.ndjson

Programmatic::

    from marlinspike.emit import ocsf
    ndjson = ocsf.render_ndjson(report_dict)

OCSF reference: https://schema.ocsf.io/
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from typing import Any

# ── Constants ────────────────────────────────────────────────────────────────

OCSF_SCHEMA_VERSION = "1.4.0"
PRODUCT_NAME = "MarlinSpike"
VENDOR_NAME = "ERISFORGE Ltd."

# OCSF class IDs (Findings category)
CLASS_DETECTION_FINDING = 2004
CATEGORY_FINDINGS = 2

# Activity IDs on Detection Finding class
ACTIVITY_CREATE = 1
ACTIVITY_UPDATE = 2
ACTIVITY_CLOSE = 3

# Severity (MarlinSpike → OCSF)
_SEVERITY_TO_OCSF = {
    "INFO": (1, "Informational"),
    "INFORMATIONAL": (1, "Informational"),
    "LOW": (2, "Low"),
    "MEDIUM": (3, "Medium"),
    "HIGH": (4, "High"),
    "CRITICAL": (5, "Critical"),
    "FATAL": (6, "Fatal"),
}

# Endpoint type IDs
_ENDPOINT_TYPE_UNKNOWN = 0


def _severity(sev: str | None) -> tuple[int, str]:
    return _SEVERITY_TO_OCSF.get((sev or "INFO").upper(), (1, "Informational"))


def _confidence_id(score: float | None) -> int:
    """Map a confidence float (0.0-1.0) to OCSF integer (1=Low, 2=Medium, 3=High)."""
    if score is None:
        return 1
    if score >= 0.8:
        return 3
    if score >= 0.5:
        return 2
    return 1


def _to_unix_ms(iso: str | None) -> int | None:
    """Parse an ISO 8601 string to Unix epoch milliseconds. Returns None if unparseable."""
    if not iso:
        return None
    try:
        # Python 3.10 fromisoformat doesn't accept 'Z' suffix; normalise
        normalised = iso.rstrip("Z")
        if normalised != iso:
            normalised += "+00:00"
        dt = datetime.fromisoformat(normalised)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    except (ValueError, TypeError):
        return None


def _metadata() -> dict:
    """OCSF metadata block — schema version + producing product."""
    # Lazy import to avoid circulars when running without the full app
    try:
        from marlinspike import __version__ as ms_version
    except Exception:
        ms_version = "0.0.0"
    return {
        "version": OCSF_SCHEMA_VERSION,
        "product": {
            "name": PRODUCT_NAME,
            "vendor_name": VENDOR_NAME,
            "version": ms_version,
        },
    }


def _affected_resources(values: list) -> list[dict]:
    """Build OCSF affected_resources[] from a list of asset identifiers (IPs/MACs/hostnames)."""
    return [
        {"type_id": _ENDPOINT_TYPE_UNKNOWN, "type": "Endpoint", "name": str(v), "uid": str(v)}
        for v in values
        if v
    ]


def _signature_for_finding(finding: dict) -> str:
    """Stable signature mirroring the server-side finding signature.

    sha256 of canonical JSON of (category, sorted nodes, sorted edges).
    """
    cat = (finding.get("category") or "").upper()
    nodes = sorted(str(n) for n in (finding.get("affected_nodes") or []) if n)
    edges = sorted(str(e) for e in (finding.get("affected_edges") or []) if e)
    raw = json.dumps({"category": cat, "nodes": nodes, "edges": edges}, sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _prune(obj: Any) -> Any:
    """Recursively drop None values and empty lists/dicts. OCSF prefers absent keys."""
    if isinstance(obj, dict):
        cleaned = {k: _prune(v) for k, v in obj.items() if v is not None}
        return {k: v for k, v in cleaned.items() if v != {} and v != []}
    if isinstance(obj, list):
        return [_prune(v) for v in obj if v is not None]
    return obj


# ── Per-finding renderers ────────────────────────────────────────────────────


def render_risk_finding(finding: dict, report: dict, capture_id: str | None = None) -> dict:
    """Map a MarlinSpike risk_finding onto OCSF Detection Finding (2004)."""
    sev_id, sev_label = _severity(finding.get("severity"))
    timestamp = _to_unix_ms(report.get("timestamp_end") or report.get("timestamp_start"))
    return {
        "class_uid": CLASS_DETECTION_FINDING,
        "class_name": "Detection Finding",
        "category_uid": CATEGORY_FINDINGS,
        "category_name": "Findings",
        "activity_id": ACTIVITY_CREATE,
        "type_uid": CLASS_DETECTION_FINDING * 100 + ACTIVITY_CREATE,
        "type_name": "Detection Finding: Create",
        "time": timestamp,
        "severity_id": sev_id,
        "severity": sev_label,
        "metadata": _metadata(),
        "finding_info": {
            "uid": _signature_for_finding(finding),
            "title": finding.get("category", "Unknown"),
            "desc": finding.get("description", ""),
            "types": [t for t in [finding.get("category")] if t],
            "first_seen_time": timestamp,
        },
        "affected_resources": _affected_resources(finding.get("affected_nodes") or []),
        "remediation": {"desc": finding.get("remediation")} if finding.get("remediation") else None,
        "attacks": _attacks_block(finding.get("attack_techniques")),
        "unmapped": {
            "marlinspike": {
                "category": finding.get("category"),
                "contextual_severity": finding.get("contextual_severity"),
                "affected_edges": finding.get("affected_edges") or [],
                "cvss_impact": finding.get("cvss_impact"),
                "capture_id": capture_id,
            },
        },
    }


def render_c2_indicator(indicator: dict, report: dict, capture_id: str | None = None) -> dict:
    """Map a c2_indicators[] entry onto OCSF Detection Finding (2004)."""
    sev_id, sev_label = _severity(indicator.get("severity"))
    timestamp = _to_unix_ms(report.get("timestamp_end") or report.get("timestamp_start"))
    indicator_type = indicator.get("type", "C2_INDICATOR")
    src = indicator.get("src") or indicator.get("src_ip") or ""
    dst = indicator.get("dst") or indicator.get("dst_ip") or ""
    port = indicator.get("port")
    transport = indicator.get("transport") or ""
    return {
        "class_uid": CLASS_DETECTION_FINDING,
        "class_name": "Detection Finding",
        "category_uid": CATEGORY_FINDINGS,
        "category_name": "Findings",
        "activity_id": ACTIVITY_CREATE,
        "type_uid": CLASS_DETECTION_FINDING * 100 + ACTIVITY_CREATE,
        "type_name": "Detection Finding: Create",
        "time": timestamp,
        "severity_id": sev_id,
        "severity": sev_label,
        "confidence_id": _confidence_id(indicator.get("beacon_score")),
        "confidence": str(int((indicator.get("beacon_score") or 0) * 100)),
        "metadata": _metadata(),
        "finding_info": {
            "uid": f"c2:{indicator_type}:{src}:{dst}:{port or ''}",
            "title": indicator_type,
            "desc": indicator.get("description", ""),
            "types": [indicator_type],
            "first_seen_time": timestamp,
        },
        "affected_resources": _affected_resources([src, dst]),
        "src_endpoint": {"ip": src} if src else None,
        "dst_endpoint": ({"ip": dst, "port": port} if dst else None),
        "connection_info": {"protocol_name": transport.upper()} if transport else None,
        "unmapped": {
            "marlinspike": {
                "type": indicator_type,
                "beacon_score": indicator.get("beacon_score"),
                "interval": indicator.get("interval"),
                "jitter": indicator.get("jitter"),
                "packets": indicator.get("packets"),
                "capture_id": capture_id,
            },
        },
    }


def render_malware_finding(finding: dict, report: dict, capture_id: str | None = None) -> dict:
    """Map a malware_findings[] entry onto OCSF Detection Finding (2004).

    Note: marlinspike-malware emits lowercase severity strings; we
    normalise to the OCSF severity enum.
    """
    sev_id, sev_label = _severity(finding.get("severity"))
    timestamp = _to_unix_ms(finding.get("timestamp")) or _to_unix_ms(
        report.get("timestamp_end") or report.get("timestamp_start")
    )
    confidence = finding.get("confidence")
    return {
        "class_uid": CLASS_DETECTION_FINDING,
        "class_name": "Detection Finding",
        "category_uid": CATEGORY_FINDINGS,
        "category_name": "Findings",
        "activity_id": ACTIVITY_CREATE,
        "type_uid": CLASS_DETECTION_FINDING * 100 + ACTIVITY_CREATE,
        "type_name": "Detection Finding: Create",
        "time": timestamp,
        "severity_id": sev_id,
        "severity": sev_label,
        "confidence_id": _confidence_id(confidence),
        "confidence": str(int((confidence or 0) * 100)),
        "metadata": _metadata(),
        "finding_info": {
            "uid": finding.get("finding_id", ""),
            "title": finding.get("rule_name") or finding.get("rule_id") or "Malware Finding",
            "desc": finding.get("summary", ""),
            "types": [finding.get("family") or "malware"],
            "first_seen_time": timestamp,
        },
        "affected_resources": _affected_resources(
            [finding.get("src_ip"), finding.get("dst_ip")]
        ),
        "src_endpoint": (
            {"ip": finding.get("src_ip"), "mac": finding.get("src_mac")}
            if finding.get("src_ip")
            else None
        ),
        "dst_endpoint": (
            {"ip": finding.get("dst_ip"), "mac": finding.get("dst_mac")}
            if finding.get("dst_ip")
            else None
        ),
        "evidences": (
            [
                {
                    "name": finding.get("observable_field", ""),
                    "value": finding.get("observable_value", ""),
                }
            ]
            if finding.get("observable_field")
            else None
        ),
        "unmapped": {
            "marlinspike": {
                "rule_id": finding.get("rule_id"),
                "family": finding.get("family"),
                "tags": finding.get("tags") or [],
                "source_feed": finding.get("source_feed"),
                "references": finding.get("references") or [],
                "capture_id": capture_id or finding.get("capture_id"),
            },
        },
    }


def render_mitre_classification(
    classification: dict, report: dict, capture_id: str | None = None
) -> dict:
    """Map a mitre_classifications[] entry onto OCSF Detection Finding (2004).

    The marlinspike-mitre plugin emits a classification per technique
    that was observed or inferred in this capture; we emit one OCSF
    Detection Finding per classification with the ATT&CK technique
    populated in the ``attacks[]`` block.
    """
    confidence = classification.get("confidence", 0.5)
    if confidence >= 0.8:
        sev_id, sev_label = 4, "High"
    elif confidence >= 0.5:
        sev_id, sev_label = 3, "Medium"
    else:
        sev_id, sev_label = 2, "Low"
    timestamp = _to_unix_ms(report.get("timestamp_end") or report.get("timestamp_start"))
    technique_id = classification.get("technique_id", "")
    return {
        "class_uid": CLASS_DETECTION_FINDING,
        "class_name": "Detection Finding",
        "category_uid": CATEGORY_FINDINGS,
        "category_name": "Findings",
        "activity_id": ACTIVITY_CREATE,
        "type_uid": CLASS_DETECTION_FINDING * 100 + ACTIVITY_CREATE,
        "type_name": "Detection Finding: Create",
        "time": timestamp,
        "severity_id": sev_id,
        "severity": sev_label,
        "confidence_id": _confidence_id(confidence),
        "confidence": str(int(confidence * 100)),
        "metadata": _metadata(),
        "finding_info": {
            "uid": f"mitre:{technique_id}:{classification.get('domain', '')}",
            "title": classification.get("attack_name") or classification.get("title") or technique_id,
            "desc": classification.get("rationale", ""),
            "types": ["mitre_attack_classification"],
            "first_seen_time": timestamp,
        },
        "affected_resources": _affected_resources(classification.get("affected_nodes") or []),
        "attacks": [
            {
                "version": classification.get("attack_version") or "",
                "technique": {
                    "uid": technique_id,
                    "name": classification.get("attack_name") or "",
                    "src_url": classification.get("technique_url") or "",
                },
                "tactics": [
                    {"uid": t.get("id"), "name": t.get("name"), "src_url": t.get("url")}
                    for t in (classification.get("tactics") or [])
                ]
                or None,
            }
        ],
        "unmapped": {
            "marlinspike": {
                "domain": classification.get("domain"),
                "basis": classification.get("basis"),
                "mapped_from": classification.get("mapped_from") or [],
                "evidence_refs": classification.get("evidence_refs") or [],
                "capture_id": capture_id,
            },
        },
    }


def _attacks_block(technique_ids: list | None) -> list[dict] | None:
    """Build a minimal OCSF attacks[] from a list of ATT&CK technique IDs.

    Used for risk_findings that carry attack_techniques but no full
    classification context. The mitre_classifications path uses
    render_mitre_classification() with full tactic detail.
    """
    if not technique_ids:
        return None
    return [{"technique": {"uid": tid}} for tid in technique_ids]


# ── Top-level entry points ───────────────────────────────────────────────────


def render_report(report: dict, capture_id: str | None = None) -> list[dict]:
    """Render every application-layer finding in the report as OCSF records.

    Returns a list of OCSF Detection Finding (2004) dicts. Wire-derived
    Bronze events (ProtocolTransaction, AssetObservation, ParseAnomaly)
    are NOT in this list — those come from ``marlinspike-dpi``'s native
    OCSF emit. Concatenate the two streams to get a complete OCSF view.
    """
    if capture_id is None:
        capture_id = (report.get("capture_info") or {}).get("capture_source", "")

    records: list[dict] = []
    for finding in report.get("risk_findings") or []:
        records.append(render_risk_finding(finding, report, capture_id))
    for indicator in report.get("c2_indicators") or []:
        records.append(render_c2_indicator(indicator, report, capture_id))
    for finding in report.get("malware_findings") or []:
        records.append(render_malware_finding(finding, report, capture_id))
    for classification in report.get("mitre_classifications") or []:
        records.append(render_mitre_classification(classification, report, capture_id))
    return records


def render_ndjson(report: dict, capture_id: str | None = None) -> str:
    """Render application-layer findings as newline-delimited OCSF JSON."""
    records = render_report(report, capture_id)
    return "\n".join(
        json.dumps(_prune(r), separators=(",", ":"), sort_keys=False) for r in records
    )


# ── CLI ──────────────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m marlinspike.emit.ocsf",
        description="Emit MarlinSpike report findings as OCSF v1.4.0 NDJSON.",
    )
    parser.add_argument("input", help="Path to report.json")
    parser.add_argument(
        "-o",
        "--output",
        help="Output NDJSON path (default: stdout)",
    )
    parser.add_argument(
        "--capture-id",
        help="Override capture_id stamped into unmapped.marlinspike.capture_id",
    )
    args = parser.parse_args(argv)

    try:
        with open(args.input) as f:
            report = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"failed to read report {args.input!r}: {exc}", file=sys.stderr)
        return 1

    ndjson = render_ndjson(report, capture_id=args.capture_id)
    if args.output:
        with open(args.output, "w") as f:
            if ndjson:
                f.write(ndjson + "\n")
    else:
        if ndjson:
            print(ndjson)
    return 0


if __name__ == "__main__":
    sys.exit(main())
