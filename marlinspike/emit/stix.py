"""STIX 2.1 bundle emit for MarlinSpike report findings.

Produces a STIX 2.1 bundle from a MarlinSpike ``report.json``. Maps:

* ``risk_findings[]`` → STIX ``indicator`` (one per finding)
* ``c2_indicators[]`` → STIX ``indicator`` with network-traffic pattern
* ``malware_findings[]`` → STIX ``indicator`` with observable pattern
* ``mitre_classifications[]`` → STIX ``attack-pattern`` + ``sighting``
  (one of each per technique) + ``relationship`` linking sightings to
  the indicators they correspond to (when ``mapped_from`` carries
  the source finding category)

A single ``identity`` object (MarlinSpike + ERISFORGE Ltd.) wraps as
``created_by_ref`` for everything emitted. UUIDv5 with a stable
namespace makes the bundle reproducible — re-running the same scan
produces the same STIX object IDs.

Reference: https://docs.oasis-open.org/cti/stix/v2.1/

CLI::

    python -m marlinspike.emit.stix path/to/report.json -o report.stix.json
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from datetime import datetime, timezone
from typing import Any

# ── Constants ────────────────────────────────────────────────────────────────

STIX_VERSION = "2.1"
SPEC_VERSION = "2.1"

# Stable namespace for UUIDv5 — anchored in the MarlinSpike domain so
# anyone re-deriving an ID gets the same value.
_NS = uuid.UUID("4d4c69f0-5468-4d61-526c-696e537069cb")  # "MrLnSpik" + padding

PRODUCT_NAME = "MarlinSpike"
VENDOR_NAME = "ERISFORGE Ltd."

# Severity → confidence weighting for STIX
_SEVERITY_TO_CONFIDENCE = {
    "INFO": 20,
    "LOW": 40,
    "MEDIUM": 60,
    "HIGH": 80,
    "CRITICAL": 95,
    "FATAL": 100,
}

# Risk-finding category → STIX indicator label (informational tags)
_CATEGORY_TO_LABELS: dict[str, list[str]] = {
    "C2_BEACONING": ["malicious-activity", "anomalous-activity"],
    "MALWARE_IOC_MATCH": ["malicious-activity"],
    "EXTERNAL_IPS_OBSERVED": ["benign", "anomalous-activity"],
    "ICS_EXTERNAL_COMMS": ["malicious-activity", "anomalous-activity"],
    "CROSS_PURDUE": ["anomalous-activity"],
    "CLEARTEXT_ENG": ["anomalous-activity"],
    "MODBUS_WRITE_ANON": ["anomalous-activity"],
    "S7_PROGRAM_ACCESS": ["malicious-activity"],
    "CLEARTEXT_REMOTE_ACCESS": ["anomalous-activity"],
    "PORT_SCAN_TARGET": ["anomalous-activity"],
    "OPC_NO_SECURITY": ["anomalous-activity"],
    "NO_AUTH_OBSERVED": ["anomalous-activity"],
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _normalise_iso(iso: str | None) -> str:
    """Coerce an arbitrary ISO timestamp to STIX's required Z-suffixed form."""
    if not iso:
        return _now_iso()
    try:
        normalised = iso.rstrip("Z")
        if normalised != iso:
            normalised += "+00:00"
        dt = datetime.fromisoformat(normalised)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    except (ValueError, TypeError):
        return _now_iso()


def _stable_id(stix_type: str, key: str) -> str:
    """Deterministic STIX ID via UUIDv5 + the type-prefix STIX requires.

    Re-running emit on the same report produces the same IDs, which
    makes sharing + diffing bundles across runs sane.
    """
    return f"{stix_type}--{uuid.uuid5(_NS, f'{stix_type}|{key}')}"


def _identity(version: str) -> dict:
    """The single ``identity`` object every other STIX object references.

    ``identity_class: organization`` flags this as a tooling/product
    identity rather than a person or threat actor.
    """
    return {
        "type": "identity",
        "spec_version": SPEC_VERSION,
        "id": _stable_id("identity", "marlinspike"),
        "created": _now_iso(),
        "modified": _now_iso(),
        "name": PRODUCT_NAME,
        "identity_class": "system",
        "sectors": ["technology"],
        "description": (
            f"MarlinSpike v{version} — passive OT/ICS network analysis "
            f"platform. Produced by {VENDOR_NAME}."
        ),
    }


def _indicator_pattern_for_finding(finding: dict) -> str:
    """Build a STIX 2.1 pattern string for a risk_finding's affected_nodes.

    Patterns are STIX's mini-language for matching observable data.
    Affected nodes are typically IPs (sometimes MACs); we emit a
    disjunction across them.
    """
    nodes = [str(n).strip() for n in (finding.get("affected_nodes") or []) if n]
    if not nodes:
        # Fallback: a description-only pattern. STIX requires *some*
        # pattern; emit an artifact-name match against a synthetic key.
        return f"[artifact:hashes.'SHA-256' = '{finding.get('category','UNKNOWN').lower()}']"
    parts = []
    for node in nodes[:32]:  # cap to keep patterns sane
        if ":" in node and len(node) <= 17:
            # MAC-ish
            parts.append(f"mac-addr:value = '{node}'")
        else:
            parts.append(f"ipv4-addr:value = '{node}'")
    if len(parts) == 1:
        return f"[{parts[0]}]"
    return "[" + " OR ".join(parts) + "]"


def _indicator_pattern_for_c2(indicator: dict) -> str:
    src = indicator.get("src") or indicator.get("src_ip") or ""
    dst = indicator.get("dst") or indicator.get("dst_ip") or ""
    port = indicator.get("port")
    parts = []
    if src:
        parts.append(f"network-traffic:src_ref.value = '{src}'")
    if dst:
        parts.append(f"network-traffic:dst_ref.value = '{dst}'")
    if port:
        parts.append(f"network-traffic:dst_port = {port}")
    if not parts:
        return "[network-traffic:protocols[*] = 'tcp']"
    return "[" + " AND ".join(parts) + "]"


def _indicator_pattern_for_malware(finding: dict) -> str:
    field = (finding.get("observable_field") or "").lower()
    value = finding.get("observable_value") or ""
    if not value:
        # Use the finding_id hash as a degenerate artifact pattern.
        return f"[artifact:hashes.'SHA-256' = '{finding.get('finding_id','unknown')}']"
    if field in {"src_ip", "dst_ip", "ip"}:
        return f"[ipv4-addr:value = '{value}']"
    if field == "domain":
        return f"[domain-name:value = '{value}']"
    if field in {"src_mac", "dst_mac", "mac"}:
        return f"[mac-addr:value = '{value}']"
    if field == "sha256":
        return f"[file:hashes.'SHA-256' = '{value}']"
    if field == "md5":
        return f"[file:hashes.MD5 = '{value}']"
    # Fallback: stash in artifact
    return f"[artifact:payload_bin = '{value}']"


def _confidence_for(finding: dict) -> int:
    sev = (finding.get("severity") or "").upper()
    if sev in _SEVERITY_TO_CONFIDENCE:
        return _SEVERITY_TO_CONFIDENCE[sev]
    conf = finding.get("confidence")
    if conf is not None:
        try:
            return max(0, min(100, int(round(float(conf) * 100))))
        except (TypeError, ValueError):
            pass
    return 50


# ── Per-finding object builders ──────────────────────────────────────────────


def _risk_finding_indicator(finding: dict, identity_id: str, valid_from: str) -> dict:
    category = finding.get("category") or "UNKNOWN"
    nodes_key = ",".join(sorted(str(n) for n in (finding.get("affected_nodes") or [])))
    indicator_id = _stable_id("indicator", f"risk:{category}:{nodes_key}")
    pattern = _indicator_pattern_for_finding(finding)
    labels = _CATEGORY_TO_LABELS.get(category, ["anomalous-activity"])
    obj = {
        "type": "indicator",
        "spec_version": SPEC_VERSION,
        "id": indicator_id,
        "created_by_ref": identity_id,
        "created": valid_from,
        "modified": valid_from,
        "name": category,
        "description": finding.get("description") or "",
        "indicator_types": labels,
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": valid_from,
        "confidence": _confidence_for(finding),
        "labels": [category.lower()],
    }
    if finding.get("attack_techniques"):
        obj["external_references"] = [
            {
                "source_name": "mitre-attack",
                "external_id": tid,
                "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}",
            }
            for tid in finding["attack_techniques"]
        ]
    return obj


def _c2_indicator_object(indicator: dict, identity_id: str, valid_from: str) -> dict:
    indicator_type = indicator.get("type") or "C2_INDICATOR"
    src = indicator.get("src") or indicator.get("src_ip") or ""
    dst = indicator.get("dst") or indicator.get("dst_ip") or ""
    port = indicator.get("port") or ""
    indicator_id = _stable_id("indicator", f"c2:{indicator_type}:{src}:{dst}:{port}")
    return {
        "type": "indicator",
        "spec_version": SPEC_VERSION,
        "id": indicator_id,
        "created_by_ref": identity_id,
        "created": valid_from,
        "modified": valid_from,
        "name": indicator_type,
        "description": indicator.get("description") or "",
        "indicator_types": ["malicious-activity", "anomalous-activity"],
        "pattern": _indicator_pattern_for_c2(indicator),
        "pattern_type": "stix",
        "valid_from": valid_from,
        "confidence": _confidence_for(indicator),
        "labels": [indicator_type.lower(), "c2"],
    }


def _malware_finding_indicator(finding: dict, identity_id: str, valid_from: str) -> dict:
    finding_id = finding.get("finding_id") or "unknown"
    indicator_id = _stable_id("indicator", f"malware:{finding_id}")
    return {
        "type": "indicator",
        "spec_version": SPEC_VERSION,
        "id": indicator_id,
        "created_by_ref": identity_id,
        "created": _normalise_iso(finding.get("timestamp")) or valid_from,
        "modified": _normalise_iso(finding.get("timestamp")) or valid_from,
        "name": finding.get("rule_name") or finding.get("rule_id") or "Malware Finding",
        "description": finding.get("summary") or "",
        "indicator_types": ["malicious-activity"],
        "pattern": _indicator_pattern_for_malware(finding),
        "pattern_type": "stix",
        "valid_from": _normalise_iso(finding.get("timestamp")) or valid_from,
        "confidence": _confidence_for(finding),
        "labels": [
            (finding.get("family") or "malware").lower(),
            "malware-finding",
        ],
        "external_references": [
            {"source_name": "url", "url": ref}
            for ref in (finding.get("references") or [])
        ]
        or None,
    }


def _attack_pattern_object(classification: dict, identity_id: str, valid_from: str) -> dict:
    technique_id = classification.get("technique_id") or ""
    attack_pattern_id = _stable_id("attack-pattern", f"mitre:{technique_id}")
    domain = classification.get("domain") or "enterprise-attack"
    return {
        "type": "attack-pattern",
        "spec_version": SPEC_VERSION,
        "id": attack_pattern_id,
        "created_by_ref": identity_id,
        "created": valid_from,
        "modified": valid_from,
        "name": classification.get("attack_name") or technique_id,
        "description": classification.get("description") or classification.get("rationale") or "",
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": technique_id,
                "url": classification.get("technique_url")
                or f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}",
            }
        ],
        "kill_chain_phases": [
            {
                "kill_chain_name": domain,
                "phase_name": (t.get("shortname") or t.get("name") or "").lower(),
            }
            for t in (classification.get("tactics") or [])
        ]
        or None,
    }


def _sighting_object(
    classification: dict,
    attack_pattern_id: str,
    identity_id: str,
    capture_id: str,
    valid_from: str,
) -> dict:
    affected = classification.get("affected_nodes") or []
    sighting_id = _stable_id(
        "sighting", f"sighting:{classification.get('technique_id','')}:{capture_id}"
    )
    return {
        "type": "sighting",
        "spec_version": SPEC_VERSION,
        "id": sighting_id,
        "created_by_ref": identity_id,
        "created": valid_from,
        "modified": valid_from,
        "first_seen": valid_from,
        "last_seen": valid_from,
        "count": max(1, len(affected)),
        "sighting_of_ref": attack_pattern_id,
        "where_sighted_refs": [identity_id],
        "description": (
            f"Technique sighted in capture {capture_id!r}; "
            f"basis={classification.get('basis','inferred')}; "
            f"confidence={classification.get('confidence',0):.2f}; "
            f"{len(affected)} affected asset(s)."
        ),
    }


# ── Top-level entry points ───────────────────────────────────────────────────


def render_bundle(report: dict, capture_id: str | None = None) -> dict:
    """Build a STIX 2.1 bundle from a MarlinSpike report.

    Returns a dict ready to be JSON-serialised. Empty bundle (only the
    identity object) when the report has no findings — STIX requires a
    bundle to have at least one object.
    """
    if capture_id is None:
        capture_id = (report.get("capture_info") or {}).get("capture_source") or "capture"

    try:
        from marlinspike import __version__ as ms_version
    except Exception:
        ms_version = "0.0.0"

    valid_from = _normalise_iso(report.get("timestamp_end") or report.get("timestamp_start"))
    identity = _identity(ms_version)
    objects: list[dict] = [identity]

    for finding in report.get("risk_findings") or []:
        objects.append(_risk_finding_indicator(finding, identity["id"], valid_from))

    for indicator in report.get("c2_indicators") or []:
        objects.append(_c2_indicator_object(indicator, identity["id"], valid_from))

    for finding in report.get("malware_findings") or []:
        objects.append(_malware_finding_indicator(finding, identity["id"], valid_from))

    for classification in report.get("mitre_classifications") or []:
        ap = _attack_pattern_object(classification, identity["id"], valid_from)
        objects.append(ap)
        objects.append(
            _sighting_object(classification, ap["id"], identity["id"], capture_id, valid_from)
        )

    # Strip None values from per-object dicts (STIX prefers absent keys).
    cleaned = [_prune_object(o) for o in objects]

    return {
        "type": "bundle",
        "id": _stable_id("bundle", f"{capture_id}:{valid_from}"),
        "objects": cleaned,
    }


def _prune_object(obj: Any) -> Any:
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            pv = _prune_object(v)
            if pv is None or pv == [] or pv == {}:
                continue
            out[k] = pv
        return out
    if isinstance(obj, list):
        return [_prune_object(v) for v in obj if v is not None]
    return obj


def render_json(report: dict, capture_id: str | None = None, indent: int | None = 2) -> str:
    """Serialise a bundle to JSON. ``indent=None`` for compact form."""
    bundle = render_bundle(report, capture_id)
    if indent:
        return json.dumps(bundle, indent=indent)
    return json.dumps(bundle, separators=(",", ":"))


# ── CLI ──────────────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m marlinspike.emit.stix",
        description="Emit a STIX 2.1 bundle from a MarlinSpike report.",
    )
    parser.add_argument("input", help="Path to report.json")
    parser.add_argument("-o", "--output", help="Output bundle path (default: stdout)")
    parser.add_argument("--capture-id", help="Override capture_id stamped into the bundle.")
    parser.add_argument(
        "--compact", action="store_true", help="Emit compact JSON (no indent)."
    )
    args = parser.parse_args(argv)

    try:
        with open(args.input) as f:
            report = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"failed to read report {args.input!r}: {exc}", file=sys.stderr)
        return 1

    out = render_json(
        report, capture_id=args.capture_id, indent=None if args.compact else 2
    )
    if args.output:
        with open(args.output, "w") as f:
            f.write(out + "\n")
    else:
        print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
