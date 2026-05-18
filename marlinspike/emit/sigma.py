"""Sigma rule emit for MarlinSpike findings that translate to log-event detections.

[Sigma](https://github.com/SigmaHQ/sigma) is a generic detection-rule
format consumed by SIEMs (Splunk, Elastic, Sentinel, etc.). Sigma is
designed for **log events** with field/value pairs — most cleanly,
network-layer Sigma rules target [Zeek](https://zeek.org/) ``conn.log``
and ``dns.log`` (the ``zeek`` product class) or
Suricata ``eve.json`` (``suricata`` class).

Not every MarlinSpike finding maps to Sigma — some are graph-shaped
or flow-aggregate-shaped and don't translate to a per-event detection
predicate. We emit Sigma for the categories that do, and skip the
rest. The user-facing benefit: defenders who found something with
MarlinSpike on a captured PCAP can ship a Sigma rule into their
production SIEM that catches the same activity next time it shows up
in a live Zeek feed.

Categories we currently emit Sigma rules for:

* ``CROSS_PURDUE`` — Zeek conn.log: src_ip in OT range AND
  dst_ip in IT/enterprise range
* ``ICS_EXTERNAL_COMMS`` — Zeek conn.log: src_ip in OT range AND
  dst_ip not in private ranges
* ``CLEARTEXT_REMOTE_ACCESS`` — Zeek conn.log: dst_port matches
  cleartext-remote-access ports (telnet 23, ftp 21, vnc 5900, rsh 514)
* ``CLEARTEXT_ENG`` — Zeek conn.log: protocol = modbus / s7comm /
  dnp3 / iec104 (any unencrypted ICS protocol on engineering-port pairs)
* ``MODBUS_WRITE_ANON`` — Zeek conn.log: protocol = modbus AND
  src_ip not in known-poller list
* ``C2_BEACONING`` — Zeek conn.log + protocol filter: dst_ip in
  observed beacon target list, low conn-duration variance (a Sigma
  consumer needs to compute this server-side; the rule documents the
  pattern)
* ``MALWARE_IOC_MATCH`` — Zeek dns.log / conn.log: query or dst_ip
  matches the IOC observable

Categories deliberately skipped (no clean log-event projection):

* ``EXTERNAL_IPS_OBSERVED`` — informational only
* ``PORT_SCAN_TARGET`` — graph-aggregate; Sigma version would
  re-implement scan detection rather than match a per-event predicate
* ``OPC_NO_SECURITY``, ``NO_AUTH_OBSERVED`` — protocol-handshake-state
  detections, not log-event detections

CLI::

    python -m marlinspike.emit.sigma path/to/report.json -o out_dir/
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

# ── Constants ────────────────────────────────────────────────────────────────

SIGMA_VERSION = "1"  # Sigma rule schema major
PRODUCT_NAME = "MarlinSpike"
VENDOR_NAME = "ERISFORGE Ltd."

# Sigma severity is one of: informational, low, medium, high, critical
_SEVERITY_TO_SIGMA = {
    "INFO": "informational",
    "LOW": "low",
    "MEDIUM": "medium",
    "HIGH": "high",
    "CRITICAL": "critical",
    "FATAL": "critical",
}

# Cleartext remote-access ports (per CLEARTEXT_REMOTE_ACCESS finding)
_CLEARTEXT_REMOTE_PORTS = [21, 23, 514, 5900]

# Cleartext ICS protocols (per CLEARTEXT_ENG finding)
_CLEARTEXT_ICS_PROTOCOLS = ["modbus", "s7comm", "dnp3", "iec104", "bacnet", "profinet"]

# Categories we emit. Map: category -> (rule builder fn name, default severity)
_EMITTABLE = {
    "CROSS_PURDUE",
    "ICS_EXTERNAL_COMMS",
    "CLEARTEXT_REMOTE_ACCESS",
    "CLEARTEXT_ENG",
    "MODBUS_WRITE_ANON",
    "C2_BEACONING",
    "MALWARE_IOC_MATCH",
}


def _now_iso_date() -> str:
    return datetime.now(timezone.utc).strftime("%Y/%m/%d")


def _stable_uuid(category: str, key: str) -> str:
    """Sigma ``id`` field — UUID-shape stable hash."""
    h = hashlib.sha1(
        f"marlinspike|{category}|{key}".encode(), usedforsecurity=False
    ).hexdigest()
    # Format as a UUID for Sigma compatibility
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def _severity_for(finding: dict) -> str:
    sev = (finding.get("severity") or "MEDIUM").upper()
    return _SEVERITY_TO_SIGMA.get(sev, "medium")


def _attack_tags(finding: dict) -> list[str]:
    """Build Sigma ``tags`` from any attack_techniques attached to the finding."""
    tags = []
    for tid in finding.get("attack_techniques") or []:
        tags.append(f"attack.{tid.lower().replace('.', '_')}")
    return tags


def _yaml_dump(rule: dict) -> str:
    """Tiny YAML serialiser for Sigma rules — avoids the PyYAML dep.

    Handles the limited subset of YAML Sigma actually uses: flat
    key/value, nested mappings, lists of scalars or mappings. No
    anchors, no folded scalars, no unicode escapes beyond what JSON
    handles. If the output ever needs to grow, swap to PyYAML.
    """
    return _emit_yaml(rule, indent=0)


def _emit_yaml(value, indent: int) -> str:
    pad = " " * indent
    if isinstance(value, dict):
        out = []
        for k, v in value.items():
            if isinstance(v, (dict, list)) and v:
                out.append(f"{pad}{k}:")
                out.append(_emit_yaml(v, indent + 2))
            elif isinstance(v, list) and not v:
                out.append(f"{pad}{k}: []")
            elif isinstance(v, dict) and not v:
                out.append(f"{pad}{k}: {{}}")
            else:
                out.append(f"{pad}{k}: {_yaml_scalar(v)}")
        return "\n".join(out)
    if isinstance(value, list):
        out = []
        for item in value:
            if isinstance(item, (dict, list)):
                out.append(f"{pad}-")
                out.append(_emit_yaml(item, indent + 2))
            else:
                out.append(f"{pad}- {_yaml_scalar(item)}")
        return "\n".join(out)
    return f"{pad}{_yaml_scalar(value)}"


def _yaml_scalar(value) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    s = str(value)
    # Quote when the string contains special YAML chars or could be
    # mistaken for another type.
    if (
        not s
        or any(c in s for c in ":{}[],&*#?|<>=!%@`'\"")
        or s.lower() in ("true", "false", "null", "yes", "no")
        or s.startswith(("- ", "  "))
        or s.strip() != s
    ):
        # Use double quotes; escape backslashes and double quotes.
        escaped = s.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    return s


# ── Per-category rule builders ───────────────────────────────────────────────


def _base_rule(finding: dict, capture_id: str) -> dict:
    """Common Sigma rule scaffolding."""
    category = finding.get("category") or "UNKNOWN"
    nodes_key = ",".join(sorted(str(n) for n in (finding.get("affected_nodes") or [])))
    return {
        "title": f"MarlinSpike — {category}",
        "id": _stable_uuid(category, nodes_key or capture_id),
        "status": "experimental",
        "description": (
            (finding.get("description") or "").strip()
            or f"Translation of MarlinSpike {category} finding to a Zeek log-event detection."
        ),
        "author": f"{PRODUCT_NAME} ({VENDOR_NAME})",
        "date": _now_iso_date(),
        "references": [
            "https://github.com/eris-ot/marlinspike",
        ],
        "tags": _attack_tags(finding) + [f"marlinspike.{category.lower()}"],
        "level": _severity_for(finding),
    }


def _rule_cross_purdue(finding: dict, capture_id: str) -> dict:
    rule = _base_rule(finding, capture_id)
    nodes = [str(n) for n in (finding.get("affected_nodes") or []) if n]
    rule["logsource"] = {"product": "zeek", "service": "conn"}
    rule["detection"] = {
        "selection": {
            "id.orig_h|in": nodes,
            "id.resp_h|in": nodes,
        },
        "condition": "selection",
    }
    rule["falsepositives"] = ["legitimate cross-zone supervisory polling"]
    return rule


def _rule_ics_external_comms(finding: dict, capture_id: str) -> dict:
    rule = _base_rule(finding, capture_id)
    nodes = [str(n) for n in (finding.get("affected_nodes") or []) if n]
    rule["logsource"] = {"product": "zeek", "service": "conn"}
    rule["detection"] = {
        "selection_ot": {"id.orig_h|in": nodes},
        "filter_private": {
            "id.resp_h|startswith": ["10.", "192.168.", "172.16.", "172.17.", "172.18.",
                                     "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                                     "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                                     "172.29.", "172.30.", "172.31.", "127.", "169.254."],
        },
        "condition": "selection_ot and not filter_private",
    }
    rule["falsepositives"] = [
        "vendor call-home over the public internet (NTP, telemetry — verify and tag)",
    ]
    return rule


def _rule_cleartext_remote(finding: dict, capture_id: str) -> dict:
    rule = _base_rule(finding, capture_id)
    rule["logsource"] = {"product": "zeek", "service": "conn"}
    rule["detection"] = {
        "selection": {
            "id.resp_p|in": _CLEARTEXT_REMOTE_PORTS,
            "proto": "tcp",
            "service": ["telnet", "ftp", "vnc", "rsh"],
        },
        "condition": "selection",
    }
    rule["falsepositives"] = ["legitimate use on isolated maintenance VLANs"]
    return rule


def _rule_cleartext_eng(finding: dict, capture_id: str) -> dict:
    rule = _base_rule(finding, capture_id)
    rule["logsource"] = {"product": "zeek", "service": "conn"}
    rule["detection"] = {
        "selection": {"service|in": _CLEARTEXT_ICS_PROTOCOLS},
        "condition": "selection",
    }
    rule["falsepositives"] = [
        "expected ICS polling traffic — Sigma cannot distinguish authorised from anomalous "
        "without site-specific tagging (asset criticality, allowlisted poller IPs)",
    ]
    return rule


def _rule_modbus_write_anon(finding: dict, capture_id: str) -> dict:
    rule = _base_rule(finding, capture_id)
    nodes = [str(n) for n in (finding.get("affected_nodes") or []) if n]
    rule["logsource"] = {"product": "zeek", "service": "modbus"}
    rule["detection"] = {
        "selection": {
            "func|contains": ["WRITE", "FORCE"],
        },
        "filter_known": {"id.orig_h|in": nodes} if nodes else {"id.orig_h|in": []},
        "condition": "selection and not filter_known",
    }
    rule["falsepositives"] = ["operator HMI traffic from an allowlisted poller"]
    return rule


def _rule_c2_beaconing(finding: dict, capture_id: str) -> dict:
    rule = _base_rule(finding, capture_id)
    nodes = [str(n) for n in (finding.get("affected_nodes") or []) if n]
    rule["logsource"] = {"product": "zeek", "service": "conn"}
    rule["detection"] = {
        "selection": {"id.resp_h|in": nodes} if nodes else {"id.resp_h|exists": True},
        "condition": "selection",
    }
    rule["fields"] = ["ts", "id.orig_h", "id.resp_h", "duration", "orig_bytes", "resp_bytes"]
    rule["falsepositives"] = [
        "periodic legitimate polling that resembles beaconing — verify against site's "
        "expected polling cadence",
    ]
    return rule


def _rule_malware_ioc_match(finding: dict, capture_id: str) -> dict:
    rule = _base_rule(finding, capture_id)
    nodes = [str(n) for n in (finding.get("affected_nodes") or []) if n]
    rule["logsource"] = {"product": "zeek", "service": "conn"}
    rule["detection"] = {
        "selection_dst": {"id.resp_h|in": nodes} if nodes else {"id.resp_h|exists": True},
        "selection_src": {"id.orig_h|in": nodes} if nodes else {"id.orig_h|exists": True},
        "condition": "selection_dst or selection_src",
    }
    rule["falsepositives"] = ["IOC overlap with legitimate traffic — verify against feed quality"]
    return rule


_BUILDERS = {
    "CROSS_PURDUE": _rule_cross_purdue,
    "ICS_EXTERNAL_COMMS": _rule_ics_external_comms,
    "CLEARTEXT_REMOTE_ACCESS": _rule_cleartext_remote,
    "CLEARTEXT_ENG": _rule_cleartext_eng,
    "MODBUS_WRITE_ANON": _rule_modbus_write_anon,
    "C2_BEACONING": _rule_c2_beaconing,
    "MALWARE_IOC_MATCH": _rule_malware_ioc_match,
}


# ── Top-level entry points ───────────────────────────────────────────────────


def render_rules(report: dict, capture_id: str | None = None) -> list[tuple[str, dict]]:
    """Emit Sigma rules for findings that have a log-event projection.

    Returns a list of ``(filename, rule_dict)`` pairs. ``filename`` is
    a stable slug derived from the rule UUID; the caller can write
    these to disk in any directory layout it likes.
    """
    if capture_id is None:
        capture_id = (report.get("capture_info") or {}).get("capture_source") or "capture"

    rules: list[tuple[str, dict]] = []
    seen_ids: set[str] = set()

    # Risk findings
    for finding in report.get("risk_findings") or []:
        category = (finding.get("category") or "").upper()
        if category not in _EMITTABLE:
            continue
        builder = _BUILDERS.get(category)
        if builder is None:
            continue
        rule = builder(finding, capture_id)
        if rule["id"] in seen_ids:
            continue
        seen_ids.add(rule["id"])
        slug = f"{category.lower().replace('_','-')}-{rule['id'][:8]}.yml"
        rules.append((slug, rule))

    # C2 indicators -> C2_BEACONING-shaped Sigma
    for indicator in report.get("c2_indicators") or []:
        synthetic = {
            "category": "C2_BEACONING",
            "severity": indicator.get("severity") or "MEDIUM",
            "description": indicator.get("description") or "",
            "affected_nodes": [
                indicator.get("dst") or indicator.get("dst_ip"),
                indicator.get("src") or indicator.get("src_ip"),
            ],
            "attack_techniques": ["T1071"],
        }
        rule = _rule_c2_beaconing(synthetic, capture_id)
        if rule["id"] in seen_ids:
            continue
        seen_ids.add(rule["id"])
        slug = f"c2-beaconing-{rule['id'][:8]}.yml"
        rules.append((slug, rule))

    # Malware findings -> MALWARE_IOC_MATCH-shaped Sigma
    for finding in report.get("malware_findings") or []:
        synthetic = {
            "category": "MALWARE_IOC_MATCH",
            "severity": (finding.get("severity") or "medium").upper(),
            "description": finding.get("summary") or "",
            "affected_nodes": [finding.get("src_ip"), finding.get("dst_ip")],
            "attack_techniques": [],
        }
        rule = _rule_malware_ioc_match(synthetic, capture_id)
        if rule["id"] in seen_ids:
            continue
        seen_ids.add(rule["id"])
        slug = f"malware-ioc-match-{rule['id'][:8]}.yml"
        rules.append((slug, rule))

    return rules


def render_yaml_concat(report: dict, capture_id: str | None = None) -> str:
    """Render all emittable Sigma rules as a single multi-document YAML stream."""
    rules = render_rules(report, capture_id)
    if not rules:
        return ""
    return "\n---\n".join(_yaml_dump(rule) for _, rule in rules)


# ── CLI ──────────────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m marlinspike.emit.sigma",
        description="Emit Sigma rules from MarlinSpike findings.",
    )
    parser.add_argument("input", help="Path to report.json")
    parser.add_argument(
        "-o",
        "--output",
        help="Output directory (one file per rule) OR a single .yml file "
        "(multi-document YAML stream).",
    )
    parser.add_argument("--capture-id", help="Override capture_id stamped into rule metadata.")
    args = parser.parse_args(argv)

    try:
        with open(args.input) as f:
            report = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"failed to read report {args.input!r}: {exc}", file=sys.stderr)
        return 1

    rules = render_rules(report, capture_id=args.capture_id)
    if not rules:
        print("no Sigma-emittable findings in this report", file=sys.stderr)
        return 1

    if args.output and (args.output.endswith("/") or os.path.isdir(args.output)):
        os.makedirs(args.output, exist_ok=True)
        for filename, rule in rules:
            path = os.path.join(args.output, filename)
            with open(path, "w") as f:
                f.write(_yaml_dump(rule) + "\n")
        print(f"wrote {len(rules)} rule(s) to {args.output}", file=sys.stderr)
    elif args.output:
        with open(args.output, "w") as f:
            f.write(render_yaml_concat(report, capture_id=args.capture_id) + "\n")
        print(f"wrote {len(rules)} rule(s) to {args.output}", file=sys.stderr)
    else:
        print(render_yaml_concat(report, capture_id=args.capture_id))
    return 0


if __name__ == "__main__":
    sys.exit(main())
