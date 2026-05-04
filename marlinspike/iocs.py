"""IOC threat-hunting helpers — line parser and cross-report scan worker.

No external dependencies: stdlib re, ipaddress only.
"""

import ipaddress
import re
from typing import Any

# ── Constants ──────────────────────────────────────────────────

VALID_IOC_TYPES = frozenset({"ip", "mac", "oui", "domain", "sha256", "md5"})
VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})

_MAC_RE = re.compile(
    r"^([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$"
)
_OUI_RE = re.compile(
    r"^[0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}$"
)
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_MD5_RE = re.compile(r"^[0-9a-fA-F]{32}$")
# Basic domain: optional wildcard prefix, labels, TLD; no bare IPs
_DOMAIN_RE = re.compile(
    r"^(?:\*\.)?(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]{2,}$"
)

_MAX_HITS_TOTAL = 1000
_MAX_HITS_PER_REPORT = 50


# ── Type detection ─────────────────────────────────────────────

def _detect_type(value: str) -> str | None:
    """Return the IOC type for *value*, or None if unrecognisable."""
    # IPv4 / IPv6
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass

    if _MAC_RE.match(value):
        return "mac"
    if _OUI_RE.match(value):
        return "oui"
    if _SHA256_RE.match(value):
        return "sha256"
    if _MD5_RE.match(value):
        return "md5"
    if _DOMAIN_RE.match(value):
        return "domain"
    return None


# ── Bulk-paste parser ──────────────────────────────────────────

def parse_ioc_paste(text: str, default_type: str = "ip") -> dict:
    """Parse a newline-separated IOC paste.

    Returns ``{"entries": [...], "errors": [...]}``.  Each entry is
    ``{"ioc_type": ..., "value": ...}``.  Comments (#) and blank lines
    are ignored.  Type is auto-detected; falls back to *default_type* when
    detection fails.
    """
    entries: list[dict] = []
    errors: list[dict] = []

    for lineno, raw in enumerate(text.splitlines(), start=1):
        # Strip inline comments
        line = raw.split("#")[0].strip()
        if not line:
            continue

        # A line may carry an optional trailing label/severity separated by
        # whitespace or comma — we only parse the first token as the IOC value
        # for now (simple MVP).  Full structured CSV is a separate endpoint.
        token = line.split()[0] if line.split() else line

        detected = _detect_type(token)
        ioc_type = detected if detected is not None else default_type

        if ioc_type not in VALID_IOC_TYPES:
            errors.append({"line": lineno, "reason": f"Unknown IOC type '{ioc_type}' for value '{token}'"})
            continue

        entries.append({"ioc_type": ioc_type, "value": token})

    return {"entries": entries, "errors": errors}


# ── Normalisation helpers ──────────────────────────────────────

def _norm_mac(v: str) -> str:
    """Normalise MAC/OUI to colon-separated lowercase."""
    return v.replace("-", ":").lower()


def _norm_ip(v: str) -> str:
    """Normalise IP address (strips leading zeros etc.)."""
    try:
        return str(ipaddress.ip_address(v))
    except ValueError:
        return v.lower()


def _norm_value(ioc_type: str, value: str) -> str:
    if ioc_type == "ip":
        return _norm_ip(value)
    if ioc_type in ("mac", "oui"):
        return _norm_mac(value)
    return value.lower()


# ── Report field extraction helpers ───────────────────────────

def _iter_strings(obj: Any):
    """Yield every string leaf reachable from *obj* (list/dict/str)."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, list):
        for item in obj:
            yield from _iter_strings(item)
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _iter_strings(v)


def _scan_report(report: dict, entries: list[dict]) -> list[dict]:
    """Scan *report* for each IOC entry.

    Returns a list of match dicts:
        {"ioc": {...}, "matches": [{"location": "...", "context": "..."}]}

    Capped at _MAX_HITS_PER_REPORT total matches (across all entries).
    """
    nodes = report.get("nodes") or []
    conversations = report.get("conversations") or []
    c2_indicators = report.get("c2_indicators") or []
    risk_findings = report.get("risk_findings") or []
    malware_findings = report.get("malware_findings") or []

    hit_count = 0
    per_entry_hits: list[dict] = []

    for entry in entries:
        if hit_count >= _MAX_HITS_PER_REPORT:
            break

        ioc_type = entry["ioc_type"]
        raw_value = entry["value"]
        norm = _norm_value(ioc_type, raw_value)
        matches: list[dict] = []

        def _record(location: str, context: str):
            nonlocal hit_count
            if hit_count < _MAX_HITS_PER_REPORT:
                matches.append({"location": location, "context": context})
                hit_count += 1

        if ioc_type == "ip":
            for node in nodes:
                node_ip = _norm_ip(str(node.get("ip") or ""))
                if node_ip == norm:
                    _record("node.ip", node_ip)
            for conv in conversations:
                for field in ("src_ip", "dst_ip"):
                    v = _norm_ip(str(conv.get(field) or ""))
                    if v == norm:
                        _record(f"conversation.{field}", v)
            for ind in c2_indicators:
                for field in ("dst", "src"):
                    v = _norm_ip(str(ind.get(field) or ""))
                    if v == norm:
                        _record(f"c2_indicator.{field}", v)
            for rf in risk_findings:
                for val in _iter_strings(rf.get("affected_nodes") or []):
                    if _norm_ip(val) == norm:
                        _record("risk_finding.affected_nodes", val)

        elif ioc_type == "mac":
            for node in nodes:
                v = _norm_mac(str(node.get("mac") or ""))
                if v == norm:
                    _record("node.mac", v)
            for conv in conversations:
                for field in ("src_mac", "dst_mac"):
                    v = _norm_mac(str(conv.get(field) or ""))
                    if v == norm:
                        _record(f"conversation.{field}", v)
            for ind in c2_indicators:
                for field in ("dst_mac", "src_mac"):
                    v = _norm_mac(str(ind.get(field) or ""))
                    if v == norm:
                        _record(f"c2_indicator.{field}", v)

        elif ioc_type == "oui":
            # OUI is the first 3 octets of a MAC
            for node in nodes:
                mac = _norm_mac(str(node.get("mac") or ""))
                if mac[:8] == norm:
                    _record("node.mac (oui)", mac)
            for conv in conversations:
                for field in ("src_mac", "dst_mac"):
                    mac = _norm_mac(str(conv.get(field) or ""))
                    if mac[:8] == norm:
                        _record(f"conversation.{field} (oui)", mac)

        elif ioc_type == "domain":
            for conv in conversations:
                dns_queries = conv.get("dns_queries") or []
                for q in dns_queries:
                    if isinstance(q, str) and norm in q.lower():
                        _record("conversation.dns_queries", q)
                    elif isinstance(q, dict):
                        for qs in _iter_strings(q):
                            if norm in qs.lower():
                                _record("conversation.dns_queries", qs)
                                break

        elif ioc_type == "sha256":
            for mf in malware_findings:
                v = str(mf.get("sha256") or "").lower()
                if v == norm:
                    _record("malware_finding.sha256", v)

        elif ioc_type == "md5":
            for mf in malware_findings:
                v = str(mf.get("md5") or "").lower()
                if v == norm:
                    _record("malware_finding.md5", v)

        if matches:
            per_entry_hits.append({
                "ioc": {
                    "id": entry.get("id"),
                    "ioc_type": ioc_type,
                    "value": raw_value,
                    "label": entry.get("label"),
                    "severity": entry.get("severity"),
                },
                "matches": matches,
            })

    return per_entry_hits


def scan_ioc_list_against_reports(
    entries: list[dict],
    report_paths: list[str],
    loader,
) -> dict:
    """Scan all *report_paths* for hits from *entries*.

    *loader* is a callable ``(path: str) -> dict`` that loads and returns a
    report dict (e.g. ``_load_report_with_extensions``).

    Returns the full scan result payload.
    """
    all_hits: list[dict] = []
    truncated = False
    scanned = 0

    for path in report_paths:
        if len(all_hits) >= _MAX_HITS_TOTAL:
            truncated = True
            break
        try:
            report = loader(path)
        except Exception:
            continue
        if not isinstance(report, dict):
            continue

        scanned += 1
        report_hits = _scan_report(report, entries)

        import os as _os
        filename = _os.path.basename(path)
        for entry_hit in report_hits:
            if len(all_hits) >= _MAX_HITS_TOTAL:
                truncated = True
                break
            all_hits.append({
                "report": filename,
                "ioc": entry_hit["ioc"],
                "matches": entry_hit["matches"],
            })

    # Build summary
    by_severity: dict[str, int] = {}
    by_ioc_type: dict[str, int] = {}
    for hit in all_hits:
        sev = (hit["ioc"].get("severity") or "unknown").lower()
        itype = hit["ioc"].get("ioc_type", "unknown")
        by_severity[sev] = by_severity.get(sev, 0) + len(hit["matches"])
        by_ioc_type[itype] = by_ioc_type.get(itype, 0) + len(hit["matches"])

    return {
        "scanned_reports": scanned,
        "hits": all_hits,
        "summary": {
            "total_hits": sum(len(h["matches"]) for h in all_hits),
            "by_severity": by_severity,
            "by_ioc_type": by_ioc_type,
        },
        "truncated": truncated,
    }
