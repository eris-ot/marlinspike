"""marlinspike-cisa advisory search plugin.

Searches a locally-synced CISA catalog (KEV + ICS advisories) by a given
term and emits a sidecar JSON artifact in the marlinspike plugin envelope.
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from . import CONTRACT_VERSION, PLUGIN_ID, PLUGIN_VERSION
from .catalog import DEFAULT_CATALOG_PATH, get_advisories, get_source_metadata, load_catalog

DEFAULT_RULES_PATH = Path(__file__).resolve().parents[2] / "rules" / "cisa" / "base.yaml"

# Fields searched in order of relevance; weight determines score contribution.
# cve_refs is a list field on ICS entries; _field_text() handles the conversion.
_SEARCH_FIELDS: list[tuple[str, int]] = [
    ("id", 100),
    ("cve_refs", 80),
    ("vendor", 60),
    ("product", 50),
    ("title", 30),
    ("description", 10),
    ("notes", 5),
]


def _normalize(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip().lower()


def _field_text(advisory: dict[str, Any], field: str) -> str:
    """Return normalized text for a field, joining list values with spaces."""
    value = advisory.get(field)
    if isinstance(value, list):
        return _normalize(" ".join(str(v) for v in value))
    return _normalize(value or "")


def _load_expansions(rules_path: Path) -> dict[str, list[str]]:
    """Parse rules YAML and return a mapping from each keyword/alias to all
    terms in its group (including the group name itself)."""
    if not rules_path.exists():
        return {}
    with rules_path.open() as fh:
        data = yaml.safe_load(fh)
    expansions: dict[str, list[str]] = {}
    for group in data.get("groups") or []:
        name = _normalize(group.get("name", ""))
        aliases = [_normalize(str(a)) for a in (group.get("aliases") or [])]
        all_terms = [t for t in [name] + aliases if t]
        for term in all_terms:
            expansions[term] = all_terms
    return expansions


def _build_term_groups(term: str, expansions: dict[str, list[str]]) -> list[list[str]]:
    """Split a search term into groups. Each group is a list of equivalent
    terms (original word + aliases). All groups must match (AND); any term
    within a group may match (OR)."""
    normalized = _normalize(term)
    # Check the full term first so multi-word aliases like "allen bradley" expand correctly.
    if normalized in expansions:
        return [expansions[normalized]]
    words = [w for w in normalized.split() if w]
    return [expansions.get(w, [w]) for w in words]


def _score_advisory(advisory: dict[str, Any], term_groups: list[list[str]]) -> int:
    """Score an advisory against term groups.

    AND logic between groups — every group must produce a non-zero score or
    the whole advisory scores 0. OR logic within each group — the best-matching
    alias contributes the group score.
    """
    total = 0
    for group in term_groups:
        group_score = 0
        for term in group:
            for field, weight in _SEARCH_FIELDS:
                haystack = _field_text(advisory, field)
                if not haystack or term not in haystack:
                    continue
                if re.search(r"\b" + re.escape(term) + r"\b", haystack):
                    group_score = max(group_score, weight * 2)
                else:
                    group_score = max(group_score, weight)
        if group_score == 0:
            return 0  # AND: one unmatched group disqualifies the advisory
        total += group_score
    return total


def search(
    term: str,
    catalog: dict[str, Any],
    *,
    limit: int = 0,
    min_score: int = 1,
    rules_path: Path = DEFAULT_RULES_PATH,
) -> list[dict[str, Any]]:
    """Return advisories matching *term*, ranked by relevance.

    Vendor aliases defined in the rules file are automatically applied:
    searching 'rockwell' also matches entries for 'allen-bradley', 'logix', etc.
    Multi-word terms use AND logic — all words must appear somewhere in the
    advisory for it to qualify.

    Primary sort: relevance score (descending).
    Secondary sort: cvss_score (descending) as a tiebreaker.
    Tertiary sort: date_added (ascending, oldest first) for stable ordering.
    """
    expansions = _load_expansions(rules_path)
    term_groups = _build_term_groups(term, expansions)
    if not term_groups:
        return []

    advisories = get_advisories(catalog)
    scored: list[tuple[int, dict[str, Any]]] = []
    for advisory in advisories:
        score = _score_advisory(advisory, term_groups)
        if score >= min_score:
            scored.append((score, advisory))

    # Sort: (-relevance_score, -cvss_score, date_added)
    def _sort_key(item: tuple[int, dict[str, Any]]) -> tuple[int, float, str]:
        score, advisory = item
        cvss = advisory.get("cvss_score")
        cvss_val = float(cvss) if cvss is not None else 0.0
        return (-score, -cvss_val, advisory.get("date_added") or "")

    scored.sort(key=_sort_key)
    results = [advisory for _, advisory in scored]
    if limit > 0:
        results = results[:limit]
    return results


def _build_output(
    term: str,
    results: list[dict[str, Any]],
    catalog: dict[str, Any],
    warnings: list[str],
    expanded_terms: list[str],
) -> dict[str, Any]:
    sources = get_source_metadata(catalog)
    kev_meta = sources.get("kev") or {}

    ransomware_total = sum(1 for a in results if a.get("ransomware"))
    kev_total = sum(1 for a in results if a.get("type") == "kev")
    ics_total = sum(1 for a in results if a.get("type") == "ics")

    by_vendor: dict[str, list[str]] = {}
    for advisory in results:
        vendor = str(advisory.get("vendor") or "")
        by_vendor.setdefault(vendor, []).append(advisory["id"])

    summary: dict[str, Any] = {
        "term": term,
        "total_matched": len(results),
        "kev_matched": kev_total,
        "ics_matched": ics_total,
        "ransomware_total": ransomware_total,
    }
    if expanded_terms and expanded_terms != [_normalize(term)]:
        summary["expanded_terms"] = expanded_terms

    return {
        "plugin_id": PLUGIN_ID,
        "plugin_version": PLUGIN_VERSION,
        "contract_version": CONTRACT_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "data": {
            "advisories": results,
            "by_vendor": {
                vendor: sorted(ids) for vendor, ids in sorted(by_vendor.items())
            },
        },
        "warnings": warnings,
        "source_metadata": {
            "kev_catalog_version": kev_meta.get("catalog_version", ""),
            "kev_date_released": kev_meta.get("date_released", ""),
            "kev_total_entries": kev_meta.get("count", 0),
            "catalog_generated_at": catalog.get("generated_at", ""),
        },
    }


def run(
    term: str,
    output_path: Path,
    catalog_path: Path = DEFAULT_CATALOG_PATH,
    *,
    limit: int = 0,
    rules_path: Path = DEFAULT_RULES_PATH,
) -> dict[str, Any]:
    warnings: list[str] = []
    catalog = load_catalog(catalog_path)

    expansions = _load_expansions(rules_path)
    term_groups = _build_term_groups(term, expansions)
    expanded_terms = sorted({t for group in term_groups for t in group})

    results = search(term, catalog, limit=limit, rules_path=rules_path)

    if not results:
        warnings.append(f"No advisories matched term: {term!r}")

    output = _build_output(term, results, catalog, warnings, expanded_terms)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w") as fh:
        json.dump(output, fh, indent=2)
        fh.write("\n")

    return output


# ---------------------------------------------------------------------------
# Feature 3: Report enrichment
# ---------------------------------------------------------------------------

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


def _extract_report_terms(
    report: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    """Parse a marlinspike report JSON and return:
      - asset_terms: list of {node_id, vendor, product, search_term}
      - bare_cve_ids: CVE IDs from risk_findings with no vendor context
      - warnings: non-fatal issues detected
    """
    warnings: list[str] = []
    seen_pairs: set[tuple[str, str]] = set()
    asset_terms: list[dict[str, Any]] = []

    def _add_asset(node_id: str, vendor: str, product: str) -> None:
        vendor = (vendor or "").strip()
        product = (product or "").strip()
        key = (vendor.lower(), product.lower())
        if not vendor and not product:
            return
        if key in seen_pairs:
            return
        seen_pairs.add(key)
        if vendor and product:
            term = f"{vendor} {product}"
        elif vendor:
            term = vendor
        else:
            term = product
        asset_terms.append(
            {
                "node_id": node_id,
                "vendor": vendor,
                "product": product,
                "search_term": term.lower(),
            }
        )

    # asset_inventory
    for item in report.get("asset_inventory") or []:
        node_id = str(item.get("node_id") or "")
        vendor = str(item.get("vendor") or "")
        product = str(item.get("product") or "")
        _add_asset(node_id, vendor, product)

    # nodes
    for item in report.get("nodes") or []:
        node_id = str(item.get("id") or "")
        vendor = str(item.get("vendor") or "")
        product = str(item.get("product") or "")
        _add_asset(node_id, vendor, product)

    # Bare CVE IDs from risk_findings
    seen_cves: set[str] = set()
    bare_cves: list[str] = []
    for finding in report.get("risk_findings") or []:
        cve_id = str(finding.get("cve_id") or "").strip()
        if cve_id and _CVE_RE.match(cve_id) and cve_id.upper() not in seen_cves:
            seen_cves.add(cve_id.upper())
            bare_cves.append(cve_id)

    if not asset_terms and not bare_cves:
        warnings.append("No recognizable assets or CVE IDs found in report")

    return asset_terms, bare_cves, warnings


def run_report(
    report_path: Path,
    output_path: Path,
    catalog_path: Path = DEFAULT_CATALOG_PATH,
    *,
    rules_path: Path = DEFAULT_RULES_PATH,
) -> dict[str, Any]:
    """Search the catalog for all assets and CVEs referenced in a marlinspike report."""
    warnings: list[str] = []

    with report_path.open() as fh:
        report: dict[str, Any] = json.load(fh)

    catalog = load_catalog(catalog_path)
    sources = get_source_metadata(catalog)
    kev_meta = sources.get("kev") or {}

    asset_terms, bare_cves, extract_warnings = _extract_report_terms(report)
    warnings.extend(extract_warnings)

    # Track all advisory IDs seen to deduplicate all_advisories
    seen_advisory_ids: set[str] = set()
    all_advisories: list[dict[str, Any]] = []

    by_asset: list[dict[str, Any]] = []

    for asset in asset_terms:
        results = search(
            asset["search_term"],
            catalog,
            rules_path=rules_path,
        )
        # Track per-asset
        by_asset.append(
            {
                "node_id": asset["node_id"],
                "vendor": asset["vendor"],
                "product": asset["product"],
                "search_term": asset["search_term"],
                "advisory_count": len(results),
                "advisories": results,
            }
        )
        # Deduplicate into all_advisories
        for adv in results:
            adv_id = adv.get("id", "")
            if adv_id not in seen_advisory_ids:
                seen_advisory_ids.add(adv_id)
                all_advisories.append(adv)

    # Bare CVE ID searches
    for cve_id in bare_cves:
        results = search(cve_id, catalog, rules_path=rules_path)
        for adv in results:
            adv_id = adv.get("id", "")
            if adv_id not in seen_advisory_ids:
                seen_advisory_ids.add(adv_id)
                all_advisories.append(adv)

    # Sort all_advisories by cvss_score descending, then date_added ascending
    def _adv_sort_key(adv: dict[str, Any]) -> tuple[float, str]:
        cvss = adv.get("cvss_score")
        cvss_val = float(cvss) if cvss is not None else 0.0
        return (-cvss_val, adv.get("date_added") or "")

    all_advisories.sort(key=_adv_sort_key)

    # Build by_vendor across all_advisories
    by_vendor: dict[str, list[str]] = {}
    for adv in all_advisories:
        vendor = str(adv.get("vendor") or "")
        by_vendor.setdefault(vendor, []).append(adv["id"])

    kev_matched = sum(1 for a in all_advisories if a.get("type") == "kev")
    ics_matched = sum(1 for a in all_advisories if a.get("type") == "ics")
    ransomware_total = sum(1 for a in all_advisories if a.get("ransomware"))
    unique_terms = len(asset_terms) + len(bare_cves)

    summary: dict[str, Any] = {
        "source_report": str(report_path),
        "assets_searched": len(asset_terms),
        "unique_terms": unique_terms,
        "total_advisories": len(all_advisories),
        "kev_matched": kev_matched,
        "ics_matched": ics_matched,
        "ransomware_total": ransomware_total,
    }

    output: dict[str, Any] = {
        "plugin_id": PLUGIN_ID,
        "plugin_version": PLUGIN_VERSION,
        "contract_version": CONTRACT_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "data": {
            "by_asset": by_asset,
            "all_advisories": all_advisories,
            "by_vendor": {
                vendor: sorted(ids) for vendor, ids in sorted(by_vendor.items())
            },
        },
        "warnings": warnings,
        "source_metadata": {
            "kev_catalog_version": kev_meta.get("catalog_version", ""),
            "kev_date_released": kev_meta.get("date_released", ""),
            "kev_total_entries": kev_meta.get("count", 0),
            "catalog_generated_at": catalog.get("generated_at", ""),
        },
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w") as fh:
        json.dump(output, fh, indent=2)
        fh.write("\n")

    return output


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Search CISA advisories by term or enrich a marlinspike report.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 -m plugins.marlinspike_cisa --term siemens --output results.json\n"
            "  python3 -m plugins.marlinspike_cisa --term 'CVE-2021-27104' --output results.json\n"
            "  python3 -m plugins.marlinspike_cisa --term 'modbus' --limit 20 --output results.json\n"
            "  python3 -m plugins.marlinspike_cisa --term rockwell --output results.json\n"
            "    (automatically expands to allen-bradley, logix, controllogix, etc.)\n"
            "  python3 -m plugins.marlinspike_cisa --input-report report.json --output report-cisa.json\n"
        ),
    )

    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "--term",
        help="Search term (CVE ID, vendor, product, or keyword)",
    )
    mode_group.add_argument(
        "--input-report",
        type=Path,
        metavar="PATH",
        help="Path to a marlinspike report JSON; enriches all assets and CVE refs found",
    )

    parser.add_argument("--output", required=True, type=Path, help="Output JSON path")
    parser.add_argument(
        "--catalog",
        type=Path,
        default=DEFAULT_CATALOG_PATH,
        help="Path to local CISA catalog JSON (default: bundled catalog)",
    )
    parser.add_argument(
        "--rules",
        type=Path,
        default=DEFAULT_RULES_PATH,
        help="Path to vendor alias rules YAML (default: rules/cisa/base.yaml)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Maximum results to return per term (0 = no limit; --term mode only)",
    )
    args = parser.parse_args()

    if args.input_report:
        result = run_report(
            args.input_report,
            args.output,
            args.catalog,
            rules_path=args.rules,
        )
        summary = result["summary"]
        print(
            f"report={summary['source_report']!r}  "
            f"assets={summary['assets_searched']}  "
            f"terms={summary['unique_terms']}  "
            f"advisories={summary['total_advisories']}  "
            f"kev={summary['kev_matched']}  "
            f"ics={summary['ics_matched']}  "
            f"ransomware={summary['ransomware_total']}"
        )
    else:
        result = run(args.term, args.output, args.catalog, limit=args.limit, rules_path=args.rules)
        summary = result["summary"]
        print(
            f"term={summary['term']!r}  matched={summary['total_matched']}  "
            f"kev={summary['kev_matched']}  ics={summary['ics_matched']}  "
            f"ransomware={summary['ransomware_total']}"
        )
        if summary.get("expanded_terms"):
            print(f"expanded: {', '.join(summary['expanded_terms'])}")

    if result["warnings"]:
        for warning in result["warnings"]:
            print(f"warning: {warning}")
    print(f"wrote {args.output}")
