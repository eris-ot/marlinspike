"""MITRE ATT&CK Navigator layer JSON emit.

Maps ``mitre_classifications`` and ``mitre_platform_coverage`` from a
MarlinSpike report to ATT&CK Navigator v4.5 layer files. One layer per
ATT&CK domain (``ics-attack`` / ``enterprise-attack``); Navigator
doesn't mix domains in a single layer.

Navigator is what defenders use to visualise technique coverage. Native
emit means a one-click upload from MarlinSpike to a hosted Navigator
instance: defender sees their capture's findings overlaid on the ATT&CK
matrix without having to manually translate technique IDs.

Score interpretation:

* 0-49: blue  (low confidence / platform coverage only)
* 50-79: orange  (medium confidence / inferred from signals)
* 80-100: red  (high confidence / directly observed)

CLI::

    python -m marlinspike.emit.navigator path/to/report.json \\
        -o path/to/report.navigator.json [--domain ics-attack|enterprise-attack]

When ``--domain`` is omitted, both ICS and Enterprise layers are emitted
side-by-side as ``<basename>.ics.json`` and ``<basename>.enterprise.json``.

Navigator reference: https://github.com/mitre-attack/attack-navigator
"""

from __future__ import annotations

import argparse
import json
import sys

# ── Constants ────────────────────────────────────────────────────────────────

NAVIGATOR_LAYER_VERSION = "4.5"
NAVIGATOR_VERSION = "4.9"  # Navigator client this layer targets
DEFAULT_ATTACK_VERSION = "16.1"

DOMAIN_ICS = "ics-attack"
DOMAIN_ENTERPRISE = "enterprise-attack"

# Color gradient — blue (low) → orange (medium) → red (high).
# Matches the severity palette used in the workbench.
GRADIENT_LOW = "#3b82f6"
GRADIENT_MID = "#f97316"
GRADIENT_HIGH = "#ef4444"

# Basis tone — used as a fallback when no confidence is available.
BASIS_SCORE = {
    "observed": 90,
    "inferred": 60,
    "platform": 25,
}


def _confidence_to_score(confidence: float | None, basis: str | None) -> int:
    """Map a confidence float (0.0-1.0) to a Navigator score (0-100).

    If confidence is None, fall back to basis-based default. The score is
    what drives the colour gradient on the rendered matrix.
    """
    if confidence is not None:
        score = int(round(float(confidence) * 100))
        return max(0, min(100, score))
    return BASIS_SCORE.get((basis or "").lower(), 50)


def _color_for_score(score: int) -> str:
    if score >= 80:
        return GRADIENT_HIGH
    if score >= 50:
        return GRADIENT_MID
    return GRADIENT_LOW


def _technique_block(classification: dict, layer_kind: str = "classification") -> dict:
    """Build one Navigator technique entry from a marlinspike-mitre row."""
    technique_id = classification.get("technique_id") or ""
    confidence = classification.get("confidence")
    basis = classification.get("basis")
    score = _confidence_to_score(confidence, basis)
    affected = classification.get("affected_nodes") or []
    name = classification.get("attack_name") or classification.get("title") or technique_id

    metadata = []
    if basis:
        metadata.append({"name": "basis", "value": str(basis)})
    if confidence is not None:
        metadata.append({"name": "confidence", "value": f"{int(round(confidence * 100))}%"})
    if affected:
        metadata.append(
            {
                "name": "affected_assets",
                "value": ", ".join(str(a) for a in affected[:8])
                + (" …" if len(affected) > 8 else ""),
            }
        )
    mapped_from = classification.get("mapped_from") or []
    if mapped_from:
        metadata.append({"name": "mapped_from", "value": ", ".join(str(m) for m in mapped_from)})
    if classification.get("family"):
        metadata.append({"name": "family", "value": str(classification["family"])})

    comment_parts = []
    if name and name != technique_id:
        comment_parts.append(name)
    if classification.get("rationale"):
        comment_parts.append(classification["rationale"][:280])
    comment = "\n\n".join(comment_parts).strip()

    block = {
        "techniqueID": technique_id,
        "score": score,
        "color": _color_for_score(score),
        "enabled": True,
    }
    if comment:
        block["comment"] = comment
    if metadata:
        block["metadata"] = metadata
    return block


def _build_layer(
    domain: str,
    classifications: list[dict],
    coverage: list[dict],
    capture_id: str,
    attack_version: str,
) -> dict | None:
    """Build a complete Navigator layer for one ATT&CK domain.

    Merges classifications (observed / inferred) and coverage (platform)
    by technique_id. If both apply to the same technique, the
    classification wins (higher score, richer metadata).
    """
    classifications = [c for c in classifications if (c.get("domain") or "").lower() == domain]
    coverage = [c for c in coverage if (c.get("domain") or "").lower() == domain]

    by_id: dict[str, dict] = {}
    for entry in coverage:
        tid = entry.get("technique_id")
        if not tid:
            continue
        by_id[tid] = _technique_block(entry, layer_kind="coverage")
    for entry in classifications:
        # Classifications override coverage — they're stronger evidence.
        tid = entry.get("technique_id")
        if not tid:
            continue
        by_id[tid] = _technique_block(entry, layer_kind="classification")

    if not by_id:
        return None

    domain_label = "ICS" if domain == DOMAIN_ICS else "Enterprise"
    return {
        "name": f"MarlinSpike — {capture_id} — {domain_label}",
        "versions": {
            "attack": attack_version,
            "navigator": NAVIGATOR_VERSION,
            "layer": NAVIGATOR_LAYER_VERSION,
        },
        "domain": domain,
        "description": (
            f"ATT&CK technique coverage for capture '{capture_id}', "
            f"derived from MarlinSpike risk findings + the marlinspike-mitre plugin. "
            f"Score reflects detection confidence (0-100); colour follows the "
            f"low/medium/high gradient. Click any cell for finding-level metadata."
        ),
        "filters": {"platforms": []},
        "sorting": 3,  # sort techniques by score descending
        "layout": {
            "layout": "side",
            "showName": True,
            "showID": True,
            "showAggregateScores": False,
            "countUnscored": False,
        },
        "hideDisabled": False,
        "techniques": sorted(by_id.values(), key=lambda t: -t.get("score", 0)),
        "gradient": {
            "colors": [GRADIENT_LOW, GRADIENT_MID, GRADIENT_HIGH],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "Observed (high confidence)", "color": GRADIENT_HIGH},
            {"label": "Inferred (medium confidence)", "color": GRADIENT_MID},
            {"label": "Platform coverage (low)", "color": GRADIENT_LOW},
        ],
        "metadata": [
            {"name": "capture_id", "value": capture_id},
            {"name": "produced_by", "value": "MarlinSpike"},
        ],
        "showTacticRowBackground": False,
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }


# ── Top-level entry points ───────────────────────────────────────────────────


def render_layers(report: dict, capture_id: str | None = None) -> dict[str, dict]:
    """Render Navigator layers for every ATT&CK domain present in the report.

    Returns a dict ``{domain: layer_dict}``. Empty dict if the report has
    no MITRE classifications or coverage entries.
    """
    if capture_id is None:
        capture_id = (report.get("capture_info") or {}).get("capture_source") or "capture"
    classifications = list(report.get("mitre_classifications") or [])
    coverage = list(report.get("mitre_platform_coverage") or [])
    if not classifications and not coverage:
        return {}

    attack_version = (
        (classifications[0].get("attack_version") if classifications else None)
        or (coverage[0].get("attack_version") if coverage else None)
        or DEFAULT_ATTACK_VERSION
    )

    layers: dict[str, dict] = {}
    for domain in (DOMAIN_ICS, DOMAIN_ENTERPRISE):
        layer = _build_layer(domain, classifications, coverage, capture_id, attack_version)
        if layer is not None:
            layers[domain] = layer
    return layers


def render_layer_for_domain(
    report: dict, domain: str, capture_id: str | None = None
) -> dict | None:
    """Render a Navigator layer for one specific domain. None if no techniques."""
    layers = render_layers(report, capture_id)
    return layers.get(domain.lower())


# ── CLI ──────────────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m marlinspike.emit.navigator",
        description="Emit MITRE ATT&CK Navigator v4.5 layer JSON from a MarlinSpike report.",
    )
    parser.add_argument("input", help="Path to report.json")
    parser.add_argument(
        "-o",
        "--output",
        help="Output path. With --domain, single file. Without, the suffix"
        " '.<domain>.json' is appended for each domain present.",
    )
    parser.add_argument(
        "--domain",
        choices=[DOMAIN_ICS, DOMAIN_ENTERPRISE],
        help="Emit a single layer for this domain only.",
    )
    parser.add_argument("--capture-id", help="Override capture_id stamped into the layer name.")
    args = parser.parse_args(argv)

    try:
        with open(args.input) as f:
            report = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"failed to read report {args.input!r}: {exc}", file=sys.stderr)
        return 1

    if args.domain:
        layer = render_layer_for_domain(report, args.domain, capture_id=args.capture_id)
        if layer is None:
            print(f"no {args.domain} techniques in this report", file=sys.stderr)
            return 1
        out = json.dumps(layer, indent=2)
        if args.output:
            with open(args.output, "w") as f:
                f.write(out + "\n")
        else:
            print(out)
        return 0

    layers = render_layers(report, capture_id=args.capture_id)
    if not layers:
        print("no MITRE classifications or coverage in this report", file=sys.stderr)
        return 1

    if args.output:
        # Append .<domain-short>.json to the requested output path.
        for domain, layer in layers.items():
            short = "ics" if domain == DOMAIN_ICS else "enterprise"
            base, ext = (args.output, "")
            if args.output.endswith(".json"):
                base = args.output[:-5]
                ext = ".json"
            out_path = f"{base}.{short}{ext or '.json'}"
            with open(out_path, "w") as f:
                json.dump(layer, f, indent=2)
                f.write("\n")
            print(f"wrote {out_path}", file=sys.stderr)
    else:
        # Concatenate all domains into one stdout document.
        # Each layer printed sequentially with a domain marker.
        for domain, layer in layers.items():
            print(f"# domain: {domain}")
            print(json.dumps(layer, indent=2))
            print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
