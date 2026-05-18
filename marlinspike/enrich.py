"""Enrichment stage — runs the MITRE / ARP / APT / CISA plugin sidecars and
merges them into a report, with no Flask / web-app dependency.

This is the single home for enrichment orchestration. It was previously
embedded in ``app.py:_finalize_run`` (web-only), which meant headless
consumers of ``engine.py chain`` (engine-svc, cloudmarlin, CI, batch)
silently produced *under-enriched* reports. The engine now calls this so
``chain`` emits a complete report; ``app.py`` delegates here too.

Contract (unchanged from the previous web-only path):
  - each plugin is ``python -u -m <module> --input-report R --output S [--rules ...]``
  - 120 s per-plugin subprocess timeout
  - gated per-plugin by ``config.MARLINSPIKE_<NAME>_ENABLED``
  - rule packs: every ``*.yaml`` in ``rules/<name>/`` plus the explicit
    ``config.MARLINSPIKE_<NAME>_RULES`` path (CISA: explicit path only)

``write_enriched()`` is idempotent: re-running drops prior plugin-sourced
risk findings and rebuilds ``extensions`` from the (freshly regenerated)
sidecars, so ``chain --enrich`` and a later standalone ``enrich`` agree.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess

from marlinspike import config

log = logging.getLogger("marlinspike.enrich")

_PLUGIN_TIMEOUT_S = 120


class _Spec:
    __slots__ = ("plugin_id", "suffix", "enabled_attr", "module_attr",
                 "rules_attr", "rules_subdir")

    def __init__(self, plugin_id, suffix, enabled_attr, module_attr,
                 rules_attr, rules_subdir):
        self.plugin_id = plugin_id
        self.suffix = suffix
        self.enabled_attr = enabled_attr
        self.module_attr = module_attr
        self.rules_attr = rules_attr
        self.rules_subdir = rules_subdir  # None ⇒ no rules/<dir> sweep


# Order matters only for log readability; merge is keyed by plugin_id.
_SPECS = [
    _Spec("marlinspike-mitre", "-mitre.json", "MARLINSPIKE_MITRE_ENABLED",
          "MARLINSPIKE_MITRE_MODULE", "MARLINSPIKE_MITRE_RULES", "mitre"),
    _Spec("marlinspike-arp", "-arp.json", "MARLINSPIKE_ARP_ENABLED",
          "MARLINSPIKE_ARP_MODULE", "MARLINSPIKE_ARP_RULES", "arp"),
    _Spec("marlinspike-apt", "-apt.json", "MARLINSPIKE_APT_ENABLED",
          "MARLINSPIKE_APT_MODULE", "MARLINSPIKE_APT_RULES", "apt"),
    _Spec("marlinspike-cisa", "-cisa.json", "MARLINSPIKE_CISA_ENABLED",
          "MARLINSPIKE_CISA_MODULE", "MARLINSPIKE_CISA_RULES", None),
]
_SPEC_BY_ID = {s.plugin_id: s for s in _SPECS}
PLUGIN_IDS = frozenset(s.plugin_id for s in _SPECS)


def sidecar_path(report_path: str, suffix: str) -> str:
    base, _ = os.path.splitext(report_path)
    return base + suffix


def _rule_packs(spec: _Spec) -> list[str]:
    packs: list[str] = []
    if spec.rules_subdir:
        rules_dir = os.path.join(config.BASE_DIR, "rules", spec.rules_subdir)
        if os.path.isdir(rules_dir):
            for fname in sorted(os.listdir(rules_dir)):
                if fname.endswith((".yaml", ".yml")):
                    packs.append(os.path.join(rules_dir, fname))
    explicit = getattr(config, spec.rules_attr, "")
    if explicit and os.path.isfile(explicit) and explicit not in packs:
        packs.insert(0, explicit)
    return packs


def _run_spec(spec: _Spec, report_path: str) -> tuple[str, list[str]]:
    """Run one plugin. Returns (sidecar_path, output_lines); ("", []) if the
    plugin is disabled. Raises RuntimeError on plugin failure (same contract
    as the previous app.py runners)."""
    if not getattr(config, spec.enabled_attr, False):
        return "", []
    if not os.path.isfile(report_path):
        raise FileNotFoundError(f"Report not found: {report_path}")

    output_path = sidecar_path(report_path, spec.suffix)
    cmd = [
        config.PYTHON_EXE, "-u", "-m", getattr(config, spec.module_attr),
        "--input-report", report_path, "--output", output_path,
    ]
    for pack in _rule_packs(spec):
        cmd.extend(["--rules", pack])

    env = os.environ.copy()
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = config.BASE_DIR + (os.pathsep + existing if existing else "")

    result = subprocess.run(
        cmd, capture_output=True, text=True, cwd=config.BASE_DIR,
        env=env, timeout=_PLUGIN_TIMEOUT_S,
    )
    lines = [
        ln.strip()
        for ln in ((result.stdout or "") + "\n" + (result.stderr or "")).splitlines()
        if ln.strip()
    ]
    if result.returncode != 0:
        raise RuntimeError(lines[-1] if lines else f"exit code {result.returncode}")
    return output_path, lines


def run_one(plugin_id: str, report_path: str) -> tuple[str, list[str]]:
    """Run a single plugin by id (back-compat surface for app.py)."""
    return _run_spec(_SPEC_BY_ID[plugin_id], report_path)


def run_all(report_path: str) -> dict[str, str]:
    """Run every enabled plugin. Returns {plugin_id: sidecar_path}; failures
    are logged and skipped (a broken plugin must not wedge the chain)."""
    produced: dict[str, str] = {}
    for spec in _SPECS:
        try:
            path, _ = _run_spec(spec, report_path)
            if path:
                produced[spec.plugin_id] = path
        except Exception as exc:  # noqa: BLE001 — plugin isolation is the point
            log.warning("%s skipped: %s", spec.plugin_id, exc)
    return produced


# ── merge ────────────────────────────────────────────────────────────────────

def load_report_with_extensions(path: str, ensure_mitre: bool = False) -> dict:
    """Load report + sidecars, return a merged dict. Idempotent: any
    pre-existing plugin-sourced risk findings are dropped before re-appending,
    so calling this on an already-merged report is stable."""
    with open(path) as fh:
        report = json.load(fh)
    if not isinstance(report, dict):
        return report

    merged = report.copy()
    extensions = dict(merged.get("extensions") or {})

    mitre_path = sidecar_path(path, "-mitre.json")
    if (ensure_mitre and getattr(config, "MARLINSPIKE_MITRE_ENABLED", False)
            and not os.path.isfile(mitre_path)):
        try:
            run_one("marlinspike-mitre", path)
        except Exception as exc:  # noqa: BLE001
            log.warning("marlinspike-mitre generation failed for %s: %s", path, exc)

    for spec in _SPECS:
        sc = sidecar_path(path, spec.suffix)
        if not os.path.isfile(sc):
            continue
        try:
            with open(sc) as fh:
                artifact = json.load(fh)
            if isinstance(artifact, dict) and artifact.get("plugin_id") == spec.plugin_id:
                extensions[spec.plugin_id] = artifact
        except Exception as exc:  # noqa: BLE001
            log.warning("Failed to load %s sidecar %s: %s", spec.plugin_id, sc, exc)

    if extensions:
        merged["extensions"] = extensions

    # Idempotency: strip prior plugin-sourced findings before re-appending.
    base_findings = [
        f for f in (merged.get("risk_findings") or [])
        if not (isinstance(f, dict) and f.get("source") in PLUGIN_IDS)
    ]
    plugin_findings = collect_plugin_risk_findings(extensions)
    merged["risk_findings"] = base_findings + plugin_findings
    return merged


def write_enriched(report_path: str) -> dict[str, str]:
    """Run all enabled plugins, then rewrite ``report_path`` in place so the
    report JSON is self-complete (extensions + merged risk_findings). Returns
    the {plugin_id: sidecar_path} map. Idempotent."""
    produced = run_all(report_path)
    merged = load_report_with_extensions(report_path)
    tmp = report_path + ".enrich.tmp"
    with open(tmp, "w") as fh:
        json.dump(merged, fh, indent=2, default=str)
    os.replace(tmp, report_path)
    return produced


# ── plugin-finding → engine risk_finding adapter (moved verbatim) ────────────

def collect_plugin_risk_findings(extensions: dict) -> list[dict]:
    out: list[dict] = []
    for plugin_id, artifact in extensions.items():
        if not isinstance(artifact, dict):
            continue
        data = artifact.get("data") if isinstance(artifact.get("data"), dict) else {}
        for raw in data.get("findings") or []:
            adapted = plugin_finding_to_risk_finding(plugin_id, raw)
            if adapted:
                out.append(adapted)
    return out


def plugin_finding_to_risk_finding(plugin_id: str, finding: dict) -> dict | None:
    if not isinstance(finding, dict):
        return None
    category = str(finding.get("category") or "").strip()
    if not category:
        return None

    affected: list[str] = []
    seen: set[str] = set()

    def _add(value):
        if value is None:
            return
        text = str(value).strip()
        if text and text not in seen:
            seen.add(text)
            affected.append(text)

    for key in ("src_ip", "ip", "host", "address", "source_ip"):
        _add(finding.get(key))
    for key in ("distinct_target_ips", "affected_nodes", "target_ips",
                "involved_ips", "claimed_by_macs"):
        for v in finding.get(key) or []:
            _add(v)

    severity = str(finding.get("severity") or "MEDIUM").upper()
    if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
        severity = "MEDIUM"

    description = (
        finding.get("detail") or finding.get("description")
        or finding.get("message") or category
    )
    attack_ids = list(finding.get("attack_techniques")
                      or finding.get("attack_ids") or [])

    return {
        "category": category,
        "severity": severity,
        "description": str(description),
        "affected_nodes": affected,
        "affected_edges": list(finding.get("affected_edges") or []),
        "cvss_impact": float(finding.get("cvss_impact") or 0.0),
        "remediation": str(finding.get("remediation") or ""),
        "attack_ids": [str(a).strip().upper() for a in attack_ids if str(a).strip()],
        "source": plugin_id,
    }
