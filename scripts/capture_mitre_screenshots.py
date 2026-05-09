#!/usr/bin/env python3
"""Render the real MarlinSpike viewer and capture documentation-grade MITRE screenshots."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import threading
from collections import defaultdict
from contextlib import contextmanager
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from jinja2 import Environment, FileSystemLoader
from playwright.async_api import async_playwright

ROOT_DIR = Path(__file__).resolve().parents[1]
TEMPLATE_DIR = ROOT_DIR / "templates"
DEFAULT_REPORT_PATH = Path("./demo/demo-report.json")
DEFAULT_OUTPUT_DIR = ROOT_DIR / "docs" / "screenshots"

DOC_CAPTURE_STYLE = """
html, body {
  overflow: auto !important;
  height: auto !important;
}

body {
  min-height: auto !important;
}

#ms-app,
#ms-app.report-open {
  display: block !important;
  height: auto !important;
  min-height: 0 !important;
}

#ms-toolbar,
#ms-viewport,
#ms-sidebar,
#ms-tab-mac-table,
.ms-report-close,
.ms-report-tabs,
#ms-header .ms-controls,
.ms-back-link {
  display: none !important;
}

#ms-header {
  display: block !important;
  padding: 24px 28px 18px !important;
  max-width: 1320px !important;
  margin: 0 auto !important;
}

.ms-header-main,
.ms-title-row,
.ms-title-copy {
  min-width: 0 !important;
}

.ms-title-row {
  display: block !important;
}

.ms-subtitle {
  margin-top: 8px !important;
}

#ms-report-pane {
  display: block !important;
  overflow: visible !important;
  border-top: none !important;
  padding: 0 28px 32px !important;
  max-width: 1320px !important;
  margin: 0 auto !important;
}

.ms-report-header {
  position: static !important;
  padding: 10px 0 12px !important;
}

.ms-report-columns {
  grid-template-columns: 1fr !important;
  gap: 0 !important;
}

.ms-report-col {
  min-width: 0 !important;
}

.ms-section {
  margin-bottom: 18px !important;
}

.ms-section-toggle {
  cursor: default !important;
}

.ms-section-body {
  display: block !important;
}

.ms-finding-card {
  break-inside: avoid;
}

body.ms-doc-focus-mitre-overview #ms-rpt-summary,
body.ms-doc-focus-mitre-overview #ms-rpt-findings,
body.ms-doc-focus-mitre-overview #ms-rpt-purdue,
body.ms-doc-focus-mitre-overview #ms-rpt-assets,
body.ms-doc-focus-mitre-overview #ms-rpt-protocols,
body.ms-doc-focus-mitre-overview #ms-rpt-ports,
body.ms-doc-focus-mitre-overview #ms-rpt-c2,
body.ms-doc-focus-mitre-guidance #ms-rpt-summary,
body.ms-doc-focus-mitre-guidance #ms-rpt-findings,
body.ms-doc-focus-mitre-guidance #ms-rpt-purdue,
body.ms-doc-focus-mitre-guidance #ms-rpt-assets,
body.ms-doc-focus-mitre-guidance #ms-rpt-protocols,
body.ms-doc-focus-mitre-guidance #ms-rpt-ports,
body.ms-doc-focus-mitre-guidance #ms-rpt-c2,
body.ms-doc-focus-finding-chips #ms-rpt-summary,
body.ms-doc-focus-finding-chips #ms-rpt-purdue,
body.ms-doc-focus-finding-chips #ms-rpt-assets,
body.ms-doc-focus-finding-chips #ms-rpt-protocols,
body.ms-doc-focus-finding-chips #ms-rpt-ports,
body.ms-doc-focus-finding-chips #ms-rpt-c2,
body.ms-doc-focus-finding-chips #ms-rpt-mitre {
  display: none !important;
}

body.ms-doc-focus-mitre-overview #ms-rpt-mitre,
body.ms-doc-focus-mitre-guidance #ms-rpt-mitre,
body.ms-doc-focus-finding-chips #ms-rpt-findings {
  display: block !important;
}
"""

if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from plugins.marlinspike_mitre.plugin import run as run_mitre_plugin


def _severity_rank(severity: str | None) -> int:
    return {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "INFO": 4,
    }.get((severity or "").upper(), 5)


def _viewer_anchor(value: str) -> str:
    value = str(value or "").strip()
    return "".join(char if char.isalnum() or char in "_-" else "-" for char in value).strip("-") or "asset"


def _build_viewer_context(report: dict) -> dict:
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

    assets_sorted = []
    write_nodes = set()
    for edge in edges:
        if edge.get("includes_writes") or edge.get("includes_program_access"):
            if edge.get("src"):
                write_nodes.add(str(edge["src"]))
            if edge.get("dst"):
                write_nodes.add(str(edge["dst"]))

    for node in nodes:
        ip = str(node.get("ip") or node.get("address") or "")
        related_risks = node_risks.get(ip, [])
        assets_sorted.append(
            {
                **node,
                "_ip": ip,
                "_anchor": _viewer_anchor(ip),
                "_risk_count": len(related_risks),
                "_top_risk": related_risks[0] if related_risks else None,
            }
        )

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
    protocol_items = [{"name": name, "count": count} for name, count in sorted(protocol_summary.items(), key=lambda item: (-int(item[1]), item[0]))]
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

    summary = {
        "asset_count": len(nodes),
        "edge_count": len(edges),
        "protocol_count": len(protocol_items),
        "classified_count": 0,
        "auth_gap_count": sum(1 for node in assets_sorted if not node.get("auth_observed", False)),
        "write_node_count": len(write_nodes),
        "write_edge_count": len([edge for edge in edges if edge.get("includes_writes") or edge.get("includes_program_access")]),
        "priority_count": len([node for node in assets_sorted if int(node.get("attack_priority") or 0) > 0]),
        "external_count": len([node for node in assets_sorted if node.get("purdue_level") == 5 or node.get("role") == "External Host"]),
        "critical_high_count": severity_counts["CRITICAL"] + severity_counts["HIGH"],
        "severity_counts": severity_counts,
        "packet_count": (report.get("capture_info") or {}).get("total_packets"),
        "duration_seconds": (report.get("capture_info") or {}).get("duration_seconds"),
        "unclassified_count": len(nodes),
        "mitre_classification_total": len(mitre_classifications),
        "mitre_platform_total": len(mitre_platform_coverage),
        "mitre_tactic_total": int(mitre_summary.get("tactic_total") or 0),
        "mitre_subtechnique_total": int(mitre_summary.get("subtechnique_total") or 0),
        "mitre_matrix_domain_total": int(mitre_summary.get("matrix_domain_total") or len(mitre_matrix_domains)),
    }

    return {
        "summary": summary,
        "assets_sorted": assets_sorted,
        "priority_nodes": [],
        "auth_gap_nodes": [],
        "unclassified_nodes": [],
        "write_paths": [],
        "top_findings": top_findings,
        "external_indicators": external_indicators,
        "protocol_items": protocol_items[:10],
        "port_items": port_items[:12],
        "purdue_violations": purdue_violations,
        "c2_indicators": c2_indicators,
        "mac_table": mac_table,
        "mitre_summary": mitre_summary,
        "mitre_attack_metadata": mitre_attack_metadata,
        "mitre_domains": mitre_domains,
        "mitre_matrix": mitre_matrix,
        "mitre_matrix_domains": mitre_matrix_domains,
        "mitre_classifications": mitre_classifications,
        "mitre_platform_coverage": mitre_platform_coverage,
    }


def _render_html(report_path: Path, html_path: Path) -> None:
    mitre_output = html_path.with_suffix(".mitre.json")
    artifact = run_mitre_plugin(
        report_path.resolve(),
        mitre_output,
        [ROOT_DIR / "rules" / "mitre" / "base.yaml"],
        ROOT_DIR / "plugins" / "marlinspike_mitre" / "catalog" / "attack_catalog.json",
    )

    report = json.loads(report_path.read_text())
    report = dict(report)
    report["extensions"] = {"marlinspike-mitre": artifact}
    viewer_context = _build_viewer_context(report)

    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))
    template = env.get_template("viewer.html")
    html = template.render(
        filename=report_path.name,
        report=report,
        report_json=report,
        viewer_context=viewer_context,
    )
    html_path.write_text(html)


@contextmanager
def _serve_directory(directory: Path):
    handler = partial(SimpleHTTPRequestHandler, directory=str(directory))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


async def _prepare_capture_page(page, page_url: str) -> None:
    await page.goto(page_url, wait_until="networkidle")
    await page.click("#ms-btn-report")
    await page.wait_for_timeout(900)
    await page.add_style_tag(content=DOC_CAPTURE_STYLE)
    await page.evaluate(
        """
        () => {
          document.getElementById('ms-app')?.classList.add('report-open');
          document.getElementById('ms-btn-report')?.classList.add('active');
          document.getElementById('ms-tab-report')?.classList.add('active');
          document.getElementById('ms-tab-mac-table')?.classList.remove('active');
          document.querySelectorAll('.ms-report-tab').forEach((el, index) => {
            el.classList.toggle('active', index === 0);
          });
          [
            'ms-rpt-summary',
            'ms-rpt-findings',
            'ms-rpt-purdue',
            'ms-rpt-assets',
            'ms-rpt-protocols',
            'ms-rpt-ports',
            'ms-rpt-c2',
            'ms-rpt-mitre',
          ].forEach((id) => document.getElementById(id)?.classList.add('open'));
        }
        """
    )
    await page.wait_for_timeout(250)


async def _set_capture_focus(page, focus: str, finding_card_limit: int | None = None, mitre_card_limit: int | None = None) -> None:
    await page.evaluate(
        """
        ({ focus, findingCardLimit, mitreCardLimit }) => {
          document.body.classList.remove(
            'ms-doc-focus-mitre-overview',
            'ms-doc-focus-mitre-guidance',
            'ms-doc-focus-finding-chips'
          );
          document.body.classList.add('ms-doc-focus-' + focus);
          document.querySelectorAll('#ms-rpt-mitre, #ms-rpt-findings').forEach((el) => {
            el.style.maxWidth = '';
            el.style.margin = '';
          });

          if (focus === 'mitre-overview') {
            const section = document.getElementById('ms-rpt-mitre');
            if (section) {
              section.style.maxWidth = '1240px';
              section.style.margin = '0 auto';
            }
          }

          if (focus === 'mitre-guidance') {
            const section = document.getElementById('ms-rpt-mitre');
            if (section) {
              section.style.maxWidth = '1120px';
              section.style.margin = '0 auto';
            }
          }

          if (focus === 'finding-chips') {
            const section = document.getElementById('ms-rpt-findings');
            if (section) {
              section.style.maxWidth = '1120px';
              section.style.margin = '0 auto';
            }
          }

          const reset = (selector) => {
            document.querySelectorAll(selector).forEach((el) => {
              el.style.display = '';
            });
          };

          const limit = (selector, count) => {
            const items = Array.from(document.querySelectorAll(selector));
            items.forEach((el, index) => {
              el.style.display = count != null && index >= count ? 'none' : '';
            });
          };

          reset('#ms-rpt-findings .ms-section-body > .ms-finding-card');
          reset('#ms-rpt-mitre .ms-section-body > .ms-finding-card');
          reset('#ms-rpt-mitre .ms-section-body > .ms-mitre-doc-hide');

          if (focus === 'finding-chips') {
            let visibleFindings = 0;
            document.querySelectorAll('#ms-rpt-findings .ms-section-body > .ms-finding-card').forEach((card) => {
              const hasAttackChip = Array.from(card.querySelectorAll('.ms-finding-chip')).some((chip) => {
                return /^T\\d/.test(String(chip.textContent || '').trim().toUpperCase());
              });
              if (!hasAttackChip || (findingCardLimit != null && visibleFindings >= findingCardLimit)) {
                card.style.display = 'none';
                return;
              }
              visibleFindings += 1;
            });
          } else {
            limit('#ms-rpt-findings .ms-section-body > .ms-finding-card', findingCardLimit);
          }

          limit('#ms-rpt-mitre .ms-section-body > .ms-finding-card', mitreCardLimit);
        }
        """,
        {"focus": focus, "findingCardLimit": finding_card_limit, "mitreCardLimit": mitre_card_limit},
    )
    await page.wait_for_timeout(150)


async def _capture(html_path: Path, output_dir: Path) -> None:
    page_path = html_path.relative_to(ROOT_DIR).as_posix()

    async with async_playwright() as p:
        with _serve_directory(ROOT_DIR) as base_url:
            browser = await p.chromium.launch()
            page = await browser.new_page(viewport={"width": 1760, "height": 2200}, device_scale_factor=1.5)
            await _prepare_capture_page(page, f"{base_url}/{page_path}")

            await _set_capture_focus(page, "mitre-overview", mitre_card_limit=3)
            mitre_section = page.locator("#ms-rpt-mitre")
            await mitre_section.scroll_into_view_if_needed()
            await mitre_section.screenshot(path=str(output_dir / "12-mitre-overview.png"))

            await _set_capture_focus(page, "mitre-guidance", mitre_card_limit=1)
            technique_card = page.locator("#ms-rpt-mitre .ms-section-body > .ms-finding-card").first
            await technique_card.scroll_into_view_if_needed()
            await technique_card.screenshot(path=str(output_dir / "13-mitre-technique-guidance.png"))

            await _set_capture_focus(page, "finding-chips", finding_card_limit=4)
            findings_section = page.locator("#ms-rpt-findings")
            await findings_section.scroll_into_view_if_needed()
            await findings_section.screenshot(path=str(output_dir / "14-mitre-finding-chips.png"))

            await browser.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Capture real MITRE screenshots from the MarlinSpike viewer template.")
    parser.add_argument("--report", default=str(DEFAULT_REPORT_PATH), help="Path to a source report JSON")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR), help="Directory for generated screenshots")
    args = parser.parse_args()

    report_path = Path(args.report).resolve()
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    html_path = output_dir / "_mitre-doc-capture.html"

    _render_html(report_path, html_path)
    asyncio.run(_capture(html_path, output_dir))
    print(f"Wrote screenshots to {output_dir}")


if __name__ == "__main__":
    main()
