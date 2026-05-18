"""End-to-end detection assertions.

Generates synthetic scenario PCAPs (a benign OT/IT baseline with one injected
attack pattern each), runs the real analysis engine on every one, and asserts
the predicted finding category + severity appears — and that the clean
control trips none of them.

Skipped automatically when the prerequisites for a real engine run are
absent (scapy for generation, and either tshark or a Rust DPI binary for
dissection) so it never breaks a bare CI image.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

pytest.importorskip("scapy", reason="scapy required to synthesize fixture PCAPs")

_has_tshark = shutil.which("tshark") is not None
_has_dpi = bool(os.environ.get("MARLINSPIKE_DPI_BIN")) and os.path.isfile(
    os.environ.get("MARLINSPIKE_DPI_BIN", "")
)
pytestmark = pytest.mark.skipif(
    not (_has_tshark or _has_dpi),
    reason="engine needs tshark or a Rust DPI binary to dissect PCAPs",
)

# scenario -> (category, allowed severities). None == no engine attack
# finding expected (clean control, or detection delegated to a plugin).
EXPECTED = {
    "clean": None,
    "c2_beacon": ("C2_BEACONING", {"CRITICAL", "HIGH"}),
    "dns_exfil": ("C2_DNS_EXFIL", {"CRITICAL"}),
    "ics_external": ("ICS_EXTERNAL_COMMS", {"CRITICAL", "HIGH"}),
    "port_scan": ("PORT_SCAN_TARGET", {"HIGH", "CRITICAL", "MEDIUM"}),
    "c2_suspect_channel": ("C2_SUSPECT_CHANNEL", {"HIGH"}),
    "c2_data_exfil": ("C2_DATA_EXFIL", {"HIGH"}),
    "modbus_write": ("MODBUS_WRITE_ANON", {"MEDIUM"}),
    # SMB fan-out is the APT plugin's job; the engine must NOT raise a
    # C2/scan false-positive on it (asserted here) and the plugin
    # detection is asserted in test_detection_plugins.py.
    "lateral_smb": None,
}

# Categories that must never appear in the clean control.
_ATTACK_CATEGORIES = {
    "C2_BEACONING",
    "C2_DNS_EXFIL",
    "C2_DNS_HIGH_ENTROPY",
    "C2_DNS_TUNNEL_SUSPECT",
    "ICS_EXTERNAL_COMMS",
    "PORT_SCAN_TARGET",
}


@pytest.fixture(scope="module")
def reports(tmp_path_factory):
    """Generate all fixtures once, run the engine on each, return
    {scenario: parsed_report_dict}."""
    import importlib.util

    gen_path = os.path.join(REPO_ROOT, "tests", "fixtures", "gen_detection_pcaps.py")
    spec = importlib.util.spec_from_file_location("gen_detection_pcaps", gen_path)
    gen_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen_mod)
    generate = gen_mod.generate

    pcap_dir = tmp_path_factory.mktemp("pcaps")
    out_dir = tmp_path_factory.mktemp("out")
    pcaps = generate(str(pcap_dir))

    env = dict(os.environ)
    env["PYTHONPATH"] = REPO_ROOT + os.pathsep + env.get("PYTHONPATH", "")

    out: dict[str, dict] = {}
    for name, pcap in pcaps.items():
        run_dir = out_dir / name
        run_dir.mkdir()
        proc = subprocess.run(
            [sys.executable, "-u", "-m", "marlinspike", "--pcap", pcap, "chain"],
            cwd=str(run_dir),
            env=env,
            capture_output=True,
            text=True,
            timeout=240,
        )
        candidates = [
            f for f in os.listdir(run_dir)
            if f.startswith("marlinspike-report-")
            and f.endswith(".json")
            and not f.endswith((".ocsf.ndjson", ".stix.json"))
            and ".ocsf" not in f
            and ".stix" not in f
        ]
        assert candidates, (
            f"engine produced no report for {name}\n"
            f"stdout tail:\n{proc.stdout[-800:]}\n"
            f"stderr tail:\n{proc.stderr[-800:]}"
        )
        report_path = max(
            (run_dir / c for c in candidates), key=os.path.getmtime
        )
        with open(report_path) as fh:
            out[name] = json.load(fh)
    return out


def _categories(report: dict) -> set[str]:
    return {f.get("category") for f in (report.get("risk_findings") or [])}


def _by_category(report: dict, category: str) -> list[dict]:
    return [
        f for f in (report.get("risk_findings") or [])
        if f.get("category") == category
    ]


@pytest.mark.parametrize("scenario", list(EXPECTED))
def test_scenario_findings(reports, scenario):
    report = reports[scenario]
    expected = EXPECTED[scenario]

    if expected is None:  # clean control
        leaked = _categories(report) & _ATTACK_CATEGORIES
        assert not leaked, f"clean control unexpectedly flagged: {sorted(leaked)}"
        return

    category, allowed_sev = expected
    matches = _by_category(report, category)
    assert matches, (
        f"{scenario}: expected finding {category} not present; "
        f"got categories {sorted(_categories(report))}"
    )
    severities = {m.get("severity") for m in matches}
    assert severities & allowed_sev, (
        f"{scenario}: {category} present but severity {sorted(severities)} "
        f"not in expected {sorted(allowed_sev)}"
    )


def test_clean_has_no_c2_indicators(reports):
    """The benign baseline must not synthesize C2 indicators."""
    assert (reports["clean"].get("c2_indicators") or []) == []


def _c2_types(report: dict) -> set[str]:
    return {c.get("type") for c in (report.get("c2_indicators") or [])}


def test_c2_indicators_emitted_per_scenario(reports):
    """Each C2 scenario must surface its structured c2_indicators entry,
    not just a risk_finding. Covers all five distinct C2 indicator types
    these fixtures are engineered to trip."""
    assert "C2_BEACONING" in _c2_types(reports["c2_beacon"])
    # The long-lived periodic channel also trips the persistence detector.
    assert "C2_PERSISTENCE" in _c2_types(reports["c2_beacon"])
    assert "C2_DNS_EXFIL" in _c2_types(reports["dns_exfil"])
    assert "C2_SUSPECT_CHANNEL" in _c2_types(reports["c2_suspect_channel"])
    assert "C2_DATA_EXFIL" in _c2_types(reports["c2_data_exfil"])
