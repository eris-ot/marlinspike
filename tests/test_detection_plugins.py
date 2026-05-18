"""End-to-end detection coverage for the report-facing plugins and the
optional Stage 4b malware engine.

The engine's own detectors are covered in test_detection_scenarios.py.
This file covers the *plugin* surfaces that consume a finished report:

  - marlinspike-apt   : lateral-movement / recon attribution
  - marlinspike-mitre : ATT&CK technique classification
  - Stage 4b malware  : marlinspike-malware IOC matching (gated — the Rust
                         binary is built only in Docker; skips cleanly when
                         absent rather than faking a result)

Skipped automatically when scapy (fixture synthesis) or tshark/DPI
(engine dissection) is unavailable, so a bare CI image stays green.
"""

from __future__ import annotations

import importlib.util
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


def _engine_env() -> dict:
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO_ROOT + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _run_engine(pcap: str, run_dir: str) -> dict:
    proc = subprocess.run(
        [sys.executable, "-u", "-m", "marlinspike", "--pcap", pcap, "chain"],
        cwd=run_dir, env=_engine_env(), capture_output=True, text=True, timeout=240,
    )
    reports = [
        f for f in os.listdir(run_dir)
        if f.startswith("marlinspike-report-") and f.endswith(".json")
        and ".ocsf" not in f and ".stix" not in f
    ]
    assert reports, (
        f"no report for {pcap}\n--stdout--\n{proc.stdout[-800:]}"
        f"\n--stderr--\n{proc.stderr[-800:]}"
    )
    path = max((os.path.join(run_dir, r) for r in reports), key=os.path.getmtime)
    with open(path) as fh:
        return {"path": path, "report": json.load(fh)}


def _run_plugin(module: str, report_path: str, out_path: str) -> dict:
    proc = subprocess.run(
        [sys.executable, "-u", "-m", module,
         "--input-report", report_path, "--output", out_path],
        cwd=REPO_ROOT, env=_engine_env(), capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, (
        f"{module} exited {proc.returncode}\n--stderr--\n{proc.stderr[-800:]}"
    )
    assert os.path.isfile(out_path), f"{module} produced no sidecar"
    with open(out_path) as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def fixtures(tmp_path_factory):
    """Generate the scenario PCAPs once and return name -> pcap path."""
    gen_path = os.path.join(REPO_ROOT, "tests", "fixtures", "gen_detection_pcaps.py")
    spec = importlib.util.spec_from_file_location("gen_detection_pcaps", gen_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.generate(str(tmp_path_factory.mktemp("pcaps")))


@pytest.fixture(scope="module")
def report_for(fixtures, tmp_path_factory):
    """Lazily build (and cache) an engine report per scenario name."""
    cache: dict[str, dict] = {}

    def _get(name: str) -> dict:
        if name not in cache:
            rd = tmp_path_factory.mktemp(f"eng_{name}")
            cache[name] = _run_engine(fixtures[name], str(rd))
        return cache[name]

    return _get


# ── marlinspike-apt ───────────────────────────────────────────────────────

def test_apt_detects_smb_lateral_movement(report_for, tmp_path):
    """lateral_smb fixture (one host fanning out SMB/445 to 15 peers) ->
    APT_LATERAL_MOVEMENT_SMB attributed to the right source."""
    rep = report_for("lateral_smb")
    sidecar = _run_plugin(
        "plugins.marlinspike_apt", rep["path"], str(tmp_path / "apt.json")
    )
    assert sidecar.get("plugin_id") == "marlinspike-apt"
    findings = (sidecar.get("data") or {}).get("findings") or []
    smb = [f for f in findings if f.get("category") == "APT_LATERAL_MOVEMENT_SMB"]
    assert smb, f"no SMB lateral finding; categories={[f.get('category') for f in findings]}"
    f = smb[0]
    assert f.get("src_ip") == "10.10.0.40"
    assert len(f.get("distinct_target_ips") or []) >= 10


def test_apt_clean_has_no_lateral_findings(report_for, tmp_path):
    """The benign baseline must not attribute APT lateral movement."""
    rep = report_for("clean")
    sidecar = _run_plugin(
        "plugins.marlinspike_apt", rep["path"], str(tmp_path / "apt_clean.json")
    )
    cats = {
        f.get("category") for f in ((sidecar.get("data") or {}).get("findings") or [])
    }
    assert not (cats & {
        "APT_LATERAL_MOVEMENT_SMB",
        "APT_LATERAL_MOVEMENT_RDP",
        "APT_LATERAL_MOVEMENT_WINRM",
    }), f"clean baseline falsely attributed: {sorted(cats)}"


# ── marlinspike-mitre ─────────────────────────────────────────────────────

def test_mitre_maps_beacon_to_t1071(report_for, tmp_path):
    """c2_beacon's C2_BEACONING finding must classify to ATT&CK T1071
    (Application Layer Protocol) on an observed basis."""
    rep = report_for("c2_beacon")
    sidecar = _run_plugin(
        "plugins.marlinspike_mitre", rep["path"], str(tmp_path / "mitre.json")
    )
    assert sidecar.get("plugin_id") == "marlinspike-mitre"
    data = sidecar.get("data") or {}
    classifications = data.get("classifications") or []
    t1071 = [c for c in classifications if c.get("technique_id") == "T1071"]
    assert t1071, (
        "C2_BEACONING did not classify to T1071; got "
        f"{sorted({c.get('technique_id') for c in classifications})}"
    )
    c = t1071[0]
    assert c.get("basis") == "observed"
    assert "C2_BEACONING" in (c.get("mapped_from") or [])
    assert "C2_BEACONING" in ((data.get("coverage") or {}).get("mapped_categories") or [])


# ── Stage 4b malware (gated) ──────────────────────────────────────────────

def _malware_available() -> bool:
    try:
        from marlinspike.engine import _find_malware_binary, _find_malware_rules_dir
    except Exception:
        return False
    return bool(_find_malware_binary() and _find_malware_rules_dir())


@pytest.mark.skipif(
    not _malware_available(),
    reason="marlinspike-malware binary/rules absent — Stage 4b is built only "
           "in the Docker image; integration cannot run here",
)
def test_stage4b_malware_ioc_match(fixtures, tmp_path):
    """With the Rust malware engine present, the malware_ioc fixture (a DNS
    lookup for the rule packs' deterministic bootstrap IOC
    ``bad.example.invalid``) must produce a real Stage 4b match that merges
    into both risk_findings and c2_indicators as MALWARE_IOC_MATCH.

    This is a genuine end-to-end signature hit, not just an integration
    smoke check — the ``bootstrap-bad-host`` rule is the rules repo's
    stable self-validation indicator. If a future rules ref drops it this
    fails loudly, which is the correct signal.
    """
    rep = _run_engine(fixtures["malware_ioc"], str(tmp_path))["report"]

    mw = rep.get("malware_findings")
    assert isinstance(mw, list), "malware_findings missing/not a list after Stage 4b"
    assert mw, "Stage 4b ran but did not match the bootstrap IOC bad.example.invalid"
    assert any(f.get("rule_id") == "bootstrap-bad-host" for f in mw), (
        f"expected bootstrap-bad-host hit; got {[f.get('rule_id') for f in mw]}"
    )

    risk_cats = {f.get("category") for f in (rep.get("risk_findings") or [])}
    assert "MALWARE_IOC_MATCH" in risk_cats, "match not merged into risk_findings"
    c2_types = {c.get("type") for c in (rep.get("c2_indicators") or [])}
    assert "MALWARE_IOC_MATCH" in c2_types, "match not merged into c2_indicators"


@pytest.mark.skipif(
    not _malware_available(),
    reason="marlinspike-malware binary/rules absent — Stage 4b is Docker-only",
)
def test_stage4b_clean_has_no_malware_match(fixtures, tmp_path):
    """Benign baseline must not produce a Stage 4b false positive."""
    rep = _run_engine(fixtures["clean"], str(tmp_path))["report"]
    assert (rep.get("malware_findings") or []) == []
