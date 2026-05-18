"""Tests for marlinspike.emit.navigator — ATT&CK Navigator v4.5 layer JSON."""

from __future__ import annotations

import json
import os
import sys

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-navigator")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from marlinspike.emit import navigator  # noqa: E402

SAMPLE_REPORT = {
    "capture_info": {"capture_source": "test-capture-001"},
    "mitre_classifications": [
        {
            "technique_id": "T0869",
            "attack_name": "Standard Application Layer Protocol",
            "domain": "ics-attack",
            "basis": "observed",
            "confidence": 0.93,
            "rationale": "Periodic beaconing detected on OT subnet",
            "affected_nodes": ["192.168.89.2"],
            "mapped_from": ["C2_BEACONING"],
            "family": "Command and Control",
            "attack_version": "16.1",
            "technique_url": "https://attack.mitre.org/techniques/T0869",
        },
        {
            "technique_id": "T1071.004",
            "attack_name": "Application Layer Protocol: DNS",
            "domain": "enterprise-attack",
            "basis": "inferred",
            "confidence": 0.55,
            "rationale": "Suspicious DNS patterns",
            "affected_nodes": ["192.168.1.5"],
            "mapped_from": ["DNS_TUNNELING"],
            "attack_version": "16.1",
        },
    ],
    "mitre_platform_coverage": [
        {
            "technique_id": "T0859",
            "attack_name": "Hardcoded Credentials",
            "domain": "ics-attack",
            "basis": "platform",
            "confidence": 0.0,
            "attack_version": "16.1",
        },
    ],
}


# ── Helpers ──────────────────────────────────────────────────────────────────


def test_confidence_to_score_high():
    assert navigator._confidence_to_score(0.93, "observed") == 93


def test_confidence_to_score_clamps():
    assert navigator._confidence_to_score(1.5, None) == 100
    assert navigator._confidence_to_score(-0.5, None) == 0


def test_confidence_to_score_falls_back_to_basis():
    assert navigator._confidence_to_score(None, "observed") == 90
    assert navigator._confidence_to_score(None, "inferred") == 60
    assert navigator._confidence_to_score(None, "platform") == 25
    assert navigator._confidence_to_score(None, None) == 50


def test_color_for_score():
    assert navigator._color_for_score(95) == navigator.GRADIENT_HIGH
    assert navigator._color_for_score(80) == navigator.GRADIENT_HIGH
    assert navigator._color_for_score(60) == navigator.GRADIENT_MID
    assert navigator._color_for_score(50) == navigator.GRADIENT_MID
    assert navigator._color_for_score(40) == navigator.GRADIENT_LOW
    assert navigator._color_for_score(0) == navigator.GRADIENT_LOW


# ── render_layers ─────────────────────────────────────────────────────────────


def test_render_layers_emits_per_domain():
    layers = navigator.render_layers(SAMPLE_REPORT)
    assert set(layers.keys()) == {"ics-attack", "enterprise-attack"}


def test_render_layers_ics_layer_shape():
    layers = navigator.render_layers(SAMPLE_REPORT)
    ics = layers["ics-attack"]
    assert ics["domain"] == "ics-attack"
    assert ics["versions"]["layer"] == "4.5"
    assert ics["versions"]["attack"] == "16.1"
    assert "ICS" in ics["name"]
    assert "test-capture-001" in ics["name"]
    # Two ICS techniques: T0869 (classification) + T0859 (coverage)
    techniques = ics["techniques"]
    assert len(techniques) == 2
    assert {t["techniqueID"] for t in techniques} == {"T0869", "T0859"}
    # T0869 should score 93 (observed, confidence 0.93)
    t0869 = next(t for t in techniques if t["techniqueID"] == "T0869")
    assert t0869["score"] == 93
    assert t0869["color"] == navigator.GRADIENT_HIGH
    # T0859 (platform coverage, confidence 0.0) should score low
    t0859 = next(t for t in techniques if t["techniqueID"] == "T0859")
    assert t0859["score"] == 0
    assert t0859["color"] == navigator.GRADIENT_LOW


def test_render_layers_enterprise_inferred():
    layers = navigator.render_layers(SAMPLE_REPORT)
    ent = layers["enterprise-attack"]
    assert ent["domain"] == "enterprise-attack"
    assert "Enterprise" in ent["name"]
    techs = ent["techniques"]
    assert len(techs) == 1
    assert techs[0]["techniqueID"] == "T1071.004"
    assert techs[0]["score"] == 55  # 0.55 * 100
    assert techs[0]["color"] == navigator.GRADIENT_MID


def test_render_layers_classification_overrides_coverage():
    """If a technique appears in both classifications and coverage,
    the classification (stronger evidence) should win."""
    report = {
        "mitre_platform_coverage": [
            {
                "technique_id": "T0869",
                "attack_name": "X",
                "domain": "ics-attack",
                "basis": "platform",
                "confidence": 0.0,
            }
        ],
        "mitre_classifications": [
            {
                "technique_id": "T0869",
                "attack_name": "Standard Application Layer Protocol",
                "domain": "ics-attack",
                "basis": "observed",
                "confidence": 0.95,
            }
        ],
    }
    layers = navigator.render_layers(report)
    ics = layers["ics-attack"]
    assert len(ics["techniques"]) == 1
    t = ics["techniques"][0]
    assert t["score"] == 95
    assert t["color"] == navigator.GRADIENT_HIGH


def test_render_layers_empty_report_yields_no_layers():
    layers = navigator.render_layers({"capture_info": {"capture_source": "x"}})
    assert layers == {}


def test_render_layers_metadata_carries_basis_and_assets():
    layers = navigator.render_layers(SAMPLE_REPORT)
    ics_t0869 = next(
        t for t in layers["ics-attack"]["techniques"] if t["techniqueID"] == "T0869"
    )
    md = {entry["name"]: entry["value"] for entry in ics_t0869.get("metadata", [])}
    assert md.get("basis") == "observed"
    assert "192.168.89.2" in md.get("affected_assets", "")
    assert md.get("confidence") == "93%"


def test_render_layers_techniques_sorted_by_score_descending():
    report = {
        "mitre_classifications": [
            {"technique_id": "T100", "domain": "ics-attack", "confidence": 0.3},
            {"technique_id": "T200", "domain": "ics-attack", "confidence": 0.9},
            {"technique_id": "T150", "domain": "ics-attack", "confidence": 0.6},
        ],
    }
    layers = navigator.render_layers(report)
    techs = layers["ics-attack"]["techniques"]
    scores = [t["score"] for t in techs]
    assert scores == sorted(scores, reverse=True)


def test_render_layer_for_domain():
    layer = navigator.render_layer_for_domain(SAMPLE_REPORT, "ics-attack")
    assert layer is not None
    assert layer["domain"] == "ics-attack"
    assert navigator.render_layer_for_domain(SAMPLE_REPORT, "mobile-attack") is None


def test_capture_id_propagation():
    layers = navigator.render_layers(SAMPLE_REPORT, capture_id="explicit-id")
    assert "explicit-id" in layers["ics-attack"]["name"]
    md = {m["name"]: m["value"] for m in layers["ics-attack"]["metadata"]}
    assert md["capture_id"] == "explicit-id"


# ── CLI ──────────────────────────────────────────────────────────────────────


def test_cli_writes_per_domain_files(tmp_path):
    in_path = tmp_path / "report.json"
    in_path.write_text(json.dumps(SAMPLE_REPORT))
    out_base = tmp_path / "report.navigator.json"
    rc = navigator.main([str(in_path), "-o", str(out_base)])
    assert rc == 0
    assert (tmp_path / "report.navigator.ics.json").exists()
    assert (tmp_path / "report.navigator.enterprise.json").exists()


def test_cli_single_domain(tmp_path):
    in_path = tmp_path / "report.json"
    out_path = tmp_path / "ics.json"
    in_path.write_text(json.dumps(SAMPLE_REPORT))
    rc = navigator.main([str(in_path), "-o", str(out_path), "--domain", "ics-attack"])
    assert rc == 0
    layer = json.loads(out_path.read_text())
    assert layer["domain"] == "ics-attack"


def test_cli_no_techniques_returns_error(tmp_path):
    in_path = tmp_path / "empty.json"
    in_path.write_text(json.dumps({"capture_info": {"capture_source": "e"}}))
    rc = navigator.main([str(in_path), "-o", str(tmp_path / "x.json")])
    assert rc == 1


def test_cli_bad_input(tmp_path):
    rc = navigator.main([str(tmp_path / "no.json")])
    assert rc == 1
