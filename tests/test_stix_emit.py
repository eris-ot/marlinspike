"""Tests for marlinspike.emit.stix — STIX 2.1 bundle emission."""

from __future__ import annotations

import json
import os
import sys

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-stix")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from marlinspike.emit import stix  # noqa: E402

SAMPLE_REPORT = {
    "timestamp_start": "2026-05-09T15:10:00Z",
    "timestamp_end": "2026-05-09T15:30:00Z",
    "capture_info": {"capture_source": "test-001"},
    "risk_findings": [
        {
            "severity": "HIGH",
            "category": "CROSS_PURDUE",
            "description": "Cross-Purdue boundary violation",
            "affected_nodes": ["10.0.0.1", "192.168.1.5"],
            "attack_techniques": ["T0815"],
        }
    ],
    "c2_indicators": [
        {
            "type": "C2_BEACONING",
            "severity": "CRITICAL",
            "src": "192.168.89.2",
            "dst": "8.8.8.8",
            "port": 53,
            "transport": "udp",
            "beacon_score": 0.733,
            "description": "Periodic beaconing",
        }
    ],
    "malware_findings": [
        {
            "finding_id": "abc123",
            "rule_id": "test-rule",
            "rule_name": "Test Rule",
            "family": "test-family",
            "severity": "high",
            "confidence": 0.85,
            "summary": "Test malware finding",
            "observable_field": "dst_ip",
            "observable_value": "1.2.3.4",
            "src_ip": "192.168.1.10",
            "dst_ip": "1.2.3.4",
            "timestamp": "2026-05-09T15:20:00Z",
        }
    ],
    "mitre_classifications": [
        {
            "technique_id": "T0869",
            "attack_name": "Standard Application Layer Protocol",
            "domain": "ics-attack",
            "basis": "observed",
            "confidence": 0.93,
            "rationale": "Beaconing detected",
            "affected_nodes": ["192.168.89.2"],
            "tactics": [{"id": "TA0101", "name": "Command and Control"}],
            "attack_version": "16.1",
            "technique_url": "https://attack.mitre.org/techniques/T0869",
        }
    ],
}


# ── Helpers ──────────────────────────────────────────────────────────────────


def test_stable_id_format():
    sid = stix._stable_id("indicator", "test")
    assert sid.startswith("indicator--")
    parts = sid.split("--")
    assert len(parts) == 2
    # Second part is a UUID
    import uuid
    uuid.UUID(parts[1])  # raises if not


def test_stable_id_reproducible():
    a = stix._stable_id("indicator", "same-key")
    b = stix._stable_id("indicator", "same-key")
    assert a == b


def test_stable_id_differs_per_type():
    a = stix._stable_id("indicator", "x")
    b = stix._stable_id("attack-pattern", "x")
    assert a != b


def test_normalise_iso_z_suffix():
    out = stix._normalise_iso("2026-05-09T15:30:00Z")
    assert out.endswith("Z")
    assert "T" in out


def test_normalise_iso_naive_assumed_utc():
    out = stix._normalise_iso("2026-05-09T15:30:00")
    assert out.endswith("Z")


def test_normalise_iso_bad_returns_now():
    out = stix._normalise_iso("not-a-date")
    assert out.endswith("Z")
    assert "T" in out


def test_indicator_pattern_for_ipv4():
    pattern = stix._indicator_pattern_for_finding({"affected_nodes": ["10.0.0.1"]})
    assert "ipv4-addr:value = '10.0.0.1'" in pattern


def test_indicator_pattern_for_mac():
    pattern = stix._indicator_pattern_for_finding({"affected_nodes": ["aa:bb:cc:dd:ee:ff"]})
    assert "mac-addr:value = 'aa:bb:cc:dd:ee:ff'" in pattern


def test_indicator_pattern_disjunction():
    pattern = stix._indicator_pattern_for_finding(
        {"affected_nodes": ["10.0.0.1", "10.0.0.2"]}
    )
    assert "OR" in pattern


def test_indicator_pattern_c2_with_src_dst_port():
    pattern = stix._indicator_pattern_for_c2(
        {"src": "1.1.1.1", "dst": "2.2.2.2", "port": 443}
    )
    assert "src_ref.value = '1.1.1.1'" in pattern
    assert "dst_ref.value = '2.2.2.2'" in pattern
    assert "dst_port = 443" in pattern


def test_indicator_pattern_malware_domain():
    pattern = stix._indicator_pattern_for_malware(
        {"observable_field": "domain", "observable_value": "evil.example.com"}
    )
    assert "domain-name:value = 'evil.example.com'" in pattern


def test_indicator_pattern_malware_sha256():
    pattern = stix._indicator_pattern_for_malware(
        {"observable_field": "sha256", "observable_value": "abc"}
    )
    assert "file:hashes.'SHA-256' = 'abc'" in pattern


def test_confidence_for_severity():
    assert stix._confidence_for({"severity": "CRITICAL"}) == 95
    assert stix._confidence_for({"severity": "HIGH"}) == 80
    assert stix._confidence_for({"severity": "MEDIUM"}) == 60


def test_confidence_for_explicit_confidence():
    assert stix._confidence_for({"confidence": 0.85}) == 85


def test_confidence_for_default():
    assert stix._confidence_for({}) == 50


# ── Bundle structure ─────────────────────────────────────────────────────────


def test_render_bundle_shape():
    bundle = stix.render_bundle(SAMPLE_REPORT)
    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    assert "objects" in bundle
    # 1 identity + 1 risk indicator + 1 c2 indicator + 1 malware indicator
    # + 1 attack-pattern + 1 sighting = 6
    assert len(bundle["objects"]) == 6


def test_render_bundle_contains_identity():
    bundle = stix.render_bundle(SAMPLE_REPORT)
    types = {o["type"] for o in bundle["objects"]}
    assert "identity" in types


def test_render_bundle_contains_indicators():
    bundle = stix.render_bundle(SAMPLE_REPORT)
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert len(indicators) == 3  # risk + c2 + malware


def test_render_bundle_contains_attack_pattern_and_sighting():
    bundle = stix.render_bundle(SAMPLE_REPORT)
    types = [o["type"] for o in bundle["objects"]]
    assert "attack-pattern" in types
    assert "sighting" in types


def test_render_bundle_attack_pattern_carries_external_ref():
    bundle = stix.render_bundle(SAMPLE_REPORT)
    ap = next(o for o in bundle["objects"] if o["type"] == "attack-pattern")
    assert ap["external_references"][0]["external_id"] == "T0869"
    assert "attack.mitre.org" in ap["external_references"][0]["url"]


def test_render_bundle_sighting_references_attack_pattern():
    bundle = stix.render_bundle(SAMPLE_REPORT)
    ap = next(o for o in bundle["objects"] if o["type"] == "attack-pattern")
    sighting = next(o for o in bundle["objects"] if o["type"] == "sighting")
    assert sighting["sighting_of_ref"] == ap["id"]


def test_render_bundle_indicators_have_patterns():
    bundle = stix.render_bundle(SAMPLE_REPORT)
    for obj in bundle["objects"]:
        if obj["type"] == "indicator":
            assert "pattern" in obj
            assert obj["pattern_type"] == "stix"
            assert obj["pattern"].startswith("[")
            assert obj["pattern"].endswith("]")


def test_render_bundle_indicators_have_created_by_ref():
    bundle = stix.render_bundle(SAMPLE_REPORT)
    identity = next(o for o in bundle["objects"] if o["type"] == "identity")
    for obj in bundle["objects"]:
        if obj["type"] != "identity":
            assert obj.get("created_by_ref") == identity["id"]


def test_render_bundle_reproducible_ids():
    """Re-running emit on the same report should produce the same object IDs."""
    b1 = stix.render_bundle(SAMPLE_REPORT, capture_id="fixed")
    b2 = stix.render_bundle(SAMPLE_REPORT, capture_id="fixed")
    ids1 = {o["id"] for o in b1["objects"]}
    ids2 = {o["id"] for o in b2["objects"]}
    assert ids1 == ids2


def test_render_bundle_empty_report_has_only_identity():
    bundle = stix.render_bundle({"timestamp_start": "2026-01-01T00:00:00Z"})
    assert len(bundle["objects"]) == 1
    assert bundle["objects"][0]["type"] == "identity"


def test_render_bundle_risk_finding_has_attack_external_ref():
    bundle = stix.render_bundle(SAMPLE_REPORT)
    risk = next(
        o
        for o in bundle["objects"]
        if o["type"] == "indicator" and o["name"] == "CROSS_PURDUE"
    )
    refs = risk.get("external_references") or []
    assert any(ref.get("external_id") == "T0815" for ref in refs)


# ── CLI ──────────────────────────────────────────────────────────────────────


def test_cli_writes_bundle(tmp_path):
    in_path = tmp_path / "report.json"
    out_path = tmp_path / "out.stix.json"
    in_path.write_text(json.dumps(SAMPLE_REPORT))
    rc = stix.main([str(in_path), "-o", str(out_path)])
    assert rc == 0
    bundle = json.loads(out_path.read_text())
    assert bundle["type"] == "bundle"


def test_cli_compact(tmp_path):
    in_path = tmp_path / "report.json"
    out_path = tmp_path / "out.stix.json"
    in_path.write_text(json.dumps(SAMPLE_REPORT))
    rc = stix.main([str(in_path), "-o", str(out_path), "--compact"])
    assert rc == 0
    text = out_path.read_text()
    # Compact: no leading whitespace on inner lines
    assert "\n  " not in text or text.count("\n") <= 2


def test_cli_bad_input(tmp_path):
    rc = stix.main([str(tmp_path / "no.json")])
    assert rc == 1
