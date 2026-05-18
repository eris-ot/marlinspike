"""Tests for marlinspike.emit.ocsf — OCSF v1.4.0 Detection Finding emission."""

from __future__ import annotations

import json
import os
import sys

# Set DATABASE_URL BEFORE importing marlinspike (config reads at import time).
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-ocsf")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from marlinspike.emit import ocsf  # noqa: E402

# ── Sample report fixture ────────────────────────────────────────────────────

SAMPLE_REPORT = {
    "timestamp_start": "2026-05-09T15:10:00Z",
    "timestamp_end": "2026-05-09T15:30:00Z",
    "capture_info": {"capture_source": "test-capture-001"},
    "risk_findings": [
        {
            "severity": "HIGH",
            "category": "CROSS_PURDUE",
            "description": "Cross-Purdue boundary violation",
            "affected_nodes": ["10.0.0.1", "192.168.1.5"],
            "affected_edges": [],
            "cvss_impact": 7.5,
            "remediation": "Implement network segmentation per IEC 62443",
            "attack_techniques": ["T0815"],
        },
        {
            "severity": "INFO",
            "category": "EXTERNAL_IPS_OBSERVED",
            "description": "Public IPs observed in capture",
            "affected_nodes": ["8.8.8.8"],
            "affected_edges": [],
        },
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
            "interval": 10.0,
            "jitter": 0.135,
            "packets": 2731,
            "description": "Possible C2 beaconing",
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
            "src_mac": "aa:bb:cc:dd:ee:ff",
            "timestamp": "2026-05-09T15:20:00Z",
            "references": ["https://attack.mitre.org/techniques/T1071/"],
            "tags": ["c2", "test"],
        }
    ],
    "mitre_classifications": [
        {
            "technique_id": "T0869",
            "attack_name": "Standard Application Layer Protocol",
            "domain": "ics-attack",
            "basis": "observed",
            "confidence": 0.93,
            "rationale": "Periodic beaconing detected",
            "affected_nodes": ["192.168.89.2"],
            "tactics": [
                {
                    "id": "TA0101",
                    "name": "Command and Control",
                    "url": "https://attack.mitre.org/tactics/TA0101",
                }
            ],
            "attack_version": "16.1",
            "technique_url": "https://attack.mitre.org/techniques/T0869",
        }
    ],
}


# ── Helpers ───────────────────────────────────────────────────────────────────


def test_severity_mapping():
    assert ocsf._severity("CRITICAL") == (5, "Critical")
    assert ocsf._severity("HIGH") == (4, "High")
    assert ocsf._severity("MEDIUM") == (3, "Medium")
    assert ocsf._severity("LOW") == (2, "Low")
    assert ocsf._severity("INFO") == (1, "Informational")
    assert ocsf._severity("info") == (1, "Informational")
    assert ocsf._severity("medium") == (3, "Medium")
    assert ocsf._severity(None) == (1, "Informational")
    assert ocsf._severity("UNKNOWN") == (1, "Informational")


def test_confidence_id():
    assert ocsf._confidence_id(0.9) == 3  # High
    assert ocsf._confidence_id(0.8) == 3  # boundary High
    assert ocsf._confidence_id(0.7) == 2  # Medium
    assert ocsf._confidence_id(0.5) == 2  # boundary Medium
    assert ocsf._confidence_id(0.3) == 1  # Low
    assert ocsf._confidence_id(0.0) == 1
    assert ocsf._confidence_id(None) == 1


def test_to_unix_ms():
    # ISO with Z suffix
    ms = ocsf._to_unix_ms("2026-05-09T15:30:00Z")
    assert ms is not None
    # ISO with explicit offset
    ms2 = ocsf._to_unix_ms("2026-05-09T15:30:00+00:00")
    assert ms == ms2
    # Naive ISO assumed UTC
    ms3 = ocsf._to_unix_ms("2026-05-09T15:30:00")
    assert ms3 == ms
    # Bad input
    assert ocsf._to_unix_ms(None) is None
    assert ocsf._to_unix_ms("") is None
    assert ocsf._to_unix_ms("not a date") is None


def test_signature_stable_across_node_order():
    f1 = {"category": "CROSS_PURDUE", "affected_nodes": ["a", "b"], "affected_edges": []}
    f2 = {"category": "CROSS_PURDUE", "affected_nodes": ["b", "a"], "affected_edges": []}
    assert ocsf._signature_for_finding(f1) == ocsf._signature_for_finding(f2)


def test_signature_differs_on_category():
    f1 = {"category": "A", "affected_nodes": ["x"], "affected_edges": []}
    f2 = {"category": "B", "affected_nodes": ["x"], "affected_edges": []}
    assert ocsf._signature_for_finding(f1) != ocsf._signature_for_finding(f2)


# ── Per-finding renderers ────────────────────────────────────────────────────


def test_render_risk_finding_shape():
    finding = SAMPLE_REPORT["risk_findings"][0]
    rec = ocsf.render_risk_finding(finding, SAMPLE_REPORT)
    assert rec["class_uid"] == 2004
    assert rec["class_name"] == "Detection Finding"
    assert rec["category_uid"] == 2
    assert rec["activity_id"] == 1
    assert rec["type_uid"] == 200401
    assert rec["severity_id"] == 4
    assert rec["severity"] == "High"
    assert rec["finding_info"]["title"] == "CROSS_PURDUE"
    assert rec["finding_info"]["uid"]
    assert len(rec["affected_resources"]) == 2
    assert rec["affected_resources"][0]["name"] in ("10.0.0.1", "192.168.1.5")
    assert rec["remediation"]["desc"].startswith("Implement")
    assert rec["attacks"][0]["technique"]["uid"] == "T0815"
    assert rec["unmapped"]["marlinspike"]["category"] == "CROSS_PURDUE"
    assert rec["metadata"]["version"] == "1.4.0"
    assert rec["metadata"]["product"]["name"] == "MarlinSpike"


def test_render_risk_finding_info_severity():
    finding = SAMPLE_REPORT["risk_findings"][1]
    rec = ocsf.render_risk_finding(finding, SAMPLE_REPORT)
    assert rec["severity_id"] == 1
    assert rec["severity"] == "Informational"


def test_render_c2_indicator_shape():
    indicator = SAMPLE_REPORT["c2_indicators"][0]
    rec = ocsf.render_c2_indicator(indicator, SAMPLE_REPORT)
    assert rec["class_uid"] == 2004
    assert rec["severity_id"] == 5  # CRITICAL
    assert rec["src_endpoint"]["ip"] == "192.168.89.2"
    assert rec["dst_endpoint"]["ip"] == "8.8.8.8"
    assert rec["dst_endpoint"]["port"] == 53
    assert rec["connection_info"]["protocol_name"] == "UDP"
    assert rec["confidence_id"] == 2  # 0.733 → Medium
    assert rec["unmapped"]["marlinspike"]["beacon_score"] == 0.733


def test_render_malware_finding_shape():
    finding = SAMPLE_REPORT["malware_findings"][0]
    rec = ocsf.render_malware_finding(finding, SAMPLE_REPORT)
    assert rec["class_uid"] == 2004
    assert rec["severity_id"] == 4  # 'high' lowercase normalised
    assert rec["confidence_id"] == 3  # 0.85 → High
    assert rec["finding_info"]["uid"] == "abc123"
    assert rec["finding_info"]["title"] == "Test Rule"
    assert rec["src_endpoint"]["mac"] == "aa:bb:cc:dd:ee:ff"
    assert rec["dst_endpoint"]["ip"] == "1.2.3.4"
    assert rec["evidences"][0]["name"] == "dst_ip"
    assert rec["evidences"][0]["value"] == "1.2.3.4"
    assert rec["unmapped"]["marlinspike"]["rule_id"] == "test-rule"


def test_render_mitre_classification_shape():
    classification = SAMPLE_REPORT["mitre_classifications"][0]
    rec = ocsf.render_mitre_classification(classification, SAMPLE_REPORT)
    assert rec["class_uid"] == 2004
    assert rec["severity_id"] == 4  # confidence 0.93 → High
    assert rec["confidence_id"] == 3
    assert rec["attacks"][0]["technique"]["uid"] == "T0869"
    assert rec["attacks"][0]["tactics"][0]["uid"] == "TA0101"
    assert rec["unmapped"]["marlinspike"]["domain"] == "ics-attack"


# ── Top-level entry points ────────────────────────────────────────────────────


def test_render_report_emits_all_finding_classes():
    records = ocsf.render_report(SAMPLE_REPORT)
    # 2 risk_findings + 1 c2_indicator + 1 malware_finding + 1 mitre_classification = 5
    assert len(records) == 5
    # All must be Detection Finding (2004)
    assert all(r["class_uid"] == 2004 for r in records)


def test_render_ndjson_one_record_per_line():
    ndjson = ocsf.render_ndjson(SAMPLE_REPORT)
    lines = ndjson.split("\n")
    assert len(lines) == 5
    # Each line must be valid JSON
    for line in lines:
        parsed = json.loads(line)
        assert parsed["class_uid"] == 2004


def test_render_ndjson_empty_report():
    empty = {"timestamp_start": "2026-05-09T00:00:00Z", "timestamp_end": "2026-05-09T01:00:00Z"}
    assert ocsf.render_ndjson(empty) == ""


def test_render_ndjson_capture_id_propagation():
    """Custom capture_id should appear in unmapped.marlinspike.capture_id."""
    ndjson = ocsf.render_ndjson(SAMPLE_REPORT, capture_id="custom-id-42")
    for line in ndjson.split("\n"):
        rec = json.loads(line)
        assert rec["unmapped"]["marlinspike"]["capture_id"] == "custom-id-42"


def test_prune_drops_none_and_empty():
    out = ocsf._prune({"a": 1, "b": None, "c": [], "d": {}, "e": [1, None, 2]})
    assert out == {"a": 1, "e": [1, 2]}


# ── CLI ───────────────────────────────────────────────────────────────────────


def test_cli_writes_to_output(tmp_path):
    in_path = tmp_path / "report.json"
    out_path = tmp_path / "report.ocsf.ndjson"
    in_path.write_text(json.dumps(SAMPLE_REPORT))
    rc = ocsf.main([str(in_path), "-o", str(out_path)])
    assert rc == 0
    assert out_path.exists()
    content = out_path.read_text().strip()
    assert content
    lines = content.split("\n")
    assert len(lines) == 5
    for line in lines:
        rec = json.loads(line)
        assert rec["class_uid"] == 2004


def test_cli_bad_input(tmp_path):
    rc = ocsf.main([str(tmp_path / "nope.json")])
    assert rc == 1


def test_cli_capture_id_override(tmp_path):
    in_path = tmp_path / "report.json"
    out_path = tmp_path / "out.ndjson"
    in_path.write_text(json.dumps(SAMPLE_REPORT))
    ocsf.main([str(in_path), "-o", str(out_path), "--capture-id", "from-cli"])
    rec = json.loads(out_path.read_text().strip().split("\n")[0])
    assert rec["unmapped"]["marlinspike"]["capture_id"] == "from-cli"
