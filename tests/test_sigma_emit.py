"""Tests for marlinspike.emit.sigma — Sigma rule emission."""

from __future__ import annotations

import json
import os
import sys

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-sigma")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from marlinspike.emit import sigma  # noqa: E402

SAMPLE_REPORT = {
    "capture_info": {"capture_source": "test-001"},
    "risk_findings": [
        {
            "severity": "HIGH",
            "category": "CROSS_PURDUE",
            "description": "Cross-zone violation",
            "affected_nodes": ["10.0.0.1", "192.168.1.5"],
            "attack_techniques": ["T0815"],
        },
        {
            "severity": "MEDIUM",
            "category": "ICS_EXTERNAL_COMMS",
            "description": "OT asset to public internet",
            "affected_nodes": ["10.0.0.5"],
        },
        {
            "severity": "HIGH",
            "category": "CLEARTEXT_REMOTE_ACCESS",
            "description": "Telnet observed",
            "affected_nodes": ["10.0.0.10"],
        },
        {
            "severity": "INFO",
            "category": "EXTERNAL_IPS_OBSERVED",
            "description": "External IPs noted",
            "affected_nodes": ["8.8.8.8"],
        },
    ],
    "c2_indicators": [
        {
            "type": "C2_BEACONING",
            "severity": "CRITICAL",
            "src": "192.168.89.2",
            "dst": "8.8.8.8",
            "port": 53,
            "description": "Beaconing",
        }
    ],
    "malware_findings": [
        {
            "finding_id": "abc123",
            "rule_name": "Test rule",
            "severity": "high",
            "summary": "Match",
            "src_ip": "10.0.0.5",
            "dst_ip": "1.2.3.4",
        }
    ],
}


# ── Helpers ──────────────────────────────────────────────────────────────────


def test_severity_mapping():
    assert sigma._severity_for({"severity": "CRITICAL"}) == "critical"
    assert sigma._severity_for({"severity": "HIGH"}) == "high"
    assert sigma._severity_for({"severity": "INFO"}) == "informational"
    assert sigma._severity_for({}) == "medium"  # default


def test_attack_tags():
    finding = {"attack_techniques": ["T0815", "T1071.004"]}
    tags = sigma._attack_tags(finding)
    assert "attack.t0815" in tags
    assert "attack.t1071_004" in tags


def test_stable_uuid_reproducible():
    a = sigma._stable_uuid("CROSS_PURDUE", "10.0.0.1,10.0.0.2")
    b = sigma._stable_uuid("CROSS_PURDUE", "10.0.0.1,10.0.0.2")
    assert a == b
    # UUID-shaped (8-4-4-4-12)
    parts = a.split("-")
    assert len(parts) == 5


def test_yaml_scalar_quoting():
    assert sigma._yaml_scalar("simple") == "simple"
    assert sigma._yaml_scalar("with: colon").startswith('"')
    assert sigma._yaml_scalar("true") == '"true"'  # quoted to disambiguate
    assert sigma._yaml_scalar(42) == "42"
    assert sigma._yaml_scalar(True) == "true"
    assert sigma._yaml_scalar(None) == "null"


# ── render_rules ─────────────────────────────────────────────────────────────


def test_render_rules_emits_for_emittable_categories():
    rules = sigma.render_rules(SAMPLE_REPORT)
    titles = [rule["title"] for _, rule in rules]
    # Should include CROSS_PURDUE, ICS_EXTERNAL_COMMS, CLEARTEXT_REMOTE_ACCESS,
    # C2_BEACONING (from c2_indicators), MALWARE_IOC_MATCH (from malware_findings)
    # Should NOT include EXTERNAL_IPS_OBSERVED
    assert any("CROSS_PURDUE" in t for t in titles)
    assert any("ICS_EXTERNAL_COMMS" in t for t in titles)
    assert any("CLEARTEXT_REMOTE_ACCESS" in t for t in titles)
    assert any("C2_BEACONING" in t for t in titles)
    assert any("MALWARE_IOC_MATCH" in t for t in titles)
    assert not any("EXTERNAL_IPS_OBSERVED" in t for t in titles)


def test_render_rules_skip_categories():
    """Categories with no log-event projection are skipped."""
    report = {
        "risk_findings": [
            {"category": "OPC_NO_SECURITY", "severity": "HIGH"},
            {"category": "PORT_SCAN_TARGET", "severity": "HIGH"},
            {"category": "NO_AUTH_OBSERVED", "severity": "MEDIUM"},
        ]
    }
    rules = sigma.render_rules(report)
    assert rules == []


def test_render_rules_have_required_sigma_fields():
    rules = sigma.render_rules(SAMPLE_REPORT)
    for _, rule in rules:
        assert "title" in rule
        assert "id" in rule
        assert "logsource" in rule
        assert "detection" in rule
        assert "level" in rule
        assert "condition" in rule["detection"]


def test_render_rules_dedupe_by_id():
    """Two findings with same category and same affected_nodes should
    produce the same rule id and be deduped."""
    report = {
        "risk_findings": [
            {"category": "CROSS_PURDUE", "severity": "HIGH",
             "affected_nodes": ["a", "b"]},
            {"category": "CROSS_PURDUE", "severity": "HIGH",
             "affected_nodes": ["a", "b"]},
        ]
    }
    rules = sigma.render_rules(report)
    assert len(rules) == 1


def test_render_rules_cross_purdue_targets_zeek_conn():
    rules = sigma.render_rules({"risk_findings": [
        {"category": "CROSS_PURDUE", "severity": "HIGH",
         "affected_nodes": ["10.0.0.1"]}
    ]})
    _, rule = rules[0]
    assert rule["logsource"]["product"] == "zeek"
    assert rule["logsource"]["service"] == "conn"


def test_render_rules_cleartext_remote_includes_known_ports():
    rules = sigma.render_rules({"risk_findings": [
        {"category": "CLEARTEXT_REMOTE_ACCESS", "severity": "HIGH",
         "affected_nodes": ["10.0.0.10"]}
    ]})
    _, rule = rules[0]
    sel = rule["detection"]["selection"]
    assert 23 in sel["id.resp_p|in"]  # telnet
    assert 21 in sel["id.resp_p|in"]  # ftp


def test_render_rules_modbus_write_targets_modbus_log():
    rules = sigma.render_rules({"risk_findings": [
        {"category": "MODBUS_WRITE_ANON", "severity": "HIGH",
         "affected_nodes": ["10.0.0.5"]}
    ]})
    _, rule = rules[0]
    assert rule["logsource"]["service"] == "modbus"


def test_render_rules_carries_attack_tags():
    rules = sigma.render_rules({"risk_findings": [
        {"category": "CROSS_PURDUE", "severity": "HIGH",
         "affected_nodes": ["a"], "attack_techniques": ["T0815"]}
    ]})
    _, rule = rules[0]
    assert "attack.t0815" in rule["tags"]


def test_render_rules_marlinspike_tag_per_rule():
    rules = sigma.render_rules(SAMPLE_REPORT)
    for _, rule in rules:
        assert any(t.startswith("marlinspike.") for t in rule["tags"])


# ── render_yaml_concat ───────────────────────────────────────────────────────


def test_render_yaml_concat_emits_separators():
    yaml_text = sigma.render_yaml_concat(SAMPLE_REPORT)
    assert yaml_text  # non-empty
    # Multiple rules should be separated by ---
    if SAMPLE_REPORT.get("risk_findings", 0):
        assert "\n---\n" in yaml_text


def test_render_yaml_concat_empty():
    assert sigma.render_yaml_concat({}) == ""


def test_render_yaml_concat_starts_with_title():
    yaml_text = sigma.render_yaml_concat(SAMPLE_REPORT)
    assert yaml_text.startswith("title:")


# ── CLI ──────────────────────────────────────────────────────────────────────


def test_cli_writes_yaml_file(tmp_path):
    in_path = tmp_path / "report.json"
    out_path = tmp_path / "rules.yml"
    in_path.write_text(json.dumps(SAMPLE_REPORT))
    rc = sigma.main([str(in_path), "-o", str(out_path)])
    assert rc == 0
    assert out_path.exists()
    text = out_path.read_text()
    assert "title:" in text


def test_cli_writes_directory(tmp_path):
    in_path = tmp_path / "report.json"
    out_dir = tmp_path / "rules"
    in_path.write_text(json.dumps(SAMPLE_REPORT))
    rc = sigma.main([str(in_path), "-o", str(out_dir) + "/"])
    assert rc == 0
    assert out_dir.is_dir()
    files = list(out_dir.glob("*.yml"))
    assert len(files) >= 1


def test_cli_no_emittable_returns_error(tmp_path):
    in_path = tmp_path / "empty.json"
    in_path.write_text(json.dumps({"risk_findings": []}))
    rc = sigma.main([str(in_path), "-o", str(tmp_path / "x.yml")])
    assert rc == 1


def test_cli_bad_input(tmp_path):
    rc = sigma.main([str(tmp_path / "no.json")])
    assert rc == 1
