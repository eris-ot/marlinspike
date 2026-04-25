"""Unit tests for the marlinspike-arp plugin.

Run with:
    python3 -m pytest tests/test_marlinspike_arp.py -v
or:
    python3 tests/test_marlinspike_arp.py
"""
import json
import sys
import tempfile
import traceback
from pathlib import Path

# Ensure the repo root is on the path regardless of how this is invoked.
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from plugins.marlinspike_arp.plugin import (
    PLUGIN_ID,
    _detect,
    _merge_packs,
    run,
)

# ---------------------------------------------------------------------------
# Minimal hand-crafted report fixtures
# ---------------------------------------------------------------------------

MINIMAL_REPORT_NO_ARP: dict = {
    "capture_info": {"filename": "test.pcap"},
    "conversations": [
        {"protocol": "TCP", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "packet_count": 5},
    ],
    "risk_findings": [],
    "nodes": [],
    "edges": [],
}

MINIMAL_REPORT_DUPLICATE_IP: dict = {
    "capture_info": {"filename": "test.pcap"},
    "conversations": [
        {
            "protocol": "ARP",
            "src_mac": "aa:bb:cc:dd:ee:01",
            "dst_mac": "ff:ff:ff:ff:ff:ff",
            "src_ip": "192.168.1.100",
            "dst_ip": "192.168.1.1",
            "src_ips": ["192.168.1.100"],
            "dst_ips": ["192.168.1.1"],
            "packet_count": 10,
            "first_seen": "1700000000.0",
        },
        {
            "protocol": "ARP",
            "src_mac": "aa:bb:cc:dd:ee:02",  # different MAC, same src_ip
            "dst_mac": "ff:ff:ff:ff:ff:ff",
            "src_ip": "192.168.1.100",
            "dst_ip": "192.168.1.1",
            "src_ips": ["192.168.1.100"],
            "dst_ips": ["192.168.1.1"],
            "packet_count": 8,
            "first_seen": "1700000005.0",
        },
    ],
    "risk_findings": [],
    "nodes": [],
    "edges": [],
}

MINIMAL_REPORT_GATEWAY_CHANGE: dict = {
    "capture_info": {"filename": "test.pcap"},
    "conversations": [
        {
            "protocol": "ARP",
            "src_mac": "de:ad:be:ef:00:01",
            "dst_mac": "ff:ff:ff:ff:ff:ff",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.254",
            "src_ips": [],
            "dst_ips": [],
            "packet_count": 3,
        },
        {
            "protocol": "ARP",
            "src_mac": "de:ad:be:ef:00:02",  # different MAC for same gateway IP
            "dst_mac": "ff:ff:ff:ff:ff:ff",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.254",
            "src_ips": [],
            "dst_ips": [],
            "packet_count": 4,
        },
    ],
    "risk_findings": [],
    "nodes": [],
    "edges": [],
}

MINIMAL_REPORT_SCAN_OBSERVATIONS: dict = {
    "capture_info": {"filename": "test.pcap"},
    "conversations": [
        {
            "protocol": "ARP",
            "src_mac": "00:11:22:33:44:55",
            "dst_mac": "ff:ff:ff:ff:ff:ff",
            "src_ip": "10.0.0.50",
            "dst_ip": f"10.0.0.{i}",
            "src_ips": ["10.0.0.50"],
            "dst_ips": [f"10.0.0.{i}"],
            "packet_count": 1,
        }
        for i in range(1, 40)
    ],
    # 30 ARP requests from the scanner, only 2 replies come back.
    "arp_observations": (
        [
            {
                "timestamp": 1700000000.0 + i,
                "src_mac": "00:11:22:33:44:55",
                "src_ip": "10.0.0.50",
                "dst_mac": "00:00:00:00:00:00",
                "dst_ip": f"10.0.0.{i}",
                "opcode": 1,
                "is_gratuitous": False,
            }
            for i in range(1, 31)
        ]
        + [
            {
                "timestamp": 1700000100.0,
                "src_mac": "aa:aa:aa:aa:aa:01",
                "src_ip": "10.0.0.1",
                "dst_mac": "00:11:22:33:44:55",
                "dst_ip": "10.0.0.50",
                "opcode": 2,
                "is_gratuitous": False,
            },
            {
                "timestamp": 1700000101.0,
                "src_mac": "aa:aa:aa:aa:aa:02",
                "src_ip": "10.0.0.2",
                "dst_mac": "00:11:22:33:44:55",
                "dst_ip": "10.0.0.50",
                "opcode": 2,
                "is_gratuitous": False,
            },
        ]
    ),
    "risk_findings": [],
    "nodes": [],
    "edges": [],
}

MINIMAL_REPORT_MAC_MANY_IPS: dict = {
    "capture_info": {"filename": "test.pcap"},
    "conversations": [
        {
            "protocol": "ARP",
            "src_mac": "ba:d0:c0:ff:ee:01",
            "dst_mac": "ff:ff:ff:ff:ff:ff",
            "src_ip": f"192.168.0.{i}",
            "dst_ip": "192.168.0.254",
            "src_ips": [f"192.168.0.{i}"],
            "packet_count": 1,
        }
        for i in range(1, 12)  # 11 distinct IPs > threshold=5
    ],
    "risk_findings": [],
    "nodes": [],
    "edges": [],
}

# Default settings (no packs, uses _merge_packs([]))
DEFAULT_SETTINGS = _merge_packs([])


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _run_detect(report: dict, settings: dict | None = None) -> dict:
    return _detect(report, settings or DEFAULT_SETTINGS)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_no_arp_conversations_does_not_crash():
    """A report with zero ARP conversations must produce a valid empty artifact."""
    result = _run_detect(MINIMAL_REPORT_NO_ARP)
    assert result["findings"] == [], f"Expected no findings, got: {result['findings']}"
    assert result["summary"]["arp_conversation_count"] == 0
    assert result["summary"]["finding_total"] == 0


def test_duplicate_ip_claim_detected():
    """Two ARP conversations with the same src_ip from different src_macs triggers ARP_DUPLICATE_IP_CLAIM."""
    result = _run_detect(MINIMAL_REPORT_DUPLICATE_IP)
    findings = result["findings"]

    dup_findings = [f for f in findings if f["category"] == "ARP_DUPLICATE_IP_CLAIM"]
    assert len(dup_findings) >= 1, (
        f"Expected at least one ARP_DUPLICATE_IP_CLAIM, got findings: {findings}"
    )

    dup = dup_findings[0]
    assert dup["ip"] == "192.168.1.100"
    claimed = sorted(dup["claimed_by_macs"])
    assert "aa:bb:cc:dd:ee:01" in claimed
    assert "aa:bb:cc:dd:ee:02" in claimed
    assert len(claimed) == 2

    # ATT&CK techniques must include T0830 and T1557.002
    techniques = dup.get("attack_techniques", [])
    assert "T0830" in techniques
    assert "T1557.002" in techniques


def test_gateway_mac_change_detected():
    """Gateway IP bound to two MACs triggers ARP_GATEWAY_MAC_CHANGE when gateway_ip is configured."""
    settings = _merge_packs([])
    settings["gateway_ip"] = "10.0.0.1"
    settings["gateway_mac_change"]["enabled"] = True

    result = _run_detect(MINIMAL_REPORT_GATEWAY_CHANGE, settings)
    findings = result["findings"]

    gw_findings = [f for f in findings if f["category"] == "ARP_GATEWAY_MAC_CHANGE"]
    assert len(gw_findings) >= 1, f"Expected ARP_GATEWAY_MAC_CHANGE, got: {findings}"
    assert gw_findings[0]["ip"] == "10.0.0.1"


def test_gateway_mac_change_not_triggered_without_config():
    """ARP_GATEWAY_MAC_CHANGE must NOT fire when gateway_ip is not configured."""
    settings = _merge_packs([])
    settings["gateway_ip"] = None

    result = _run_detect(MINIMAL_REPORT_GATEWAY_CHANGE, settings)
    gw_findings = [f for f in result["findings"] if f["category"] == "ARP_GATEWAY_MAC_CHANGE"]
    assert gw_findings == [], f"Unexpected gateway findings: {gw_findings}"


def test_mac_claims_many_ips():
    """A MAC claiming more IPs than threshold triggers ARP_MAC_CLAIMS_MANY_IPS."""
    result = _run_detect(MINIMAL_REPORT_MAC_MANY_IPS)
    findings = result["findings"]

    many_ip_findings = [f for f in findings if f["category"] == "ARP_MAC_CLAIMS_MANY_IPS"]
    assert len(many_ip_findings) >= 1, f"Expected ARP_MAC_CLAIMS_MANY_IPS, got: {findings}"
    assert many_ip_findings[0]["ip_count"] == 11


def test_mac_claims_many_ips_disabled():
    """Disabling the mac_claims_many_ips rule suppresses the finding."""
    settings = _merge_packs([])
    settings["mac_claims_many_ips"]["enabled"] = False
    result = _run_detect(MINIMAL_REPORT_MAC_MANY_IPS, settings)
    assert not any(f["category"] == "ARP_MAC_CLAIMS_MANY_IPS" for f in result["findings"])


def test_duplicate_ip_rule_disabled():
    """Disabling the duplicate_ip rule suppresses the finding."""
    settings = _merge_packs([])
    settings["duplicate_ip"]["enabled"] = False
    result = _run_detect(MINIMAL_REPORT_DUPLICATE_IP, settings)
    assert not any(f["category"] == "ARP_DUPLICATE_IP_CLAIM" for f in result["findings"])


def test_scan_behavior_uses_arp_observations_when_available():
    """When arp_observations is populated, scan detection uses exact opcode-based ratio."""
    result = _run_detect(MINIMAL_REPORT_SCAN_OBSERVATIONS)
    scan_findings = [f for f in result["findings"] if f["category"] == "ARP_SCAN_BEHAVIOR"]
    assert len(scan_findings) == 1, f"Expected one scan finding, got: {scan_findings}"

    f = scan_findings[0]
    assert f["mac"] == "00:11:22:33:44:55"
    assert f["target_count"] == 30
    assert f["replies_received"] == 2
    assert f["response_ratio"] == round(2 / 30, 3)
    assert f["signal_source"] == "arp_observations"
    assert result["summary"]["arp_observation_count"] == 32


def test_scan_behavior_falls_back_to_conversation_proxy():
    """Without arp_observations, scan detection falls back to the proxy signal.

    Proxy fires when conv_count / distinct_target_count is below ratio_max. Uses a fixture
    where a single src_mac has 2 conversations aggregating 25 distinct dst_ips via dst_ips
    lists, giving ratio 2/25 = 0.08 < 0.2 ratio_max.
    """
    report = {
        "capture_info": {"filename": "proxy.pcap"},
        "conversations": [
            {
                "protocol": "ARP",
                "src_mac": "c0:ff:ee:00:00:01",
                "dst_mac": "ff:ff:ff:ff:ff:ff",
                "src_ip": "172.16.0.50",
                "dst_ip": "172.16.0.1",
                "src_ips": ["172.16.0.50"],
                "dst_ips": [f"172.16.0.{i}" for i in range(1, 13)],
                "packet_count": 12,
            },
            {
                "protocol": "ARP",
                "src_mac": "c0:ff:ee:00:00:01",
                "dst_mac": "ff:ff:ff:ff:ff:ff",
                "src_ip": "172.16.0.50",
                "dst_ip": "172.16.0.100",
                "src_ips": ["172.16.0.50"],
                "dst_ips": [f"172.16.0.{i}" for i in range(100, 113)],
                "packet_count": 13,
            },
        ],
        "risk_findings": [],
        "nodes": [],
        "edges": [],
    }
    result = _run_detect(report)
    scan_findings = [f for f in result["findings"] if f["category"] == "ARP_SCAN_BEHAVIOR"]
    assert len(scan_findings) == 1, f"Expected one scan finding via fallback, got: {scan_findings}"
    f = scan_findings[0]
    assert f["signal_source"] == "conversation_proxy"
    assert "estimated_response_ratio" in f
    assert "replies_received" not in f
    assert result["summary"]["arp_observation_count"] == 0


def test_l2_anomaly_arp_spoof_produces_duplicate_ip_claim():
    """A bilgepump:arp_spoof event should map to ARP_DUPLICATE_IP_CLAIM with the
    parsed before/after MACs, even when no ARP conversations are present.
    """
    report = {
        "capture_info": {"filename": "rust.pcap"},
        "conversations": [],
        "l2_anomalies": [
            {
                "decoder": "bilgepump:arp_spoof",
                "reason": "ARP spoof: 192.168.1.100 moved from bb:bb:bb:00:00:01 to bb:bb:bb:00:00:02",
                "timestamp": "1700000005.0",
            },
        ],
        "risk_findings": [],
        "nodes": [],
        "edges": [],
    }
    result = _run_detect(report)
    dup = [f for f in result["findings"] if f["category"] == "ARP_DUPLICATE_IP_CLAIM"]
    assert len(dup) == 1, f"Expected one duplicate-ip finding, got: {result['findings']}"
    f = dup[0]
    assert f["ip"] == "192.168.1.100"
    assert sorted(f["claimed_by_macs"]) == ["bb:bb:bb:00:00:01", "bb:bb:bb:00:00:02"]
    assert f["signal_source"] == "l2_anomalies"
    assert f["engine_event_count"] == 1
    assert result["summary"]["l2_anomaly_count"] == 1


def test_l2_anomaly_reason_can_be_nested_under_details():
    """Bilgepump events from the Rust DPI engine carry the reason string under
    `details.reason`. The plugin must read both that and a top-level `reason`.
    """
    report = {
        "capture_info": {"filename": "rust.pcap"},
        "conversations": [],
        "l2_anomalies": [
            {
                "decoder": "bilgepump:arp_spoof",
                "anomaly_type": "arp_spoof",
                "timestamp": "2023-11-14T22:13:23.010Z",
                "details": {
                    "decoder": "bilgepump:arp_spoof",
                    "severity": "critical",
                    "reason": "ARP spoof: 10.0.0.1 moved from cc:cc:cc:00:00:01 to de:ad:be:ef:00:99",
                },
            },
        ],
        "risk_findings": [],
        "nodes": [],
        "edges": [],
    }
    result = _run_detect(report)
    dup = [f for f in result["findings"] if f["category"] == "ARP_DUPLICATE_IP_CLAIM"]
    assert len(dup) == 1, f"Expected nested-reason event to produce a finding, got: {result['findings']}"
    assert dup[0]["ip"] == "10.0.0.1"
    assert sorted(dup[0]["claimed_by_macs"]) == ["cc:cc:cc:00:00:01", "de:ad:be:ef:00:99"]


def test_l2_anomaly_arp_gratuitous_produces_gratuitous_reply():
    """A bilgepump:arp_gratuitous event maps to ARP_GRATUITOUS_REPLY."""
    report = {
        "capture_info": {"filename": "rust.pcap"},
        "conversations": [],
        "l2_anomalies": [
            {
                "decoder": "bilgepump:arp_gratuitous",
                "reason": "gratuitous ARP from f0:f0:f0:00:00:01 claiming 192.168.50.10",
                "timestamp": "1700000010.0",
            },
            {
                "decoder": "bilgepump:arp_gratuitous",
                "reason": "gratuitous ARP from f0:f0:f0:00:00:01 claiming 192.168.50.10",
                "timestamp": "1700000011.0",
            },
        ],
        "risk_findings": [],
        "nodes": [],
        "edges": [],
    }
    result = _run_detect(report)
    grat = [f for f in result["findings"] if f["category"] == "ARP_GRATUITOUS_REPLY"]
    assert len(grat) == 1, f"Expected single aggregated gratuitous finding, got: {grat}"
    f = grat[0]
    assert f["mac"] == "f0:f0:f0:00:00:01"
    assert f["ip"] == "192.168.50.10"
    assert f["packet_count"] == 2
    assert f["signal_source"] == "l2_anomalies"


def test_gratuitous_from_observations():
    """An opcode=2 packet with src_ip == dst_ip should produce ARP_GRATUITOUS_REPLY
    even when l2_anomalies is empty (tshark / Python DPI path).
    """
    report = {
        "capture_info": {"filename": "tshark.pcap"},
        "conversations": [],
        "arp_observations": [
            {
                "timestamp": 1700000020.0,
                "src_mac": "de:ad:be:ef:00:99",
                "src_ip": "10.0.0.1",
                "dst_mac": "ff:ff:ff:ff:ff:ff",
                "dst_ip": "10.0.0.1",
                "opcode": 2,
                "is_gratuitous": True,
            },
        ],
        "risk_findings": [],
        "nodes": [],
        "edges": [],
    }
    result = _run_detect(report)
    grat = [f for f in result["findings"] if f["category"] == "ARP_GRATUITOUS_REPLY"]
    assert len(grat) == 1, f"Expected gratuitous finding from observations, got: {grat}"
    f = grat[0]
    assert f["mac"] == "de:ad:be:ef:00:99"
    assert f["ip"] == "10.0.0.1"
    assert f["signal_source"] == "arp_observations"


def test_l2_and_observation_gratuitous_are_deduped():
    """The same (src_mac, src_ip) gratuitous event should not appear twice
    when both observations and l2_anomalies report it.
    """
    report = {
        "capture_info": {"filename": "rust.pcap"},
        "conversations": [],
        "arp_observations": [
            {
                "timestamp": 1700000020.0,
                "src_mac": "de:ad:be:ef:00:99",
                "src_ip": "10.0.0.1",
                "dst_mac": "ff:ff:ff:ff:ff:ff",
                "dst_ip": "10.0.0.1",
                "opcode": 2,
                "is_gratuitous": True,
            },
        ],
        "l2_anomalies": [
            {
                "decoder": "bilgepump:arp_gratuitous",
                "reason": "gratuitous ARP from de:ad:be:ef:00:99 claiming 10.0.0.1",
                "timestamp": "1700000020.0",
            },
        ],
        "risk_findings": [],
        "nodes": [],
        "edges": [],
    }
    result = _run_detect(report)
    grat = [f for f in result["findings"] if f["category"] == "ARP_GRATUITOUS_REPLY"]
    assert len(grat) == 1, f"Expected exactly one gratuitous finding after dedup, got: {grat}"
    # Observation-derived signal wins (runs first in _detect)
    assert grat[0]["signal_source"] == "arp_observations"


def test_gratuitous_reply_disabled():
    """Disabling gratuitous_reply suppresses both observation- and engine-derived findings."""
    settings = _merge_packs([])
    settings["gratuitous_reply"]["enabled"] = False
    report = {
        "capture_info": {"filename": "x.pcap"},
        "conversations": [],
        "arp_observations": [
            {
                "timestamp": 1700000020.0,
                "src_mac": "de:ad:be:ef:00:99",
                "src_ip": "10.0.0.1",
                "dst_mac": "ff:ff:ff:ff:ff:ff",
                "dst_ip": "10.0.0.1",
                "opcode": 2,
                "is_gratuitous": True,
            },
        ],
        "l2_anomalies": [
            {
                "decoder": "bilgepump:arp_gratuitous",
                "reason": "gratuitous ARP from de:ad:be:ef:00:99 claiming 10.0.0.1",
                "timestamp": "1700000020.0",
            },
        ],
        "risk_findings": [],
        "nodes": [],
        "edges": [],
    }
    result = _run_detect(report, settings)
    grat = [f for f in result["findings"] if f["category"] == "ARP_GRATUITOUS_REPLY"]
    assert grat == [], f"Expected gratuitous to be suppressed, got: {grat}"


def test_output_is_deterministic():
    """Running detection twice on the same input produces identical sorted output."""
    r1 = _run_detect(MINIMAL_REPORT_DUPLICATE_IP)
    r2 = _run_detect(MINIMAL_REPORT_DUPLICATE_IP)
    assert r1["findings"] == r2["findings"]


def test_run_end_to_end_writes_artifact():
    """Full end-to-end: run() writes a valid sidecar JSON artifact to disk."""
    rules_path = REPO_ROOT / "rules" / "arp" / "base.yaml"
    assert rules_path.is_file(), f"Rule pack not found at {rules_path}"

    with tempfile.TemporaryDirectory() as tmpdir:
        input_path = Path(tmpdir) / "report.json"
        output_path = Path(tmpdir) / "report-arp.json"

        input_path.write_text(json.dumps(MINIMAL_REPORT_DUPLICATE_IP))

        artifact = run(input_path, output_path, [rules_path])

        assert output_path.is_file(), "Output sidecar was not written to disk"

        with output_path.open() as fh:
            on_disk = json.load(fh)

        # Envelope fields
        assert on_disk["artifact_type"] == "plugin_output"
        assert on_disk["plugin_id"] == PLUGIN_ID
        assert on_disk["contract_version"] == 1
        assert "generated_at" in on_disk
        assert "summary" in on_disk
        assert "data" in on_disk
        assert "warnings" in on_disk

        # The duplicate IP finding must be present
        findings = on_disk["data"]["findings"]
        dup = [f for f in findings if f["category"] == "ARP_DUPLICATE_IP_CLAIM"]
        assert len(dup) >= 1, f"ARP_DUPLICATE_IP_CLAIM not found in artifact findings: {findings}"

        # workbench_views present
        assert "workbench_views" in on_disk
        assert len(on_disk["workbench_views"]) == 1
        assert on_disk["workbench_views"][0]["location"] == "risk"


# ---------------------------------------------------------------------------
# Standalone runner (no pytest dependency)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    tests = [
        test_no_arp_conversations_does_not_crash,
        test_duplicate_ip_claim_detected,
        test_gateway_mac_change_detected,
        test_gateway_mac_change_not_triggered_without_config,
        test_mac_claims_many_ips,
        test_mac_claims_many_ips_disabled,
        test_duplicate_ip_rule_disabled,
        test_scan_behavior_uses_arp_observations_when_available,
        test_scan_behavior_falls_back_to_conversation_proxy,
        test_l2_anomaly_arp_spoof_produces_duplicate_ip_claim,
        test_l2_anomaly_reason_can_be_nested_under_details,
        test_l2_anomaly_arp_gratuitous_produces_gratuitous_reply,
        test_gratuitous_from_observations,
        test_l2_and_observation_gratuitous_are_deduped,
        test_gratuitous_reply_disabled,
        test_output_is_deterministic,
        test_run_end_to_end_writes_artifact,
    ]

    passed = 0
    failed = 0
    for test_fn in tests:
        name = test_fn.__name__
        try:
            test_fn()
            print(f"  PASS  {name}")
            passed += 1
        except Exception:
            print(f"  FAIL  {name}")
            traceback.print_exc()
            failed += 1

    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
