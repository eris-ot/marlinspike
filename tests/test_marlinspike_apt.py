"""Unit tests for the marlinspike-apt plugin.

Run with:
    python3 -m pytest tests/test_marlinspike_apt.py -v
or:
    python3 tests/test_marlinspike_apt.py
"""
import json
import sys
import tempfile
import traceback
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from plugins.marlinspike_apt.plugin import (
    PLUGIN_ID,
    _detect,
    _merge_packs,
    run,
)

DEFAULT_SETTINGS = _merge_packs([])


def _conv(src_ip, dst_ip, *, protocol="TCP", dst_port=None, packet_count=10,
          first_seen=None, src_mac="aa:bb:cc:00:00:01", dst_mac="aa:bb:cc:00:00:02"):
    c = {
        "protocol": protocol,
        "src_mac": src_mac,
        "dst_mac": dst_mac,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "packet_count": packet_count,
    }
    if dst_port is not None:
        c["dst_port"] = dst_port
    if first_seen is not None:
        c["first_seen"] = first_seen
    return c


def _node(ip, role):
    return {"ip": ip, "role": role}


def _run(report, settings=None):
    return _detect(report, settings or DEFAULT_SETTINGS)


# ---------------------------------------------------------------------------

def test_no_conversations_does_not_crash():
    result = _run({"conversations": [], "nodes": []})
    assert result["findings"] == []
    assert result["summary"]["finding_total"] == 0
    assert result["summary"]["conversation_count"] == 0


def test_smb_lateral_movement_detected():
    """One src → 6 distinct dst on port 445 trips the detector (threshold 5)."""
    convs = [_conv("10.0.0.50", f"10.0.0.{100 + i}", dst_port=445, protocol="SMB2")
             for i in range(6)]
    result = _run({"conversations": convs, "nodes": []})
    smb = [f for f in result["findings"] if f["category"] == "APT_LATERAL_MOVEMENT_SMB"]
    assert len(smb) == 1
    assert smb[0]["src_ip"] == "10.0.0.50"
    assert smb[0]["target_count"] == 6
    assert "T1021.002" in smb[0]["attack_techniques"]


def test_smb_below_threshold_not_flagged():
    convs = [_conv("10.0.0.50", f"10.0.0.{100 + i}", dst_port=445)
             for i in range(4)]
    result = _run({"conversations": convs, "nodes": []})
    assert not any(f["category"] == "APT_LATERAL_MOVEMENT_SMB" for f in result["findings"])


def test_rdp_lateral_detected_and_jump_host_allowlisted():
    convs = [
        _conv("10.0.0.99", "10.0.0.10", dst_port=3389, protocol="RDP"),
        _conv("10.0.0.99", "10.0.0.11", dst_port=3389, protocol="RDP"),
        _conv("10.0.0.99", "10.0.0.12", dst_port=3389, protocol="RDP"),
        # Jump host hits 3 hosts but is allowlisted
        _conv("10.0.0.5", "10.0.0.20", dst_port=3389, protocol="RDP"),
        _conv("10.0.0.5", "10.0.0.21", dst_port=3389, protocol="RDP"),
        _conv("10.0.0.5", "10.0.0.22", dst_port=3389, protocol="RDP"),
    ]
    settings = _merge_packs([])
    settings["jump_hosts"] = ["10.0.0.5"]
    result = _run({"conversations": convs, "nodes": []}, settings)
    rdp = [f for f in result["findings"] if f["category"] == "APT_LATERAL_MOVEMENT_RDP"]
    assert len(rdp) == 1, f"Expected 1 RDP finding (jump host suppressed), got: {rdp}"
    assert rdp[0]["src_ip"] == "10.0.0.99"


def test_winrm_lateral_detected():
    convs = [
        _conv("10.0.0.99", "10.0.0.50", dst_port=5985, protocol="HTTP"),
        _conv("10.0.0.99", "10.0.0.51", dst_port=5986, protocol="HTTPS"),
    ]
    result = _run({"conversations": convs, "nodes": []})
    winrm = [f for f in result["findings"] if f["category"] == "APT_LATERAL_MOVEMENT_WINRM"]
    assert len(winrm) == 1
    assert winrm[0]["target_count"] == 2


def test_ot_recon_detected_for_unknown_source():
    """Unknown source talking Modbus to many PLCs → flagged."""
    convs = [_conv("172.16.0.99", f"172.16.0.{10 + i}", dst_port=502, protocol="Modbus")
             for i in range(6)]
    result = _run({"conversations": convs, "nodes": []})
    recon = [f for f in result["findings"] if f["category"] == "APT_OT_RECONNAISSANCE"]
    assert len(recon) == 1
    assert recon[0]["src_ip"] == "172.16.0.99"
    assert recon[0]["target_count"] == 6


def test_ot_recon_suppressed_for_hmi_role():
    """HMI is a legitimate poller — same fan-out should NOT fire."""
    convs = [_conv("172.16.0.99", f"172.16.0.{10 + i}", dst_port=502, protocol="Modbus")
             for i in range(6)]
    nodes = [_node("172.16.0.99", "HMI")]
    result = _run({"conversations": convs, "nodes": nodes})
    assert not any(f["category"] == "APT_OT_RECONNAISSANCE" for f in result["findings"])


def test_ot_recon_allowlist_overrides():
    """Explicit polling_source_allowlist also suppresses (regardless of role)."""
    convs = [_conv("172.16.0.99", f"172.16.0.{10 + i}", dst_port=502, protocol="Modbus")
             for i in range(6)]
    settings = _merge_packs([])
    settings["ot_polling_source_allowlist"] = ["172.16.0.99"]
    result = _run({"conversations": convs, "nodes": []}, settings)
    assert not any(f["category"] == "APT_OT_RECONNAISSANCE" for f in result["findings"])


def test_new_host_protocol_hmi_does_smb():
    """An HMI initiating SMB is unexpected (HMI's expected set excludes SMB)."""
    convs = [
        _conv("10.0.0.50", "10.0.0.100", dst_port=445, protocol="SMB2", packet_count=20),
    ]
    nodes = [_node("10.0.0.50", "HMI")]
    result = _run({"conversations": convs, "nodes": nodes})
    nhp = [f for f in result["findings"] if f["category"] == "APT_NEW_HOST_PROTOCOL"]
    assert len(nhp) == 1
    assert nhp[0]["src_ip"] == "10.0.0.50"
    assert nhp[0]["src_role"] == "HMI"
    assert nhp[0]["unexpected_protocol"] == "SMB2"


def test_new_host_protocol_skipped_for_unknown_role():
    """Hosts without a known role are skipped (no expectation set means we cannot judge)."""
    convs = [_conv("10.0.0.50", "10.0.0.100", dst_port=445, protocol="SMB2", packet_count=20)]
    result = _run({"conversations": convs, "nodes": []})
    assert not any(f["category"] == "APT_NEW_HOST_PROTOCOL" for f in result["findings"])


def test_new_host_protocol_low_packet_count_filtered():
    """Packets below min_packet_count threshold are ignored."""
    convs = [_conv("10.0.0.50", "10.0.0.100", dst_port=445, protocol="SMB2", packet_count=1)]
    nodes = [_node("10.0.0.50", "HMI")]
    result = _run({"conversations": convs, "nodes": nodes})
    assert not any(f["category"] == "APT_NEW_HOST_PROTOCOL" for f in result["findings"])


def test_new_host_protocol_engineering_smb_is_allowed():
    """Engineering Workstation is allowed to talk SMB (it's in the expected set)."""
    convs = [_conv("10.0.0.10", "10.0.0.100", dst_port=445, protocol="SMB2", packet_count=20)]
    nodes = [_node("10.0.0.10", "Engineering Workstation")]
    result = _run({"conversations": convs, "nodes": nodes})
    assert not any(f["category"] == "APT_NEW_HOST_PROTOCOL" for f in result["findings"])


def test_disabled_rule_suppresses_findings():
    convs = [_conv("10.0.0.50", f"10.0.0.{100 + i}", dst_port=445)
             for i in range(6)]
    settings = _merge_packs([])
    settings["lateral_movement_smb"]["enabled"] = False
    result = _run({"conversations": convs, "nodes": []}, settings)
    assert not any(f["category"] == "APT_LATERAL_MOVEMENT_SMB" for f in result["findings"])


def test_protocol_match_overrides_port():
    """SMB protocol string wins even when port isn't 445 (e.g. on 139)."""
    convs = [_conv("10.0.0.50", f"10.0.0.{100 + i}", dst_port=139, protocol="SMB")
             for i in range(6)]
    result = _run({"conversations": convs, "nodes": []})
    assert any(f["category"] == "APT_LATERAL_MOVEMENT_SMB" for f in result["findings"])


def _beacon(src_ip, dst_ip, *, protocol="HTTPS", dst_port=443, score=0.85,
            interval=120.0, jitter=0.05, packet_count=20):
    return {
        "protocol": protocol,
        "src_mac": "aa:bb:cc:00:00:01",
        "dst_mac": "aa:bb:cc:00:00:02",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "packet_count": packet_count,
        "beacon_score": score,
        "beacon_interval": interval,
        "beacon_jitter": jitter,
    }


def test_c2_beacon_to_external_flagged():
    convs = [_beacon("10.0.0.50", "8.8.8.8")]
    result = _run({"conversations": convs, "nodes": []})
    beacons = [f for f in result["findings"] if f["category"] == "APT_C2_BEACON"]
    assert len(beacons) == 1
    assert beacons[0]["src_ip"] == "10.0.0.50"
    assert beacons[0]["dst_ip"] == "8.8.8.8"
    assert "T1071" in beacons[0]["attack_techniques"]


def test_c2_beacon_internal_dst_suppressed_by_default():
    convs = [_beacon("10.0.0.50", "10.0.0.99")]
    result = _run({"conversations": convs, "nodes": []})
    assert not any(f["category"] == "APT_C2_BEACON" for f in result["findings"])


def test_c2_beacon_internal_allowed_when_external_only_false():
    convs = [_beacon("10.0.0.50", "10.0.0.99")]
    settings = _merge_packs([])
    settings["c2_beaconing"]["external_dst_only"] = False
    result = _run({"conversations": convs, "nodes": []}, settings)
    assert any(f["category"] == "APT_C2_BEACON" for f in result["findings"])


def test_c2_beacon_excluded_protocol_suppressed():
    convs = [_beacon("10.0.0.50", "8.8.8.8", protocol="DNS", dst_port=53)]
    result = _run({"conversations": convs, "nodes": []})
    assert not any(f["category"] == "APT_C2_BEACON" for f in result["findings"])


def test_c2_beacon_low_score_suppressed():
    convs = [_beacon("10.0.0.50", "8.8.8.8", score=0.5)]
    result = _run({"conversations": convs, "nodes": []})
    assert not any(f["category"] == "APT_C2_BEACON" for f in result["findings"])


def test_c2_beacon_interval_bounds_respected():
    too_fast = _beacon("10.0.0.50", "8.8.8.8", interval=10.0)
    too_slow = _beacon("10.0.0.50", "1.1.1.1", interval=10000.0)
    result = _run({"conversations": [too_fast, too_slow], "nodes": []})
    assert not any(f["category"] == "APT_C2_BEACON" for f in result["findings"])


def test_c2_beacon_disabled_rule_suppresses():
    convs = [_beacon("10.0.0.50", "8.8.8.8")]
    settings = _merge_packs([])
    settings["c2_beaconing"]["enabled"] = False
    result = _run({"conversations": convs, "nodes": []}, settings)
    assert not any(f["category"] == "APT_C2_BEACON" for f in result["findings"])


def test_engine_port_field_alias_recognized():
    """Engine emits 'port' (not 'dst_port'); detector must accept both."""
    convs = []
    for i in range(6):
        c = {
            "protocol": "SMB",
            "src_mac": "aa:bb:cc:00:00:01",
            "dst_mac": "aa:bb:cc:00:00:02",
            "src_ip": "10.0.0.50",
            "dst_ip": f"10.0.0.{100 + i}",
            "packet_count": 10,
            "port": 445,
        }
        convs.append(c)
    result = _run({"conversations": convs, "nodes": []})
    assert any(f["category"] == "APT_LATERAL_MOVEMENT_SMB" for f in result["findings"])


def test_output_is_deterministic():
    convs = [_conv("10.0.0.50", f"10.0.0.{100 + i}", dst_port=445)
             for i in range(6)]
    r1 = _run({"conversations": convs, "nodes": []})
    r2 = _run({"conversations": convs, "nodes": []})
    assert r1["findings"] == r2["findings"]


def test_run_end_to_end_writes_artifact():
    rules_path = REPO_ROOT / "rules" / "apt" / "base.yaml"
    assert rules_path.is_file(), f"Rule pack missing at {rules_path}"

    convs = [_conv("10.0.0.50", f"10.0.0.{100 + i}", dst_port=445, protocol="SMB2")
             for i in range(6)]
    report = {
        "capture_info": {"filename": "test.pcap"},
        "conversations": convs,
        "nodes": [],
        "edges": [],
        "risk_findings": [],
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        input_path = Path(tmpdir) / "report.json"
        output_path = Path(tmpdir) / "report-apt.json"
        input_path.write_text(json.dumps(report))

        artifact = run(input_path, output_path, [rules_path])

        assert output_path.is_file()
        with output_path.open() as fh:
            on_disk = json.load(fh)

        assert on_disk["artifact_type"] == "plugin_output"
        assert on_disk["plugin_id"] == PLUGIN_ID
        assert on_disk["contract_version"] == 1
        assert on_disk["summary"]["finding_total"] >= 1
        assert any(
            f["category"] == "APT_LATERAL_MOVEMENT_SMB"
            for f in on_disk["data"]["findings"]
        )
        assert len(on_disk["workbench_views"]) == 1
        assert on_disk["workbench_views"][0]["location"] == "risk"


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    tests = [
        test_no_conversations_does_not_crash,
        test_smb_lateral_movement_detected,
        test_smb_below_threshold_not_flagged,
        test_rdp_lateral_detected_and_jump_host_allowlisted,
        test_winrm_lateral_detected,
        test_ot_recon_detected_for_unknown_source,
        test_ot_recon_suppressed_for_hmi_role,
        test_ot_recon_allowlist_overrides,
        test_new_host_protocol_hmi_does_smb,
        test_new_host_protocol_skipped_for_unknown_role,
        test_new_host_protocol_low_packet_count_filtered,
        test_new_host_protocol_engineering_smb_is_allowed,
        test_disabled_rule_suppresses_findings,
        test_protocol_match_overrides_port,
        test_c2_beacon_to_external_flagged,
        test_c2_beacon_internal_dst_suppressed_by_default,
        test_c2_beacon_internal_allowed_when_external_only_false,
        test_c2_beacon_excluded_protocol_suppressed,
        test_c2_beacon_low_score_suppressed,
        test_c2_beacon_interval_bounds_respected,
        test_c2_beacon_disabled_rule_suppresses,
        test_engine_port_field_alias_recognized,
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
