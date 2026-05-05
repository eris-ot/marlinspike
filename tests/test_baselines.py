"""Tests for longitudinal asset baseline computation (v3.2.0)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from marlinspike.baselines import compute_asset_baseline


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

MAC_A = "aa:bb:cc:dd:ee:01"
MAC_B = "aa:bb:cc:dd:ee:02"
IP_A  = "10.0.0.10"
IP_B  = "10.0.0.20"
IP_C  = "10.0.0.30"


def _report(
    filename="report-001.json",
    ts="2025-12-01T00:00:00+00:00",
    nodes=None,
    conversations=None,
    risk_findings=None,
    l2_anomalies=None,
):
    """Minimal well-shaped report dict."""
    return {
        "_report_filename": filename,
        "timestamp_start": ts,
        "nodes": nodes or [],
        "conversations": conversations or [],
        "risk_findings": risk_findings or [],
        "l2_anomalies": l2_anomalies or [],
    }


def _node(mac=MAC_A, ip=IP_A, vendor="Schneider", device_type="Modbus PLC",
          role="PLC", purdue_level=1, system_name="Modicon-A",
          auth_observed=True, protocols=None):
    return {
        "mac": mac,
        "ip": ip,
        "vendor": vendor,
        "device_type": device_type,
        "role": role,
        "purdue_level": purdue_level,
        "system_name": system_name,
        "auth_observed": auth_observed,
        "protocols": protocols or ["Modbus"],
    }


def _conv(src_ip=IP_A, dst_ip=IP_B, src_mac=MAC_A, dst_mac=MAC_B,
          protocol="Modbus", packet_count=100):
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_mac": src_mac,
        "dst_mac": dst_mac,
        "protocol": protocol,
        "packet_count": packet_count,
    }


def _finding(category="NO_AUTH_OBSERVED", affected_nodes=None):
    return {
        "category": category,
        "severity": "MEDIUM",
        "affected_nodes": affected_nodes or [IP_A],
        "affected_edges": [],
    }


# ---------------------------------------------------------------------------
# Test: single-report input
# ---------------------------------------------------------------------------

def test_single_report_basic():
    """report_count=1, everything is new, novelty_vs_baseline is empty."""
    r = _report(nodes=[_node()], conversations=[_conv()],
                risk_findings=[_finding()])
    result = compute_asset_baseline([r], MAC_A)
    assert result is not None
    assert result["report_count"] == 1
    assert result["matched_by"] == "mac"
    assert result["asset_key"] == MAC_A


def test_single_report_is_new_flags():
    """With one report, is_new should be True for protocol, peer, finding."""
    r = _report(nodes=[_node()], conversations=[_conv()],
                risk_findings=[_finding()])
    result = compute_asset_baseline([r], MAC_A)

    assert all(
        entry["is_new"]
        for proto_entries in result["protocol_history"].values()
        for entry in proto_entries
    )
    assert all(p["is_new_in_latest"] for p in result["peer_history"])
    assert all(f["is_new_in_latest"] for f in result["finding_history"])


def test_single_report_novelty_all_items_are_new():
    """With one report baseline is empty, so every item appears in new_* lists.

    The spec states baseline=reports[:-1]; with only one report the baseline
    is empty, making every protocol/peer/finding "new".  lost_* are empty
    because nothing existed in the (empty) baseline to go missing.
    """
    r = _report(nodes=[_node()], conversations=[_conv()],
                risk_findings=[_finding()])
    result = compute_asset_baseline([r], MAC_A)
    nov = result["novelty_vs_baseline"]
    # Everything present in the single report is "new" vs the empty baseline.
    assert "Modbus" in nov["new_protocols"]
    assert IP_B in nov["new_peers"]
    assert "NO_AUTH_OBSERVED" in nov["new_findings"]
    # Nothing was in baseline to go missing.
    assert nov["lost_protocols"] == []
    assert nov["lost_peers"] == []


# ---------------------------------------------------------------------------
# Test: multi-report stability
# ---------------------------------------------------------------------------

def test_vendor_stable_across_reports():
    r1 = _report("r1.json", "2025-12-01T00:00:00+00:00",
                 nodes=[_node(vendor="Siemens")])
    r2 = _report("r2.json", "2026-01-01T00:00:00+00:00",
                 nodes=[_node(vendor="Siemens")])
    r3 = _report("r3.json", "2026-02-01T00:00:00+00:00",
                 nodes=[_node(vendor="Siemens")])
    result = compute_asset_baseline([r1, r2, r3], MAC_A)
    assert result["stability"]["vendor_stable"] is True


def test_role_drift_detected():
    """Vendor stable but role drifts → vendor_stable True, role_stable False."""
    r1 = _report("r1.json", "2025-12-01T00:00:00+00:00",
                 nodes=[_node(vendor="Schneider", role="PLC")])
    r2 = _report("r2.json", "2026-01-01T00:00:00+00:00",
                 nodes=[_node(vendor="Schneider", role="PLC")])
    r3 = _report("r3.json", "2026-02-01T00:00:00+00:00",
                 nodes=[_node(vendor="Schneider", role="Network Switch")])
    result = compute_asset_baseline([r1, r2, r3], MAC_A)
    assert result["stability"]["vendor_stable"] is True
    assert result["stability"]["role_stable"] is False
    dist = result["stability"]["role_distribution"]
    assert dist.get("PLC") == 2
    assert dist.get("Network Switch") == 1


def test_role_stable_distribution_empty():
    """When role is stable the role_distribution dict is empty."""
    r1 = _report("r1.json", nodes=[_node(role="PLC")])
    r2 = _report("r2.json", nodes=[_node(role="PLC")])
    result = compute_asset_baseline([r1, r2], MAC_A)
    assert result["stability"]["role_stable"] is True
    assert result["stability"]["role_distribution"] == {}


# ---------------------------------------------------------------------------
# Test: new-peer detection
# ---------------------------------------------------------------------------

def test_new_peer_in_latest_report():
    """Peer present only in last report → is_new_in_latest True, in new_peers."""
    r1 = _report("r1.json", "2025-12-01T00:00:00+00:00",
                 nodes=[_node()],
                 conversations=[_conv(dst_ip=IP_B)])
    r2 = _report("r2.json", "2026-01-01T00:00:00+00:00",
                 nodes=[_node()],
                 conversations=[_conv(dst_ip=IP_C)])  # new peer IP_C
    result = compute_asset_baseline([r1, r2], MAC_A)

    new_peer_entries = [p for p in result["peer_history"]
                        if p["peer"] == IP_C and p["is_new_in_latest"]]
    assert new_peer_entries, "IP_C should be flagged as new in latest"
    assert IP_C in result["novelty_vs_baseline"]["new_peers"]

    # IP_B was in baseline and is not in latest → not new_in_latest
    old_peer_entries = [p for p in result["peer_history"] if p["peer"] == IP_B]
    assert old_peer_entries
    assert old_peer_entries[0]["is_new_in_latest"] is False


# ---------------------------------------------------------------------------
# Test: lost-peer detection
# ---------------------------------------------------------------------------

def test_lost_peer_not_in_latest():
    """Peer present in baseline but absent from latest → in lost_peers."""
    r1 = _report("r1.json", "2025-12-01T00:00:00+00:00",
                 nodes=[_node()],
                 conversations=[_conv(dst_ip=IP_B)])
    r2 = _report("r2.json", "2026-01-01T00:00:00+00:00",
                 nodes=[_node()],
                 conversations=[_conv(dst_ip=IP_C)])  # IP_B gone
    result = compute_asset_baseline([r1, r2], MAC_A)
    assert IP_B in result["novelty_vs_baseline"]["lost_peers"]
    assert IP_C not in result["novelty_vs_baseline"]["lost_peers"]


# ---------------------------------------------------------------------------
# Test: MAC-vs-IP match
# ---------------------------------------------------------------------------

def test_match_by_mac():
    r = _report(nodes=[_node(mac=MAC_A, ip=IP_A)])
    result = compute_asset_baseline([r], MAC_A)
    assert result is not None
    assert result["matched_by"] == "mac"


def test_match_by_ip():
    """IP lookup ignores the mac field."""
    r = _report(nodes=[_node(mac=MAC_A, ip=IP_A)])
    result = compute_asset_baseline([r], IP_A)
    assert result is not None
    assert result["matched_by"] == "ip"


def test_mac_and_ip_same_asset_independent():
    """Query by MAC and query by IP both return a valid result for the same node."""
    r = _report(nodes=[_node(mac=MAC_A, ip=IP_A)])
    by_mac = compute_asset_baseline([r], MAC_A)
    by_ip  = compute_asset_baseline([r], IP_A)
    assert by_mac is not None
    assert by_ip  is not None
    assert by_mac["matched_by"] == "mac"
    assert by_ip["matched_by"]  == "ip"


def test_mac_case_insensitive():
    """MAC lookup is case-insensitive."""
    r = _report(nodes=[_node(mac="AA:BB:CC:DD:EE:01")])
    result = compute_asset_baseline([r], "aa:bb:cc:dd:ee:01")
    assert result is not None
    result2 = compute_asset_baseline([r], "AA:BB:CC:DD:EE:01")
    assert result2 is not None


# ---------------------------------------------------------------------------
# Test: asset not present → None
# ---------------------------------------------------------------------------

def test_asset_not_present_returns_none():
    r = _report(nodes=[_node(mac=MAC_B, ip=IP_B)])
    assert compute_asset_baseline([r], MAC_A) is None
    assert compute_asset_baseline([r], "192.168.1.1") is None


def test_empty_reports_returns_none():
    assert compute_asset_baseline([], MAC_A) is None


# ---------------------------------------------------------------------------
# Test: limit_reports
# ---------------------------------------------------------------------------

def test_limit_reports_trims_oldest():
    """limit_reports=2 should use only the 2 most recent of 4 reports."""
    r1 = _report("r1.json", "2025-09-01T00:00:00+00:00", nodes=[_node()])
    r2 = _report("r2.json", "2025-10-01T00:00:00+00:00", nodes=[_node()])
    r3 = _report("r3.json", "2025-11-01T00:00:00+00:00", nodes=[_node()])
    r4 = _report("r4.json", "2025-12-01T00:00:00+00:00", nodes=[_node()])
    result = compute_asset_baseline([r1, r2, r3, r4], MAC_A, limit_reports=2)
    assert result is not None
    assert result["report_count"] == 2
    assert result["first_seen_report"]["filename"] == "r3.json"
    assert result["last_seen_report"]["filename"] == "r4.json"


def test_limit_reports_larger_than_available():
    """limit_reports exceeding available reports uses all of them."""
    r1 = _report("r1.json", nodes=[_node()])
    r2 = _report("r2.json", nodes=[_node()])
    result = compute_asset_baseline([r1, r2], MAC_A, limit_reports=99)
    assert result["report_count"] == 2


def test_limit_reports_one_makes_single_report():
    """limit_reports=1 behaves identically to single-report input."""
    r1 = _report("r1.json", nodes=[_node()])
    r2 = _report("r2.json", nodes=[_node()])
    result = compute_asset_baseline([r1, r2], MAC_A, limit_reports=1)
    assert result["report_count"] == 1
    assert result["first_seen_report"]["filename"] == "r2.json"


# ---------------------------------------------------------------------------
# Test: asset absent from some reports but present in others
# ---------------------------------------------------------------------------

def test_asset_absent_from_middle_reports():
    """Asset only in r1 and r3; report_count should be 2, not 3."""
    r1 = _report("r1.json", "2025-12-01T00:00:00+00:00", nodes=[_node()])
    r2 = _report("r2.json", "2026-01-01T00:00:00+00:00", nodes=[])  # asset absent
    r3 = _report("r3.json", "2026-02-01T00:00:00+00:00", nodes=[_node()])
    result = compute_asset_baseline([r1, r2, r3], MAC_A)
    assert result is not None
    assert result["report_count"] == 2
    assert result["first_seen_report"]["filename"] == "r1.json"
    assert result["last_seen_report"]["filename"] == "r3.json"


# ---------------------------------------------------------------------------
# Test: protocol new flag across reports
# ---------------------------------------------------------------------------

def test_protocol_is_new_flag():
    """Protocol appearing only in the latest report gets is_new=True."""
    r1 = _report("r1.json", "2025-12-01T00:00:00+00:00",
                 nodes=[_node(protocols=["Modbus"])],
                 conversations=[])
    r2 = _report("r2.json", "2026-01-01T00:00:00+00:00",
                 nodes=[_node(protocols=["Modbus", "S7comm"])],
                 conversations=[])
    result = compute_asset_baseline([r1, r2], MAC_A)

    s7_entries = result["protocol_history"].get("S7comm", [])
    assert s7_entries, "S7comm should appear in protocol_history"
    assert s7_entries[-1]["is_new"] is True

    modbus_entries = result["protocol_history"].get("Modbus", [])
    assert modbus_entries
    # Latest Modbus entry should NOT be new (it was in baseline)
    assert modbus_entries[-1]["is_new"] is False


# ---------------------------------------------------------------------------
# Test: finding history across reports
# ---------------------------------------------------------------------------

def test_finding_in_multiple_reports():
    """Same finding category across N reports → in_reports=N."""
    r1 = _report("r1.json", "2025-12-01T00:00:00+00:00",
                 nodes=[_node()], risk_findings=[_finding("NO_AUTH_OBSERVED")])
    r2 = _report("r2.json", "2026-01-01T00:00:00+00:00",
                 nodes=[_node()], risk_findings=[_finding("NO_AUTH_OBSERVED")])
    r3 = _report("r3.json", "2026-02-01T00:00:00+00:00",
                 nodes=[_node()], risk_findings=[_finding("NO_AUTH_OBSERVED")])
    result = compute_asset_baseline([r1, r2, r3], MAC_A)
    fh = {f["category"]: f for f in result["finding_history"]}
    assert fh["NO_AUTH_OBSERVED"]["in_reports"] == 3
    assert fh["NO_AUTH_OBSERVED"]["is_new_in_latest"] is False


def test_finding_new_in_latest():
    """Finding only in last report → is_new_in_latest True, in new_findings."""
    r1 = _report("r1.json", "2025-12-01T00:00:00+00:00",
                 nodes=[_node()], risk_findings=[])
    r2 = _report("r2.json", "2026-01-01T00:00:00+00:00",
                 nodes=[_node()],
                 risk_findings=[_finding("ICS_EXTERNAL_COMMS")])
    result = compute_asset_baseline([r1, r2], MAC_A)
    fh = {f["category"]: f for f in result["finding_history"]}
    assert fh["ICS_EXTERNAL_COMMS"]["is_new_in_latest"] is True
    assert "ICS_EXTERNAL_COMMS" in result["novelty_vs_baseline"]["new_findings"]


# ---------------------------------------------------------------------------
# Test: anomaly cadence
# ---------------------------------------------------------------------------

def test_anomaly_cadence_tracked():
    """L2 anomaly involving the asset is counted per report."""
    anomaly = {"src_mac": MAC_A, "dst_mac": MAC_B, "anomaly_type": "mac_local"}
    r1 = _report("r1.json", "2025-12-01T00:00:00+00:00",
                 nodes=[_node()], l2_anomalies=[anomaly])
    r2 = _report("r2.json", "2026-01-01T00:00:00+00:00",
                 nodes=[_node()], l2_anomalies=[anomaly])
    result = compute_asset_baseline([r1, r2], MAC_A)
    assert "mac_local" in result["anomaly_cadence"]
    assert result["anomaly_cadence"]["mac_local"]["reports_with_event"] == 2


def test_anomaly_cadence_unrelated_mac_excluded():
    """Anomaly not involving this asset's MAC is not counted."""
    anomaly = {"src_mac": MAC_B, "dst_mac": "ff:ff:ff:ff:ff:ff",
               "anomaly_type": "arp_flood"}
    r = _report("r1.json", nodes=[_node()], l2_anomalies=[anomaly])
    result = compute_asset_baseline([r], MAC_A)
    assert "arp_flood" not in result["anomaly_cadence"]


# ---------------------------------------------------------------------------
# Test: MAC-matched asset IP drift
# ---------------------------------------------------------------------------

def test_mac_matched_ip_can_vary():
    """When matched by MAC, the asset's IP may change across reports."""
    r1 = _report("r1.json", "2025-12-01T00:00:00+00:00",
                 nodes=[_node(mac=MAC_A, ip="192.168.1.10")])
    r2 = _report("r2.json", "2026-01-01T00:00:00+00:00",
                 nodes=[_node(mac=MAC_A, ip="192.168.1.99")])  # re-IP'd
    result = compute_asset_baseline([r1, r2], MAC_A)
    assert result is not None
    assert result["report_count"] == 2
    # identity_timeline should reflect both IPs
    ips_seen = {e["report"] for e in result["identity_timeline"]}
    assert "r1.json" in ips_seen and "r2.json" in ips_seen


# ---------------------------------------------------------------------------
# Test: capture_info fallback for timestamp / filename
# ---------------------------------------------------------------------------

def test_capture_info_fallback_ts():
    """Falls back to capture_info.start_ts when timestamp_start absent."""
    r = {
        "capture_info": {
            "start_ts": "2026-03-15T12:00:00+00:00",
            "pcap_path": "/captures/march.pcap",
        },
        "nodes": [_node()],
        "conversations": [],
        "risk_findings": [],
        "l2_anomalies": [],
    }
    result = compute_asset_baseline([r], MAC_A)
    assert result is not None
    assert result["first_seen_report"]["ts"] == "2026-03-15T12:00:00+00:00"
    assert result["first_seen_report"]["filename"] == "march.pcap"


# ---------------------------------------------------------------------------
# Test: peer_history sort order
# ---------------------------------------------------------------------------

def test_peer_history_sorted_by_last_seen_desc():
    """peer_history is ordered most-recently-seen first."""
    r1 = _report("r1.json", "2025-12-01T00:00:00+00:00",
                 nodes=[_node()],
                 conversations=[_conv(dst_ip="10.0.0.101")])
    r2 = _report("r2.json", "2026-01-01T00:00:00+00:00",
                 nodes=[_node()],
                 conversations=[_conv(dst_ip="10.0.0.102")])
    result = compute_asset_baseline([r1, r2], MAC_A)
    peers = result["peer_history"]
    assert len(peers) >= 2
    # The peer last seen in r2 should come first.
    last_seen_reports = [p["last_seen_report"] for p in peers]
    assert last_seen_reports == sorted(last_seen_reports, reverse=True)


if __name__ == "__main__":
    import sys
    # Quick smoke run — pytest is the real runner.
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"  PASS  {fn.__name__}")
        except Exception as exc:
            print(f"  FAIL  {fn.__name__}: {exc}")
            failed += 1
    print(f"\n{len(fns) - failed}/{len(fns)} passed.")
    sys.exit(failed)
