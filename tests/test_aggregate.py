"""Unit tests for project-level report aggregation."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from marlinspike.aggregate import aggregate_reports


def _meta(filename, modified):
    return {"filename": filename, "modified": modified}


def make_loader(reports_by_path):
    def _loader(path):
        return reports_by_path[path]
    return _loader


def test_empty():
    agg = aggregate_reports([], loader=make_loader({}))
    assert agg["report_count"] == 0
    assert agg["totals"]["assets"] == 0
    assert agg["totals"]["findings"] == 0
    assert agg["assets"] == []
    assert agg["findings"] == []


def test_asset_dedup_within_report():
    """Same MAC appearing as multiple node entries in one report counts as one occurrence."""
    report = {
        "timestamp_start": "2026-04-01T00:00:00+00:00",
        "nodes": [
            {"mac": "aa:aa:aa:aa:aa:01", "ip": "10.0.0.5", "role": "Switch"},
            {"mac": "aa:aa:aa:aa:aa:01", "ip": "10.0.0.6", "role": "Switch"},
            {"mac": "aa:aa:aa:aa:aa:01", "ip": "10.0.0.7", "role": "Switch"},
        ],
    }
    paths = ["a.json"]
    loader = make_loader({"a.json": report})
    agg = aggregate_reports(paths, loader=loader, report_meta={"a.json": _meta("a.json", "2026-04-01")})
    assert agg["totals"]["assets"] == 1
    asset = agg["assets"][0]
    assert asset["report_count"] == 1
    assert sorted(asset["ips"]) == ["10.0.0.5", "10.0.0.6", "10.0.0.7"]


def test_asset_across_reports():
    """Same MAC across reports increments report_count once per report; IPs accrue."""
    r1 = {"nodes": [{"mac": "bb:bb:bb:bb:bb:01", "ip": "10.0.0.10", "role": "PLC"}]}
    r2 = {"nodes": [{"mac": "bb:bb:bb:bb:bb:01", "ip": "10.0.0.42", "role": "PLC"}]}  # re-IP'd
    loader = make_loader({"r1.json": r1, "r2.json": r2})
    meta = {
        "r1.json": _meta("r1.json", "2026-01-01"),
        "r2.json": _meta("r2.json", "2026-04-01"),
    }
    agg = aggregate_reports(["r1.json", "r2.json"], loader=loader, report_meta=meta)
    assert agg["totals"]["assets"] == 1
    asset = agg["assets"][0]
    assert asset["report_count"] == 2
    assert sorted(asset["ips"]) == ["10.0.0.10", "10.0.0.42"]
    assert asset["first_seen_report"] == "r1.json"
    assert asset["last_seen_report"] == "r2.json"


def test_asset_key_falls_back_to_ip():
    report = {"nodes": [{"ip": "10.0.0.99", "role": "External"}]}
    loader = make_loader({"a.json": report})
    agg = aggregate_reports(["a.json"], loader=loader, report_meta={"a.json": _meta("a.json", "2026-04-01")})
    assert agg["assets"][0]["key"] == "10.0.0.99"
    assert agg["assets"][0]["key_type"] == "ip"


def test_finding_dedup_same_key_across_reports():
    """A finding with the same (category, nodes, edges) across N reports has occurrences=N."""
    f = {
        "category": "C2_BEACONING",
        "severity": "HIGH",
        "affected_nodes": ["10.0.0.50"],
        "affected_edges": [],
        "description": "Periodic outbound traffic",
    }
    r1 = {"risk_findings": [dict(f)]}
    r2 = {"risk_findings": [dict(f)]}
    r3 = {"risk_findings": [dict(f)]}
    loader = make_loader({"a.json": r1, "b.json": r2, "c.json": r3})
    meta = {
        "a.json": _meta("a.json", "2026-01-01"),
        "b.json": _meta("b.json", "2026-02-01"),
        "c.json": _meta("c.json", "2026-03-01"),
    }
    agg = aggregate_reports(["a.json", "b.json", "c.json"], loader=loader, report_meta=meta)
    assert agg["totals"]["findings"] == 1
    assert agg["findings"][0]["occurrences"] == 3
    assert agg["severity_counts"]["HIGH"] == 3


def test_finding_severity_promotes_to_max():
    """If severity escalates across reports, the aggregated finding reflects the highest."""
    base = {
        "category": "EXTERNAL_IPS_OBSERVED",
        "affected_nodes": ["8.8.8.8"],
        "affected_edges": [],
    }
    r1 = {"risk_findings": [dict(base, severity="INFO", description="d1")]}
    r2 = {"risk_findings": [dict(base, severity="CRITICAL", description="d2")]}
    loader = make_loader({"a.json": r1, "b.json": r2})
    meta = {"a.json": _meta("a.json", "2026-01-01"), "b.json": _meta("b.json", "2026-04-01")}
    agg = aggregate_reports(["a.json", "b.json"], loader=loader, report_meta=meta)
    assert agg["findings"][0]["severity"] == "CRITICAL"
    # Latest description wins (more current view of the finding)
    assert agg["findings"][0]["description"] == "d2"


def test_protocol_report_count_distinct():
    r1 = {"capture_info": {"protocols_seen": {"MODBUS": 100, "DNS": 5}}}
    r2 = {"capture_info": {"protocols_seen": {"MODBUS": 50}}}
    loader = make_loader({"a.json": r1, "b.json": r2})
    meta = {"a.json": _meta("a.json", "2026-01"), "b.json": _meta("b.json", "2026-02")}
    agg = aggregate_reports(["a.json", "b.json"], loader=loader, report_meta=meta)
    protos = {p["name"]: p for p in agg["protocols"]}
    assert protos["MODBUS"]["report_count"] == 2
    assert protos["MODBUS"]["packet_count"] == 150
    assert protos["DNS"]["report_count"] == 1


def test_attack_coverage_aggregated_from_findings():
    f = {
        "category": "APT_LATERAL_MOVEMENT_SMB",
        "severity": "HIGH",
        "affected_nodes": ["10.0.0.5"],
        "affected_edges": [],
        "attack_ids": ["T1021.002", "T1570"],
    }
    loader = make_loader({"a.json": {"risk_findings": [f]}})
    meta = {"a.json": _meta("a.json", "2026-01")}
    agg = aggregate_reports(["a.json"], loader=loader, report_meta=meta)
    ids = {t["id"] for t in agg["attack_coverage"]}
    assert ids == {"T1021.002", "T1570"}


def test_scan_profiles_tracked():
    loader = make_loader({"a.json": {"nodes": []}, "b.json": {"nodes": []}, "c.json": {"nodes": []}})
    meta = {
        "a.json": dict(_meta("a.json", "2026-01"), scan_profile="full"),
        "b.json": dict(_meta("b.json", "2026-02"), scan_profile="full"),
        "c.json": dict(_meta("c.json", "2026-03"), scan_profile="fast"),
    }
    agg = aggregate_reports(["a.json", "b.json", "c.json"], loader=loader, report_meta=meta)
    assert agg["scan_profiles"] == {"full": 2, "fast": 1}


def test_loader_failure_skipped_silently():
    def loader(path):
        if path == "broken.json":
            raise ValueError("corrupt")
        return {"nodes": [{"mac": "aa:bb:cc:dd:ee:ff", "ip": "1.1.1.1", "role": "x"}]}

    meta = {"good.json": _meta("good.json", "2026-01"), "broken.json": _meta("broken.json", "2026-01")}
    agg = aggregate_reports(["good.json", "broken.json"], loader=loader, report_meta=meta)
    assert agg["report_count"] == 1
    assert agg["totals"]["assets"] == 1


if __name__ == "__main__":
    test_empty()
    test_asset_dedup_within_report()
    test_asset_across_reports()
    test_asset_key_falls_back_to_ip()
    test_finding_dedup_same_key_across_reports()
    test_finding_severity_promotes_to_max()
    test_protocol_report_count_distinct()
    test_attack_coverage_aggregated_from_findings()
    test_scan_profiles_tracked()
    test_loader_failure_skipped_silently()
    print("All 10 aggregation tests passed.")
