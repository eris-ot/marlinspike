"""Tests for the marlinspike-cisa app integration: sidecar path derivation,
the _run_cisa_plugin subprocess wrapper, and sidecar pickup in
_load_report_with_extensions."""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret-key-cisa")

from marlinspike import config
from marlinspike.app import (
    _cisa_sidecar_path,
    _load_report_with_extensions,
    _run_cisa_plugin,
)

# A report whose assets reliably match the bundled KEV catalog (Microsoft is
# the single largest vendor in the catalog).
_REPORT = {
    "asset_inventory": [
        {"node_id": "n1", "vendor": "Microsoft", "product": "Exchange Server"}
    ],
    "nodes": [],
    "risk_findings": [],
}


def test_cisa_sidecar_path():
    assert _cisa_sidecar_path("/data/reports/u/p/report.json") == (
        "/data/reports/u/p/report-cisa.json"
    )
    assert _cisa_sidecar_path("report").endswith("report-cisa.json")


def test_run_cisa_plugin_disabled(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "MARLINSPIKE_CISA_ENABLED", False)
    report = tmp_path / "report.json"
    report.write_text(json.dumps(_REPORT))
    assert _run_cisa_plugin(str(report)) == ("", [])


def test_run_cisa_plugin_missing_report(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "MARLINSPIKE_CISA_ENABLED", True)
    with pytest.raises(FileNotFoundError):
        _run_cisa_plugin(str(tmp_path / "does-not-exist.json"))


def test_run_cisa_plugin_happy_path(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "MARLINSPIKE_CISA_ENABLED", True)
    report = tmp_path / "report.json"
    report.write_text(json.dumps(_REPORT))

    artifact_path, output = _run_cisa_plugin(str(report))

    assert artifact_path == str(tmp_path / "report-cisa.json")
    assert os.path.isfile(artifact_path)
    assert isinstance(output, list)

    with open(artifact_path) as fh:
        envelope = json.load(fh)
    assert envelope["plugin_id"] == "marlinspike-cisa"
    assert envelope["summary"]["assets_searched"] == 1
    # Microsoft has hundreds of KEV entries — the search must find some.
    assert envelope["summary"]["total_advisories"] >= 1


def test_run_cisa_plugin_raises_on_plugin_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "MARLINSPIKE_CISA_ENABLED", True)
    report = tmp_path / "report.json"
    report.write_text("{ this is not valid json")
    with pytest.raises(RuntimeError):
        _run_cisa_plugin(str(report))


def test_load_report_with_extensions_picks_up_cisa(tmp_path):
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"summary": {}, "findings": []}))
    sidecar = tmp_path / "report-cisa.json"
    sidecar.write_text(json.dumps({
        "plugin_id": "marlinspike-cisa",
        "summary": {"total_advisories": 3},
        "data": {"all_advisories": []},
    }))

    merged = _load_report_with_extensions(str(report))
    assert "extensions" in merged
    assert merged["extensions"]["marlinspike-cisa"]["summary"]["total_advisories"] == 3


def test_load_report_ignores_foreign_sidecar(tmp_path):
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"summary": {}}))
    sidecar = tmp_path / "report-cisa.json"
    # Wrong plugin_id — must not be merged in as the CISA extension.
    sidecar.write_text(json.dumps({"plugin_id": "something-else", "data": {}}))

    merged = _load_report_with_extensions(str(report))
    assert "marlinspike-cisa" not in merged.get("extensions", {})
