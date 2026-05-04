"""Tests for IOC threat-hunting feature (Bet 3).

Covers:
- Bulk-paste auto-detection (IPv4/IPv6/MAC/OUI/sha256/md5/domain)
- Scan against fabricated reports for all 6 IOC types
- Full API roundtrip: create -> import -> scan
- Owner scoping (404 for cross-user access)
- Truncation at _MAX_HITS_TOTAL
"""

import json
import os
import sys
import tempfile

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

# ── Parser unit tests (no DB/app needed) ───────────────────────

from marlinspike.iocs import (
    _MAX_HITS_TOTAL,
    parse_ioc_paste,
    scan_ioc_list_against_reports,
)


class TestParseIocPaste:
    """Auto-detection of IOC types from a mixed paste."""

    PASTE = """
# comment line — ignored
192.168.1.1
2001:db8::1
aa:bb:cc:dd:ee:ff
11:22:33:44:55:66
aa:bb:cc
aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899
d41d8cd98f00b204e9800998ecf8427e
evil.example.com
*.wildcard.test
""".strip()

    def test_ipv4_detected(self):
        result = parse_ioc_paste(self.PASTE)
        types = {e["value"]: e["ioc_type"] for e in result["entries"]}
        assert types["192.168.1.1"] == "ip"

    def test_ipv6_detected(self):
        result = parse_ioc_paste(self.PASTE)
        types = {e["value"]: e["ioc_type"] for e in result["entries"]}
        assert types["2001:db8::1"] == "ip"

    def test_mac_detected(self):
        result = parse_ioc_paste(self.PASTE)
        types = {e["value"]: e["ioc_type"] for e in result["entries"]}
        assert types["aa:bb:cc:dd:ee:ff"] == "mac"
        assert types["11:22:33:44:55:66"] == "mac"

    def test_oui_detected(self):
        result = parse_ioc_paste(self.PASTE)
        types = {e["value"]: e["ioc_type"] for e in result["entries"]}
        assert types["aa:bb:cc"] == "oui"

    def test_sha256_detected(self):
        result = parse_ioc_paste(self.PASTE)
        types = {e["value"]: e["ioc_type"] for e in result["entries"]}
        assert types["aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"] == "sha256"

    def test_md5_detected(self):
        result = parse_ioc_paste(self.PASTE)
        types = {e["value"]: e["ioc_type"] for e in result["entries"]}
        assert types["d41d8cd98f00b204e9800998ecf8427e"] == "md5"

    def test_domain_detected(self):
        result = parse_ioc_paste(self.PASTE)
        types = {e["value"]: e["ioc_type"] for e in result["entries"]}
        assert types["evil.example.com"] == "domain"
        assert types["*.wildcard.test"] == "domain"

    def test_hex_short_falls_back_to_default(self):
        # 8-char hex is not a recognised type, falls back to default_type
        result = parse_ioc_paste("a3b4c5ef", default_type="domain")
        assert result["entries"][0]["ioc_type"] == "domain"

    def test_comments_and_blanks_ignored(self):
        result = parse_ioc_paste("# comment\n\n10.0.0.1\n")
        assert len(result["entries"]) == 1
        assert result["entries"][0]["value"] == "10.0.0.1"

    def test_no_errors_on_clean_paste(self):
        result = parse_ioc_paste(self.PASTE)
        assert result["errors"] == []


class TestScanWorker:
    """Scan against fabricated reports — one hit per IOC type."""

    REPORT = {
        "nodes": [
            {"ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:ff", "role": "PLC"},
            {"ip": "10.0.0.2", "mac": "aa:bb:cc:11:22:33", "role": "HMI"},
        ],
        "conversations": [
            {
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.3",
                "src_mac": "aa:bb:cc:dd:ee:ff",
                "dst_mac": "dd:ee:ff:00:11:22",
                "dns_queries": ["evil.example.com"],
            },
        ],
        "c2_indicators": [
            {"dst": "198.51.100.99", "src": "10.0.0.1"},
        ],
        "risk_findings": [
            {"category": "TEST", "affected_nodes": ["172.16.0.1"]},
        ],
        "malware_findings": [
            {
                "sha256": "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
                "md5": "d41d8cd98f00b204e9800998ecf8427e",
            },
        ],
    }

    def _loader(self, path):
        return self.REPORT

    def _run(self, entries):
        return scan_ioc_list_against_reports(
            entries=entries,
            report_paths=["fake.json"],
            loader=self._loader,
        )

    def test_ip_hit_node(self):
        result = self._run([{"ioc_type": "ip", "value": "10.0.0.1"}])
        assert result["summary"]["total_hits"] >= 1
        locations = [m["location"] for h in result["hits"] for m in h["matches"]]
        assert any("node.ip" in loc for loc in locations)

    def test_ip_hit_conversation(self):
        result = self._run([{"ioc_type": "ip", "value": "10.0.0.3"}])
        locations = [m["location"] for h in result["hits"] for m in h["matches"]]
        assert any("conversation" in loc for loc in locations)

    def test_ip_hit_c2_indicator(self):
        result = self._run([{"ioc_type": "ip", "value": "198.51.100.99"}])
        locations = [m["location"] for h in result["hits"] for m in h["matches"]]
        assert any("c2_indicator" in loc for loc in locations)

    def test_ip_hit_risk_finding(self):
        result = self._run([{"ioc_type": "ip", "value": "172.16.0.1"}])
        locations = [m["location"] for h in result["hits"] for m in h["matches"]]
        assert any("risk_finding" in loc for loc in locations)

    def test_mac_hit(self):
        result = self._run([{"ioc_type": "mac", "value": "aa:bb:cc:dd:ee:ff"}])
        assert result["summary"]["total_hits"] >= 1
        locations = [m["location"] for h in result["hits"] for m in h["matches"]]
        assert any("mac" in loc for loc in locations)

    def test_oui_hit(self):
        # OUI aa:bb:cc matches nodes with mac aa:bb:cc:*
        result = self._run([{"ioc_type": "oui", "value": "aa:bb:cc"}])
        assert result["summary"]["total_hits"] >= 1

    def test_domain_hit(self):
        result = self._run([{"ioc_type": "domain", "value": "evil.example.com"}])
        assert result["summary"]["total_hits"] >= 1
        locations = [m["location"] for h in result["hits"] for m in h["matches"]]
        assert any("dns" in loc for loc in locations)

    def test_sha256_hit(self):
        result = self._run([{
            "ioc_type": "sha256",
            "value": "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
        }])
        assert result["summary"]["total_hits"] >= 1
        locations = [m["location"] for h in result["hits"] for m in h["matches"]]
        assert any("sha256" in loc for loc in locations)

    def test_md5_hit(self):
        result = self._run([{"ioc_type": "md5", "value": "d41d8cd98f00b204e9800998ecf8427e"}])
        assert result["summary"]["total_hits"] >= 1
        locations = [m["location"] for h in result["hits"] for m in h["matches"]]
        assert any("md5" in loc for loc in locations)

    def test_no_match_returns_empty_hits(self):
        result = self._run([{"ioc_type": "ip", "value": "1.2.3.4"}])
        assert result["hits"] == []
        assert result["summary"]["total_hits"] == 0

    def test_truncation_at_limit(self):
        """Generate enough fake reports to trigger total-hit truncation."""
        n_reports = _MAX_HITS_TOTAL + 5
        paths = [f"report_{i}.json" for i in range(n_reports)]
        fake = {"nodes": [{"ip": "10.0.0.1"}], "conversations": [], "c2_indicators": [],
                "risk_findings": [], "malware_findings": []}

        result = scan_ioc_list_against_reports(
            entries=[{"ioc_type": "ip", "value": "10.0.0.1"}],
            report_paths=paths,
            loader=lambda path: fake,
        )
        assert result["truncated"] is True
        assert result["summary"]["total_hits"] <= _MAX_HITS_TOTAL


# ── Flask API integration tests ────────────────────────────────

# Host used by the test server; must match CSRF origin check
_TEST_HOST = "localhost"
_CSRF_HEADERS = {"Origin": f"http://{_TEST_HOST}"}


@pytest.fixture(scope="module")
def flask_app():
    """Spin up a test Flask app backed by in-memory SQLite."""
    import marlinspike.config as _cfg
    _cfg.DATABASE_URL = "sqlite:///:memory:"

    tmpdir = tempfile.mkdtemp(prefix="ms_ioc_test_")
    _cfg.REPORTS_DIR = tmpdir
    _cfg.UPLOADS_DIR = os.path.join(tmpdir, "uploads")
    _cfg.SUBMISSIONS_DIR = os.path.join(tmpdir, "submissions")
    _cfg.PRESETS_DIR = os.path.join(tmpdir, "presets_rw")
    _cfg.PRESETS_BAKED_DIR = os.path.join(tmpdir, "presets_baked")
    os.makedirs(_cfg.UPLOADS_DIR, exist_ok=True)

    from marlinspike.app import create_app
    application = create_app()
    application.config["TESTING"] = True
    application.config["SERVER_NAME"] = _TEST_HOST

    # Create test users
    with application.app_context():
        from marlinspike.auth import create_user
        from marlinspike.models import User, Project, db
        for username, password in [("owner", "pass1"), ("other", "pass2")]:
            try:
                create_user(username, password, role="user")
            except Exception:
                pass
        # Ensure owner has a Default project
        u = User.query.filter_by(username="owner").first()
        proj = Project.query.filter_by(user_id=u.id, name="Default").first()
        if not proj:
            proj = Project(user_id=u.id, name="Default")
            db.session.add(proj)
            db.session.commit()

    yield application, tmpdir


def _make_client(flask_app, username, password):
    """Return a test client already authenticated as *username*."""
    client = flask_app.test_client()
    with flask_app.app_context():
        resp = client.post(
            "/login",
            data={"username": username, "password": password},
            headers=_CSRF_HEADERS,
            follow_redirects=False,
        )
    return client


@pytest.fixture(scope="module")
def owner_client(flask_app):
    app, tmpdir = flask_app
    return _make_client(app, "owner", "pass1"), app, tmpdir


@pytest.fixture(scope="module")
def other_client(flask_app):
    app, tmpdir = flask_app
    return _make_client(app, "other", "pass2"), app, tmpdir


def _owner_pid(app):
    with app.app_context():
        from marlinspike.models import User, Project
        u = User.query.filter_by(username="owner").first()
        proj = Project.query.filter_by(user_id=u.id, name="Default").first()
        return proj.id


class TestIocApiRoundtrip:

    def test_create_list(self, owner_client):
        client, app, tmpdir = owner_client
        pid = _owner_pid(app)

        resp = client.post(
            f"/api/projects/{pid}/iocs",
            json={"name": "Test List", "source": "manual",
                  "entries": [{"ioc_type": "ip", "value": "10.0.0.1", "severity": "high"}]},
            headers=_CSRF_HEADERS,
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["ok"] is True
        assert data["list"]["name"] == "Test List"
        assert data["list"]["entry_count"] == 1

    def test_get_lists(self, owner_client):
        client, app, tmpdir = owner_client
        pid = _owner_pid(app)

        resp = client.get(f"/api/projects/{pid}/iocs")
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data["lists"]) >= 1

    def test_get_list_detail(self, owner_client):
        client, app, tmpdir = owner_client
        pid = _owner_pid(app)

        with app.app_context():
            from marlinspike.models import IocList
            lst = IocList.query.filter_by(project_id=pid).first()
            assert lst is not None, "No IOC list found — test ordering issue"
            list_id = lst.id

        resp = client.get(f"/api/projects/{pid}/iocs/{list_id}")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "entries" in data["list"]

    def test_import_paste(self, owner_client):
        client, app, tmpdir = owner_client
        pid = _owner_pid(app)

        with app.app_context():
            from marlinspike.models import IocList
            lst = IocList.query.filter_by(project_id=pid).first()
            list_id = lst.id

        paste = "10.0.0.2\n10.0.0.3\nevil.example.com\n"
        resp = client.post(
            f"/api/projects/{pid}/iocs/{list_id}/import",
            json={"text": paste, "default_type": "ip"},
            headers=_CSRF_HEADERS,
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["added"] == 3
        assert data["skipped"] == 0

    def test_import_idempotent(self, owner_client):
        """Re-importing same IOCs should result in skipped=N, added=0."""
        client, app, tmpdir = owner_client
        pid = _owner_pid(app)

        with app.app_context():
            from marlinspike.models import IocList
            lst = IocList.query.filter_by(project_id=pid).first()
            list_id = lst.id

        paste = "10.0.0.2\n10.0.0.3\n"
        resp = client.post(
            f"/api/projects/{pid}/iocs/{list_id}/import",
            json={"text": paste, "default_type": "ip"},
            headers=_CSRF_HEADERS,
        )
        data = resp.get_json()
        assert data["added"] == 0
        assert data["skipped"] == 2

    def test_scan_with_report(self, owner_client):
        """Write a fake report to disk; scan should return hits."""
        client, app, tmpdir = owner_client
        pid = _owner_pid(app)

        with app.app_context():
            from marlinspike.models import User, IocList
            import marlinspike.config as _cfg
            u = User.query.filter_by(username="owner").first()
            lst = IocList.query.filter_by(project_id=pid).first()
            list_id = lst.id

            rdir = os.path.join(_cfg.REPORTS_DIR, str(u.id), str(pid))
            os.makedirs(rdir, exist_ok=True)
            report = {
                "nodes": [{"ip": "10.0.0.1", "mac": "00:11:22:33:44:55", "role": "PLC"}],
                "conversations": [
                    {"src_ip": "10.0.0.2", "dst_ip": "10.0.0.3",
                     "src_mac": "aa:bb:cc:00:00:01", "dst_mac": "aa:bb:cc:00:00:02",
                     "dns_queries": ["evil.example.com"]},
                ],
                "c2_indicators": [],
                "risk_findings": [],
                "malware_findings": [],
            }
            with open(os.path.join(rdir, "test_report.json"), "w") as fh:
                json.dump(report, fh)

        resp = client.post(
            f"/api/projects/{pid}/iocs/{list_id}/scan",
            headers=_CSRF_HEADERS,
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["scanned_reports"] == 1
        # The list has: 10.0.0.1 (node), 10.0.0.2/10.0.0.3 (conv), evil.example.com (dns)
        assert data["summary"]["total_hits"] > 0
        assert data["list"]["id"] == list_id

    def test_put_replace_entries(self, owner_client):
        client, app, tmpdir = owner_client
        pid = _owner_pid(app)

        with app.app_context():
            from marlinspike.models import IocList
            lst = IocList.query.filter_by(project_id=pid).first()
            list_id = lst.id

        resp = client.put(
            f"/api/projects/{pid}/iocs/{list_id}",
            json={"entries": [
                {"ioc_type": "ip", "value": "1.2.3.4"},
                {"ioc_type": "domain", "value": "new.example.com"},
            ]},
            headers=_CSRF_HEADERS,
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["list"]["entry_count"] == 2

    def test_delete_list(self, owner_client):
        """Create a new list and delete it; verify 404 after deletion."""
        client, app, tmpdir = owner_client
        pid = _owner_pid(app)

        resp = client.post(
            f"/api/projects/{pid}/iocs",
            json={"name": "ToDelete"},
            headers=_CSRF_HEADERS,
        )
        assert resp.status_code == 201
        list_id = resp.get_json()["list"]["id"]

        resp = client.delete(
            f"/api/projects/{pid}/iocs/{list_id}",
            headers=_CSRF_HEADERS,
        )
        assert resp.status_code == 200
        assert resp.get_json()["ok"] is True

        resp = client.get(f"/api/projects/{pid}/iocs/{list_id}")
        assert resp.status_code == 404


class TestOwnerScoping:
    """Cross-user access should return 404."""

    def test_other_user_cannot_access_project_iocs(self, owner_client, other_client):
        _, app, _ = owner_client
        other, _, _ = other_client
        pid = _owner_pid(app)

        # GET /iocs on owner's project returns 404 for other user (project not found)
        resp = other.get(f"/api/projects/{pid}/iocs")
        assert resp.status_code == 404

    def test_other_user_cannot_read_ioc_list(self, owner_client, other_client):
        _, app, _ = owner_client
        other, _, _ = other_client
        pid = _owner_pid(app)

        with app.app_context():
            from marlinspike.models import IocList
            lst = IocList.query.filter_by(project_id=pid).first()
            list_id = lst.id if lst else 999

        resp = other.get(f"/api/projects/{pid}/iocs/{list_id}")
        assert resp.status_code == 404

    def test_other_user_cannot_import(self, owner_client, other_client):
        _, app, _ = owner_client
        other, _, _ = other_client
        pid = _owner_pid(app)

        with app.app_context():
            from marlinspike.models import IocList
            lst = IocList.query.filter_by(project_id=pid).first()
            list_id = lst.id if lst else 999

        resp = other.post(
            f"/api/projects/{pid}/iocs/{list_id}/import",
            json={"text": "10.0.0.1"},
            headers=_CSRF_HEADERS,
        )
        assert resp.status_code == 404

    def test_other_user_cannot_scan(self, owner_client, other_client):
        _, app, _ = owner_client
        other, _, _ = other_client
        pid = _owner_pid(app)

        with app.app_context():
            from marlinspike.models import IocList
            lst = IocList.query.filter_by(project_id=pid).first()
            list_id = lst.id if lst else 999

        resp = other.post(
            f"/api/projects/{pid}/iocs/{list_id}/scan",
            headers=_CSRF_HEADERS,
        )
        assert resp.status_code == 404


class TestTruncation:
    """Verify truncated flag fires when total hits >= _MAX_HITS_TOTAL."""

    def test_truncated_flag(self):
        n = _MAX_HITS_TOTAL + 10
        paths = [f"r{i}.json" for i in range(n)]
        fake_report = {
            "nodes": [{"ip": "10.0.0.1"}],
            "conversations": [],
            "c2_indicators": [],
            "risk_findings": [],
            "malware_findings": [],
        }
        result = scan_ioc_list_against_reports(
            entries=[{"ioc_type": "ip", "value": "10.0.0.1"}],
            report_paths=paths,
            loader=lambda p: fake_report,
        )
        assert result["truncated"] is True
        assert result["summary"]["total_hits"] <= _MAX_HITS_TOTAL

    def test_not_truncated_below_limit(self):
        n = 5
        paths = [f"r{i}.json" for i in range(n)]
        fake_report = {
            "nodes": [{"ip": "10.0.0.1"}],
            "conversations": [],
            "c2_indicators": [],
            "risk_findings": [],
            "malware_findings": [],
        }
        result = scan_ioc_list_against_reports(
            entries=[{"ioc_type": "ip", "value": "10.0.0.1"}],
            report_paths=paths,
            loader=lambda p: fake_report,
        )
        assert result["truncated"] is False
        assert result["summary"]["total_hits"] == n
