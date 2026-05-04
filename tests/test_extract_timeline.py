"""Tests for Bet 1: /api/reports/<filename>/timeline and /extract endpoints."""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret-key-bet1")

# Stable test credentials — must not collide with other test modules.
_TEST_USER = "bet1_user"
_TEST_PASS = "bet1Pass1!"


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def app():
    from marlinspike.app import create_app
    application = create_app()
    application.config["TESTING"] = True
    application.config["WTF_CSRF_ENABLED"] = False
    return application


@pytest.fixture(scope="module")
def db(app):
    from marlinspike.models import db as _db
    with app.app_context():
        _db.create_all()
        yield _db


@pytest.fixture(scope="module")
def user_info(app, db):
    """Create test user once per module; return (user_id, project_id)."""
    from marlinspike.auth import create_user
    from marlinspike.models import db as _db, User, Project
    with app.app_context():
        try:
            create_user(_TEST_USER, _TEST_PASS)
            _db.session.commit()
        except Exception:
            _db.session.rollback()
        user = User.query.filter_by(username=_TEST_USER).first()
        assert user is not None
        proj = Project.query.filter_by(user_id=user.id, name="Default").first()
        if proj is None:
            proj = Project(user_id=user.id, name="Default")
            _db.session.add(proj)
            _db.session.commit()
        return user.id, proj.id


@pytest.fixture(scope="module")
def authed_client(app, db, user_info):
    """Module-scoped test client — logs in once, reused across all endpoint tests.

    Module scope avoids hitting the /login rate limit (5 per minute) when
    multiple tests set up their own client in rapid succession.
    """
    with app.test_client() as c:
        # POST /login — must pass CSRF origin check: include Origin header
        resp = c.post(
            "/login",
            data={"username": _TEST_USER, "password": _TEST_PASS},
            headers={"Origin": "http://localhost"},
            follow_redirects=True,
        )
        assert resp.status_code == 200, f"Login failed: {resp.status_code}"
        yield c


def _reports_dir_for(app_obj, user_id, project_id):
    from marlinspike import config
    return os.path.join(config.REPORTS_DIR, str(user_id), str(project_id))


def _uploads_dir_for(app_obj, user_id, project_id):
    from marlinspike import config
    return os.path.join(config.UPLOADS_DIR, str(user_id), str(project_id))


def _write_report(path: str, report: dict):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(report, f)


# ── _compute_timeline_buckets unit tests (no Flask needed) ────────────────────

def test_timeline_empty_conversations():
    """Empty conversations list returns buckets=[], first/last_seen=None."""
    from marlinspike.app import _compute_timeline_buckets
    result = _compute_timeline_buckets([])
    assert result["buckets"] == []
    assert result["first_seen"] is None
    assert result["last_seen"] is None
    assert result["bucket_seconds"] >= 1


def test_timeline_no_timestamps_skipped():
    """Conversations without first_seen are silently skipped."""
    from marlinspike.app import _compute_timeline_buckets
    convs = [{"packet_count": 100, "bytes_total": 5000}]  # no timestamps
    result = _compute_timeline_buckets(convs)
    assert result["buckets"] == []


def test_timeline_single_conversation():
    """Single conversation → 1 bucket with correct totals."""
    from marlinspike.app import _compute_timeline_buckets
    convs = [{
        "first_seen": 1445520000.0,
        "last_seen": 1445520000.0,
        "packet_count": 42,
        "bytes_total": 1234,
    }]
    result = _compute_timeline_buckets(convs)
    assert result["first_seen"] == 1445520000.0
    assert result["last_seen"] == 1445520000.0
    assert len(result["buckets"]) == 1
    assert result["buckets"][0]["packets"] == 42
    assert result["buckets"][0]["bytes"] == 1234
    assert result["buckets"][0]["conv_count"] == 1


def test_timeline_adaptive_bucket_10min():
    """10-minute span (600 s) → bucket_seconds = max(1, ceil(600/120)) = 5."""
    import math
    from marlinspike.app import _compute_timeline_buckets
    t0 = 1445520000.0
    convs = [{"first_seen": t0, "last_seen": t0 + 600, "packet_count": 600, "bytes_total": 60000}]
    result = _compute_timeline_buckets(convs)
    assert result["bucket_seconds"] == max(1, math.ceil(600 / 120))
    assert result["bucket_seconds"] == 5
    # All packets must be preserved after distribution
    total_pkts = sum(b["packets"] for b in result["buckets"])
    assert total_pkts == 600


def test_timeline_adaptive_bucket_24h():
    """24-hour span (86400 s) → bucket_seconds = max(1, ceil(86400/120)) = 720."""
    import math
    from marlinspike.app import _compute_timeline_buckets
    t0 = 1445520000.0
    span = 86400.0
    convs = [{"first_seen": t0, "last_seen": t0 + span, "packet_count": 1000, "bytes_total": 100000}]
    result = _compute_timeline_buckets(convs)
    expected_bucket_s = max(1, math.ceil(span / 120))
    assert result["bucket_seconds"] == expected_bucket_s
    assert result["bucket_seconds"] == 720
    total_pkts = sum(b["packets"] for b in result["buckets"])
    assert total_pkts == 1000


def test_timeline_multiple_conversations_packet_sum():
    """Packets across all conversations sum correctly across all buckets."""
    from marlinspike.app import _compute_timeline_buckets
    t0 = 1445520000.0
    convs = [
        {"first_seen": t0, "last_seen": t0 + 60, "packet_count": 100, "bytes_total": 10000},
        {"first_seen": t0 + 30, "last_seen": t0 + 90, "packet_count": 200, "bytes_total": 20000},
        {"first_seen": t0 + 80, "last_seen": t0 + 120, "packet_count": 50, "bytes_total": 5000},
    ]
    result = _compute_timeline_buckets(convs)
    total_pkts = sum(b["packets"] for b in result["buckets"])
    total_bytes = sum(b["bytes"] for b in result["buckets"])
    assert total_pkts == 350
    assert total_bytes == 35000


def test_timeline_iso_timestamp_strings():
    """Conversations with ISO-format first_seen strings are parsed correctly."""
    from marlinspike.app import _compute_timeline_buckets
    convs = [{
        "first_seen": "2015-10-22T10:00:00+00:00",
        "last_seen": "2015-10-22T10:00:30+00:00",
        "packet_count": 99,
        "bytes_total": 9900,
    }]
    result = _compute_timeline_buckets(convs)
    assert len(result["buckets"]) > 0
    assert sum(b["packets"] for b in result["buckets"]) == 99


def test_timeline_bucket_seconds_field_present():
    """Response always includes bucket_seconds key."""
    from marlinspike.app import _compute_timeline_buckets
    result = _compute_timeline_buckets([])
    assert "bucket_seconds" in result


# ── Flask endpoint tests ───────────────────────────────────────────────────────

def test_timeline_404_on_missing_report(authed_client, user_info):
    """GET /api/reports/<missing>/timeline → 404."""
    _, project_id = user_info
    resp = authed_client.get(
        "/api/reports/nonexistent_report.json/timeline",
        query_string={"project_id": project_id},
    )
    assert resp.status_code == 404


def test_timeline_returns_correct_shape(app, authed_client, user_info):
    """Timeline endpoint returns expected JSON shape for a synthetic report."""
    user_id, project_id = user_info

    t0 = 1445520000.0
    report = {
        "capture_info": {"pcap_path": "test.pcap"},
        "conversations": [
            {
                "first_seen": t0,
                "last_seen": t0 + 600.0,
                "packet_count": 300,
                "bytes_total": 30000,
            },
            {
                "first_seen": t0 + 300.0,
                "last_seen": t0 + 600.0,
                "packet_count": 100,
                "bytes_total": 10000,
            },
        ],
    }
    rdir = _reports_dir_for(app, user_id, project_id)
    _write_report(os.path.join(rdir, "test_timeline.json"), report)

    resp = authed_client.get(
        "/api/reports/test_timeline.json/timeline",
        query_string={"project_id": project_id},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert "first_seen" in data
    assert "last_seen" in data
    assert "bucket_seconds" in data
    assert "buckets" in data
    assert isinstance(data["buckets"], list)
    assert data["first_seen"] == pytest.approx(t0)
    assert data["last_seen"] == pytest.approx(t0 + 600.0)
    total_pkts = sum(b["packets"] for b in data["buckets"])
    assert total_pkts == 400
    for bucket in data["buckets"]:
        assert "t" in bucket
        assert "packets" in bucket
        assert "bytes" in bucket
        assert "conv_count" in bucket


def test_extract_404_when_report_missing(authed_client, user_info):
    """POST /api/reports/<missing>/extract → 404."""
    _, project_id = user_info
    resp = authed_client.post(
        "/api/reports/no_such_report.json/extract",
        json={},
        headers={"Origin": "http://localhost"},
        query_string={"project_id": project_id},
    )
    assert resp.status_code == 404


def test_extract_404_when_pcap_missing(app, authed_client, user_info):
    """POST extract → 404 when report exists but PCAP file is absent."""
    user_id, project_id = user_info

    report = {
        "capture_info": {"pcap_path": "missing_capture.pcap"},
        "conversations": [],
    }
    rdir = _reports_dir_for(app, user_id, project_id)
    _write_report(os.path.join(rdir, "no_pcap_report.json"), report)

    resp = authed_client.post(
        "/api/reports/no_pcap_report.json/extract",
        json={"src": "192.168.1.10"},
        headers={"Origin": "http://localhost"},
        query_string={"project_id": project_id},
    )
    assert resp.status_code == 404
    body = resp.get_json()
    assert body is not None
    assert "PCAP not found" in body.get("error", "")


def test_extract_504_on_timeout(app, authed_client, user_info):
    """POST extract → 504 when subprocess.run raises TimeoutExpired."""
    import subprocess as _sp
    from unittest.mock import patch

    user_id, project_id = user_info

    # Write a stub PCAP file on disk so the "PCAP not found" check passes
    pcap_bytes = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00"
    udir = _uploads_dir_for(app, user_id, project_id)
    os.makedirs(udir, exist_ok=True)
    pcap_path = os.path.join(udir, "timeout_test.pcap")
    with open(pcap_path, "wb") as f:
        f.write(pcap_bytes)

    report = {
        "capture_info": {"pcap_path": "timeout_test.pcap"},
        "conversations": [],
    }
    rdir = _reports_dir_for(app, user_id, project_id)
    _write_report(os.path.join(rdir, "timeout_report.json"), report)

    def _raise_timeout(*args, **kwargs):
        raise _sp.TimeoutExpired(cmd=args[0], timeout=60)

    with patch("subprocess.run", side_effect=_raise_timeout):
        resp = authed_client.post(
            "/api/reports/timeout_report.json/extract",
            json={"src": "10.0.0.1"},
            headers={"Origin": "http://localhost"},
            query_string={"project_id": project_id},
        )
    assert resp.status_code == 504
    body = resp.get_json()
    assert body is not None
    assert "timed out" in body.get("error", "").lower()


def test_extract_200_on_success(app, authed_client, user_info):
    """POST extract → 200 with application/vnd.tcpdump.pcap when tshark writes output."""
    import subprocess as _sp
    from unittest.mock import patch

    user_id, project_id = user_info

    fake_pcap = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00"

    udir = _uploads_dir_for(app, user_id, project_id)
    os.makedirs(udir, exist_ok=True)
    pcap_path = os.path.join(udir, "success_test.pcap")
    with open(pcap_path, "wb") as f:
        f.write(fake_pcap)

    report = {
        "capture_info": {"pcap_path": "success_test.pcap"},
        "conversations": [],
    }
    rdir = _reports_dir_for(app, user_id, project_id)
    _write_report(os.path.join(rdir, "success_report.json"), report)

    def _mock_run(cmd, *args, **kwargs):
        """Simulate tshark writing the output file."""
        if "-w" in cmd:
            out_idx = cmd.index("-w") + 1
            out_file = cmd[out_idx]
            with open(out_file, "wb") as f:
                f.write(fake_pcap)
        return _sp.CompletedProcess(args=cmd, returncode=0)

    with patch("subprocess.run", side_effect=_mock_run):
        resp = authed_client.post(
            "/api/reports/success_report.json/extract",
            json={"src": "192.168.1.10", "dst": "192.168.1.20", "port": 502},
            headers={"Origin": "http://localhost"},
            query_string={"project_id": project_id},
        )
    assert resp.status_code == 200
    assert resp.content_type == "application/vnd.tcpdump.pcap"
    assert "attachment" in resp.headers.get("Content-Disposition", "")
    assert resp.data == fake_pcap
