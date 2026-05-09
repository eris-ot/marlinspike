"""Drive Playwright through MarlinSpike's UI and capture screenshots.

Boots the Flask app against a fresh SQLite DB pointing at the existing
data directory (which already has real report JSONs from prior scans
of the 4SICS preset). Logs in, navigates each surface that needs a
screenshot, and writes PNGs to docs/screenshots/.

Run from repo root:
    python3 scripts/capture-screenshots.py
"""

from __future__ import annotations

import os
import shutil
import sys
import threading
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# Use a temp data dir cloned from the real one so we don't pollute live state.
SCRATCH_DATA = Path("/tmp/ms-screenshot-data")
if SCRATCH_DATA.exists():
    shutil.rmtree(SCRATCH_DATA)
shutil.copytree(REPO_ROOT / "data", SCRATCH_DATA)

# DB lives separately so we get a fresh user table.
DB_PATH = "/tmp/ms-screenshot.db"
if os.path.exists(DB_PATH):
    os.unlink(DB_PATH)

ADMIN_PW = "screenshot-admin-pw"

os.environ["DATABASE_URL"] = f"sqlite:///{DB_PATH}"
os.environ["SECRET_KEY"] = "screenshot-secret"
os.environ["MARLINSPIKE_DATA_DIR"] = str(SCRATCH_DATA)
os.environ["ADMIN_PASSWORD"] = ADMIN_PW
os.environ["LIVE_CAPTURE_ENABLED"] = "true"
os.environ["LIVE_CAPTURE_SOCKET"] = "/tmp/no-such-socket"  # so /capture renders disabled-banner-free but capd-unreachable

from datetime import datetime, timedelta, timezone  # noqa: E402

from werkzeug.security import generate_password_hash  # noqa: E402

from marlinspike.app import create_app  # noqa: E402
from marlinspike.models import (  # noqa: E402
    AssetTag, AuditLog, CaptureSession, FindingNote, IocEntry, IocList,
    Project, SavedFilter, ScanHistory, User, db,
)


def seed():
    """Create admin user, link the existing on-disk reports to a project."""
    app = create_app()
    with app.app_context():
        # The bootstrap flow already created an admin via ADMIN_PASSWORD.
        admin = User.query.filter_by(username="admin").first()
        if admin is None:
            admin = User(username="admin",
                         password_hash=generate_password_hash(ADMIN_PW),
                         role="admin")
            db.session.add(admin)
            db.session.commit()
        admin_id = admin.id

        # Drop the auto-created Default project so 4SICS-tutorial is the only
        # one and auto-selects in every per-project picker.
        for default_proj in Project.query.filter_by(user_id=admin_id, name="Default").all():
            db.session.delete(default_proj)
        db.session.commit()

        proj = Project.query.filter_by(user_id=admin_id, name="4SICS-tutorial").first()
        if proj is None:
            proj = Project(user_id=admin_id, name="4SICS-tutorial")
            db.session.add(proj)
            db.session.commit()

        # Move existing reports/uploads into <user_id>/<project_id>/ paths.
        src_reports = SCRATCH_DATA / "reports" / "1" / "2"
        src_uploads = SCRATCH_DATA / "uploads" / "1" / "2"
        dst_reports = SCRATCH_DATA / "reports" / str(admin_id) / str(proj.id)
        dst_uploads = SCRATCH_DATA / "uploads" / str(admin_id) / str(proj.id)
        if src_reports.exists() and src_reports != dst_reports:
            dst_reports.parent.mkdir(parents=True, exist_ok=True)
            if dst_reports.exists():
                shutil.rmtree(dst_reports)
            shutil.copytree(src_reports, dst_reports)
        if src_uploads.exists() and src_uploads != dst_uploads:
            dst_uploads.parent.mkdir(parents=True, exist_ok=True)
            if dst_uploads.exists():
                shutil.rmtree(dst_uploads)
            shutil.copytree(src_uploads, dst_uploads)

        # Seed an asset tag so the contextual-severity overlay is visible.
        # We pick a node we know exists in the report (a 10.0.0.x host).
        existing_tag = AssetTag.query.filter_by(project_id=proj.id, asset_key="10.0.0.5").first()
        if existing_tag is None:
            tag = AssetTag(project_id=proj.id, asset_key="10.0.0.5",
                           owner="Erisforge Ltd.", criticality="critical",
                           zone="process-control", business_function="DCS poller",
                           free_text="Tagged during screenshot pass",
                           updated_by=admin_id)
            db.session.add(tag)

        # Seed an IOC list so the /iocs page has content.
        existing_list = IocList.query.filter_by(project_id=proj.id, name="cisa-aa24-038a").first()
        if existing_list is None:
            ioc_list = IocList(project_id=proj.id,
                               name="cisa-aa24-038a",
                               description="Sample CISA advisory indicators (demo data)",
                               source="manual",
                               created_by=admin_id)
            db.session.add(ioc_list)
            db.session.commit()
            for entry in [
                ("ip", "21.2.2.2", "C2 — primary", "high"),
                ("ip", "198.51.100.7", "C2 — secondary", "high"),
                ("ip", "203.0.113.42", "Staging", "medium"),
                ("domain", "c2.example.com", "Beacon target", "high"),
                ("domain", "exfil.bad.tld", "Exfiltration", "critical"),
                ("mac", "00:1c:06:27:64:11", "Suspicious endpoint", "medium"),
                ("oui", "00:1c:06", "Vendor OUI of interest", "low"),
                ("sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                 "Known sample", "high"),
            ]:
                db.session.add(IocEntry(list_id=ioc_list.id, ioc_type=entry[0],
                                        value=entry[1], label=entry[2], severity=entry[3]))

        # Seed a saved BPF filter so the /capture saved-filter dropdown has content.
        existing_filter = SavedFilter.query.filter_by(project_id=proj.id, name="modbus-only").first()
        if existing_filter is None:
            db.session.add(SavedFilter(project_id=proj.id, user_id=admin_id,
                                       name="modbus-only", expression="tcp port 502"))
            db.session.add(SavedFilter(project_id=proj.id, user_id=admin_id,
                                       name="ot-broad",
                                       expression="tcp port 502 or tcp port 102 or "
                                                  "tcp port 44818 or udp port 47808"))

        db.session.commit()
        return app, proj.id, admin_id


def list_reports(data_dir: Path, user_id: int, project_id: int) -> list[str]:
    """Return ordered list of report .json filenames in the project."""
    rdir = data_dir / "reports" / str(user_id) / str(project_id)
    files = sorted(p.name for p in rdir.iterdir()
                   if p.is_file() and p.name.endswith(".json")
                   and not p.name.endswith("-apt.json")
                   and not p.name.endswith("-arp.json")
                   and not p.name.endswith("-mitre.json"))
    return files


def reseed_with_real_report_data(app, project_id: int, user_id: int, report_path: Path):
    """Tie seeded asset tags / finding notes / IOCs to actual identifiers in the report.

    Reading the report JSON before seeding lets us produce a fully-populated
    UI: a tag attached to a real node, a note attached to a real finding, an
    IOC list with at least one entry that matches real traffic.
    """
    import json
    import hashlib
    rpt = json.loads(report_path.read_text())

    nodes = rpt.get("nodes") or []
    real_asset_key = None
    for n in nodes:
        ak = n.get("mac") or n.get("ip")
        if ak:
            real_asset_key = ak
            break

    findings = rpt.get("risk_findings") or []
    real_finding_sig = None
    real_finding_cat = None
    if findings:
        f0 = findings[0]
        # Match the server-side _finding_signature() formula exactly.
        payload = {
            "category": str(f0.get("category") or ""),
            "nodes": sorted(str(n) for n in (f0.get("affected_nodes") or [])),
            "edges": sorted(str(e) for e in (f0.get("affected_edges") or [])),
        }
        real_finding_sig = hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode()
        ).hexdigest()[:32]
        real_finding_cat = payload["category"]

    real_ips = []
    for n in nodes:
        ip = n.get("ip")
        if ip and not ip.startswith(("169.254.", "224.", "239.", "255.")):
            real_ips.append(ip)
        if len(real_ips) >= 3:
            break

    with app.app_context():
        # Tag a real asset.
        if real_asset_key:
            existing = AssetTag.query.filter_by(project_id=project_id,
                                                asset_key=real_asset_key).first()
            if existing is None:
                tag = AssetTag(
                    project_id=project_id, asset_key=real_asset_key,
                    owner="Erisforge Ltd.", criticality="critical",
                    zone="process-control", business_function="DCS poller",
                    free_text="Site-tagged after first triage. Vendor PSIRT contact: psirt@vendor.example.",
                    updated_by=user_id,
                )
                db.session.add(tag)
                print(f"    seeded asset tag for {real_asset_key}")

        # Note against a real finding.
        if real_finding_sig:
            existing = FindingNote.query.filter_by(
                project_id=project_id, finding_signature=real_finding_sig).first()
            if existing is None:
                note = FindingNote(
                    project_id=project_id,
                    finding_signature=real_finding_sig,
                    report_filename=report_path.name,
                    status="investigating",
                    body=f"Confirmed real on 2026-05-07. Engaging vendor PSIRT for {real_finding_cat}. "
                         "Tracking under change-control 4781.",
                    author_id=user_id,
                )
                db.session.add(note)
                print(f"    seeded finding note for {real_finding_cat}")

        # Add real IPs to the IOC list so the scan produces hits.
        if real_ips:
            ioc_list = IocList.query.filter_by(project_id=project_id,
                                               name="cisa-aa24-038a").first()
            if ioc_list is not None:
                for ip in real_ips:
                    if not IocEntry.query.filter_by(list_id=ioc_list.id, ioc_type="ip", value=ip).first():
                        db.session.add(IocEntry(
                            list_id=ioc_list.id, ioc_type="ip", value=ip,
                            label="Demo — matches real traffic in 4SICS captures",
                            severity="medium",
                        ))
                print(f"    seeded {len(real_ips)} IOC entries for real traffic")

        # Seed audit-log entries representing a typical day's auth + capture
        # activity, so /audit screenshots show populated state.
        if AuditLog.query.count() <= 1:  # only the bootstrap login event
            now = datetime.now(timezone.utc)
            audit_entries = [
                # Newest first; we insert with descending created_at offsets.
                (0,    "auth.login",              "auth",    "success", "admin",   None,                None,                "127.0.0.1",
                 "{}"),
                (5,    "capture.stop",            "capture", "success", "admin",   "capture_session",   "42",                "127.0.0.1",
                 '{"packets": 4831029, "drops": 12, "bytes": 1147302841}'),
                (62,   "capture.start",           "capture", "success", "admin",   "capture_session",   "42",                "127.0.0.1",
                 '{"interface": "eth1", "bpf": "tcp port 502 or tcp port 102", "project_id": 4}'),
                (135,  "auth.login",              "auth",    "success", "analyst", None,                None,                "10.0.40.91",
                 "{}"),
                (210,  "auth.login_failed",       "auth",    "failure", "analyst", None,                None,                "10.0.40.91",
                 '{"reason": "invalid_password"}'),
                (3700, "capture.admin_stop",      "capture", "success", "admin",   "capture_session",   "41",                "127.0.0.1",
                 '{"owner_user_id": 3, "packets": 12903, "drops": 0}'),
                (3850, "auth.password_changed",   "auth",    "success", "analyst", "user",              "3",                 "10.0.40.91",
                 "{}"),
                (7200, "auth.token_used",         "auth",    "success", "analyst", "password_reset",    None,                "10.0.40.91",
                 "{}"),
                (7260, "auth.token_issued",       "auth",    "success", "admin",   "password_reset",    "3",                 "127.0.0.1",
                 '{"target_user": "analyst"}'),
                (8400, "auth.logout",             "auth",    "success", "admin",   None,                None,                "127.0.0.1",
                 "{}"),
                (10800,"auth.token_rejected",     "auth",    "failure", None,      "password_reset",    None,                "172.16.5.4",
                 '{"reason": "expired"}'),
                (14400,"auth.login",              "auth",    "success", "admin",   None,                None,                "127.0.0.1",
                 "{}"),
            ]
            for offset_s, event_type, category, status, username, ttype, tid, ip, detail in audit_entries:
                actor_id = user_id if username == "admin" else (3 if username == "analyst" else None)
                role = "admin" if username == "admin" else "user" if username == "analyst" else None
                db.session.add(AuditLog(
                    event_type=event_type, category=category, status=status,
                    actor_user_id=actor_id, actor_username=username,
                    actor_role=role, target_type=ttype, target_id=tid,
                    ip_address=ip, detail=detail,
                    created_at=now - timedelta(seconds=offset_s),
                ))

        # Seed ScanHistory rows that match the on-disk reports so /scans is
        # populated and the project History tab shows the runs.
        if ScanHistory.query.count() == 0:
            now = datetime.now(timezone.utc)
            rdir = SCRATCH_DATA / "reports" / str(user_id) / str(project_id)
            for idx, rfile in enumerate(sorted(p.name for p in rdir.iterdir()
                                               if p.is_file()
                                               and p.name.endswith(".json")
                                               and not p.name.endswith("-apt.json")
                                               and not p.name.endswith("-arp.json")
                                               and not p.name.endswith("-mitre.json"))):
                pcap_stem = rfile.split("-marlinspike-")[0]
                started = now - timedelta(hours=24 * (idx + 1))
                completed = started + timedelta(seconds=58 + idx * 7)
                db.session.add(ScanHistory(
                    run_id=f"seed-{idx:08d}",
                    user_id=user_id, project_id=project_id,
                    command="chain", scan_profile="full",
                    pcap_source=f"{pcap_stem}.pcap",
                    pcap_hash="a" * 64,
                    status="completed",
                    started_at=started, completed_at=completed,
                    report_path=str(rdir / rfile),
                    node_count=12 + idx * 3,
                    edge_count=18 + idx * 5,
                ))
            # Also add one failed and one running so the page shows variety.
            db.session.add(ScanHistory(
                run_id="seed-failed-01",
                user_id=user_id, project_id=project_id,
                command="chain", scan_profile="full",
                pcap_source="contractor-laptop-export.pcap",
                pcap_hash="b" * 64,
                status="failed",
                started_at=now - timedelta(hours=12),
                completed_at=now - timedelta(hours=12) + timedelta(seconds=4),
                error_tail="ingest stage exit 1: capinfos couldn't read file (truncated PCAP header)",
            ))
            db.session.add(ScanHistory(
                run_id="seed-running-01",
                user_id=user_id, project_id=project_id,
                command="chain", scan_profile="fast",
                pcap_source="live-eth1-rotation-00007.pcapng",
                pcap_hash="c" * 64,
                status="running",
                started_at=now - timedelta(seconds=18),
                node_count=0, edge_count=0,
            ))

        db.session.commit()
    return real_asset_key, real_finding_sig


def run_app(app):
    """Run Flask in a background thread on port 5901."""
    app.run(host="127.0.0.1", port=5901, debug=False, use_reloader=False)


def main():
    print("[1/5] seeding…", flush=True)
    app, project_id, admin_id = seed()

    reports = list_reports(SCRATCH_DATA, admin_id, project_id)
    print(f"  reports in project: {reports}")
    if not reports:
        print("ERROR: no reports found; cannot screenshot the workbench.", file=sys.stderr)
        sys.exit(1)
    primary_report = reports[0]
    primary_report_path = SCRATCH_DATA / "reports" / str(admin_id) / str(project_id) / primary_report
    real_asset_key, real_finding_sig = reseed_with_real_report_data(
        app, project_id, admin_id, primary_report_path)

    # Boot Flask in a background thread.
    print("[2/5] booting Flask on http://127.0.0.1:5901 …", flush=True)
    server_thread = threading.Thread(target=run_app, args=(app,), daemon=True)
    server_thread.start()

    # Wait for liveness.
    import urllib.request
    for i in range(40):
        try:
            urllib.request.urlopen("http://127.0.0.1:5901/login", timeout=1).read()
            break
        except Exception:
            time.sleep(0.25)
    else:
        print("ERROR: Flask did not come up within 10s.", file=sys.stderr)
        sys.exit(1)
    print("  Flask is up.")

    print("[3/5] launching Playwright…", flush=True)
    from playwright.sync_api import sync_playwright

    out_dir = REPO_ROOT / "docs" / "screenshots"
    out_dir.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            viewport={"width": 1600, "height": 1000},
            device_scale_factor=2,  # crisp screenshots
        )
        page = context.new_page()

        # Surface browser-side errors so we know what's failing.
        page.on("console", lambda msg: msg.type == "error"
                and print(f"  [console.error] {msg.text}"))
        page.on("pageerror", lambda exc: print(f"  [pageerror] {exc}"))

        # ── login ───────────────────────────────────────────
        print("[4/5] logging in…", flush=True)
        page.goto("http://127.0.0.1:5901/login")
        page.fill("input[name='username']", "admin")
        page.fill("input[name='password']", ADMIN_PW)
        page.click("button[type='submit']")
        page.wait_for_url("**/dashboard", timeout=10_000)
        print("  logged in.")

        print("[5/5] capturing screenshots…", flush=True)
        captures: list[tuple[str, str, dict]] = [
            # (output_filename, url, options)
            ("29-capture-page.png",
             "/capture", {}),
            ("30-iocs-page.png",
             "/iocs", {}),
            ("31-audit-page.png",
             "/audit", {}),
            ("32-projects-list.png",
             "/projects", {}),
            ("33-scans-page.png",
             "/scans", {}),
            ("34-system-page.png",
             "/system", {}),
            ("35-users-page.png",
             "/users", {}),
            ("37-dashboard.png",
             "/dashboard", {}),
        ]

        for filename, url, opts in captures:
            full = f"http://127.0.0.1:5901{url}"
            print(f"  → {filename}  ({url})")
            page.goto(full)
            try:
                page.wait_for_load_state("networkidle", timeout=8_000)
            except Exception:
                pass
            time.sleep(1.0)  # let any post-render JS paint

            # Per-page interactions to populate detail panes before capturing.
            if url == "/iocs":
                try:
                    page.click(".iocs-list-item", timeout=3_000)
                    time.sleep(0.8)
                except Exception:
                    pass
            if url == "/projects":
                # Initial load auto-selects the project but doesn't call
                # setTab() — the Overview tab is visually active but
                # loadOverview() never fires until clicked. Explicitly trigger.
                time.sleep(2.5)
                try:
                    page.click(".proj-tab[data-tab='overview']", timeout=5_000)
                except Exception as exc:
                    print(f"    overview tab click failed: {exc}")
                try:
                    page.wait_for_function("""
                      () => {
                        const c = document.getElementById('overview-content');
                        return c && getComputedStyle(c).display !== 'none';
                      }
                    """, timeout=20_000)
                    time.sleep(2.5)
                except Exception as exc:
                    print(f"    overview render wait failed: {exc}")

            page.screenshot(path=str(out_dir / filename),
                            full_page=opts.get("full_page", True))

            # IOC scan with hits — runs after the basic /iocs screenshot.
            if url == "/iocs":
                try:
                    # Trigger IOC.runScan() directly since the button isn't
                    # selectable by a stable id/class.
                    page.evaluate("IOC.runScan()")
                    time.sleep(4.0)  # walking N reports server-side
                    page.screenshot(path=str(out_dir / "46-ioc-scan-hits.png"),
                                    full_page=True)
                except Exception as exc:
                    print(f"    ioc scan capture failed: {exc}")

        # ── workbench ───────────────────────────────────────
        print(f"  → workbench (report: {primary_report})")
        page.goto(f"http://127.0.0.1:5901/api/reports/{primary_report}/viewer?project_id={project_id}")
        try:
            page.wait_for_load_state("networkidle", timeout=15_000)
        except Exception:
            pass
        time.sleep(2.0)

        # v3.4 workbench: map is always visible, lens strip replaces old nav rail.
        # Default view — Comms lens (map renders immediately after load).
        time.sleep(3.0)  # let SVG2D layout settle
        page.screenshot(path=str(out_dir / "38-workbench-comms-lens.png"),
                        full_page=False)

        # HP-HMI mode toggle — desaturates everything except alarm-state assets.
        # Capture HP-HMI versions of each lens so docs can show the discipline
        # applied across the workbench, not just the Comms lens.
        try:
            page.evaluate("window.msSetHmi(true)")
            time.sleep(2.0)  # SVG re-renders on ms:hmi-changed
            page.screenshot(path=str(out_dir / "51-workbench-hp-hmi-comms.png"),
                            full_page=False)
            # Findings lens, HP-HMI
            page.click("button[data-lens='findings']", timeout=3_000)
            time.sleep(1.5)
            page.screenshot(path=str(out_dir / "52-workbench-hp-hmi-findings.png"),
                            full_page=False)
            # IOC lens, HP-HMI
            page.click("button[data-lens='ioc']", timeout=3_000)
            time.sleep(1.5)
            page.screenshot(path=str(out_dir / "53-workbench-hp-hmi-ioc.png"),
                            full_page=False)
            # ATT&CK lens, HP-HMI
            page.click("button[data-lens='attck']", timeout=3_000)
            time.sleep(1.5)
            page.screenshot(path=str(out_dir / "54-workbench-hp-hmi-attck.png"),
                            full_page=False)
            # Peers lens, HP-HMI
            page.click("button[data-lens='peers']", timeout=3_000)
            time.sleep(1.5)
            page.screenshot(path=str(out_dir / "55-workbench-hp-hmi-peers.png"),
                            full_page=False)
            # Back to Comms + select a node so inspector shows in HP-HMI
            page.click("button[data-lens='comms']", timeout=3_000)
            time.sleep(1.0)
            page.evaluate("""
              () => {
                const node = document.querySelector('#ms-svg-container g circle');
                if (node) node.dispatchEvent(new MouseEvent('click', {bubbles: true}));
              }
            """)
            time.sleep(1.5)
            page.screenshot(path=str(out_dir / "56-workbench-hp-hmi-inspector.png"),
                            full_page=False)
            page.evaluate("window.msSetHmi(false)")
            time.sleep(1.0)
        except Exception as exc:
            print(f"    HP-HMI toggle failed: {exc}")

        # Node selected — inspector panel populated on the right.
        try:
            page.evaluate("""
              () => {
                const node = document.querySelector('#ms-svg-container g circle');
                if (node) node.dispatchEvent(new MouseEvent('click', {bubbles: true}));
              }
            """)
            time.sleep(1.5)
            page.screenshot(path=str(out_dir / "39-workbench-inspector.png"),
                            full_page=False)
        except Exception as exc:
            print(f"    inspector click failed: {exc}")

        # Deselect / clear inspector.
        try:
            page.evaluate("() => MS.deselectNode()")
            time.sleep(0.5)
        except Exception:
            pass

        # Findings lens.
        try:
            page.click("button[data-lens='findings']", timeout=3_000)
            time.sleep(1.5)
            page.screenshot(path=str(out_dir / "40-workbench-findings-lens.png"),
                            full_page=False)
        except Exception as exc:
            print(f"    findings lens click failed: {exc}")

        # IOC lens.
        try:
            page.click("button[data-lens='ioc']", timeout=3_000)
            time.sleep(1.5)
            page.screenshot(path=str(out_dir / "41-workbench-ioc-lens.png"),
                            full_page=False)
        except Exception as exc:
            print(f"    IOC lens click failed: {exc}")

        # ATT&CK lens (real, marlinspike-mitre output).
        try:
            page.click("button[data-lens='attck']", timeout=3_000)
            time.sleep(1.5)
            page.screenshot(path=str(out_dir / "48-workbench-attck-lens.png"),
                            full_page=False)
        except Exception as exc:
            print(f"    ATT&CK lens click failed: {exc}")

        # Baseline lens (per-asset novelty, async fetches).
        try:
            page.click("button[data-lens='baseline']", timeout=3_000)
            time.sleep(3.0)  # allow baseline fetches to land
            page.screenshot(path=str(out_dir / "49-workbench-baseline-lens.png"),
                            full_page=False)
        except Exception as exc:
            print(f"    Baseline lens click failed: {exc}")

        # Peers lens (role/vendor/Purdue grouping + anomalous-by-context).
        try:
            page.click("button[data-lens='peers']", timeout=3_000)
            time.sleep(1.5)
            page.screenshot(path=str(out_dir / "50-workbench-peers-lens.png"),
                            full_page=False)
        except Exception as exc:
            print(f"    Peers lens click failed: {exc}")

        # Return to Comms lens.
        try:
            page.click("button[data-lens='comms']", timeout=3_000)
            time.sleep(1.5)
        except Exception:
            pass

        # Bottom drawer — open it and screenshot Findings tab.
        try:
            page.click("#ms-drawer-handle", timeout=3_000)
            time.sleep(1.0)
            page.screenshot(path=str(out_dir / "42-workbench-drawer-findings.png"),
                            full_page=False)
        except Exception as exc:
            print(f"    drawer open failed: {exc}")

        # Drawer — Conversations tab.
        try:
            page.click(".ms-drawer-tab[data-tab='conversations']", timeout=3_000)
            time.sleep(1.0)
            page.screenshot(path=str(out_dir / "43-workbench-drawer-conversations.png"),
                            full_page=False)
        except Exception as exc:
            print(f"    conversations tab failed: {exc}")

        # Drawer — Assets tab.
        try:
            page.click(".ms-drawer-tab[data-tab='assets']", timeout=3_000)
            time.sleep(1.0)
            page.screenshot(path=str(out_dir / "44-workbench-drawer-assets.png"),
                            full_page=False)
        except Exception as exc:
            print(f"    assets tab failed: {exc}")

        # Close drawer.
        try:
            page.click("#ms-drawer-handle", timeout=3_000)
            time.sleep(0.5)
        except Exception:
            pass

        # Node selected with drawer open — map + inspector + drawer all visible.
        try:
            page.evaluate("""
              () => {
                const node = document.querySelector('#ms-svg-container g circle');
                if (node) node.dispatchEvent(new MouseEvent('click', {bubbles: true}));
              }
            """)
            time.sleep(1.0)
            page.screenshot(path=str(out_dir / "45-workbench-selected-asset.png"),
                            full_page=False)
        except Exception as exc:
            print(f"    selected-asset click failed: {exc}")

        # Time-scrubber drag on the timeline bar row.
        try:
            histo = page.query_selector("#ms-timeline-canvas")
            if histo is not None:
                box = histo.bounding_box()
                if box:
                    x1 = box["x"] + box["width"] * 0.30
                    y_mid = box["y"] + box["height"] / 2
                    x2 = box["x"] + box["width"] * 0.55
                    page.mouse.move(x1, y_mid)
                    page.mouse.down()
                    page.mouse.move(x2, y_mid, steps=18)
                    page.mouse.up()
                    time.sleep(1.5)
                    page.screenshot(path=str(out_dir / "47-time-scrubber-window.png"),
                                    full_page=False)
                    print("    time-scrubber drag captured")
                else:
                    print("    timeline element had no bounding box")
            else:
                print("    timeline element not found (timeline may be hidden if no data)")
        except Exception as exc:
            print(f"    time-scrubber drag failed: {exc}")

        # ── per-asset baseline page ─────────────────────────
        # The seeded asset 10.0.0.5 might not exist in this report. Use whichever
        # asset_key the report actually contains.
        try:
            print("  → per-asset baseline")
            # Pick any asset_key from the report itself.
            import json
            rpt = json.loads((SCRATCH_DATA / "reports" / str(admin_id) / str(project_id)
                              / primary_report).read_text())
            nodes = rpt.get("nodes") or []
            asset_key = None
            for n in nodes:
                ak = n.get("mac") or n.get("ip")
                if ak:
                    asset_key = ak
                    break
            if asset_key:
                page.goto(f"http://127.0.0.1:5901/projects/{project_id}/assets/{asset_key}")
                try:
                    page.wait_for_load_state("networkidle", timeout=10_000)
                except Exception:
                    pass
                time.sleep(2.0)
                page.screenshot(path=str(out_dir / "44-asset-baseline.png"),
                                full_page=True)
                print(f"    used asset_key {asset_key}")
        except Exception as exc:
            print(f"    baseline page failed: {exc}")

        browser.close()

    print("done.")


if __name__ == "__main__":
    main()
