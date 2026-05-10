# Security Policy

## Past advisories

- **MS-2026-001 (v3.5.2, 2026-05-10) — Password reset account takeover.** The pre-v3.5.2 `/api/auth/reset-request` endpoint returned the generated reset token directly in the HTTP response. Anyone who knew a username could obtain a reset token without authentication and use it to take over the account via `/api/auth/reset-confirm`. **Severity: CRITICAL.** Fixed in v3.5.2 — token is never returned in the response; delivery configurable via `MARLINSPIKE_RESET_TOKEN_DELIVERY` (`disabled` by default, `file` writes to `data/instance/reset-tokens/<user>-<ts>.txt` mode 0600, `log` writes to server stderr). Cloudmarlin and other wrappers can override via `marlinspike.auth.set_reset_token_delivery(fn)`.
- **MS-2026-002 (v3.5.2, 2026-05-10) — Live capture exposed to non-admin users.** The pre-v3.5.2 capture session start/stop endpoints required only `@login_required`. Live capture drives a privileged sidecar (`capd`) holding `CAP_NET_RAW` — granting capture-start to a low-privilege account effectively gave raw-socket access on the engagement network. **Severity: HIGH.** Fixed in v3.5.2 — capture session control gated to `MARLINSPIKE_CAPTURE_REQUIRE=admin` by default. `=any` opts back into the legacy behaviour for deployments where it's known-safe.
- **MS-2026-003 (v3.5.2, 2026-05-10) — Sub-PCAP extraction fail-open.** The pre-v3.5.2 `/api/reports/<filename>/extract` endpoint fell back to the original PCAP if `tshark` or `editcap` failed. A "give me just this slice" request that the filter stage couldn't satisfy returned the entire capture. **Severity: HIGH.** Fixed in v3.5.2 — extraction fails closed; any stage failure returns HTTP 500 with no PCAP body.
- **MS-2026-004 (v3.5.2, 2026-05-10) — Default DATABASE_URL with predictable credentials.** Pre-v3.5.2 shipped a default `DATABASE_URL=postgresql://marlinspike:marlinspike@localhost:5432/marlinspike`. **Severity: HIGH.** Fixed in v3.5.2 — `create_app()` refuses to start without `DATABASE_URL` set explicitly. Test/dev escape hatch: `MARLINSPIKE_ALLOW_NO_DATABASE_URL=true`.
- **MS-2026-005 (v3.5.2, 2026-05-10) — Silent ephemeral SECRET_KEY.** Pre-v3.5.2 generated a random `SECRET_KEY` if none was set, with only a stdout warning. Sessions invalidated on every restart and there was no operator-controlled rotation. **Severity: HIGH.** Fixed in v3.5.2 — `create_app()` refuses to start without `SECRET_KEY` set. Dev escape hatch: `MARLINSPIKE_ALLOW_GENERATED_SECRET=true`.
- **MS-2026-006 (v3.5.2, 2026-05-10) — CSRF check hostname-only.** Pre-v3.5.2 compared only the hostname portion of `Origin`/`Referer` headers, allowing same-host different-port and mixed-scheme requests to pass. **Severity: MEDIUM.** Fixed in v3.5.2 — full-origin comparison (scheme + host + port). Allowlist of additional origins via `MARLINSPIKE_ALLOWED_ORIGINS`.
- **MS-2026-007 (v3.5.2, 2026-05-10) — Admin password to stdout on first run.** Pre-v3.5.2 printed the generated bootstrap admin password to stdout, which container/journald logs typically persist. **Severity: MEDIUM.** Fixed in v3.5.2 — written to `data/instance/admin-bootstrap-password.txt` (mode 0600) instead.
- **MS-2026-008 (v3.5.2, 2026-05-10) — Missing browser security headers.** Pre-v3.5.2 templates carried `nonce="{{ csp_nonce }}"` markers but no code generated the nonce or emitted a CSP header. **Severity: MEDIUM.** Fixed in v3.5.2 — per-request nonce generation, full CSP with `frame-ancestors 'none'` + `object-src 'none'`, plus `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy` lockdown, and HSTS when `SESSION_COOKIE_SECURE`.
- **MS-2026-009 (v3.5.2, 2026-05-10) — `SESSION_COOKIE_SECURE` defaulted to False.** Pre-v3.5.2 cookies were sent over plain HTTP by default. **Severity: MEDIUM.** Fixed in v3.5.2 — defaults to True. Dev opt-out: `MARLINSPIKE_DEV_INSECURE_COOKIES=true`.

## CSRF token model (v3.5.4)

MarlinSpike v3.5.4 added a proper per-session CSRF token as the **primary** defense against cross-site request forgery. The origin/referer check from v3.5.2 (MS-2026-006) is retained as defense-in-depth.

**Token lifecycle:**

| Event | Action |
|---|---|
| First state-changing request (or `csrf_token()` called in a template) | 32-byte URL-safe token minted via `secrets.token_urlsafe(32)`, stored in `session['_csrf']` |
| Subsequent requests in the same session | Same token returned (idempotent) |
| Successful login (`/login` POST) | `rotate_csrf()` drops `session['_csrf']`; next access mints a fresh token |
| Session cleared (logout) | Token destroyed with the session |

**Validation (v3.5.4):** `before_request` in `create_app()` (app.py, `csrf_check` function, ~line 2955) enforces for POST/PUT/DELETE/PATCH:

1. If the view is decorated with `@csrf_exempt` — skip all checks.
2. Read `X-CSRF-Token` header (all content types) or `_csrf` form field (`multipart/form-data`).
3. Validate with `validate_csrf()` in `marlinspike/csrf.py` — uses `secrets.compare_digest` (constant-time).
4. If valid → allow. If invalid or absent → fall back to origin/referer check (v3.5.2 logic, unchanged).
5. If both fail → 403 JSON `{"error": "CSRF token missing or invalid"}`.

**Jinja context:** `csrf_token()` is a callable injected into every template context via the `inject_csrf_token` context processor. Use as:

```jinja
<meta name="csrf-token" content="{{ csrf_token() }}">
<input type="hidden" name="_csrf" value="{{ csrf_token() }}">
```

**JS integration:** `base.html` monkey-patches `window.fetch` to automatically set `X-CSRF-Token` on every non-GET/HEAD/OPTIONS request using the value in `<meta name="csrf-token">`. All existing JS fetch call sites gain CSRF protection without modification.

**Login exemption:** `/login` is `@csrf_exempt` because no session token exists before login. The endpoint is protected by `flask-limiter` (5 req/min). A CSRF on login at most logs the attacker into their own account.

**Origin check (belt-and-suspenders):** The v3.5.2 full-origin comparison (scheme + host + port) remains active. A request that passes *either* the token check or the origin check is allowed. Both must fail to get a 403.

## Tracked for v3.5.5+

These are flagged but not yet shipped:
- Password-change endpoint audit logging + rate limiting.
- Live capture per-project capture policy + interface allowlist.
- Schema migrations: ad-hoc `ALTER TABLE` in `create_app()` → proper Alembic.
- Splitting `app.py` (~5800 LOC, 86 routes) and `engine.py` (~5800 LOC) into per-domain modules.
- Removing remaining inline `style="..."` and `onclick="..."` attributes from templates so `'unsafe-inline'` can be dropped from CSP.

## Reporting a vulnerability

MarlinSpike is a passive OT/ICS analysis tool deployed by defenders on
engagement networks. Vulnerabilities here can put real engagement
networks and the captures collected from them at risk. This document
is the policy for reporting them.

## Reporting a vulnerability

Email **erisforge@erisforge.com** with the subject line beginning
`[security]`. Encrypt sensitive details with the ERISFORGE Ltd. GPG
key:

```
8C4879D492DE808D52D2C3F02CBC9B8E1FBAF06C
ERISFORGE Ltd. (a Rwanda Corp) <erisforge@erisforge.com>
```

Fetch with `gpg --recv-keys 2CBC9B8E1FBAF06C`.

What to include:

- The MarlinSpike version (`marlinspike --version` or
  `import marlinspike; marlinspike.__version__`).
- A clear description of the vulnerability and its impact.
- Reproduction steps. A minimal PCAP / config that triggers the issue
  is gold; if it contains anything sensitive, send the SHA-256 hash
  and we'll arrange secure transfer.
- Whether you've disclosed elsewhere (other vendors, CERT, public).
- Your preferred attribution in the eventual advisory.

## What to expect

| Step | Timeline |
|---|---|
| Acknowledgment of receipt | Within 72 hours |
| Triage + severity assessment | Within 7 days |
| Fix development + coordinated disclosure window negotiation | Typically 30-90 days, severity-dependent |
| Security advisory + patched release | At end of disclosure window |

We coordinate disclosure. We won't publicly disclose without giving
the reporter time to be credited; we won't sit on a critical issue
indefinitely. The default disclosure window is **90 days from initial
report**, extended for severe / complex issues by mutual agreement.

## Scope

In scope:

- The Python application package (`marlinspike/` — engine, web app,
  recovery, taxonomy, run store, plugins).
- The optional `marlinspike-capd` privileged sidecar.
- The Rust DPI engine (`marlinspike-dpi`, separate repository — link
  from there to here only if the issue affects integration).
- The published Docker images for the official tags.
- The plugin sidecars when running via auto-discovery
  (`plugins.marlinspike_{mitre,arp,apt}`).

Out of scope:

- Vulnerabilities in third-party dependencies that we don't control —
  please report those upstream first; if the issue is in *how
  MarlinSpike uses* a dependency, that is in scope.
- Self-hosted misconfigurations of MarlinSpike (e.g. running with
  `SECRET_KEY=""` or exposing the web UI to the public internet
  without auth) — not vulnerabilities, configuration errors. Cover
  these in [INSTALL.md](INSTALL.md) instead.
- Findings against `data/anon/` synthetic captures or example PCAPs
  in `presets/` — those are not adversary-controlled inputs.
- Findings that require local administrative access to the host
  running MarlinSpike — the threat model assumes local admin is
  trusted.

## Supported versions

| Version | Status | Receives security fixes |
|---|---|---|
| `3.5.x` | Current | Yes |
| `3.4.x` | Recent | Yes |
| `3.3.x` | Older | Yes (best-effort) |
| `3.0.x` – `3.2.x` | Superseded | No — please upgrade |
| `2.x` and earlier | Unsupported | No |

If you're running on an unsupported version, the first response will
likely be "please upgrade and reproduce". We cannot back-port fixes
indefinitely for a small team.

## Threat model summary

MarlinSpike's threat model assumes:

- The web app is served behind authentication (admin or per-user
  login). Anonymous-mode is opt-in via cloudmarlin and rate-limited.
- The host running MarlinSpike is administered by the same defender
  team that operates the tool. Local admin compromise is not in
  scope.
- PCAP uploads are user-controlled. The engine subprocess is treated
  as the trust boundary — any code path that runs *because* a PCAP
  triggered it is in scope. Memory-corruption-style bugs in the
  parser are in scope (we shell to `tshark` / Rust DPI).
- The engagement network the captures were collected from is
  potentially adversarial. We don't trust the contents of any PCAP.
- The capd sidecar runs with `CAP_NET_RAW` and is therefore the
  most-privileged component. The uds JSON-RPC between the web app
  and capd is the security boundary; bugs in capd's protocol parser
  or in `pcap_compile_nopcap` integration are in scope.

## Coordinated disclosure

For issues that affect multiple downstream consumers (cloudmarlin,
FATHOM, third-party deployments), we'll coordinate the disclosure
across affected parties before publishing the advisory. Please give us
notice of any other parties you've contacted.

## Hall of fame

After a fix ships, the security advisory at
`https://github.com/eris-ot/marlinspike/security/advisories` credits
the reporter (unless you ask us not to).

## What we do *not* offer

- No bug bounty program currently. Reports are welcomed and
  acknowledged in the advisory; there is no monetary reward.
- No SLA on response time beyond the 72-hour acknowledgment.
- No private security mailing list — reports go to the email above.

## See also

- [RELEASING.md](RELEASING.md) — how releases are signed, hashed, and
  archived. Verifying a release you downloaded.
- [docs/run-store-and-recovery.md](docs/run-store-and-recovery.md) —
  PID-reuse defense and the trust boundary at scan recovery time.
- [COMPATIBILITY.md](COMPATIBILITY.md) — stable-API surface that
  downstream wrappers depend on.
