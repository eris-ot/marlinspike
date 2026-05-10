# Security Policy

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
