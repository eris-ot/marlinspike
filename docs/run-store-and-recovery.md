# Run store and mid-scan recovery

> **Audience:** operators running marlinspike (standalone or wrapped).
> **TL;DR:** scans no longer get stuck in `running` after a Flask
> restart. The engine subprocess survives parent-process death;
> marlinspike now persists enough to find it again on the next boot.

## What problem this solves

Before v3.4.0, marlinspike tracked in-flight scans entirely in a
process-local Python dictionary (`_run_registry`). When the Flask
process died — deploy, OOM, container restart, host reboot — that
dictionary evaporated.

The engine subprocess, however, was reparented to `init` / `launchd`
and usually ran to completion, writing its report file as if
nothing happened. But `scan_history.status` stayed `'running'`
forever, the user saw a stalled scan in the UI, and the only
recovery was a manual SQL update.

v3.4.0 closes this gap.

## How it works

Two new modules:

- `marlinspike/run_store.py` — persists the **recovery essentials**
  on `scan_history`: the engine PID, the engine argv (for PID-reuse
  defense), and a timeout deadline. Writes happen inline at scan
  launch and at scan completion.

- `marlinspike/recovery.py` — runs **once on every `create_app()`
  boot**. Walks `scan_history WHERE status='running'` and reconciles
  each row.

### The four reconciliation outcomes

For each in-flight row found at boot:

| Outcome | When | Result |
|---|---|---|
| **reattached** | PID alive AND argv matches | Watcher thread polls until engine exits, then ingests the report |
| **reaped_completed** | PID dead, report file is complete | Ingests `node_count` / `edge_count`, marks `completed` |
| **reaped_failed** | PID dead, report missing or partial | Marks `failed` with diagnostic `error_tail` |
| **reaped_abandoned** | `timeout_at` is in the past | Marks `failed` with abandonment reason |

The `recovery_state` column on `scan_history` records which path the
row took, so you can audit how many of your runs are completing
normally vs. being recovered.

### PID-reuse defense

A bare `os.kill(pid, 0)` check is unsafe — the kernel recycles PIDs.
A short-lived shell can land on the PID our long-running engine had,
and a naive liveness probe would silently re-attach to the wrong
process.

`recovery.pid_argv_matches()` reads the live process's argv:

- **Linux:** `/proc/<pid>/cmdline`
- **macOS:** `ps -p <pid> -o command=`

It compares against the `engine_argv` we saved at scan launch. If
the live process is not the same Python+marlinspike invocation, we
treat the original engine as dead.

## Schema additions

`scan_history` gains four nullable columns (created automatically
by `db.create_all()` on first boot — no Alembic migration needed):

| Column | Type | Purpose |
|---|---|---|
| `engine_pid` | `INTEGER` | PID of the engine subprocess |
| `engine_argv` | `TEXT` | JSON-encoded argv list (PID-reuse defense) |
| `timeout_at` | `TIMESTAMP` | Hard deadline for abandonment reaping |
| `recovery_state` | `VARCHAR(20)` | NULL / `reattached` / `reaped_completed` / `reaped_failed` / `reaped_abandoned` |
| `pcap_path` | `TEXT` | Absolute PCAP path (so retries can re-launch) |

All five are nullable. Existing rows are unaffected; new rows
populate them at scan launch.

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `MARLINSPIKE_RUN_STORE` | `memory` | `memory` (legacy in-process) or `db` (cross-worker concurrency check via `scan_history`) |
| `MARLINSPIKE_SCAN_TIMEOUT_S` | `3600` | Default per-scan deadline. Reaper marks past-deadline rows as abandoned. |

### When to set `MARLINSPIKE_RUN_STORE=db`

If you run more than one Gunicorn worker, set this. The default
`memory` mode keeps the legacy `_run_registry` in-process, which
means worker A doesn't see worker B's runs — per-tier concurrency
silently breaks (a user can run `tier_limit × num_workers` scans),
and `/api/runs/<id>/status` returns 404 when the LB hits a
different worker than the one that started the scan.

In `db` mode, the concurrency check and run lookup both query
`scan_history` directly — Postgres becomes the source of truth.

## Operator FAQ

### How do I tell if a scan was recovered vs. completed normally?

```sql
SELECT recovery_state, count(*)
  FROM scan_history
 WHERE recovery_state IS NOT NULL
 GROUP BY recovery_state;
```

`NULL` means the run completed under its original Flask process.
Anything non-NULL was reaped or re-attached on a subsequent boot.

### What happens to live stdout output for re-attached runs?

Lost. The original Popen pipes were closed when Flask died. The
re-attached watcher only knows the engine PID and report path —
it can mark the run completed/failed but can't replay output.
Acceptable trade-off: completion status is what matters, not
the live tail.

### Does this work for chunked scans (large PCAPs)?

Partial. Chunked scans spawn multiple subprocesses sequentially
(editcap, then per-chunk dissect, then merged chain). `run_store.update_pid()`
is called at each spawn, so recovery sees the **currently-running
child**. If the chunked supervisor itself crashes between children,
the row will be reaped as `failed` with the appropriate `error_tail`.

### How long is the recovery probe loop?

Two seconds. A re-attached watcher polls PID liveness every 2s.
Reasonable trade-off between responsiveness and wakeups for an
operation that runs for minutes.

### Can I disable the reaper?

Not directly. If the boot reconciliation step is causing problems,
delete or set `status='failed'` on the offending `scan_history`
rows manually before restart.

## Testing your deployment

After upgrading, verify the reaper works:

```bash
# 1. Start a long-running scan via the UI.
# 2. Find the engine PID:
ps aux | grep "python.*-m marlinspike --pcap"
# 3. Kill Flask only (NOT the engine):
sudo systemctl restart marlinspike   # or: docker restart marlinspike-web
# 4. Watch the logs on restart:
journalctl -u marlinspike -f | grep recovery
#    Expected: "recovery: 1 scan(s) left running from previous boot"
#              "recovery: re-attached watcher to live engine pid=NNN ..."
# 5. The scan should complete normally and show in the report list.
```

If you see `recovery: reaped failed run` instead of `re-attached`,
the engine subprocess died with the parent — usually because of a
container with `restart: always` that takes down everything in the
process group. Check that the engine is reparented to `init` (PID 1)
after Flask exits, not killed.

## Cross-references

- Cloudmarlin's per-tier concurrency hook depends on `_get_active_runs(user_id=...)`.
  Setting `MARLINSPIKE_RUN_STORE=db` is required for cloudmarlin's
  horizontal scaling story (otherwise the per-tier limit silently
  breaks across pods).
- The eventual ValkeyRunStore (sub-second polling, pubsub for SSE)
  builds on the same `run_store` interface and is planned for a
  later release.
