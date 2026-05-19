# Operations — Bluesky-Account-Role

Operational runbook for the Bluesky-Account-Role plugin. Mirrors the runbook
shape used by the other RoleLogic plugins so on-call playbooks transfer.

## Service map

- **Plugin app**: Rust HTTP server on port `8095`, path `/bluesky-account-role/*`.
- **Postgres**: one DB per plugin (`bluesky_account_role`), schema applied
  by `db::run_migrations` on startup. Migrations are idempotent.
- **Auth Gateway**: shared service at `${AUTH_GATEWAY_URL}/auth/*`. Plugins
  call `/auth/internal/*` server-to-server with `X-Internal-Key`.
- **Bluesky XRPC**: public AT Protocol API. Default host `https://bsky.social`
  for session/session-refresh and `https://public.api.bsky.app` for unauth
  reads. Per-user PDS is discovered from their handle's DID document.

## Critical env vars

`POSTGRES_PASSWORD`, `SESSION_SECRET`, `BASE_URL`, `INTERNAL_API_KEY`,
`AUTH_GATEWAY_URL`. Missing any of these is a hard panic at startup —
prefer that over a silently broken deploy.

`SESSION_SECRET` is *both* the HMAC key for session/iframe tokens *and* the
HKDF input that derives the KEK used to encrypt stored Bluesky session JWTs
at rest. Rotating it requires re-encrypting every row in `bsky_accounts`.

## Migrations

- Files in `migrations/` are wired into `src/db.rs` (`run_migrations`).
  Adding a file alone does nothing — register it in the slice.
- All migrations follow expand → contract: add columns/indexes additively,
  ship the code that uses them, then drop the old shape in a follow-up.
- Run-only mode: `bluesky-account-role migrate` applies migrations and exits.
  Suitable for a pre-deploy job step ahead of swapping replicas.

## Background workers

| Worker | Cadence | Job kinds | Purpose |
| --- | --- | --- | --- |
| `job_worker` (N) | event-driven | `player_sync`, `config_sync`, `account_sync` | All single-target sync work; claimed with `FOR UPDATE SKIP LOCKED` |
| `job_listener` | n/a | n/a | `LISTEN jobs_pending`; wakes workers within ~ms of enqueue |
| `reconcile` | every 6h | refresh broadcaster facts (followers, lists, starter packs) + GC | Safety net for the "no webhooks on Bluesky" reality |

## Rate limits

The AT Protocol's public XRPC has rate limits (broadly ~3000 requests per
5 minutes per IP, varies by endpoint). The reconcile worker paginates with
small sleeps between cursors; per-viewer lookups go through the broadcaster's
authenticated session, which has its own per-account budget. If you start
seeing 429s the symptom is `bsky` log warnings of "rate limited (will retry)"
and a back-off applied to job retries.

## Troubleshooting

**"Plugin shows 'RoleLogic didn't pass an authentication token'"** —
`BASE_URL` doesn't exactly match the plugin URL registered in RoleLogic. The
iframe page validates JWT `aud` against `BASE_URL`; a path-prefix or
trailing-slash mismatch fails verification.

**"Members link Bluesky but the role doesn't apply"** — almost always one of:
1. No broadcaster connected for the role link's guild yet.
2. Rule references channel facts (followers, list membership, etc.) but no
   broadcaster account is bound to the role — Convention 42 grants to nobody.
3. The Bluesky session for the broadcaster expired and refresh failed; check
   `bsky_accounts.refresh_failed_at` and re-connect through the iframe.

**"Followers / list members are stale"** — reconcile runs every 6 hours. To
force a refresh: enqueue a `bsky_account_sync` job via SQL or restart the
service (reconcile runs ~90s after boot).

**"Stuck `in_progress` jobs"** — the worker's reap loop releases them after
45 minutes. To clear sooner:
```sql
UPDATE jobs SET status='pending', next_run_at=now(),
  locked_by=NULL, locked_at=NULL
WHERE status='in_progress' AND locked_at < now() - interval '5 minutes';
```

## Capacity

- App pod: 30–50MB RAM at idle, scales linearly with worker count.
- DB pool sizing: replicas × `DB_MAX_CONNECTIONS` ≤ Postgres `max_connections`.
- Bluesky API is the bottleneck before the DB at every scale we've measured.
