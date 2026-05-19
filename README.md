# Bluesky-Account-Role

A RoleLogic plugin that grants Discord roles based on a member's relationship
to a Bluesky account — followers, mutuals, starter-pack members, list members,
post engagement, account properties (age, post count, follower count, custom
domain), and more.

Conditions compose as a **DNF rule tree** (OR of AND-groups), so admins can
express rules like *"(mutual follower) OR (on my starter pack) OR (follower
AND followed-for ≥30 days)"* without nesting.

Written in Rust (axum, sqlx, tokio). Stateless HTTP tier + N durable
job-polling workers + reconcile poller. Modeled after
[Kick-Channel-Role](../Kick-Channel-Role/), but tuned for AT Protocol /
Bluesky's data shape.

## Why is this richer than Kick-Channel-Role?

Bluesky exposes more relationship surface than a streaming channel, so this
plugin has **21 condition targets** (Kick has 15):

| Group | Targets |
| --- | --- |
| Follow graph | `is_follower`, `is_followed_back`, `is_mutual`, `follow_age_days` |
| Containers | `is_on_list`, `is_on_starter_pack` (pick from the broadcaster's own) |
| Engagement (per-broadcaster) | `liked_posts_count`, `reposted_posts_count`, `replied_posts_count` |
| Account properties | `account_age_days`, `posts_count`, `followers_count`, `follows_count`, `handle`, `handle_domain`, `has_custom_domain`, `display_name`, `description`, `has_avatar`, `has_banner`, `pds_host` |

Plus the same 11 operators (`eq`, `neq`, `gt`, `gte`, `lt`, `lte`, `between`,
`contains`, `regex`, `in`, `not_in`).

## Newbie-friendly defaults

The iframe role-config page leads with **one-click presets** before the
advanced rule builder:

- **Anyone who linked their Bluesky** — no Bluesky account needed; matches every linked member.
- **People who follow my Bluesky** — drops in `is_follower=true`.
- **Mutuals only** — `is_mutual=true`.
- **People on my starter pack** — picks the broadcaster's most recent starter pack.
- **Long-time followers** — `is_follower=true AND follow_age_days >= N` (admin sets N).
- **Advanced rule** — full DNF builder.

Member-side linking is **App Password** based (simpler than full OAuth for
non-technical users) — the member generates an app password at
<https://bsky.app/settings/app-passwords>, pastes their handle + that one
password into the verify page, and we discard the password after extracting
the DID. Their bio etc. is then fetched via the broadcaster's session.

## Quick start (local)

You need Docker. Postgres + the plugin start together in `compose.yml`.

```bash
cp .env.example .env
# Fill in: POSTGRES_PASSWORD, SESSION_SECRET, INTERNAL_API_KEY, BASE_URL.
# Suggested generators:
#   openssl rand -base64 24    # POSTGRES_PASSWORD
#   openssl rand -base64 48    # SESSION_SECRET
#   openssl rand -hex 32       # INTERNAL_API_KEY
docker compose up --build
```

Then visit `http://localhost:8095/bluesky-account-role/health` — should
return `{"status":"healthy"}`. Member verification lives at
`/bluesky-account-role/verify`; broadcaster connect happens inside the
iframe role-config page at `/admin/{guild_id}/role/{role_id}`.

The Auth Gateway it talks to (cookie minting, guild-membership lookup) is a
separate service. Point `AUTH_GATEWAY_URL` at it and share `INTERNAL_API_KEY`.

## Configuration

All config lives in env vars. See [`.env.example`](.env.example) for the
full list with comments. Required:

| Var | What |
| --- | --- |
| `DATABASE_URL` | `postgres://…` |
| `SESSION_SECRET` | HMAC key for `rl_session` + iframe-session + Bluesky-session-token KEK |
| `BASE_URL` | Public-facing plugin URL (https in prod, no trailing slash) |
| `INTERNAL_API_KEY` | Shared secret for plugin → Auth Gateway calls |
| `POSTGRES_PASSWORD` | Used by both the DB container and `DATABASE_URL` |

Optional but commonly set: `AUTH_GATEWAY_URL`, `ROLELOGIC_API_URL`,
`RL_DASHBOARD_ORIGIN`, `BSKY_DEFAULT_PDS`, `DB_MAX_CONNECTIONS`,
`WORKER_CONCURRENCY`.

## Repo layout

```
src/
  main.rs              # Router, middleware stack, worker spawn, signal handler
  config.rs            # AppConfig from env (incl. BskyConfig)
  db.rs                # Pool + migrations
  error.rs             # AppError + sqlx-error → HTTP-status classifier
  schema.rs            # RoleLogic iframe /config builder
  models/
    condition.rs       # ConditionTarget / Operator / TargetKind
    rule.rs            # RuleTree (DNF: OR of AND-groups)
    facts.rs           # POD (viewer × bsky-account) facts for evaluation
  routes/
    plugin.rs          # POST /register, GET/POST/DELETE /config
    admin.rs           # broadcaster CRUD + iframe role-config + save/preview
    verify.rs          # member-facing app-password verification
    users.rs           # public linked-users list + view-permission setting
    health.rs          # /health, /ready, /favicon.ico
  services/
    rolelogic.rs       # RoleLogic API client (PUT/POST/DELETE users)
    auth_gateway.rs    # Auth Gateway /auth/internal/* (sync workers)
    auth.rs            # cookie+manager / guild-permission helpers
    bsky.rs            # AT-Protocol XRPC client (sessions, profile, follow, lists, packs)
    crypto.rs          # HKDF + AES-256-GCM at-rest encryption (broadcaster JWTs)
    broadcaster_session.rs # decrypt → refresh → re-persist Bluesky access JWTs
    condition_eval.rs  # sync Rust rule evaluator
    rule_sql.rs        # SQL WHERE pushdown for bulk per-role-link sync
    rule_validator.rs  # save-time rule-tree validation
    jobs.rs            # durable queue (enqueue/claim/retry/DLQ/reap)
    sync.rs            # per-player / per-role-link / per-bsky-account sync
    session.rs         # rl_session cookie verify
    rl_token.rs        # rl_token JWT + iframe-session token
    csrf.rs            # Origin allowlist check
    security_headers.rs# CSP/HSTS/nosniff/Referrer-Policy middleware
  tasks/
    job_listener.rs    # LISTEN jobs_pending → wake workers
    job_worker.rs      # FOR UPDATE SKIP LOCKED dispatch loop
    reconcile.rs       # periodic refresh of followers / lists / starter packs
    shutdown.rs        # tokio broadcast-based shutdown
migrations/            # 001–…, applied in numeric order on startup
templates/             # iframe rule builder, verify, users list, link-done
```

## Development

```bash
cargo build               # debug build
cargo check               # type-check only
cargo test                # all unit tests
cargo clippy --no-deps --all-targets -- -D warnings
cargo fmt --all --check
docker compose up --build # full local stack
```
