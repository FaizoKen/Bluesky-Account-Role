-- Bsky_users: linked Discord ↔ Bluesky identity. Populated by the viewer
-- verification flow; one row per verified Discord member.
--
-- `did` is UNIQUE because a Bluesky account can be linked to at most one
-- Discord account at a time. Re-linking from a second Discord ID would raise
-- a unique-violation; the handler must explicitly DELETE the old row. This
-- prevents a "share-the-handle" exploit where one Bluesky account grants
-- a role to multiple Discord accounts.
--
-- All denormalized profile columns are refreshed on every successful link
-- and on reconcile. NULLs are tolerated for fields Bluesky doesn't populate
-- (e.g. account without a custom domain → handle_domain may be bsky.social).

CREATE TABLE IF NOT EXISTS bsky_users (
    discord_id          TEXT PRIMARY KEY,
    did                 TEXT UNIQUE NOT NULL,
    handle              TEXT NOT NULL,
    -- The portion of the handle after the first dot, e.g. "alice.bsky.social"
    -- → "bsky.social". Empty/null when handle has no dot (rare).
    handle_domain       TEXT,
    has_custom_domain   BOOLEAN NOT NULL DEFAULT FALSE,
    pds_host            TEXT,
    display_name        TEXT,
    description         TEXT,
    has_avatar          BOOLEAN NOT NULL DEFAULT FALSE,
    has_banner          BOOLEAN NOT NULL DEFAULT FALSE,
    posts_count         INTEGER NOT NULL DEFAULT 0,
    followers_count     INTEGER NOT NULL DEFAULT 0,
    follows_count       INTEGER NOT NULL DEFAULT 0,
    bsky_created_at     TIMESTAMPTZ,

    discord_name        TEXT,
    linked_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    refreshed_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_bsky_users_did ON bsky_users (did);
CREATE INDEX IF NOT EXISTS idx_bsky_users_handle ON bsky_users (lower(handle));
