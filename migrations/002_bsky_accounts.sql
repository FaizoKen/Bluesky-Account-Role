-- Bsky_accounts: one row per Bluesky account an admin has connected
-- ("broadcaster" in the Kick plugin's vocabulary). A single guild can connect
-- multiple accounts; a single account can be referenced by many role_links
-- across many guilds.
--
-- access_jwt_enc / refresh_jwt_enc are AES-256-GCM ciphertexts whose key is
-- HKDF-derived from SESSION_SECRET (see services/crypto.rs). Storing them
-- encrypted means a DB dump alone can't be used to impersonate the
-- broadcaster against Bluesky.
--
-- `handle` is the current handle (it can change; we re-fetch on each
-- reconcile and on session refresh). `pds_host` is the broadcaster's PDS
-- (almost always bsky.social today, but custom PDSes exist).
--
-- Profile properties (display_name, description, has_avatar, has_banner,
-- followers_count, follows_count, posts_count, created_at) are denormalized
-- here so the public users-list page and condition evaluator don't need a
-- per-call XRPC round-trip. They're refreshed on reconcile.

CREATE TABLE IF NOT EXISTS bsky_accounts (
    did                     TEXT PRIMARY KEY,
    handle                  TEXT NOT NULL,
    pds_host                TEXT NOT NULL DEFAULT 'https://bsky.social',
    display_name            TEXT,
    description             TEXT,
    has_avatar              BOOLEAN NOT NULL DEFAULT FALSE,
    has_banner              BOOLEAN NOT NULL DEFAULT FALSE,
    followers_count         INTEGER NOT NULL DEFAULT 0,
    follows_count           INTEGER NOT NULL DEFAULT 0,
    posts_count             INTEGER NOT NULL DEFAULT 0,
    bsky_created_at         TIMESTAMPTZ,

    -- Encrypted session JWTs. Refreshed via com.atproto.server.refreshSession.
    access_jwt_enc          BYTEA NOT NULL,
    refresh_jwt_enc         BYTEA NOT NULL,
    -- Access JWT expiry. We refresh on access if within ~5 minutes of it.
    token_expires_at        TIMESTAMPTZ NOT NULL,
    refresh_failed_at       TIMESTAMPTZ,

    last_synced_at          TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_bsky_accounts_handle
    ON bsky_accounts (lower(handle));
