-- A Bluesky account can be connected by multiple guilds (each via its own
-- consent). `bsky_accounts` rows are globally keyed by DID; this join table
-- records which guilds have opted into using that account.
--
-- Disconnect-from-a-guild only DELETEs the join row. The `bsky_accounts` row
-- (with its session JWTs) survives as long as at least one other guild is
-- still using it. When the last guild disconnects, a cleanup task can GC
-- the orphaned account.

CREATE TABLE IF NOT EXISTS guild_bsky_accounts (
    guild_id                TEXT NOT NULL,
    bsky_account_did        TEXT NOT NULL REFERENCES bsky_accounts (did) ON DELETE CASCADE,
    connected_by_discord_id TEXT,
    connected_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (guild_id, bsky_account_did)
);

CREATE INDEX IF NOT EXISTS idx_guild_bsky_accounts_guild
    ON guild_bsky_accounts (guild_id);
