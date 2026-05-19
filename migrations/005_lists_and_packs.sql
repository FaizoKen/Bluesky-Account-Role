-- Lists and starter packs owned by connected broadcasters, with their
-- memberships pre-computed so the rule engine can ask "is this DID on the
-- list at $1?" as a single index lookup.
--
-- We don't track every list on Bluesky — only the broadcasters' own. The
-- iframe rule builder lets admins pick from a dropdown populated by
-- `bsky_lists` / `bsky_starter_packs` scoped to the role link's bound
-- account.
--
-- Memberships are refreshed by the reconcile worker. A list / starter pack
-- whose owner DID matches a connected `bsky_accounts.did` will have its
-- members refreshed; orphans (broadcaster disconnect) cascade-delete.

CREATE TABLE IF NOT EXISTS bsky_lists (
    list_uri        TEXT PRIMARY KEY,
    owner_did       TEXT NOT NULL REFERENCES bsky_accounts (did) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    description     TEXT,
    -- "moderation" | "curatelist" | "referencelist" — different list purposes
    -- in atproto. Surface so admins know which kind they're picking.
    purpose         TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_bsky_lists_owner ON bsky_lists (owner_did);

CREATE TABLE IF NOT EXISTS bsky_list_members (
    list_uri        TEXT NOT NULL REFERENCES bsky_lists (list_uri) ON DELETE CASCADE,
    member_did      TEXT NOT NULL,
    added_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (list_uri, member_did)
);
CREATE INDEX IF NOT EXISTS idx_bsky_list_members_did
    ON bsky_list_members (member_did);

CREATE TABLE IF NOT EXISTS bsky_starter_packs (
    pack_uri        TEXT PRIMARY KEY,
    owner_did       TEXT NOT NULL REFERENCES bsky_accounts (did) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    description     TEXT,
    list_uri        TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_bsky_starter_packs_owner
    ON bsky_starter_packs (owner_did);

CREATE TABLE IF NOT EXISTS bsky_starter_pack_members (
    pack_uri        TEXT NOT NULL REFERENCES bsky_starter_packs (pack_uri) ON DELETE CASCADE,
    member_did      TEXT NOT NULL,
    added_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (pack_uri, member_did)
);
CREATE INDEX IF NOT EXISTS idx_bsky_starter_pack_members_did
    ON bsky_starter_pack_members (member_did);
