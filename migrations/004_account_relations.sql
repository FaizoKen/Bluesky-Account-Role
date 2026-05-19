-- Account_relations: the denormalized facts table that every rule
-- evaluation reads from. One row per (broadcaster bsky account, viewer) pair.
--
-- Every condition target that filters via SQL has its own column here so
-- `build_rule_where` can emit straight `WHERE ar.is_follower` predicates
-- instead of JSONB extraction.
--
-- Rows are created/updated by:
--   * reconcile worker — refreshes follower lists, list memberships,
--     starter pack memberships, engagement counts from the broadcaster's
--     authenticated session
--   * player_sync_worker on demand when a viewer's role eligibility is
--     reevaluated (creates a baseline row if missing so the user shows up
--     on the public users-list page even with no relation)
--
-- A row may exist with all-false / all-zero columns if the viewer is known
-- (linked) but has no relationship to the account yet — that's the
-- "no relation" state, distinct from "row missing" (= never evaluated).

CREATE TABLE IF NOT EXISTS account_relations (
    bsky_account_did        TEXT NOT NULL REFERENCES bsky_accounts (did) ON DELETE CASCADE,
    viewer_did              TEXT NOT NULL,

    -- Follow graph
    is_follower             BOOLEAN NOT NULL DEFAULT FALSE,
    followed_at             TIMESTAMPTZ,
    is_followed_back        BOOLEAN NOT NULL DEFAULT FALSE,

    -- Engagement counters (per broadcaster). Refreshed by reconcile when
    -- list-engagement endpoints are available; bumped on demand from on-the-
    -- fly per-post lookups.
    liked_posts_count       INTEGER NOT NULL DEFAULT 0,
    reposted_posts_count    INTEGER NOT NULL DEFAULT 0,
    replied_posts_count     INTEGER NOT NULL DEFAULT 0,

    last_seen_at            TIMESTAMPTZ,
    last_synced_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (bsky_account_did, viewer_did)
);

-- Reverse lookup: when a viewer's link is updated, we re-evaluate every
-- account they're known to.
CREATE INDEX IF NOT EXISTS idx_account_relations_viewer
    ON account_relations (viewer_did);

-- Partial indexes for hot booleans. The bulk-sync SQL is shape
-- `WHERE ar.bsky_account_did = $1 AND ar.is_follower [AND …]`, so
-- per-account filters scoped to the hot boolean are the right shape.
CREATE INDEX IF NOT EXISTS idx_account_relations_followers
    ON account_relations (bsky_account_did)
    WHERE is_follower;
CREATE INDEX IF NOT EXISTS idx_account_relations_followed_back
    ON account_relations (bsky_account_did)
    WHERE is_followed_back;
