//! Reconcile worker. Every 6h, for each connected Bluesky account: refresh
//! the profile, the follower set, the lists + memberships, and the starter
//! packs + memberships, then fan out an account_sync so role assignments
//! converge. Bluesky has no public webhook channel for the data we care
//! about, so this is the only source of truth-refresh for derived facts.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use crate::error::AppError;
use crate::services::broadcaster_session::valid_access_jwt;
use crate::services::bsky::{self, BskyClient};
use crate::services::jobs;
use crate::tasks::shutdown::ShutdownGuard;
use crate::AppState;

const TICK: Duration = Duration::from_secs(6 * 60 * 60);
const INITIAL_DELAY: Duration = Duration::from_secs(90);
/// Cap follower list per account per reconcile. 50k is plenty for typical
/// communities; very-large accounts can raise this in a follow-up.
const MAX_FOLLOWERS_PER_ACCOUNT: usize = 50_000;
/// Cap list-member fetch per list (same reasoning).
const MAX_MEMBERS_PER_LIST: usize = 25_000;

pub async fn run(state: Arc<AppState>, mut shutdown: ShutdownGuard) {
    tracing::info!("Reconcile worker started");

    tokio::select! {
        _ = tokio::time::sleep(INITIAL_DELAY) => {}
        _ = shutdown.wait() => return,
    }

    let mut interval = tokio::time::interval(TICK);
    loop {
        let dids: Vec<String> = sqlx::query_scalar("SELECT did FROM bsky_accounts")
            .fetch_all(&state.pool)
            .await
            .unwrap_or_default();

        for did in dids {
            if shutdown.is_triggered() {
                break;
            }
            if let Err(e) = refresh_account(&state, &did).await {
                tracing::warn!(did = %did, "reconcile failed: {e}");
            } else if let Err(e) = jobs::enqueue_account_sync(&state.pool, &did).await {
                tracing::warn!(did = %did, "enqueue post-reconcile account_sync: {e}");
            }
        }

        tokio::select! {
            _ = interval.tick() => {}
            _ = shutdown.wait() => break,
        }
    }

    tracing::info!("Reconcile worker stopped");
}

/// Pull fresh state for a single connected Bluesky account.
///
/// Takes `&AppState` rather than `&Arc<AppState>` so the per-job worker
/// (which holds only a borrowed `&AppState` inside `dispatch`) can call it
/// directly. The reconcile loop above passes `&*state` via auto-deref.
pub async fn refresh_account(state: &AppState, did: &str) -> Result<(), AppError> {
    let client = BskyClient::new(&state.config.bsky.default_pds);
    let token = valid_access_jwt(state, &client, did).await?;

    // 1. Profile (counts, display_name, etc.)
    if let Ok(p) = client.get_profile_authed(&token, did).await {
        let created_at = p
            .created_at
            .as_deref()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&chrono::Utc));
        let _ = sqlx::query(
            "UPDATE bsky_accounts SET \
                handle = $2, display_name = $3, description = $4, \
                has_avatar = $5, has_banner = $6, \
                followers_count = $7, follows_count = $8, posts_count = $9, \
                bsky_created_at = COALESCE($10, bsky_created_at), \
                last_synced_at = now(), updated_at = now() \
             WHERE did = $1",
        )
        .bind(did)
        .bind(&p.handle)
        .bind(p.display_name.as_deref())
        .bind(p.description.as_deref())
        .bind(p.avatar.is_some())
        .bind(p.banner.is_some())
        .bind(p.followers_count as i32)
        .bind(p.follows_count as i32)
        .bind(p.posts_count as i32)
        .bind(created_at)
        .execute(&state.pool)
        .await;
    }

    // 2. Followers — authoritative source for `is_follower`.
    let followers = match client
        .list_followers(&token, did, MAX_FOLLOWERS_PER_ACCOUNT)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(did, "list_followers failed: {e}");
            vec![]
        }
    };
    let follows = match client
        .list_follows(&token, did, MAX_FOLLOWERS_PER_ACCOUNT)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(did, "list_follows failed: {e}");
            vec![]
        }
    };

    let followers_set: HashSet<String> = followers.iter().map(|a| a.did.clone()).collect();
    let follows_set: HashSet<String> = follows.iter().map(|a| a.did.clone()).collect();

    // Reset the two booleans for this account, then rewrite via SQL.
    let mut tx = state.pool.begin().await?;
    sqlx::query(
        "UPDATE account_relations SET is_follower = false, is_followed_back = false \
         WHERE bsky_account_did = $1",
    )
    .bind(did)
    .execute(&mut *tx)
    .await?;
    // Ensure rows exist for everyone we're about to mark.
    let union: HashSet<&str> = followers_set
        .iter()
        .chain(follows_set.iter())
        .map(|s| s.as_str())
        .collect();
    for v in &union {
        sqlx::query(
            "INSERT INTO account_relations (bsky_account_did, viewer_did) \
             VALUES ($1, $2) ON CONFLICT DO NOTHING",
        )
        .bind(did)
        .bind(v)
        .execute(&mut *tx)
        .await?;
    }
    if !followers_set.is_empty() {
        let v: Vec<&str> = followers_set.iter().map(|s| s.as_str()).collect();
        sqlx::query(
            "UPDATE account_relations SET is_follower = true, \
                 followed_at = COALESCE(followed_at, now()), \
                 last_synced_at = now() \
             WHERE bsky_account_did = $1 AND viewer_did = ANY($2::text[])",
        )
        .bind(did)
        .bind(&v)
        .execute(&mut *tx)
        .await?;
    }
    if !follows_set.is_empty() {
        let v: Vec<&str> = follows_set.iter().map(|s| s.as_str()).collect();
        sqlx::query(
            "UPDATE account_relations SET is_followed_back = true, last_synced_at = now() \
             WHERE bsky_account_did = $1 AND viewer_did = ANY($2::text[])",
        )
        .bind(did)
        .bind(&v)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;

    // 3. Lists + memberships.
    if let Ok(lists) = client.list_user_lists(&token, did).await {
        // Upsert list rows.
        let live_uris: HashSet<String> = lists.iter().map(|l| l.uri.clone()).collect();
        for l in &lists {
            let _ = sqlx::query(
                "INSERT INTO bsky_lists (list_uri, owner_did, name, description, purpose, updated_at) \
                 VALUES ($1,$2,$3,$4,$5, now()) \
                 ON CONFLICT (list_uri) DO UPDATE SET \
                     name = EXCLUDED.name, description = EXCLUDED.description, \
                     purpose = EXCLUDED.purpose, updated_at = now()",
            )
            .bind(&l.uri)
            .bind(did)
            .bind(&l.name)
            .bind(l.description.as_deref())
            .bind(l.purpose.as_deref())
            .execute(&state.pool)
            .await;
        }
        // GC lists the user has deleted upstream.
        let _ = sqlx::query(
            "DELETE FROM bsky_lists WHERE owner_did = $1 AND list_uri <> ALL($2::text[])",
        )
        .bind(did)
        .bind(live_uris.iter().cloned().collect::<Vec<_>>())
        .execute(&state.pool)
        .await;

        // Refresh each list's members.
        for l in &lists {
            if let Ok(members) = client
                .list_members(&token, &l.uri, MAX_MEMBERS_PER_LIST)
                .await
            {
                let dids: Vec<String> = members.into_iter().map(|m| m.did).collect();
                refresh_list_members(state, &l.uri, &dids).await?;
            }
        }
    }

    // 4. Starter packs + memberships.
    if let Ok(packs) = client.list_starter_packs(&token, did).await {
        let live_uris: HashSet<String> = packs.iter().map(|p| p.uri.clone()).collect();
        for p in &packs {
            // Try to pull a name out of the record (lexicon: app.bsky.graph.starterpack).
            let name = p
                .record
                .as_ref()
                .and_then(|r| r.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("Starter pack")
                .to_string();
            let description = p
                .record
                .as_ref()
                .and_then(|r| r.get("description"))
                .and_then(|v| v.as_str())
                .map(String::from);
            let list_uri = p.list.as_ref().map(|l| l.uri.clone());
            let _ = sqlx::query(
                "INSERT INTO bsky_starter_packs (pack_uri, owner_did, name, description, list_uri, updated_at) \
                 VALUES ($1,$2,$3,$4,$5, now()) \
                 ON CONFLICT (pack_uri) DO UPDATE SET \
                     name = EXCLUDED.name, description = EXCLUDED.description, \
                     list_uri = EXCLUDED.list_uri, updated_at = now()",
            )
            .bind(&p.uri)
            .bind(did)
            .bind(&name)
            .bind(description.as_deref())
            .bind(list_uri.as_deref())
            .execute(&state.pool)
            .await;

            // Refresh members via the embedded list.
            if let Some(luri) = list_uri.as_deref() {
                if let Ok(members) = client
                    .list_members(&token, luri, MAX_MEMBERS_PER_LIST)
                    .await
                {
                    let dids: Vec<String> = members.into_iter().map(|m| m.did).collect();
                    refresh_starter_pack_members(state, &p.uri, &dids).await?;
                }
            }
        }
        let _ = sqlx::query(
            "DELETE FROM bsky_starter_packs WHERE owner_did = $1 AND pack_uri <> ALL($2::text[])",
        )
        .bind(did)
        .bind(live_uris.iter().cloned().collect::<Vec<_>>())
        .execute(&state.pool)
        .await;
    }

    // 5. Touch `last_synced_at`.
    let _ = sqlx::query(
        "UPDATE bsky_accounts SET last_synced_at = now(), updated_at = now() WHERE did = $1",
    )
    .bind(did)
    .execute(&state.pool)
    .await;

    // Silence unused-import warning for the bsky module facade in this file.
    let _ = bsky::PUBLIC_API_BASE;

    Ok(())
}

async fn refresh_list_members(
    state: &AppState,
    list_uri: &str,
    dids: &[String],
) -> Result<(), AppError> {
    let mut tx = state.pool.begin().await?;
    // Trivial truth-source replace: drop old, insert new.
    sqlx::query("DELETE FROM bsky_list_members WHERE list_uri = $1")
        .bind(list_uri)
        .execute(&mut *tx)
        .await?;
    if !dids.is_empty() {
        sqlx::query(
            "INSERT INTO bsky_list_members (list_uri, member_did) \
             SELECT $1, UNNEST($2::text[]) \
             ON CONFLICT DO NOTHING",
        )
        .bind(list_uri)
        .bind(dids)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

async fn refresh_starter_pack_members(
    state: &AppState,
    pack_uri: &str,
    dids: &[String],
) -> Result<(), AppError> {
    let mut tx = state.pool.begin().await?;
    sqlx::query("DELETE FROM bsky_starter_pack_members WHERE pack_uri = $1")
        .bind(pack_uri)
        .execute(&mut *tx)
        .await?;
    if !dids.is_empty() {
        sqlx::query(
            "INSERT INTO bsky_starter_pack_members (pack_uri, member_did) \
             SELECT $1, UNNEST($2::text[]) \
             ON CONFLICT DO NOTHING",
        )
        .bind(pack_uri)
        .bind(dids)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}
