//! Sync engine — per-player (lightweight) and per-role-link (bulk).
//!
//! Dispatch targets for jobs claimed by [`crate::tasks::job_worker`].

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use futures_util::stream::{self, StreamExt};

use crate::error::AppError;
use crate::models::facts::Facts;
use crate::models::rule::RuleTree;
use crate::services::condition_eval::{self, Memberships};
use crate::services::rule_sql::{self, Bind};
use crate::services::{auth_gateway, jobs};
use crate::AppState;

#[derive(sqlx::FromRow)]
struct FactsRow {
    is_follower: bool,
    followed_at: Option<DateTime<Utc>>,
    is_followed_back: bool,
    liked_posts_count: i32,
    reposted_posts_count: i32,
    replied_posts_count: i32,
    viewer_did: String,
    handle: String,
    handle_domain: Option<String>,
    has_custom_domain: bool,
    pds_host: Option<String>,
    display_name: Option<String>,
    description: Option<String>,
    has_avatar: bool,
    has_banner: bool,
    posts_count: i32,
    followers_count: i32,
    follows_count: i32,
    bsky_created_at: Option<DateTime<Utc>>,
}

impl From<FactsRow> for Facts {
    fn from(r: FactsRow) -> Self {
        Facts {
            is_follower: r.is_follower,
            followed_at: r.followed_at,
            is_followed_back: r.is_followed_back,
            liked_posts_count: r.liked_posts_count as i64,
            reposted_posts_count: r.reposted_posts_count as i64,
            replied_posts_count: r.replied_posts_count as i64,
            handle: r.handle,
            handle_domain: r.handle_domain,
            has_custom_domain: r.has_custom_domain,
            display_name: r.display_name,
            description: r.description,
            has_avatar: r.has_avatar,
            has_banner: r.has_banner,
            posts_count: r.posts_count as i64,
            followers_count: r.followers_count as i64,
            follows_count: r.follows_count as i64,
            bsky_created_at: r.bsky_created_at,
            pds_host: r.pds_host,
        }
    }
}

const FACTS_SELECT: &str = "SELECT \
    COALESCE(ar.is_follower, false)        AS is_follower, \
    ar.followed_at                         AS followed_at, \
    COALESCE(ar.is_followed_back, false)   AS is_followed_back, \
    COALESCE(ar.liked_posts_count, 0)      AS liked_posts_count, \
    COALESCE(ar.reposted_posts_count, 0)   AS reposted_posts_count, \
    COALESCE(ar.replied_posts_count, 0)    AS replied_posts_count, \
    bu.did                                 AS viewer_did, \
    bu.handle                              AS handle, \
    bu.handle_domain                       AS handle_domain, \
    bu.has_custom_domain                   AS has_custom_domain, \
    bu.pds_host                            AS pds_host, \
    bu.display_name                        AS display_name, \
    bu.description                         AS description, \
    bu.has_avatar                          AS has_avatar, \
    bu.has_banner                          AS has_banner, \
    bu.posts_count                         AS posts_count, \
    bu.followers_count                     AS followers_count, \
    bu.follows_count                       AS follows_count, \
    bu.bsky_created_at                     AS bsky_created_at \
  FROM bsky_users bu \
  LEFT JOIN account_relations ar \
    ON ar.viewer_did = bu.did AND ar.bsky_account_did = $2 \
  WHERE bu.discord_id = $1";

// ---------------------------------------------------------------------------
// Baseline relation seeding
// ---------------------------------------------------------------------------

/// Insert an empty `account_relations` row for every (broadcaster connected
/// to one of `guild_ids`, this user) pair that doesn't already have one.
pub async fn ensure_baseline_relations(
    pool: &sqlx::PgPool,
    discord_id: &str,
    guild_ids: &[String],
) -> Result<(), AppError> {
    if guild_ids.is_empty() {
        return Ok(());
    }
    let did: Option<String> =
        sqlx::query_scalar("SELECT did FROM bsky_users WHERE discord_id = $1")
            .bind(discord_id)
            .fetch_optional(pool)
            .await?;
    let Some(viewer_did) = did else {
        return Ok(());
    };

    sqlx::query(
        "INSERT INTO account_relations (bsky_account_did, viewer_did) \
         SELECT gba.bsky_account_did, $1 \
         FROM guild_bsky_accounts gba \
         WHERE gba.guild_id = ANY($2) \
         ON CONFLICT (bsky_account_did, viewer_did) DO NOTHING",
    )
    .bind(&viewer_did)
    .bind(guild_ids)
    .execute(pool)
    .await?;

    Ok(())
}

/// Resolve which lists / starter packs a viewer DID is on, scoped to the
/// rule's bound broadcaster. Returns empty sets if `bsky_account_did` is None.
async fn load_memberships(
    pool: &sqlx::PgPool,
    bsky_account_did: Option<&str>,
    viewer_did: &str,
) -> Result<Memberships, AppError> {
    let mut m = Memberships::default();
    let Some(did) = bsky_account_did else {
        return Ok(m);
    };

    // Lists owned by this broadcaster, where this viewer is a member.
    let list_rows: Vec<(String,)> = sqlx::query_as(
        "SELECT lm.list_uri \
         FROM bsky_list_members lm \
         JOIN bsky_lists l ON l.list_uri = lm.list_uri \
         WHERE l.owner_did = $1 AND lm.member_did = $2",
    )
    .bind(did)
    .bind(viewer_did)
    .fetch_all(pool)
    .await?;
    for (uri,) in list_rows {
        m.list_uris.insert(uri);
    }

    let pack_rows: Vec<(String,)> = sqlx::query_as(
        "SELECT pm.pack_uri \
         FROM bsky_starter_pack_members pm \
         JOIN bsky_starter_packs p ON p.pack_uri = pm.pack_uri \
         WHERE p.owner_did = $1 AND pm.member_did = $2",
    )
    .bind(did)
    .bind(viewer_did)
    .fetch_all(pool)
    .await?;
    for (uri,) in pack_rows {
        m.starter_pack_uris.insert(uri);
    }
    Ok(m)
}

// ---------------------------------------------------------------------------
// Per-player sync
// ---------------------------------------------------------------------------

pub async fn sync_for_player(discord_id: &str, state: &AppState) -> Result<(), AppError> {
    let pool = &state.pool;
    let rl_client = &state.rl_client;

    let guild_ids = auth_gateway::fetch_user_guild_ids(
        &state.http,
        &state.config.auth_gateway_url,
        &state.config.internal_api_key,
        discord_id,
    )
    .await?;
    if guild_ids.is_empty() {
        return Ok(());
    }

    ensure_baseline_relations(pool, discord_id, &guild_ids).await?;

    let role_links =
        sqlx::query_as::<_, (String, String, String, Option<String>, serde_json::Value)>(
            "SELECT guild_id, role_id, api_token, bsky_account_did, rule_tree \
             FROM role_links WHERE guild_id = ANY($1)",
        )
        .bind(&guild_ids[..])
        .fetch_all(pool)
        .await?;
    if role_links.is_empty() {
        return Ok(());
    }

    // "Linked" = the member connected a Bluesky account at all.
    let is_linked: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM bsky_users WHERE discord_id = $1)")
            .bind(discord_id)
            .fetch_one(pool)
            .await?;

    let existing: HashSet<(String, String)> = sqlx::query_as::<_, (String, String)>(
        "SELECT guild_id, role_id FROM role_assignments WHERE discord_id = $1",
    )
    .bind(discord_id)
    .fetch_all(pool)
    .await?
    .into_iter()
    .collect();

    enum Action {
        Add(String, String, String),
        Remove(String, String, String),
    }

    let mut actions: Vec<Action> = Vec::new();
    for (guild_id, role_id, api_token, account_did, raw_tree) in &role_links {
        let tree: RuleTree = serde_json::from_value(raw_tree.clone()).unwrap_or_default();

        let qualifies = if tree.grant_on_any_relation {
            is_linked
        } else if account_did.is_none() {
            false
        } else {
            let did_ref = account_did.as_deref();
            let facts_row: Option<FactsRow> = sqlx::query_as(FACTS_SELECT)
                .bind(discord_id)
                .bind(did_ref)
                .fetch_optional(pool)
                .await?;
            match facts_row {
                Some(row) => {
                    let viewer_did = row.viewer_did.clone();
                    let facts = Facts::from(row);
                    let memberships = load_memberships(pool, did_ref, &viewer_did).await?;
                    condition_eval::evaluate_with_memberships(&tree, &facts, &memberships)
                }
                None => false,
            }
        };

        let assigned = existing.contains(&(guild_id.clone(), role_id.clone()));
        match (qualifies, assigned) {
            (true, false) => actions.push(Action::Add(
                guild_id.clone(),
                role_id.clone(),
                api_token.clone(),
            )),
            (false, true) => actions.push(Action::Remove(
                guild_id.clone(),
                role_id.clone(),
                api_token.clone(),
            )),
            _ => {}
        }
    }

    if actions.is_empty() {
        return Ok(());
    }

    let did = discord_id.to_string();
    stream::iter(actions)
        .for_each_concurrent(10, |action| {
            let pool = pool.clone();
            let rl = rl_client.clone();
            let did = did.clone();
            async move {
                match action {
                    Action::Add(g, r, tok) => {
                        match rl.add_user(&g, &r, &did, &tok).await {
                            Err(AppError::RoleLinkNotFound) => {
                                delete_orphan_role_link(&g, &r, &pool).await;
                                return;
                            }
                            Err(AppError::UserLimitReached { limit }) => {
                                tracing::warn!(g, r, did, limit, "user limit reached");
                                return;
                            }
                            Err(e) => {
                                tracing::error!(g, r, did, "add_user failed: {e}");
                                return;
                            }
                            Ok(_) => {}
                        }
                        let _ = sqlx::query(
                            "INSERT INTO role_assignments (guild_id, role_id, discord_id) \
                             VALUES ($1,$2,$3) ON CONFLICT DO NOTHING",
                        )
                        .bind(&g)
                        .bind(&r)
                        .bind(&did)
                        .execute(&pool)
                        .await;
                    }
                    Action::Remove(g, r, tok) => {
                        match rl.remove_user(&g, &r, &did, &tok).await {
                            Err(AppError::RoleLinkNotFound) => {
                                delete_orphan_role_link(&g, &r, &pool).await;
                                return;
                            }
                            Err(e) => {
                                tracing::error!(g, r, did, "remove_user failed: {e}");
                                return;
                            }
                            Ok(_) => {}
                        }
                        let _ = sqlx::query(
                            "DELETE FROM role_assignments \
                             WHERE guild_id=$1 AND role_id=$2 AND discord_id=$3",
                        )
                        .bind(&g)
                        .bind(&r)
                        .bind(&did)
                        .execute(&pool)
                        .await;
                    }
                }
            }
        })
        .await;

    Ok(())
}

// ---------------------------------------------------------------------------
// Per-role-link sync (bulk)
// ---------------------------------------------------------------------------

pub async fn sync_for_role_link(
    guild_id: &str,
    role_id: &str,
    state: &AppState,
) -> Result<(), AppError> {
    let pool = &state.pool;
    let rl = &state.rl_client;

    let link = sqlx::query_as::<_, (String, Option<String>, serde_json::Value)>(
        "SELECT api_token, bsky_account_did, rule_tree \
         FROM role_links WHERE guild_id = $1 AND role_id = $2",
    )
    .bind(guild_id)
    .bind(role_id)
    .fetch_optional(pool)
    .await?;

    let Some((api_token, account_did, raw_tree)) = link else {
        return Ok(());
    };
    let tree: RuleTree = serde_json::from_value(raw_tree).unwrap_or_default();

    // NOT grant_on_any AND (no account bound OR no groups) ⇒ grant to nobody.
    if !tree.grant_on_any_relation && (account_did.is_none() || tree.groups.is_empty()) {
        drain_to_empty(guild_id, role_id, &api_token, state).await?;
        return Ok(());
    }

    let member_ids = auth_gateway::fetch_guild_member_ids(
        &state.http,
        &state.config.auth_gateway_url,
        &state.config.internal_api_key,
        guild_id,
    )
    .await?;
    if member_ids.is_empty() {
        drain_to_empty(guild_id, role_id, &api_token, state).await?;
        return Ok(());
    }

    let (_count, user_limit) = match rl.get_user_info(guild_id, role_id, &api_token).await {
        Ok(v) => v,
        Err(AppError::RoleLinkNotFound) => {
            delete_orphan_role_link(guild_id, role_id, pool).await;
            return Ok(());
        }
        Err(_) => (0, 100),
    };

    let qualifying: Vec<String> = if tree.grant_on_any_relation {
        sqlx::query_scalar(
            "SELECT discord_id FROM bsky_users \
             WHERE discord_id = ANY($1::text[]) \
             ORDER BY discord_id LIMIT $2",
        )
        .bind(&member_ids)
        .bind(user_limit as i64)
        .fetch_all(pool)
        .await?
    } else {
        let account_did = account_did.expect("account bound for non-grant rule");
        let (rule_where, binds) = rule_sql::build_rule_where(&tree, 2);
        let limit_idx = 2 + binds.len() + 1;
        let query = format!(
            "SELECT DISTINCT bu.discord_id \
             FROM bsky_users bu \
             LEFT JOIN account_relations ar \
               ON ar.viewer_did = bu.did AND ar.bsky_account_did = $1 \
             WHERE bu.discord_id = ANY($2::text[]) \
               AND ({rule_where}) \
             ORDER BY bu.discord_id \
             LIMIT ${limit_idx}"
        );
        let mut q = sqlx::query_scalar::<_, String>(&query)
            .bind(account_did)
            .bind(&member_ids);
        for b in &binds {
            q = match b {
                Bind::Bool(v) => q.bind(*v),
                Bind::Int(v) => q.bind(*v),
                Bind::Text(v) => q.bind(v.clone()),
                Bind::TextArray(v) => q.bind(v.clone()),
            };
        }
        q = q.bind(user_limit as i64);
        q.fetch_all(pool).await?
    };

    let current: Vec<String> = sqlx::query_scalar(
        "SELECT discord_id FROM role_assignments \
         WHERE guild_id = $1 AND role_id = $2 ORDER BY discord_id",
    )
    .bind(guild_id)
    .bind(role_id)
    .fetch_all(pool)
    .await?;
    if current == qualifying {
        return Ok(());
    }

    match rl
        .upload_users(guild_id, role_id, &qualifying, &api_token)
        .await
    {
        Ok(_) => {}
        Err(AppError::RoleLinkNotFound) => {
            delete_orphan_role_link(guild_id, role_id, pool).await;
            return Ok(());
        }
        Err(e) => return Err(e),
    }

    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM role_assignments WHERE guild_id=$1 AND role_id=$2")
        .bind(guild_id)
        .bind(role_id)
        .execute(&mut *tx)
        .await?;
    if !qualifying.is_empty() {
        sqlx::query(
            "INSERT INTO role_assignments (guild_id, role_id, discord_id) \
             SELECT $1, $2, UNNEST($3::text[])",
        )
        .bind(guild_id)
        .bind(role_id)
        .bind(&qualifying)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

async fn drain_to_empty(
    guild_id: &str,
    role_id: &str,
    api_token: &str,
    state: &AppState,
) -> Result<(), AppError> {
    let any: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM role_assignments WHERE guild_id=$1 AND role_id=$2)",
    )
    .bind(guild_id)
    .bind(role_id)
    .fetch_one(&state.pool)
    .await?;
    if !any {
        return Ok(());
    }

    match state
        .rl_client
        .upload_users(guild_id, role_id, &[], api_token)
        .await
    {
        Ok(_) => {}
        Err(AppError::RoleLinkNotFound) => {
            delete_orphan_role_link(guild_id, role_id, &state.pool).await;
            return Ok(());
        }
        Err(e) => return Err(e),
    }
    sqlx::query("DELETE FROM role_assignments WHERE guild_id=$1 AND role_id=$2")
        .bind(guild_id)
        .bind(role_id)
        .execute(&state.pool)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Account sync — fan a per-account state refresh out to all bound role links.
// ---------------------------------------------------------------------------

pub async fn sync_for_account(bsky_account_did: &str, state: &AppState) -> Result<(), AppError> {
    let links = sqlx::query_as::<_, (String, String)>(
        "SELECT guild_id, role_id FROM role_links WHERE bsky_account_did = $1",
    )
    .bind(bsky_account_did)
    .fetch_all(&state.pool)
    .await?;
    for (guild_id, role_id) in links {
        jobs::enqueue_config_sync(&state.pool, &guild_id, &role_id).await?;
    }
    Ok(())
}

async fn delete_orphan_role_link(guild_id: &str, role_id: &str, pool: &sqlx::PgPool) {
    tracing::warn!(
        guild_id,
        role_id,
        "Role link not found on RoleLogic; removing orphaned local row"
    );
    if let Err(e) = sqlx::query("DELETE FROM role_links WHERE guild_id=$1 AND role_id=$2")
        .bind(guild_id)
        .bind(role_id)
        .execute(pool)
        .await
    {
        tracing::error!(guild_id, role_id, "Failed to delete orphan role_link: {e}");
    }
}

// silence "unused" if no caller; the HashMap import is used elsewhere
#[allow(dead_code)]
fn _hashmap_ref(_: &HashMap<String, String>) {}
