//! Public "all users" listing — every linked viewer with any relation to a
//! Bluesky account connected to this guild.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use axum_extra::extract::cookie::CookieJar;
use serde_json::{json, Value};

use crate::error::AppError;
use crate::services::auth::{extract_bearer, guild_members, guild_permission, require_guild_admin};
use crate::services::csrf;
use crate::AppState;

const USERS_PAGE: &str = include_str!("../../templates/users.html");

pub async fn users_page(
    State(state): State<Arc<AppState>>,
    Path(guild_id): Path<String>,
) -> impl IntoResponse {
    let html = USERS_PAGE
        .replace("{{BASE_URL}}", &state.config.base_url)
        .replace("{{GUILD_ID}}", &guild_id);
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
}

#[allow(clippy::type_complexity)]
pub async fn users_data(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(guild_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let view_permission: String =
        sqlx::query_scalar("SELECT view_permission FROM guild_settings WHERE guild_id = $1")
            .bind(&guild_id)
            .fetch_optional(&state.pool)
            .await?
            .unwrap_or_else(|| "managers".to_string());

    if view_permission == "disabled" {
        return Err(AppError::Forbidden(
            "The user list is disabled for this server.".into(),
        ));
    }

    let perm = guild_permission(&state, &jar, &guild_id).await?;
    if !perm.is_member {
        return Err(AppError::Forbidden(
            "You're not a member of this server.".into(),
        ));
    }
    if view_permission == "managers" && !perm.is_manager {
        return Err(AppError::Forbidden(
            "This list is visible to server managers only.".into(),
        ));
    }

    let (member_ids, guild_name) = guild_members(&state, &jar, &guild_id).await?;

    // One row per linked viewer who is a member of this guild. Relations are
    // LEFT-joined and scoped to the broadcasters connected here, then
    // collapsed (OR / max / sum) so a viewer linked to several of the guild's
    // accounts appears once.
    let rows = sqlx::query_as::<
        _,
        (
            String,                                // discord_id
            Option<String>,                        // discord_name
            String,                                // handle
            String,                                // did
            Option<String>,                        // display_name
            bool,                                  // has_avatar
            i32,                                   // followers_count
            i32,                                   // follows_count
            i32,                                   // posts_count
            Option<chrono::DateTime<chrono::Utc>>, // bsky_created_at
            bool,                                  // is_follower
            bool,                                  // is_followed_back
            bool,                                  // is_mutual (derived)
            Option<chrono::DateTime<chrono::Utc>>, // followed_at
            chrono::DateTime<chrono::Utc>,         // linked_at
        ),
    >(
        "SELECT bu.discord_id, \
                bu.discord_name, \
                bu.handle, \
                bu.did, \
                bu.display_name, \
                bu.has_avatar, \
                bu.followers_count, \
                bu.follows_count, \
                bu.posts_count, \
                bu.bsky_created_at, \
                COALESCE(bool_or(ar.is_follower),      false) AS is_follower, \
                COALESCE(bool_or(ar.is_followed_back), false) AS is_followed_back, \
                COALESCE(bool_or(ar.is_follower AND ar.is_followed_back), false) AS is_mutual, \
                min(ar.followed_at)           AS followed_at, \
                bu.linked_at \
         FROM bsky_users bu \
         LEFT JOIN guild_bsky_accounts gba ON gba.guild_id = $1 \
         LEFT JOIN account_relations ar \
                ON ar.viewer_did = bu.did \
               AND ar.bsky_account_did = gba.bsky_account_did \
         WHERE bu.discord_id = ANY($2) \
         GROUP BY bu.discord_id, bu.discord_name, bu.handle, bu.did, bu.display_name, \
                  bu.has_avatar, bu.followers_count, bu.follows_count, bu.posts_count, \
                  bu.bsky_created_at, bu.linked_at \
         ORDER BY bu.handle ASC \
         LIMIT 1000",
    )
    .bind(&guild_id)
    .bind(&member_ids)
    .fetch_all(&state.pool)
    .await?;

    let users = rows
        .into_iter()
        .map(
            |(
                discord_id,
                discord_name,
                handle,
                did,
                display_name,
                has_avatar,
                followers_count,
                follows_count,
                posts_count,
                bsky_created_at,
                is_follower,
                is_followed_back,
                is_mutual,
                followed_at,
                linked_at,
            )| {
                json!({
                    "discord_id": discord_id,
                    "discord_name": discord_name,
                    "handle": handle,
                    "did": did,
                    "display_name": display_name,
                    "has_avatar": has_avatar,
                    "followers_count": followers_count,
                    "follows_count": follows_count,
                    "posts_count": posts_count,
                    "bsky_created_at": bsky_created_at.map(|x| x.to_rfc3339()),
                    "is_follower": is_follower,
                    "is_followed_back": is_followed_back,
                    "is_mutual": is_mutual,
                    "followed_at": followed_at.map(|x| x.to_rfc3339()),
                    "linked_at": linked_at.to_rfc3339(),
                })
            },
        )
        .collect::<Vec<_>>();

    Ok(Json(json!({
        "guild_id": guild_id,
        "guild_name": guild_name,
        "count": users.len(),
        "users": users,
    })))
}

#[derive(serde::Deserialize)]
pub struct ViewPermBody {
    pub view_permission: String,
}

pub async fn set_view_permission(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(guild_id): Path<String>,
    Json(body): Json<ViewPermBody>,
) -> Result<Json<Value>, AppError> {
    if extract_bearer(&headers).is_none() {
        csrf::verify_origin(&headers, &state.allowed_origins)?;
    }
    require_guild_admin(&state, &jar, &headers, &guild_id).await?;

    let vp = match body.view_permission.as_str() {
        "disabled" | "managers" | "members" => body.view_permission.as_str(),
        other => {
            return Err(AppError::BadRequest(format!(
                "Unknown view_permission '{other}' (expected disabled|managers|members)."
            )))
        }
    };

    sqlx::query(
        "INSERT INTO guild_settings (guild_id, view_permission, updated_at) \
         VALUES ($1, $2, now()) \
         ON CONFLICT (guild_id) DO UPDATE SET view_permission = EXCLUDED.view_permission, \
                                              updated_at = now()",
    )
    .bind(&guild_id)
    .bind(vp)
    .execute(&state.pool)
    .await?;

    Ok(Json(json!({ "success": true, "view_permission": vp })))
}
