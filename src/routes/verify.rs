//! Member-facing verification flow: link a Bluesky account to a Discord ID
//! using a handle + app password. The app password is used only to prove
//! ownership (a one-shot `com.atproto.server.createSession`); we discard it
//! immediately and only persist the resulting DID/handle/profile.
//!
//! Routes:
//!   GET  /verify                       — landing page (HTML)
//!   POST /verify/login                 — redirect to Auth Gateway Discord login
//!   POST /verify/bsky                  — exchange handle + app password
//!   GET  /verify/status                — JSON status for the page's JS
//!   POST /verify/unlink                — drop the caller's Bluesky link

use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect};
use axum::Json;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::error::AppError;
use crate::services::auth::read_session;
use crate::services::bsky::{self, BskyClient};
use crate::services::csrf;
use crate::AppState;

const VERIFY_PAGE: &str = include_str!("../../templates/verify.html");
const VERIFY_DONE_PAGE: &str = include_str!("../../templates/verify_done.html");

// ---------------------------------------------------------------------

pub async fn verify_page(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let html = VERIFY_PAGE.replace("{{BASE_URL}}", &state.config.base_url);
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
}

// ---------------------------------------------------------------------

pub async fn verify_status(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<Json<Value>, AppError> {
    let discord = read_session(&jar, &state.config.session_secret).ok();

    let bsky_link: Option<(String, String, Option<String>)> = match &discord {
        Some((did, _)) => {
            sqlx::query_as("SELECT did, handle, display_name FROM bsky_users WHERE discord_id = $1")
                .bind(did)
                .fetch_optional(&state.pool)
                .await?
        }
        None => None,
    };

    Ok(Json(json!({
        "signed_in_discord": discord.is_some(),
        "discord_username": discord.as_ref().map(|(_, n)| n.clone()),
        "linked_bsky": bsky_link.is_some(),
        "bsky_did": bsky_link.as_ref().map(|(d, _, _)| d.clone()),
        "bsky_handle": bsky_link.as_ref().map(|(_, h, _)| h.clone()),
        "bsky_display_name": bsky_link.as_ref().and_then(|(_, _, n)| n.clone()),
    })))
}

// ---------------------------------------------------------------------

pub async fn verify_unlink(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    csrf::verify_origin(&headers, &state.allowed_origins)?;
    let (discord_id, _) = read_session(&jar, &state.config.session_secret)?;

    let removed: Option<(String,)> =
        sqlx::query_as("DELETE FROM bsky_users WHERE discord_id = $1 RETURNING did")
            .bind(&discord_id)
            .fetch_optional(&state.pool)
            .await?;

    let Some((did,)) = removed else {
        return Err(AppError::NotFound(
            "No linked Bluesky account to unlink.".into(),
        ));
    };

    // Cascade-clean the per-account relations and per-list/pack memberships
    // that referenced this viewer. These tables are keyed by DID with no FK
    // to bsky_users, so they don't auto-cascade.
    sqlx::query("DELETE FROM account_relations WHERE viewer_did = $1")
        .bind(&did)
        .execute(&state.pool)
        .await?;
    sqlx::query("DELETE FROM bsky_list_members WHERE member_did = $1")
        .bind(&did)
        .execute(&state.pool)
        .await?;
    sqlx::query("DELETE FROM bsky_starter_pack_members WHERE member_did = $1")
        .bind(&did)
        .execute(&state.pool)
        .await?;

    crate::services::jobs::enqueue_player_sync(&state.pool, &discord_id).await?;

    tracing::info!(discord_id = %discord_id, did = %did, "Viewer unlinked");

    Ok(Json(json!({ "success": true })))
}

// ---------------------------------------------------------------------

pub async fn verify_login(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let path = path_only(&state.config.base_url);
    let return_to = format!("{path}/verify");
    let url = format!(
        "{}/auth/login?return_to={}",
        state.config.auth_gateway_url,
        urlencoding::encode(&return_to)
    );
    Redirect::to(&url)
}

fn path_only(base_url: &str) -> String {
    if let Some(scheme_end) = base_url.find("://") {
        let after_scheme = scheme_end + 3;
        if let Some(slash) = base_url[after_scheme..].find('/') {
            return base_url[after_scheme + slash..]
                .trim_end_matches('/')
                .to_string();
        }
    }
    String::new()
}

// ---------------------------------------------------------------------

#[derive(Deserialize)]
pub struct VerifyBskyBody {
    pub identifier: String,
    pub app_password: String,
}

pub async fn verify_bsky(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(body): Json<VerifyBskyBody>,
) -> Result<impl IntoResponse, AppError> {
    csrf::verify_origin(&headers, &state.allowed_origins)?;
    let (discord_id, discord_name) = read_session(&jar, &state.config.session_secret)?;

    let identifier = body.identifier.trim().trim_start_matches('@').to_string();
    let app_password = body.app_password.trim().to_string();
    if identifier.is_empty() || app_password.is_empty() {
        return Err(AppError::BadRequest(
            "Both your handle and an app password are required.".into(),
        ));
    }
    if app_password.contains(' ') {
        return Err(AppError::BadRequest(
            "Your app password shouldn't contain spaces — paste exactly as Bluesky shows it."
                .into(),
        ));
    }

    let client = BskyClient::new(&state.config.bsky.default_pds);
    // The createSession proves ownership of the handle.
    let session = client.create_session(&identifier, &app_password).await?;
    // Now grab the full profile from the public API — viewer fields aren't
    // needed and the public endpoint is cheaper.
    let profile = match client.get_profile_public(&session.handle).await {
        Ok(p) => p,
        Err(_) => {
            // Fallback: authenticated read; works even when public mirror is
            // momentarily stale.
            client
                .get_profile_authed(&session.access_jwt, &session.did)
                .await?
        }
    };

    let handle_domain = bsky::handle_domain(&session.handle);
    let has_custom_domain = bsky::is_custom_domain(&session.handle);
    let bsky_created_at = profile
        .created_at
        .as_deref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.with_timezone(&chrono::Utc));
    let pds_host = state.config.bsky.default_pds.clone();

    // We intentionally do NOT persist `session.refresh_jwt` for viewers — we
    // proved ownership and that's all we needed. The access JWT lives only
    // in process memory for the duration of this handler.
    let _ = session.access_jwt;
    let _ = session.refresh_jwt;

    let upsert = sqlx::query(
        "INSERT INTO bsky_users (\
             discord_id, did, handle, handle_domain, has_custom_domain, pds_host,\
             display_name, description, has_avatar, has_banner,\
             posts_count, followers_count, follows_count, bsky_created_at, discord_name,\
             linked_at, refreshed_at\
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15, now(), now())\
         ON CONFLICT (discord_id) DO UPDATE SET \
             did = EXCLUDED.did, \
             handle = EXCLUDED.handle, \
             handle_domain = EXCLUDED.handle_domain, \
             has_custom_domain = EXCLUDED.has_custom_domain, \
             pds_host = EXCLUDED.pds_host, \
             display_name = EXCLUDED.display_name, \
             description = EXCLUDED.description, \
             has_avatar = EXCLUDED.has_avatar, \
             has_banner = EXCLUDED.has_banner, \
             posts_count = EXCLUDED.posts_count, \
             followers_count = EXCLUDED.followers_count, \
             follows_count = EXCLUDED.follows_count, \
             bsky_created_at = COALESCE(EXCLUDED.bsky_created_at, bsky_users.bsky_created_at), \
             discord_name = COALESCE(EXCLUDED.discord_name, bsky_users.discord_name), \
             refreshed_at = now()",
    )
    .bind(&discord_id)
    .bind(&session.did)
    .bind(&session.handle)
    .bind(handle_domain.as_deref())
    .bind(has_custom_domain)
    .bind(&pds_host)
    .bind(profile.display_name.as_deref())
    .bind(profile.description.as_deref())
    .bind(profile.avatar.is_some())
    .bind(profile.banner.is_some())
    .bind(profile.posts_count as i32)
    .bind(profile.followers_count as i32)
    .bind(profile.follows_count as i32)
    .bind(bsky_created_at)
    .bind(&discord_name)
    .execute(&state.pool)
    .await;

    if let Err(e) = upsert {
        if let sqlx::Error::Database(db_err) = &e {
            if db_err.code().as_deref() == Some("23505")
                && db_err.constraint() == Some("bsky_users_did_key")
            {
                return Err(AppError::Forbidden(format!(
                    "Bluesky account @{} is already linked to a different Discord account. \
                     Unlink there first, then try again.",
                    session.handle
                )));
            }
        }
        return Err(AppError::from(e));
    }

    // Seed empty account_relations for every connected broadcaster across
    // every guild this user is in, so they appear on the public users page
    // immediately.
    match crate::services::auth_gateway::fetch_user_guild_ids(
        &state.http,
        &state.config.auth_gateway_url,
        &state.config.internal_api_key,
        &discord_id,
    )
    .await
    {
        Ok(guild_ids) => {
            if let Err(e) = crate::services::sync::ensure_baseline_relations(
                &state.pool,
                &discord_id,
                &guild_ids,
            )
            .await
            {
                tracing::warn!(
                    discord_id = %discord_id,
                    "ensure_baseline_relations failed at link time: {e}"
                );
            }
        }
        Err(e) => {
            tracing::warn!(
                discord_id = %discord_id,
                "auth_gateway guild lookup failed at link time: {e}"
            );
        }
    }

    crate::services::jobs::enqueue_player_sync(&state.pool, &discord_id).await?;

    tracing::info!(
        discord_id = %discord_id,
        did = %session.did,
        handle = %session.handle,
        "Viewer linked"
    );

    let profile_url = bsky::profile_url(&session.handle);
    let html = VERIFY_DONE_PAGE
        .replace("{{BASE_URL}}", &state.config.base_url)
        .replace("{{BSKY_HANDLE}}", &session.handle)
        .replace("{{BSKY_DID}}", &session.did)
        .replace("{{BSKY_PROFILE_URL}}", &profile_url);
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    ))
}
