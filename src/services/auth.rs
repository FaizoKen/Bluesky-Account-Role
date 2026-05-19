//! Admin-permission helpers used by routes that mix cookie-auth (direct nav)
//! and iframe-Bearer auth (RoleLogic iframe).

use std::sync::Arc;

use axum_extra::extract::cookie::{Cookie, CookieJar};
use serde::Deserialize;

use crate::error::AppError;
use crate::services::rl_token;
use crate::services::session::verify_session;
use crate::AppState;

#[derive(Debug, Deserialize)]
struct GuildPermissionResp {
    #[serde(default)]
    is_member: bool,
    #[serde(default)]
    is_manager: bool,
}

#[derive(Debug, Deserialize)]
struct GuildMembersResp {
    #[serde(default)]
    discord_ids: Vec<String>,
    #[serde(default)]
    guild_name: Option<String>,
}

/// Classify a non-success Auth Gateway HTTP response.
///
/// Only a genuine `401 Unauthorized` means the caller's session is actually
/// bad. Everything else is a transient server problem and gets mapped to
/// `Internal` so we don't tell signed-in users to re-authenticate on every
/// gateway hiccup.
fn classify_gateway_status(status: reqwest::StatusCode, body: &str, gateway_url: &str) -> AppError {
    if status == reqwest::StatusCode::UNAUTHORIZED {
        AppError::UnauthorizedWith(format!(
            "The Auth Gateway rejected your session ({status}). Please sign in again."
        ))
    } else {
        AppError::Internal(format!(
            "Auth Gateway at {gateway_url} returned {status}: {body}"
        ))
    }
}

pub fn read_session(jar: &CookieJar, secret: &str) -> Result<(String, String), AppError> {
    let cookie = jar.get("rl_session").ok_or_else(|| {
        AppError::UnauthorizedWith("Not signed in. Log in with Discord to continue.".into())
    })?;
    verify_session(cookie.value(), secret)
        .ok_or_else(|| AppError::UnauthorizedWith("Session expired or invalid.".into()))
}

pub async fn require_manager(
    state: &Arc<AppState>,
    jar: &CookieJar,
    guild_id: &str,
) -> Result<String, AppError> {
    let (discord_id, _) = read_session(jar, &state.config.session_secret)?;

    let cookie_val = jar
        .get("rl_session")
        .map(|c| {
            Cookie::build(("rl_session", c.value().to_string()))
                .build()
                .encoded()
                .to_string()
        })
        .unwrap_or_default();

    let url = format!(
        "{}/auth/guild_permission?guild_id={guild_id}",
        state.config.auth_gateway_url
    );
    let resp = state
        .http
        .get(&url)
        .header("Cookie", cookie_val)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("auth_gateway permission request: {e}")))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(classify_gateway_status(
            status,
            &body,
            &state.config.auth_gateway_url,
        ));
    }
    let parsed: GuildPermissionResp = resp
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("auth_gateway response not JSON: {e}")))?;
    if !parsed.is_member {
        return Err(AppError::Forbidden(
            "You're not a member of this server.".into(),
        ));
    }
    if !parsed.is_manager {
        return Err(AppError::Forbidden(
            "You need Manage Server to do this.".into(),
        ));
    }
    Ok(discord_id)
}

pub fn extract_bearer(headers: &axum::http::HeaderMap) -> Option<String> {
    let val = headers.get("authorization")?.to_str().ok()?;
    val.strip_prefix("Bearer ").map(String::from)
}

/// Guild-scoped dual gate for admin actions that aren't tied to a single
/// role link (account connect/list/disconnect, per-guild settings).
pub async fn require_guild_admin(
    state: &Arc<AppState>,
    jar: &CookieJar,
    headers: &axum::http::HeaderMap,
    guild_id: &str,
) -> Result<String, AppError> {
    if let Some(bearer) = extract_bearer(headers) {
        let s = rl_token::verify_iframe_session(&bearer, &state.config.session_secret).ok_or_else(
            || {
                AppError::UnauthorizedWith(
                    "Your session expired. Reopen the plugin in the RoleLogic dashboard.".into(),
                )
            },
        )?;
        if s.guild_id != guild_id {
            return Err(AppError::Forbidden(
                "Token does not grant access to this server.".into(),
            ));
        }
        return Ok(s.discord_id);
    }
    require_manager(state, jar, guild_id).await
}

pub struct GuildPermission {
    #[allow(dead_code)]
    pub discord_id: String,
    pub is_member: bool,
    pub is_manager: bool,
}

pub async fn guild_permission(
    state: &Arc<AppState>,
    jar: &CookieJar,
    guild_id: &str,
) -> Result<GuildPermission, AppError> {
    let (discord_id, _) = read_session(jar, &state.config.session_secret)?;
    let cookie_val = jar
        .get("rl_session")
        .map(|c| {
            Cookie::build(("rl_session", c.value().to_string()))
                .build()
                .encoded()
                .to_string()
        })
        .unwrap_or_default();

    let url = format!(
        "{}/auth/guild_permission?guild_id={guild_id}",
        state.config.auth_gateway_url
    );
    let resp = state
        .http
        .get(&url)
        .header("Cookie", cookie_val)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("auth_gateway permission request: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(classify_gateway_status(
            status,
            &body,
            &state.config.auth_gateway_url,
        ));
    }
    let parsed: GuildPermissionResp = resp
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("auth_gateway response not JSON: {e}")))?;
    Ok(GuildPermission {
        discord_id,
        is_member: parsed.is_member,
        is_manager: parsed.is_manager,
    })
}

pub async fn guild_members(
    state: &Arc<AppState>,
    jar: &CookieJar,
    guild_id: &str,
) -> Result<(Vec<String>, Option<String>), AppError> {
    read_session(jar, &state.config.session_secret)?;

    let cookie_val = jar
        .get("rl_session")
        .map(|c| {
            Cookie::build(("rl_session", c.value().to_string()))
                .build()
                .encoded()
                .to_string()
        })
        .unwrap_or_default();

    let url = format!(
        "{}/auth/guild_members?guild_id={guild_id}",
        state.config.auth_gateway_url
    );
    let resp = state
        .http
        .get(&url)
        .header("Cookie", cookie_val)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("auth_gateway members request: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(classify_gateway_status(
            status,
            &body,
            &state.config.auth_gateway_url,
        ));
    }
    let parsed: GuildMembersResp = resp
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("auth_gateway response not JSON: {e}")))?;
    Ok((parsed.discord_ids, parsed.guild_name))
}
