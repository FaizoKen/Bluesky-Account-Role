//! Admin routes — broadcaster (Bluesky account) connect/list/disconnect and
//! the iframe role-config page (deep-linked from RoleLogic).

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use axum_extra::extract::cookie::CookieJar;
use chrono::{Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error::AppError;
use crate::models::condition::{ConditionOperator, ConditionTarget, TargetKind};
use crate::models::rule::{RuleTree, MAX_CONDITIONS_PER_GROUP, MAX_GROUPS};
use crate::services::auth::{extract_bearer, require_guild_admin, require_manager};
use crate::services::bsky::BskyClient;
use crate::services::rule_sql::{self, Bind};
use crate::services::rule_validator::{self, RuleTreeBody};
use crate::services::security_headers::admin_iframe_csp;
use crate::services::{auth_gateway, broadcaster_session, crypto, csrf, jobs, rl_token};
use crate::AppState;

const ROLE_CONFIG_TEMPLATE: &str = include_str!("../../templates/role_config.html");

// ---------------------------------------------------------------------
// POST /admin/{guild_id}/accounts/connect
// Broadcaster connect via App Password (handle + app password).
// ---------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ConnectBody {
    pub identifier: String,
    pub app_password: String,
}

#[derive(Serialize)]
pub struct ConnectResponse {
    pub did: String,
    pub handle: String,
}

pub async fn broadcaster_connect(
    State(state): State<Arc<AppState>>,
    Path(guild_id): Path<String>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(body): Json<ConnectBody>,
) -> Result<Json<ConnectResponse>, AppError> {
    if extract_bearer(&headers).is_none() {
        csrf::verify_origin(&headers, &state.allowed_origins)?;
    }
    let admin_did = require_guild_admin(&state, &jar, &headers, &guild_id).await?;

    let identifier = body.identifier.trim().trim_start_matches('@').to_string();
    let app_password = body.app_password.trim().to_string();
    if identifier.is_empty() || app_password.is_empty() {
        return Err(AppError::BadRequest(
            "Both your Bluesky handle and an app password are required.".into(),
        ));
    }
    // Light hint: real app-passwords are formatted `xxxx-xxxx-xxxx-xxxx`.
    // A regular account password might also work, but using one is a
    // security antipattern; nudge towards an app password.
    if app_password.contains(' ') {
        return Err(AppError::BadRequest(
            "Your app password shouldn't contain spaces — paste exactly as Bluesky shows it."
                .into(),
        ));
    }

    let client = BskyClient::new(&state.config.bsky.default_pds);
    let session = client.create_session(&identifier, &app_password).await?;

    // Pull the profile so we can populate display_name / counts / created_at.
    let profile = client
        .get_profile_authed(&session.access_jwt, &session.did)
        .await?;

    let secret = &state.config.session_secret;
    let access_enc = crypto::encrypt(secret, session.access_jwt.as_bytes());
    let refresh_enc = crypto::encrypt(secret, session.refresh_jwt.as_bytes());
    // We don't know exact expiry — set ~2h and let the refresh path bump it.
    let expires_at = Utc::now() + ChronoDuration::seconds(2 * 60 * 60);

    let bsky_created_at = parse_rfc3339(profile.created_at.as_deref());
    let pds_host = state.config.bsky.default_pds.clone();

    let mut tx = state.pool.begin().await?;
    sqlx::query(
        "INSERT INTO bsky_accounts (\
             did, handle, pds_host, display_name, description, has_avatar, has_banner,\
             followers_count, follows_count, posts_count, bsky_created_at,\
             access_jwt_enc, refresh_jwt_enc, token_expires_at,\
             last_synced_at, updated_at\
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14, now(), now())\
         ON CONFLICT (did) DO UPDATE SET \
             handle = EXCLUDED.handle, \
             pds_host = EXCLUDED.pds_host, \
             display_name = EXCLUDED.display_name, \
             description = EXCLUDED.description, \
             has_avatar = EXCLUDED.has_avatar, \
             has_banner = EXCLUDED.has_banner, \
             followers_count = EXCLUDED.followers_count, \
             follows_count = EXCLUDED.follows_count, \
             posts_count = EXCLUDED.posts_count, \
             bsky_created_at = COALESCE(EXCLUDED.bsky_created_at, bsky_accounts.bsky_created_at), \
             access_jwt_enc = EXCLUDED.access_jwt_enc, \
             refresh_jwt_enc = EXCLUDED.refresh_jwt_enc, \
             token_expires_at = EXCLUDED.token_expires_at, \
             refresh_failed_at = NULL, \
             last_synced_at = now(), \
             updated_at = now()",
    )
    .bind(&session.did)
    .bind(&session.handle)
    .bind(&pds_host)
    .bind(profile.display_name.as_deref())
    .bind(profile.description.as_deref())
    .bind(profile.avatar.is_some())
    .bind(profile.banner.is_some())
    .bind(profile.followers_count as i32)
    .bind(profile.follows_count as i32)
    .bind(profile.posts_count as i32)
    .bind(bsky_created_at)
    .bind(&access_enc)
    .bind(&refresh_enc)
    .bind(expires_at)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        "INSERT INTO guild_bsky_accounts (guild_id, bsky_account_did, connected_by_discord_id) \
         VALUES ($1,$2,$3) \
         ON CONFLICT (guild_id, bsky_account_did) DO NOTHING",
    )
    .bind(&guild_id)
    .bind(&session.did)
    .bind(&admin_did)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    // Kick off an account_sync to populate followers/lists/packs.
    jobs::enqueue_account_sync(&state.pool, &session.did).await?;

    tracing::info!(
        guild_id = %guild_id,
        did = %session.did,
        handle = %session.handle,
        connected_by = %admin_did,
        "Bluesky account connected"
    );

    Ok(Json(ConnectResponse {
        did: session.did,
        handle: session.handle,
    }))
}

fn parse_rfc3339(s: Option<&str>) -> Option<chrono::DateTime<Utc>> {
    s.and_then(|raw| chrono::DateTime::parse_from_rfc3339(raw).ok())
        .map(|d| d.with_timezone(&Utc))
}

// ---------------------------------------------------------------------
// GET /admin/{guild_id}/accounts
// ---------------------------------------------------------------------

#[derive(sqlx::FromRow, Serialize)]
pub struct AccountRow {
    pub did: String,
    pub handle: String,
    pub display_name: Option<String>,
    pub followers_count: i32,
    pub follows_count: i32,
    pub posts_count: i32,
    pub has_avatar: bool,
    pub has_banner: bool,
    pub refresh_failed: bool,
    pub connected_at: chrono::DateTime<chrono::Utc>,
}

pub async fn broadcaster_list(
    State(state): State<Arc<AppState>>,
    Path(guild_id): Path<String>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    require_guild_admin(&state, &jar, &headers, &guild_id).await?;
    let rows: Vec<AccountRow> = sqlx::query_as(
        "SELECT a.did, a.handle, a.display_name, a.followers_count, a.follows_count, \
                a.posts_count, a.has_avatar, a.has_banner, \
                (a.refresh_failed_at IS NOT NULL) AS refresh_failed, \
                gba.connected_at \
         FROM guild_bsky_accounts gba \
         JOIN bsky_accounts a ON a.did = gba.bsky_account_did \
         WHERE gba.guild_id = $1 \
         ORDER BY gba.connected_at DESC",
    )
    .bind(&guild_id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(json!({ "accounts": rows })))
}

// ---------------------------------------------------------------------
// DELETE /admin/{guild_id}/accounts/{did}
// ---------------------------------------------------------------------

pub async fn broadcaster_disconnect(
    State(state): State<Arc<AppState>>,
    Path((guild_id, did)): Path<(String, String)>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    if extract_bearer(&headers).is_none() {
        csrf::verify_origin(&headers, &state.allowed_origins)?;
    }
    require_guild_admin(&state, &jar, &headers, &guild_id).await?;

    let mut tx = state.pool.begin().await?;
    sqlx::query(
        "UPDATE role_links SET bsky_account_did = NULL, updated_at = now() \
         WHERE guild_id = $1 AND bsky_account_did = $2",
    )
    .bind(&guild_id)
    .bind(&did)
    .execute(&mut *tx)
    .await?;

    let result = sqlx::query(
        "DELETE FROM guild_bsky_accounts WHERE guild_id = $1 AND bsky_account_did = $2",
    )
    .bind(&guild_id)
    .bind(&did)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(Json(json!({
        "removed": result.rows_affected() > 0
    })))
}

// ---------------------------------------------------------------------
// Iframe role-config page (dual-mode: rl_token JWT entry OR cookie+manager)
// ---------------------------------------------------------------------

#[derive(Deserialize)]
pub struct RoleConfigPageQuery {
    #[serde(default)]
    rl_token: Option<String>,
}

pub async fn role_config_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
    Path((guild_id, role_id)): Path<(String, String)>,
    Query(query): Query<RoleConfigPageQuery>,
) -> Response {
    let has_rl_token = query
        .rl_token
        .as_deref()
        .map(|t| !t.is_empty())
        .unwrap_or(false);

    let iframe_session = match query.rl_token.as_deref() {
        Some(token) if !token.is_empty() => {
            match verify_iframe_entry(&state, &guild_id, &role_id, token).await {
                Ok(t) => Some(t),
                Err(resp) => return resp,
            }
        }
        _ => None,
    };

    if iframe_session.is_none() {
        if let Err(e) = require_manager(&state, &jar, &guild_id).await {
            if !has_rl_token && looks_embedded(&headers) {
                tracing::warn!(
                    guild_id,
                    role_id,
                    base_url = %state.config.base_url,
                    "role_config_page reached inside an iframe with no rl_token"
                );
                return render_iframe_no_token(&state);
            }
            return render_signin_page(&state, &e.to_string());
        }
    }

    let body = ROLE_CONFIG_TEMPLATE
        .replace("__BASE_URL__", &state.config.base_url)
        .replace("__GUILD_ID__", &guild_id)
        .replace("__ROLE_ID__", &role_id)
        .replace("__IFRAME_TOKEN__", iframe_session.as_deref().unwrap_or(""));

    let csp = admin_iframe_csp(state.config.rl_dashboard_origin.as_deref());
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8".to_string()),
            (header::CONTENT_SECURITY_POLICY, csp),
            (
                header::CACHE_CONTROL,
                "private, max-age=300, must-revalidate".to_string(),
            ),
        ],
        body,
    )
        .into_response()
}

async fn verify_iframe_entry(
    state: &AppState,
    guild_id: &str,
    role_id: &str,
    rl_token_str: &str,
) -> Result<String, Response> {
    let api_token: Option<String> =
        sqlx::query_scalar("SELECT api_token FROM role_links WHERE guild_id = $1 AND role_id = $2")
            .bind(guild_id)
            .bind(role_id)
            .fetch_optional(&state.pool)
            .await
            .map_err(|e| render_inline_error(state, &format!("Database error: {e}")))?;

    let Some(api_token) = api_token else {
        return Err(render_inline_error(
            state,
            "This role link isn't registered with this plugin yet.",
        ));
    };

    let verified =
        rl_token::verify(rl_token_str, &api_token, &state.config.base_url).map_err(|e| {
            let msg = match e {
                rl_token::RlTokenError::Expired => {
                    "Your session expired. Reopen the plugin in the RoleLogic dashboard."
                }
                rl_token::RlTokenError::BadSignature | rl_token::RlTokenError::Malformed => {
                    "Invalid auth token."
                }
                rl_token::RlTokenError::WrongAudience => "Token is for a different plugin.",
                rl_token::RlTokenError::WrongIssuer => "Token was not issued by RoleLogic.",
            };
            render_inline_error(state, msg)
        })?;

    if verified.guild_id != guild_id || verified.role_id != role_id {
        return Err(render_inline_error(
            state,
            "Token does not match this role link.",
        ));
    }

    Ok(rl_token::mint_iframe_session(
        &verified.discord_id,
        guild_id,
        role_id,
        &state.config.session_secret,
    ))
}

fn render_inline_error(state: &AppState, message: &str) -> Response {
    let base_url = &state.config.base_url;
    let msg = message
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    let body = format!(
        r##"<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cannot load configuration</title>
<link rel="icon" href="{base_url}/favicon.ico">
<style>body{{font-family:system-ui,sans-serif;background:#0f1115;color:#e8eaed;padding:32px 24px;line-height:1.5}}
h1{{color:#fca5a5;font-size:18px;margin-bottom:10px}}p{{color:#9aa3b2}}</style>
</head><body><h1>Cannot load configuration</h1><p>{msg}</p>
<p style="margin-top:14px;color:#7a8497">If you opened this from the RoleLogic dashboard, close and reopen the role's plugin tab.</p>
</body></html>"##
    );
    let csp = admin_iframe_csp(state.config.rl_dashboard_origin.as_deref());
    (
        StatusCode::FORBIDDEN,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8".to_string()),
            (header::CONTENT_SECURITY_POLICY, csp),
        ],
        body,
    )
        .into_response()
}

fn looks_embedded(headers: &HeaderMap) -> bool {
    let h = |k: &str| {
        headers
            .get(k)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase()
    };
    let dest = h("sec-fetch-dest");
    dest == "iframe" || dest == "frame" || h("sec-fetch-site") == "cross-site"
}

fn render_iframe_no_token(state: &AppState) -> Response {
    let base_url = &state.config.base_url;
    let body = format!(
        r##"<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Configuration unavailable</title>
<link rel="icon" href="{base_url}/favicon.ico">
<style>body{{font-family:system-ui,sans-serif;background:#0f1115;color:#e8eaed;padding:32px 24px;line-height:1.55;max-width:560px}}
h1{{color:#fbbf24;font-size:18px;margin:0 0 10px}}p{{color:#9aa3b2;margin:8px 0}}
code{{background:#0b0d12;padding:2px 6px;border-radius:4px;font-size:12px}}</style>
</head><body>
<h1>RoleLogic didn't pass an authentication token</h1>
<p>This plugin page must be opened from inside the RoleLogic dashboard, which
attaches a one-time token. None arrived with this request.</p>
<p><strong>If you're the server admin:</strong> close this tab and reopen the
role's plugin tab from RoleLogic. If it keeps happening, the plugin is
mis-registered — its <code>BASE_URL</code> must exactly match the URL
configured for this plugin in RoleLogic: HTTPS, no trailing slash, and
including the <code>/bluesky-account-role</code> path prefix.</p>
<p style="color:#7a8497;font-size:12px;margin-top:16px">Configured BASE_URL:
<code>{base_url}</code></p>
</body></html>"##
    );
    let csp = admin_iframe_csp(state.config.rl_dashboard_origin.as_deref());
    (
        StatusCode::UNAUTHORIZED,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8".to_string()),
            (header::CONTENT_SECURITY_POLICY, csp),
        ],
        body,
    )
        .into_response()
}

fn render_signin_page(state: &AppState, reason: &str) -> Response {
    let base_url = &state.config.base_url;
    let reason = reason
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    let body = format!(
        r##"<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in — Bluesky Account Role</title>
<link rel="icon" href="{base_url}/favicon.ico">
<style>body{{font-family:system-ui,sans-serif;background:#0f1115;color:#e8eaed;padding:48px 24px;max-width:520px;margin:0 auto;line-height:1.55}}
h1{{font-size:22px;margin:0 0 12px}}p{{color:#9aa3b2}}
a.btn{{display:inline-block;margin-top:18px;background:#5865f2;color:#fff;padding:12px 22px;border-radius:8px;text-decoration:none;font-weight:600}}
.actions{{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:18px}}
.actions a.btn{{margin-top:0}}
form.logout-form{{margin:0}}
button.logout{{background:none;color:#8a93a4;border:1px solid #2a2f3a;
  padding:10px 16px;border-radius:8px;font-size:13px;font-weight:600;
  cursor:pointer;font-family:inherit}}
button.logout:hover{{color:#fca5a5;border-color:#5c2630}}</style>
</head><body>
<h1>Sign in to continue</h1>
<p>You need <strong>Manage Server</strong> on this guild to edit its
Bluesky-Account-Role configuration.</p>
<p style="color:#7a8497;font-size:12px">{reason}</p>
<div class="actions">
  <a class="btn" id="login">Sign in with Discord</a>
  <form class="logout-form" method="POST" action="/auth/logout">
    <button type="submit" class="logout">Sign out &amp; try another account</button>
  </form>
</div>
<script>
const ORIGIN=new URL("{base_url}").origin;
const RET=encodeURIComponent(location.pathname);
document.getElementById('login').href=ORIGIN+'/auth/login?return_to='+RET;
document.querySelectorAll('form.logout-form').forEach(f=>{{
  f.action=ORIGIN+'/auth/logout?return_to='+RET;
}});
</script>
</body></html>"##
    );
    let csp = admin_iframe_csp(state.config.rl_dashboard_origin.as_deref());
    (
        StatusCode::UNAUTHORIZED,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8".to_string()),
            (header::CONTENT_SECURITY_POLICY, csp),
        ],
        body,
    )
        .into_response()
}

async fn require_role_config_access(
    state: &Arc<AppState>,
    jar: &CookieJar,
    headers: &HeaderMap,
    guild_id: &str,
    role_id: &str,
) -> Result<String, AppError> {
    if let Some(bearer) = extract_bearer(headers) {
        let s = rl_token::verify_iframe_session(&bearer, &state.config.session_secret).ok_or_else(
            || {
                AppError::UnauthorizedWith(
                    "Your session expired. Reopen the plugin in the RoleLogic dashboard.".into(),
                )
            },
        )?;
        if s.guild_id != guild_id || s.role_id != role_id {
            return Err(AppError::Forbidden(
                "Token does not grant access to this role link.".into(),
            ));
        }
        return Ok(s.discord_id);
    }
    require_manager(state, jar, guild_id).await
}

// ---------------------------------------------------------------------
// GET /admin/{guild_id}/role/{role_id}/data
// ---------------------------------------------------------------------

#[derive(sqlx::FromRow, Serialize)]
pub struct ListPickerRow {
    pub uri: String,
    pub name: String,
    pub purpose: Option<String>,
}

#[derive(sqlx::FromRow, Serialize)]
pub struct PackPickerRow {
    pub uri: String,
    pub name: String,
}

pub async fn role_config_data(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
    Path((guild_id, role_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    require_role_config_access(&state, &jar, &headers, &guild_id, &role_id).await?;

    let link = sqlx::query_as::<_, (Option<String>, Value, i32)>(
        "SELECT bsky_account_did, rule_tree, rule_tree_version \
         FROM role_links WHERE guild_id = $1 AND role_id = $2",
    )
    .bind(&guild_id)
    .bind(&role_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| {
        AppError::NotFound("This role link doesn't exist. Has it been added in RoleLogic?".into())
    })?;
    let (account_did, rule_tree, rule_tree_version) = link;
    let tree: RuleTree = serde_json::from_value(rule_tree).unwrap_or_default();

    let accounts: Vec<AccountRow> = sqlx::query_as(
        "SELECT a.did, a.handle, a.display_name, a.followers_count, a.follows_count, \
                a.posts_count, a.has_avatar, a.has_banner, \
                (a.refresh_failed_at IS NOT NULL) AS refresh_failed, \
                gba.connected_at \
         FROM guild_bsky_accounts gba \
         JOIN bsky_accounts a ON a.did = gba.bsky_account_did \
         WHERE gba.guild_id = $1 ORDER BY gba.connected_at DESC",
    )
    .bind(&guild_id)
    .fetch_all(&state.pool)
    .await?;

    // For the currently-bound (or first) account, pre-fetch lists + packs
    // so the rule builder can populate dropdowns without a follow-up XHR.
    let pick_did = account_did
        .clone()
        .or_else(|| accounts.first().map(|a| a.did.clone()));
    let (lists, packs) = if let Some(did) = &pick_did {
        let l: Vec<ListPickerRow> = sqlx::query_as(
            "SELECT list_uri AS uri, name, purpose FROM bsky_lists WHERE owner_did = $1 ORDER BY name",
        )
        .bind(did)
        .fetch_all(&state.pool)
        .await?;
        let p: Vec<PackPickerRow> =
            sqlx::query_as("SELECT pack_uri AS uri, name FROM bsky_starter_packs WHERE owner_did = $1 ORDER BY name")
                .bind(did)
                .fetch_all(&state.pool)
                .await?;
        (l, p)
    } else {
        (vec![], vec![])
    };

    let view_permission: String =
        sqlx::query_scalar("SELECT view_permission FROM guild_settings WHERE guild_id = $1")
            .bind(&guild_id)
            .fetch_optional(&state.pool)
            .await?
            .unwrap_or_else(|| "managers".to_string());

    Ok(Json(json!({
        "guild_id": guild_id,
        "role_id": role_id,
        "config": {
            "bsky_account_did": account_did,
            "grant_on_any_relation": tree.grant_on_any_relation,
            "groups": tree.groups,
        },
        "rule_tree_version": rule_tree_version,
        "accounts": accounts,
        "lists": lists,
        "starter_packs": packs,
        "targets": target_catalog(),
        "operators": operator_catalog(),
        "limits": {
            "max_groups": MAX_GROUPS,
            "max_conditions_per_group": MAX_CONDITIONS_PER_GROUP,
        },
        "users": {
            "url": format!("{}/users/{}", state.config.base_url, guild_id),
            "view_permission": view_permission,
        },
        "verify_url": format!("{}/verify", state.config.base_url),
    })))
}

// ---------------------------------------------------------------------
// POST /admin/{guild_id}/role/{role_id}/save
// ---------------------------------------------------------------------

#[derive(Deserialize)]
pub struct RoleConfigSaveBody {
    pub rule_tree_version: i32,
    #[serde(flatten)]
    pub tree: RuleTreeBody,
}

pub async fn role_config_save(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
    Path((guild_id, role_id)): Path<(String, String)>,
    Json(body): Json<RoleConfigSaveBody>,
) -> Result<Json<Value>, AppError> {
    if extract_bearer(&headers).is_none() {
        csrf::verify_origin(&headers, &state.allowed_origins)?;
    }
    require_role_config_access(&state, &jar, &headers, &guild_id, &role_id).await?;

    let expected_version = body.rule_tree_version;

    if let Some(did) = &body.tree.bsky_account_did {
        let ok: Option<String> = sqlx::query_scalar(
            "SELECT bsky_account_did FROM guild_bsky_accounts \
             WHERE guild_id = $1 AND bsky_account_did = $2",
        )
        .bind(&guild_id)
        .bind(did)
        .fetch_optional(&state.pool)
        .await?;
        if ok.is_none() {
            return Err(AppError::BadRequest(
                "Selected Bluesky account isn't connected to this server.".into(),
            ));
        }
    }

    let parsed = rule_validator::parse_rule_tree(body.tree)?;

    if parsed.bsky_account_did.is_none()
        && !parsed.rule_tree.grant_on_any_relation
        && !parsed.rule_tree.groups.is_empty()
    {
        return Err(AppError::BadRequest(
            "Pick the Bluesky account this rule checks against before saving — \
             without a connected account it would grant the role to nobody."
                .into(),
        ));
    }

    let tree_json = serde_json::to_value(&parsed.rule_tree)
        .map_err(|e| AppError::Internal(format!("serialize rule_tree: {e}")))?;

    let result = sqlx::query(
        "UPDATE role_links \
         SET bsky_account_did = $1, rule_tree = $2, \
             rule_tree_version = rule_tree_version + 1, updated_at = now() \
         WHERE guild_id = $3 AND role_id = $4 AND rule_tree_version = $5",
    )
    .bind(parsed.bsky_account_did.as_deref())
    .bind(&tree_json)
    .bind(&guild_id)
    .bind(&role_id)
    .bind(expected_version)
    .execute(&state.pool)
    .await?;

    if result.rows_affected() == 0 {
        let exists: Option<i32> = sqlx::query_scalar(
            "SELECT rule_tree_version FROM role_links WHERE guild_id=$1 AND role_id=$2",
        )
        .bind(&guild_id)
        .bind(&role_id)
        .fetch_optional(&state.pool)
        .await?;
        return match exists {
            None => Err(AppError::NotFound(
                "This role link doesn't exist. Has it been added in RoleLogic?".into(),
            )),
            Some(_) => Err(AppError::StaleVersion),
        };
    }

    let new_version: i32 = sqlx::query_scalar(
        "SELECT rule_tree_version FROM role_links WHERE guild_id=$1 AND role_id=$2",
    )
    .bind(&guild_id)
    .bind(&role_id)
    .fetch_one(&state.pool)
    .await?;

    if let Err(e) = jobs::enqueue_config_sync(&state.pool, &guild_id, &role_id).await {
        tracing::warn!(
            guild_id,
            role_id,
            "enqueue config_sync after save failed: {e}"
        );
    }

    tracing::info!(
        guild_id,
        role_id,
        groups = parsed.rule_tree.groups.len(),
        grant_on_any = parsed.rule_tree.grant_on_any_relation,
        "Role rule_tree updated"
    );

    Ok(Json(
        json!({ "success": true, "rule_tree_version": new_version }),
    ))
}

// ---------------------------------------------------------------------
// GET / POST  /admin/{guild_id}/role/{role_id}/preview
// ---------------------------------------------------------------------

pub async fn role_config_preview(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
    Path((guild_id, role_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    require_role_config_access(&state, &jar, &headers, &guild_id, &role_id).await?;

    let link = sqlx::query_as::<_, (Option<String>, Value)>(
        "SELECT bsky_account_did, rule_tree FROM role_links WHERE guild_id=$1 AND role_id=$2",
    )
    .bind(&guild_id)
    .bind(&role_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Role link not found.".into()))?;
    let (account_did, raw_tree) = link;
    let tree: RuleTree = serde_json::from_value(raw_tree).unwrap_or_default();

    preview_count_for(&state, &guild_id, account_did, &tree).await
}

pub async fn role_config_preview_edit(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
    Path((guild_id, role_id)): Path<(String, String)>,
    Json(body): Json<RuleTreeBody>,
) -> Result<Json<Value>, AppError> {
    if extract_bearer(&headers).is_none() {
        csrf::verify_origin(&headers, &state.allowed_origins)?;
    }
    require_role_config_access(&state, &jar, &headers, &guild_id, &role_id).await?;

    if let Some(did) = &body.bsky_account_did {
        let ok: Option<String> = sqlx::query_scalar(
            "SELECT bsky_account_did FROM guild_bsky_accounts \
             WHERE guild_id = $1 AND bsky_account_did = $2",
        )
        .bind(&guild_id)
        .bind(did)
        .fetch_optional(&state.pool)
        .await?;
        if ok.is_none() {
            return Err(AppError::BadRequest(
                "Selected Bluesky account isn't connected to this server.".into(),
            ));
        }
    }

    let parsed = rule_validator::parse_rule_tree(body)?;
    preview_count_for(
        &state,
        &guild_id,
        parsed.bsky_account_did,
        &parsed.rule_tree,
    )
    .await
}

async fn preview_count_for(
    state: &Arc<AppState>,
    guild_id: &str,
    account_did: Option<String>,
    tree: &RuleTree,
) -> Result<Json<Value>, AppError> {
    let nobody = !tree.grant_on_any_relation && (account_did.is_none() || tree.groups.is_empty());
    if nobody {
        return Ok(Json(
            json!({ "matching": 0, "linked": 0, "available": true }),
        ));
    }

    let member_ids = match auth_gateway::fetch_guild_member_ids(
        &state.http,
        &state.config.auth_gateway_url,
        &state.config.internal_api_key,
        guild_id,
    )
    .await
    {
        Ok(v) => v,
        Err(_) => {
            return Ok(Json(json!({
                "available": false,
                "reason": "Member list temporarily unavailable; preview will work once the Auth Gateway responds."
            })))
        }
    };
    if member_ids.is_empty() {
        return Ok(Json(
            json!({ "matching": 0, "linked": 0, "available": true }),
        ));
    }

    let linked: i64 =
        sqlx::query_scalar("SELECT count(*) FROM bsky_users WHERE discord_id = ANY($1::text[])")
            .bind(&member_ids)
            .fetch_one(&state.pool)
            .await?;

    if tree.grant_on_any_relation {
        return Ok(Json(json!({
            "available": true,
            "matching": linked,
            "linked": linked,
        })));
    }

    let account_did = account_did.expect("account bound for non-grant preview");

    let (rule_where, binds) = rule_sql::build_rule_where(tree, 2);
    let query = format!(
        "SELECT count(DISTINCT bu.discord_id) \
         FROM bsky_users bu \
         LEFT JOIN account_relations ar \
           ON ar.viewer_did = bu.did AND ar.bsky_account_did = $1 \
         WHERE bu.discord_id = ANY($2::text[]) AND ({rule_where})"
    );
    let mut q = sqlx::query_scalar::<_, i64>(&query)
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
    let matching: i64 = q.fetch_one(&state.pool).await?;

    Ok(Json(json!({
        "available": true,
        "matching": matching,
        "linked": linked,
    })))
}

// ---------------------------------------------------------------------
// Catalogs consumed by the rule-builder front-end
// ---------------------------------------------------------------------

fn kind_str(k: TargetKind) -> &'static str {
    match k {
        TargetKind::Bool => "bool",
        TargetKind::Int => "int",
        TargetKind::String => "string",
    }
}

fn target_catalog() -> Vec<Value> {
    use ConditionTarget::*;
    let entries: &[(ConditionTarget, &str, &str, &str)] = &[
        // Relation
        (
            IsFollower,
            "Is a follower",
            "relation",
            "Currently follows the connected Bluesky account.",
        ),
        (
            FollowAgeDays,
            "Days since started following",
            "relation",
            "How long they've followed the account.",
        ),
        (
            IsFollowedBack,
            "Account follows them back",
            "relation",
            "The connected Bluesky account follows the viewer.",
        ),
        (
            IsMutual,
            "Mutual follow",
            "relation",
            "Both follow each other.",
        ),
        (
            LikedPostsCount,
            "Likes on the account's posts",
            "relation",
            "How many of the connected account's posts they've liked.",
        ),
        (
            RepostedPostsCount,
            "Reposts of the account's posts",
            "relation",
            "How many they've reposted.",
        ),
        (
            RepliedPostsCount,
            "Replies to the account's posts",
            "relation",
            "How many they've replied to.",
        ),
        // Containers
        (
            IsOnList,
            "On a specific list",
            "containers",
            "Member of one of the account's Bluesky lists.",
        ),
        (
            IsOnStarterPack,
            "On a specific starter pack",
            "containers",
            "Listed in one of the account's starter packs.",
        ),
        // Account
        (
            AccountAgeDays,
            "Bluesky account age (days)",
            "account",
            "Age of the viewer's Bluesky account in days.",
        ),
        (
            PostsCount,
            "Total posts",
            "account",
            "Viewer's total post count.",
        ),
        (
            FollowersCount,
            "Followers",
            "account",
            "Number of people who follow the viewer.",
        ),
        (
            FollowsCount,
            "Follows",
            "account",
            "Number of accounts the viewer follows.",
        ),
        (
            Handle,
            "Handle",
            "account",
            "Viewer's Bluesky handle (alice.bsky.social).",
        ),
        (
            HandleDomain,
            "Handle domain",
            "account",
            "The part after the first dot (e.g. bsky.social).",
        ),
        (
            HasCustomDomain,
            "Has a custom domain handle",
            "account",
            "Uses a non-bsky.social handle domain.",
        ),
        (
            DisplayName,
            "Display name",
            "account",
            "Viewer's display name on Bluesky.",
        ),
        (
            Description,
            "Bio / description contains",
            "account",
            "Substring or regex match against their bio.",
        ),
        (
            HasAvatar,
            "Has set an avatar",
            "account",
            "Has uploaded a profile picture.",
        ),
        (
            HasBanner,
            "Has set a banner",
            "account",
            "Has uploaded a profile banner.",
        ),
        (
            PdsHost,
            "PDS host",
            "account",
            "Which PDS hosts their account (e.g. bsky.social).",
        ),
    ];
    entries
        .iter()
        .map(|(t, label, group, help)| {
            json!({
                "key": t.as_str(),
                "label": label,
                "kind": kind_str(t.kind()),
                "group": group,
                "help": help,
            })
        })
        .collect()
}

fn operator_catalog() -> Vec<Value> {
    use ConditionOperator::*;
    let all = [
        (Eq, "equals"),
        (Neq, "not equals"),
        (Gt, "greater than"),
        (Gte, "at least"),
        (Lt, "less than"),
        (Lte, "at most"),
        (Between, "between"),
        (Contains, "contains"),
        (Regex, "matches regex"),
        (In, "is one of"),
        (NotIn, "is not one of"),
    ];
    all.iter()
        .map(|(op, label)| {
            json!({
                "key": op.as_str(),
                "label": label,
                "valid_for": {
                    "bool": op.valid_for(TargetKind::Bool),
                    "int": op.valid_for(TargetKind::Int),
                    "string": op.valid_for(TargetKind::String),
                },
                "needs_value_end": matches!(op, Between),
                "value_is_list": matches!(op, In | NotIn),
            })
        })
        .collect()
}

// ---------------------------------------------------------------------
// POST /admin/{guild_id}/accounts/{did}/refresh
// Operator-triggered refresh of a connected account's followers / lists /
// starter packs. Useful immediately after a "I just made a new list, why
// doesn't it show in the dropdown" moment, without waiting 6h for reconcile.
// ---------------------------------------------------------------------

pub async fn broadcaster_refresh(
    State(state): State<Arc<AppState>>,
    Path((guild_id, did)): Path<(String, String)>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    if extract_bearer(&headers).is_none() {
        csrf::verify_origin(&headers, &state.allowed_origins)?;
    }
    require_guild_admin(&state, &jar, &headers, &guild_id).await?;

    // Must belong to this guild.
    let ok: Option<String> = sqlx::query_scalar(
        "SELECT bsky_account_did FROM guild_bsky_accounts \
         WHERE guild_id = $1 AND bsky_account_did = $2",
    )
    .bind(&guild_id)
    .bind(&did)
    .fetch_optional(&state.pool)
    .await?;
    if ok.is_none() {
        return Err(AppError::Forbidden(
            "That Bluesky account isn't connected to this server.".into(),
        ));
    }

    // Verify the session is still valid; surface the friendly "reconnect
    // needed" hint when it isn't.
    let client = BskyClient::new(&state.config.bsky.default_pds);
    broadcaster_session::valid_access_jwt(&state, &client, &did).await?;

    jobs::enqueue_account_sync(&state.pool, &did).await?;
    Ok(Json(json!({ "queued": true })))
}
