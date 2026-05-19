//! Get a valid Bluesky access JWT for a connected broadcaster account.
//!
//! - Reads the encrypted access/refresh JWTs from `bsky_accounts`.
//! - If the access JWT is within ~5 minutes of expiry (or already expired),
//!   refresh via `com.atproto.server.refreshSession` and persist the new pair.
//! - Returns the plaintext access JWT to the caller.
//!
//! On hard refresh failure (refresh JWT itself rejected) we stamp
//! `refresh_failed_at` so the admin sees "re-connect needed" in the iframe,
//! and propagate `BskyApi`. The bulk-sync worker treats this as a "skip
//! this account this cycle" rather than clearing every member's role.

use chrono::{Duration as ChronoDuration, Utc};

use crate::error::AppError;
use crate::services::bsky::BskyClient;
use crate::services::crypto;
use crate::AppState;

/// How close to expiry (in seconds) we proactively refresh.
const REFRESH_LEAD_SECS: i64 = 5 * 60;

#[derive(Debug, sqlx::FromRow)]
struct StoredSession {
    access_jwt_enc: Vec<u8>,
    refresh_jwt_enc: Vec<u8>,
    token_expires_at: chrono::DateTime<Utc>,
}

/// Return a valid plaintext access JWT for `did`, refreshing if needed.
pub async fn valid_access_jwt(
    state: &AppState,
    client: &BskyClient,
    did: &str,
) -> Result<String, AppError> {
    let stored: Option<StoredSession> = sqlx::query_as(
        "SELECT access_jwt_enc, refresh_jwt_enc, token_expires_at \
         FROM bsky_accounts WHERE did = $1",
    )
    .bind(did)
    .fetch_optional(&state.pool)
    .await?;

    let Some(s) = stored else {
        return Err(AppError::NotFound(format!(
            "No connected Bluesky account for DID {did}"
        )));
    };

    let secret = &state.config.session_secret;
    let needs_refresh =
        Utc::now() + ChronoDuration::seconds(REFRESH_LEAD_SECS) >= s.token_expires_at;

    if !needs_refresh {
        let pt = crypto::decrypt(secret, &s.access_jwt_enc)
            .map_err(|e| AppError::Internal(format!("decrypt access_jwt: {e}")))?;
        return String::from_utf8(pt)
            .map_err(|e| AppError::Internal(format!("access_jwt not utf-8: {e}")));
    }

    let refresh_pt = crypto::decrypt(secret, &s.refresh_jwt_enc)
        .map_err(|e| AppError::Internal(format!("decrypt refresh_jwt: {e}")))?;
    let refresh_str = String::from_utf8(refresh_pt)
        .map_err(|e| AppError::Internal(format!("refresh_jwt not utf-8: {e}")))?;

    match client.refresh_session(&refresh_str).await {
        Ok(refreshed) => {
            let access_enc = crypto::encrypt(secret, refreshed.access_jwt.as_bytes());
            let refresh_enc = crypto::encrypt(secret, refreshed.refresh_jwt.as_bytes());
            // AT Proto access JWTs are typically valid ~2h; the response
            // doesn't include exp, so estimate conservatively.
            let new_expires = Utc::now() + ChronoDuration::seconds(60 * 60);
            sqlx::query(
                "UPDATE bsky_accounts \
                 SET access_jwt_enc = $1, refresh_jwt_enc = $2, \
                     token_expires_at = $3, refresh_failed_at = NULL, updated_at = now() \
                 WHERE did = $4",
            )
            .bind(&access_enc)
            .bind(&refresh_enc)
            .bind(new_expires)
            .bind(did)
            .execute(&state.pool)
            .await?;
            Ok(refreshed.access_jwt)
        }
        Err(e) => {
            // Persistent failure (refresh JWT rejected). Mark the row so the
            // admin sees a "re-connect" badge in the iframe.
            let _ = sqlx::query(
                "UPDATE bsky_accounts SET refresh_failed_at = now(), updated_at = now() \
                 WHERE did = $1",
            )
            .bind(did)
            .execute(&state.pool)
            .await;
            Err(e)
        }
    }
}
