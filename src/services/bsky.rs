//! AT Protocol / Bluesky XRPC client.
//!
//! Methods we hit:
//!   * `com.atproto.server.createSession`    — log in with handle + app password
//!   * `com.atproto.server.refreshSession`   — refresh an access JWT
//!   * `com.atproto.identity.resolveHandle`  — handle → DID
//!   * `app.bsky.actor.getProfile`           — full profile (followers/follows/posts counts, etc.)
//!   * `app.bsky.graph.getFollowers`         — paginated followers of a DID
//!   * `app.bsky.graph.getFollows`           — paginated follows of a DID
//!   * `app.bsky.graph.getLists`             — lists owned by a DID
//!   * `app.bsky.graph.getList`              — members of a list (paginated)
//!   * `app.bsky.graph.getActorStarterPacks` — starter packs by a DID
//!   * `app.bsky.graph.getStarterPack`       — single starter pack (with list URI)
//!   * `app.bsky.graph.getRelationships`     — bidirectional follow-state probe
//!
//! Hosts:
//!   * `https://bsky.social`            — auth + writes go to the user's PDS
//!   * `https://public.api.bsky.app`    — unauthenticated reads (faster, no rate-limit on viewer's PDS)
//!
//! TODO(bsky-docs): a small handful of fields (e.g. `viewer.followedBy`,
//! exact pagination cursor shape on `getList`) are coded to the documented
//! AT Protocol conventions. Re-verify against live API on first integration.
//!
//! Many of the deserialized struct fields below are reachable as a public
//! API surface but aren't read by the current `services::sync` / `tasks::
//! reconcile` paths. They are intentionally allowed to live as
//! ready-to-use future surface (e.g. `viewer.followedBy` would let us cut
//! a `getRelationships` call when refreshing a single viewer). Annotating
//! the module rather than every field keeps drift low when new ones land.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};

use crate::error::AppError;

pub const PUBLIC_API_BASE: &str = "https://public.api.bsky.app";
pub const DEFAULT_PDS: &str = "https://bsky.social";

/// Build a friendly Bluesky profile URL from a handle. Used for the public
/// users page link-outs (`bsky.app/profile/{handle}`).
pub fn profile_url(handle: &str) -> String {
    format!("https://bsky.app/profile/{handle}")
}

#[derive(Clone)]
pub struct BskyClient {
    http: reqwest::Client,
    default_pds: String,
}

// ---------------------------------------------------------------------
// Response shapes — only the fields we actually read.
// ---------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CreateSessionResp {
    #[serde(rename = "accessJwt")]
    pub access_jwt: String,
    #[serde(rename = "refreshJwt")]
    pub refresh_jwt: String,
    pub did: String,
    pub handle: String,
    #[serde(rename = "didDoc", default)]
    pub did_doc: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct RefreshSessionResp {
    #[serde(rename = "accessJwt")]
    pub access_jwt: String,
    #[serde(rename = "refreshJwt")]
    pub refresh_jwt: String,
    pub did: String,
    pub handle: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Profile {
    pub did: String,
    pub handle: String,
    #[serde(rename = "displayName", default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub avatar: Option<String>,
    #[serde(default)]
    pub banner: Option<String>,
    #[serde(rename = "followersCount", default)]
    pub followers_count: i64,
    #[serde(rename = "followsCount", default)]
    pub follows_count: i64,
    #[serde(rename = "postsCount", default)]
    pub posts_count: i64,
    #[serde(rename = "createdAt", default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub viewer: Option<ProfileViewer>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ProfileViewer {
    #[serde(default)]
    pub following: Option<String>,
    #[serde(rename = "followedBy", default)]
    pub followed_by: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ActorRef {
    pub did: String,
    pub handle: String,
}

#[derive(Debug, Deserialize)]
pub struct PaginatedActors {
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default)]
    pub followers: Vec<ActorRef>,
    #[serde(default)]
    pub follows: Vec<ActorRef>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ListView {
    pub uri: String,
    pub name: String,
    #[serde(default)]
    pub purpose: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(rename = "listItemCount", default)]
    pub list_item_count: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct ListsResp {
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default)]
    pub lists: Vec<ListView>,
}

#[derive(Debug, Deserialize)]
pub struct ListMembersResp {
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default)]
    pub items: Vec<ListMemberItem>,
}

#[derive(Debug, Deserialize)]
pub struct ListMemberItem {
    pub subject: ActorRef,
}

#[derive(Debug, Deserialize, Clone)]
pub struct StarterPackView {
    pub uri: String,
    #[serde(default)]
    pub record: Option<serde_json::Value>,
    #[serde(default)]
    pub creator: Option<ActorRef>,
    #[serde(default)]
    pub list: Option<ListView>,
}

#[derive(Debug, Deserialize)]
pub struct StarterPacksResp {
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(rename = "starterPacks", default)]
    pub starter_packs: Vec<StarterPackView>,
}

/// Result of `app.bsky.graph.getRelationships` for one subject. We use this
/// to fill in `followed_by`/`following` flags between the broadcaster and a
/// viewer in one call.
#[derive(Debug, Deserialize, Default)]
pub struct RelationshipFlags {
    #[serde(default)]
    pub following: Option<String>,
    #[serde(rename = "followedBy", default)]
    pub followed_by: Option<String>,
}

#[derive(Debug, Serialize)]
struct CreateSessionBody<'a> {
    identifier: &'a str,
    password: &'a str,
}

#[derive(Debug, Deserialize)]
struct XrpcError {
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    message: Option<String>,
}

// ---------------------------------------------------------------------

impl BskyClient {
    pub fn new(default_pds: &str) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .user_agent("bluesky-account-role/0.1 (+RoleLogic plugin)")
            .build()
            .expect("Failed to build HTTP client");
        Self {
            http,
            default_pds: default_pds.trim_end_matches('/').to_string(),
        }
    }

    fn pds(&self) -> &str {
        &self.default_pds
    }

    // -----------------------------------------------------------------
    // Authentication
    // -----------------------------------------------------------------

    /// Log in with a handle (or email/DID) and app-password. Returns
    /// {accessJwt, refreshJwt, did, handle}.
    ///
    /// Goes to the broadcaster's PDS — for now we always send to the
    /// default PDS (almost universally bsky.social). Custom-PDS users
    /// receive a 400 we surface back so the admin knows to set
    /// `BSKY_DEFAULT_PDS`.
    pub async fn create_session(
        &self,
        identifier: &str,
        app_password: &str,
    ) -> Result<CreateSessionResp, AppError> {
        let url = format!("{}/xrpc/com.atproto.server.createSession", self.pds());
        let resp = self
            .http
            .post(&url)
            .json(&CreateSessionBody {
                identifier,
                password: app_password,
            })
            .send()
            .await
            .map_err(|e| AppError::BskyApi(format!("createSession network: {e}")))?;

        if !resp.status().is_success() {
            return Err(parse_xrpc_error(resp).await);
        }
        resp.json::<CreateSessionResp>()
            .await
            .map_err(|e| AppError::BskyApi(format!("createSession parse: {e}")))
    }

    /// Refresh an access JWT using the refresh JWT.
    pub async fn refresh_session(&self, refresh_jwt: &str) -> Result<RefreshSessionResp, AppError> {
        let url = format!("{}/xrpc/com.atproto.server.refreshSession", self.pds());
        let resp = self
            .http
            .post(&url)
            .bearer_auth(refresh_jwt)
            .send()
            .await
            .map_err(|e| AppError::BskyApi(format!("refreshSession network: {e}")))?;
        if !resp.status().is_success() {
            return Err(parse_xrpc_error(resp).await);
        }
        resp.json::<RefreshSessionResp>()
            .await
            .map_err(|e| AppError::BskyApi(format!("refreshSession parse: {e}")))
    }

    // -----------------------------------------------------------------
    // Public reads
    // -----------------------------------------------------------------

    /// Resolve a handle to its DID. Unauthenticated.
    pub async fn resolve_handle(&self, handle: &str) -> Result<String, AppError> {
        let url = format!("{PUBLIC_API_BASE}/xrpc/com.atproto.identity.resolveHandle");
        let resp = self
            .http
            .get(&url)
            .query(&[("handle", handle)])
            .send()
            .await
            .map_err(|e| AppError::BskyApi(format!("resolveHandle network: {e}")))?;
        if !resp.status().is_success() {
            return Err(parse_xrpc_error(resp).await);
        }
        #[derive(Deserialize)]
        struct R {
            did: String,
        }
        let r: R = resp
            .json()
            .await
            .map_err(|e| AppError::BskyApi(format!("resolveHandle parse: {e}")))?;
        Ok(r.did)
    }

    /// Fetch a profile by handle-or-DID. Public, unauthenticated.
    pub async fn get_profile_public(&self, actor: &str) -> Result<Profile, AppError> {
        let url = format!("{PUBLIC_API_BASE}/xrpc/app.bsky.actor.getProfile");
        let resp = self
            .http
            .get(&url)
            .query(&[("actor", actor)])
            .send()
            .await
            .map_err(|e| AppError::BskyApi(format!("getProfile network: {e}")))?;
        if !resp.status().is_success() {
            return Err(parse_xrpc_error(resp).await);
        }
        resp.json::<Profile>()
            .await
            .map_err(|e| AppError::BskyApi(format!("getProfile parse: {e}")))
    }

    /// Authenticated profile fetch — extra fields (viewer.following /
    /// viewer.followedBy) require the broadcaster's session.
    pub async fn get_profile_authed(
        &self,
        access_jwt: &str,
        actor: &str,
    ) -> Result<Profile, AppError> {
        // Authenticated reads still go through the PDS.
        let url = format!("{}/xrpc/app.bsky.actor.getProfile", self.pds());
        let resp = self
            .http
            .get(&url)
            .bearer_auth(access_jwt)
            .query(&[("actor", actor)])
            .send()
            .await
            .map_err(|e| AppError::BskyApi(format!("getProfile (auth) network: {e}")))?;
        if !resp.status().is_success() {
            return Err(parse_xrpc_error(resp).await);
        }
        resp.json::<Profile>()
            .await
            .map_err(|e| AppError::BskyApi(format!("getProfile (auth) parse: {e}")))
    }

    /// Page through every follower of `actor`. Returns a fully drained list;
    /// bails out at `max_items` to stay polite.
    pub async fn list_followers(
        &self,
        access_jwt: &str,
        actor: &str,
        max_items: usize,
    ) -> Result<Vec<ActorRef>, AppError> {
        let mut cursor: Option<String> = None;
        let mut out: Vec<ActorRef> = Vec::new();
        loop {
            let url = format!("{}/xrpc/app.bsky.graph.getFollowers", self.pds());
            let mut req = self
                .http
                .get(&url)
                .bearer_auth(access_jwt)
                .query(&[("actor", actor), ("limit", "100")]);
            if let Some(c) = &cursor {
                req = req.query(&[("cursor", c.as_str())]);
            }
            let resp = req
                .send()
                .await
                .map_err(|e| AppError::BskyApi(format!("getFollowers network: {e}")))?;
            if !resp.status().is_success() {
                return Err(parse_xrpc_error(resp).await);
            }
            let page: PaginatedActors = resp
                .json()
                .await
                .map_err(|e| AppError::BskyApi(format!("getFollowers parse: {e}")))?;
            for a in page.followers {
                out.push(a);
                if out.len() >= max_items {
                    return Ok(out);
                }
            }
            cursor = page.cursor;
            if cursor.is_none() {
                break;
            }
        }
        Ok(out)
    }

    pub async fn list_follows(
        &self,
        access_jwt: &str,
        actor: &str,
        max_items: usize,
    ) -> Result<Vec<ActorRef>, AppError> {
        let mut cursor: Option<String> = None;
        let mut out: Vec<ActorRef> = Vec::new();
        loop {
            let url = format!("{}/xrpc/app.bsky.graph.getFollows", self.pds());
            let mut req = self
                .http
                .get(&url)
                .bearer_auth(access_jwt)
                .query(&[("actor", actor), ("limit", "100")]);
            if let Some(c) = &cursor {
                req = req.query(&[("cursor", c.as_str())]);
            }
            let resp = req
                .send()
                .await
                .map_err(|e| AppError::BskyApi(format!("getFollows network: {e}")))?;
            if !resp.status().is_success() {
                return Err(parse_xrpc_error(resp).await);
            }
            let page: PaginatedActors = resp
                .json()
                .await
                .map_err(|e| AppError::BskyApi(format!("getFollows parse: {e}")))?;
            for a in page.follows {
                out.push(a);
                if out.len() >= max_items {
                    return Ok(out);
                }
            }
            cursor = page.cursor;
            if cursor.is_none() {
                break;
            }
        }
        Ok(out)
    }

    /// All lists owned by `actor`. Paginated; we bail at 200 since real
    /// users rarely have more.
    pub async fn list_user_lists(
        &self,
        access_jwt: &str,
        actor: &str,
    ) -> Result<Vec<ListView>, AppError> {
        let mut cursor: Option<String> = None;
        let mut out: Vec<ListView> = Vec::new();
        for _ in 0..10 {
            let url = format!("{}/xrpc/app.bsky.graph.getLists", self.pds());
            let mut req = self
                .http
                .get(&url)
                .bearer_auth(access_jwt)
                .query(&[("actor", actor), ("limit", "50")]);
            if let Some(c) = &cursor {
                req = req.query(&[("cursor", c.as_str())]);
            }
            let resp = req
                .send()
                .await
                .map_err(|e| AppError::BskyApi(format!("getLists network: {e}")))?;
            if !resp.status().is_success() {
                return Err(parse_xrpc_error(resp).await);
            }
            let page: ListsResp = resp
                .json()
                .await
                .map_err(|e| AppError::BskyApi(format!("getLists parse: {e}")))?;
            out.extend(page.lists);
            cursor = page.cursor;
            if cursor.is_none() {
                break;
            }
        }
        Ok(out)
    }

    /// Page through a list's members.
    pub async fn list_members(
        &self,
        access_jwt: &str,
        list_uri: &str,
        max_items: usize,
    ) -> Result<Vec<ActorRef>, AppError> {
        let mut cursor: Option<String> = None;
        let mut out: Vec<ActorRef> = Vec::new();
        loop {
            let url = format!("{}/xrpc/app.bsky.graph.getList", self.pds());
            let mut req = self
                .http
                .get(&url)
                .bearer_auth(access_jwt)
                .query(&[("list", list_uri), ("limit", "100")]);
            if let Some(c) = &cursor {
                req = req.query(&[("cursor", c.as_str())]);
            }
            let resp = req
                .send()
                .await
                .map_err(|e| AppError::BskyApi(format!("getList network: {e}")))?;
            if !resp.status().is_success() {
                return Err(parse_xrpc_error(resp).await);
            }
            let page: ListMembersResp = resp
                .json()
                .await
                .map_err(|e| AppError::BskyApi(format!("getList parse: {e}")))?;
            for it in page.items {
                out.push(it.subject);
                if out.len() >= max_items {
                    return Ok(out);
                }
            }
            cursor = page.cursor;
            if cursor.is_none() {
                break;
            }
        }
        Ok(out)
    }

    /// Starter packs created by `actor`.
    pub async fn list_starter_packs(
        &self,
        access_jwt: &str,
        actor: &str,
    ) -> Result<Vec<StarterPackView>, AppError> {
        let mut cursor: Option<String> = None;
        let mut out: Vec<StarterPackView> = Vec::new();
        for _ in 0..10 {
            let url = format!("{}/xrpc/app.bsky.graph.getActorStarterPacks", self.pds());
            let mut req = self
                .http
                .get(&url)
                .bearer_auth(access_jwt)
                .query(&[("actor", actor), ("limit", "50")]);
            if let Some(c) = &cursor {
                req = req.query(&[("cursor", c.as_str())]);
            }
            let resp = req
                .send()
                .await
                .map_err(|e| AppError::BskyApi(format!("getActorStarterPacks network: {e}")))?;
            if !resp.status().is_success() {
                return Err(parse_xrpc_error(resp).await);
            }
            let page: StarterPacksResp = resp
                .json()
                .await
                .map_err(|e| AppError::BskyApi(format!("getActorStarterPacks parse: {e}")))?;
            out.extend(page.starter_packs);
            cursor = page.cursor;
            if cursor.is_none() {
                break;
            }
        }
        Ok(out)
    }
}

/// Pull a structured XRPC error out of a failure response. Falls back to a
/// terse "{status}: {body}" string if the JSON isn't an XRPC error envelope.
async fn parse_xrpc_error(resp: reqwest::Response) -> AppError {
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if let Ok(parsed) = serde_json::from_str::<XrpcError>(&body) {
        let msg = parsed
            .message
            .or(parsed.error)
            .unwrap_or_else(|| body.clone());
        // 401/403 from createSession is "wrong credentials" — surface as a
        // user-facing BadRequest rather than a generic Bsky failure.
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            return AppError::BadRequest(format!("Bluesky rejected the credentials: {msg}"));
        }
        if status == reqwest::StatusCode::BAD_REQUEST {
            return AppError::BadRequest(format!("Bluesky rejected the request: {msg}"));
        }
        return AppError::BskyApi(format!("{status}: {msg}"));
    }
    AppError::BskyApi(format!("{status}: {body}"))
}

/// Extract the portion after the FIRST dot of a handle. Used for the
/// `handle_domain` condition target. Returns `None` for handles with no dot
/// (rare; usually a DID-as-handle fallback or an invalid handle).
pub fn handle_domain(handle: &str) -> Option<String> {
    let h = handle.trim().to_ascii_lowercase();
    h.split_once('.').map(|(_, dom)| dom.to_string())
}

/// Does the handle use a "custom" (non-bsky.social) domain?
pub fn is_custom_domain(handle: &str) -> bool {
    match handle_domain(handle) {
        Some(d) => d != "bsky.social",
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_domain_basic() {
        assert_eq!(
            handle_domain("alice.bsky.social"),
            Some("bsky.social".into())
        );
        assert_eq!(
            handle_domain("ALICE.BSKY.SOCIAL"),
            Some("bsky.social".into())
        );
        assert_eq!(
            handle_domain("custom.example.com"),
            Some("example.com".into())
        );
        assert_eq!(handle_domain("no-dots"), None);
        assert_eq!(handle_domain(""), None);
    }

    #[test]
    fn is_custom_domain_basic() {
        assert!(!is_custom_domain("alice.bsky.social"));
        assert!(is_custom_domain("alice.example.com"));
        assert!(is_custom_domain("alice.example.bsky.social.fake"));
        assert!(!is_custom_domain("no-dots"));
    }

    #[test]
    fn profile_url_format() {
        assert_eq!(
            profile_url("alice.bsky.social"),
            "https://bsky.app/profile/alice.bsky.social"
        );
    }
}
