//! Plain-data view of (viewer × bsky-account) facts needed for condition
//! evaluation. Constructed by sync workers from `account_relations`,
//! `bsky_users`, and `bsky_accounts` joined on (bsky_account_did, viewer_did).
//!
//! Kept POD (no methods, no I/O) so [services::condition_eval::evaluate]
//! stays sync and fast.

use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Default)]
pub struct Facts {
    // -- per-viewer-per-account (account_relations) --
    pub is_follower: bool,
    pub followed_at: Option<DateTime<Utc>>,
    pub is_followed_back: bool,
    pub liked_posts_count: i64,
    pub reposted_posts_count: i64,
    pub replied_posts_count: i64,

    // -- per-viewer (bsky_users) --
    pub handle: String,
    pub handle_domain: Option<String>,
    pub has_custom_domain: bool,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub has_avatar: bool,
    pub has_banner: bool,
    pub posts_count: i64,
    pub followers_count: i64,
    pub follows_count: i64,
    pub bsky_created_at: Option<DateTime<Utc>>,
    pub pds_host: Option<String>,
}

impl Facts {
    /// Derived: is_mutual = both directions of the follow graph hold.
    pub fn is_mutual(&self) -> bool {
        self.is_follower && self.is_followed_back
    }
}
