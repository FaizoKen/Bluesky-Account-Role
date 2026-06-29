//! RoleLogic GET/POST /config helpers. Iframe UI mode (Section 1b of the
//! plugin blueprint) — `GET /config` returns an embed URL pointing at the
//! plugin's own role-config page; all real editing happens there.
//!
//! POST /config is a no-op kept for contract compliance: iframe-mode plugins
//! never receive it in practice, but we still verify the token so a stale
//! call can't ping silently.

use serde_json::{json, Value};

pub fn build_iframe_config(base_url: &str, guild_id: &str, role_id: &str) -> Value {
    let embed_url = format!("{base_url}/admin/{guild_id}/role/{role_id}");
    json!({
        "version": 1,
        "ui_mode": "iframe",
        "name": "Bluesky Account Role",
        "description": "Grant Discord roles based on a member's relationship to a Bluesky account — followers, mutuals, list / starter-pack members, post engagement, and richer account properties.",
        "embed_url": embed_url,
        // We honor read_only impersonation tokens (writes are blocked server-side),
        // so RoleLogic may hand us a read-only token for viewing.
        "supports_impersonation_readonly": true,
    })
}

pub fn accept_empty_config() -> Value {
    json!({ "success": true })
}
