//! The rule tree: OR of AND-groups (DNF).
//!
//! Stored verbatim as the JSONB `rule_tree` column on `role_links`. Two-level
//! structure keeps validation, SQL translation, and the iframe rule-builder
//! UI simple while still expressing every boolean rule.
//!
//! Convention 42 invariant: an unconfigured role link grants the role to
//! nobody. `grant_on_any_relation = false` AND `groups.is_empty()` means
//! "match nobody" — both the Rust evaluator and the SQL builder enforce this
//! BEFORE inspecting groups.

use serde::{Deserialize, Serialize};

use crate::models::condition::Condition;

pub const MAX_GROUPS: usize = 8;
pub const MAX_CONDITIONS_PER_GROUP: usize = 12;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleTree {
    #[serde(default)]
    pub grant_on_any_relation: bool,
    #[serde(default)]
    pub groups: Vec<ConditionGroup>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConditionGroup {
    #[serde(default)]
    pub conditions: Vec<Condition>,
}
