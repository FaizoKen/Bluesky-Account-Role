//! Rust-side condition evaluation. Sync, fast, no I/O.
//!
//! Used by:
//!   * `player_sync` worker — evaluate a single (viewer, account) pair when
//!     a verify event or per-player sync fires.
//!
//! The bulk per-role-link path uses [services::rule_sql::build_rule_where]
//! instead — it pushes the same predicates down into Postgres.
//!
//! NOTE: list-membership conditions (`is_on_list`, `is_on_starter_pack`) are
//! NOT evaluated here in the Rust path; they require a DB lookup against
//! `bsky_list_members` / `bsky_starter_pack_members`. The
//! `evaluate_with_memberships` helper accepts the set of list URIs / pack
//! URIs the viewer belongs to so the caller can pre-fetch them once.

use std::collections::HashSet;

use serde_json::Value;

use crate::models::condition::{Condition, ConditionOperator, ConditionTarget};
use crate::models::facts::Facts;
use crate::models::rule::RuleTree;

/// Sets of list / starter-pack URIs the viewer is a member of, sized for the
/// broadcaster being evaluated against. Empty sets mean "no memberships
/// known" — list/pack conditions fail closed.
#[derive(Default, Debug, Clone)]
pub struct Memberships {
    pub list_uris: HashSet<String>,
    pub starter_pack_uris: HashSet<String>,
}

/// Convenience for callers that don't have membership context. The bulk
/// sync paths use [`evaluate_with_memberships`] directly.
#[allow(dead_code)]
pub fn evaluate(tree: &RuleTree, facts: &Facts) -> bool {
    evaluate_with_memberships(tree, facts, &Memberships::default())
}

pub fn evaluate_with_memberships(tree: &RuleTree, facts: &Facts, m: &Memberships) -> bool {
    if tree.grant_on_any_relation {
        return true;
    }
    if tree.groups.is_empty() {
        return false;
    }
    tree.groups.iter().any(|g| {
        !g.conditions.is_empty() && g.conditions.iter().all(|c| evaluate_single(c, facts, m))
    })
}

fn evaluate_single(c: &Condition, f: &Facts, m: &Memberships) -> bool {
    use ConditionTarget::*;

    match c.target {
        // -- booleans --
        IsFollower => bool_match(c, f.is_follower),
        IsFollowedBack => bool_match(c, f.is_followed_back),
        IsMutual => bool_match(c, f.is_mutual()),
        HasCustomDomain => bool_match(c, f.has_custom_domain),
        HasAvatar => bool_match(c, f.has_avatar),
        HasBanner => bool_match(c, f.has_banner),

        // -- integers --
        FollowAgeDays => int_match(c, days_since(f.followed_at)),
        LikedPostsCount => int_match(c, Some(f.liked_posts_count)),
        RepostedPostsCount => int_match(c, Some(f.reposted_posts_count)),
        RepliedPostsCount => int_match(c, Some(f.replied_posts_count)),
        AccountAgeDays => int_match(c, days_since(f.bsky_created_at)),
        PostsCount => int_match(c, Some(f.posts_count)),
        FollowersCount => int_match(c, Some(f.followers_count)),
        FollowsCount => int_match(c, Some(f.follows_count)),

        // -- list / starter-pack: value is the URI we're checking membership
        // against. Always `Eq` — the validator rejects anything else.
        IsOnList => match c.value.as_str() {
            Some(uri) => m.list_uris.contains(uri),
            None => false,
        },
        IsOnStarterPack => match c.value.as_str() {
            Some(uri) => m.starter_pack_uris.contains(uri),
            None => false,
        },

        // -- strings (nullable) --
        Handle => string_match(c, Some(f.handle.as_str())),
        HandleDomain => string_match(c, f.handle_domain.as_deref()),
        DisplayName => string_match(c, f.display_name.as_deref()),
        Description => string_match(c, f.description.as_deref()),
        PdsHost => string_match(c, f.pds_host.as_deref()),
    }
}

fn bool_match(c: &Condition, actual: bool) -> bool {
    if !matches!(c.operator, ConditionOperator::Eq) {
        return false;
    }
    c.value.as_bool().map(|v| v == actual).unwrap_or(false)
}

fn int_match(c: &Condition, actual: Option<i64>) -> bool {
    let Some(a) = actual else {
        return false; // missing data ⇒ fail-closed
    };
    let v = c.value.as_i64();
    match c.operator {
        ConditionOperator::Eq => v.map(|n| a == n).unwrap_or(false),
        ConditionOperator::Neq => v.map(|n| a != n).unwrap_or(false),
        ConditionOperator::Gt => v.map(|n| a > n).unwrap_or(false),
        ConditionOperator::Gte => v.map(|n| a >= n).unwrap_or(false),
        ConditionOperator::Lt => v.map(|n| a < n).unwrap_or(false),
        ConditionOperator::Lte => v.map(|n| a <= n).unwrap_or(false),
        ConditionOperator::Between => {
            let lo = v;
            let hi = c.value_end.as_ref().and_then(|x| x.as_i64());
            match (lo, hi) {
                (Some(lo), Some(hi)) => a >= lo && a <= hi,
                _ => false,
            }
        }
        _ => false,
    }
}

fn string_match(c: &Condition, actual: Option<&str>) -> bool {
    let Some(a) = actual else {
        return matches!(c.operator, ConditionOperator::Neq);
    };
    let v = c.value.as_str();
    match c.operator {
        ConditionOperator::Eq => v.map(|s| a == s).unwrap_or(false),
        ConditionOperator::Neq => v.map(|s| a != s).unwrap_or(false),
        ConditionOperator::Contains => v
            .map(|s| a.to_ascii_lowercase().contains(&s.to_ascii_lowercase()))
            .unwrap_or(false),
        ConditionOperator::Regex => {
            let Some(pattern) = v else { return false };
            let Ok(re) = regex::RegexBuilder::new(pattern)
                .size_limit(1 << 20)
                .dfa_size_limit(1 << 20)
                .build()
            else {
                return false;
            };
            re.is_match(a)
        }
        ConditionOperator::In => list_contains(&c.value, a),
        ConditionOperator::NotIn => !list_contains(&c.value, a),
        _ => false,
    }
}

fn list_contains(value: &Value, needle: &str) -> bool {
    value
        .as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).any(|s| s == needle))
        .unwrap_or(false)
}

fn days_since(ts: Option<chrono::DateTime<chrono::Utc>>) -> Option<i64> {
    ts.map(|t| (chrono::Utc::now() - t).num_days())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::condition::ConditionTarget as T;
    use crate::models::rule::{ConditionGroup, RuleTree};
    use chrono::Duration;
    use serde_json::json;

    fn c(target: T, op: ConditionOperator, value: Value) -> Condition {
        Condition {
            target,
            operator: op,
            value,
            value_end: None,
        }
    }

    fn one_group(conds: Vec<Condition>) -> RuleTree {
        RuleTree {
            grant_on_any_relation: false,
            groups: vec![ConditionGroup { conditions: conds }],
        }
    }

    fn or_groups(g: Vec<Vec<Condition>>) -> RuleTree {
        RuleTree {
            grant_on_any_relation: false,
            groups: g
                .into_iter()
                .map(|cs| ConditionGroup { conditions: cs })
                .collect(),
        }
    }

    fn facts() -> Facts {
        Facts::default()
    }

    #[test]
    fn no_groups_no_grant_means_nobody() {
        let t = RuleTree::default();
        assert!(!evaluate(&t, &facts()));
    }

    #[test]
    fn grant_on_any_short_circuits_true() {
        let t = RuleTree {
            grant_on_any_relation: true,
            groups: vec![],
        };
        assert!(evaluate(&t, &facts()));
    }

    #[test]
    fn empty_group_is_false_defensive() {
        let t = RuleTree {
            grant_on_any_relation: false,
            groups: vec![ConditionGroup { conditions: vec![] }],
        };
        assert!(!evaluate(&t, &facts()));
    }

    #[test]
    fn and_all_conditions_required() {
        let t = one_group(vec![
            c(T::IsFollower, ConditionOperator::Eq, json!(true)),
            c(T::FollowAgeDays, ConditionOperator::Gte, json!(30)),
        ]);
        let mut f = facts();
        f.is_follower = true;
        f.followed_at = Some(chrono::Utc::now() - Duration::days(45));
        assert!(evaluate(&t, &f));

        f.followed_at = Some(chrono::Utc::now() - Duration::days(10));
        assert!(!evaluate(&t, &f));
    }

    #[test]
    fn or_any_group_satisfies() {
        let t = or_groups(vec![
            vec![c(T::IsMutual, ConditionOperator::Eq, json!(true))],
            vec![c(T::FollowersCount, ConditionOperator::Gte, json!(1000))],
        ]);

        let mut f = facts();
        f.is_follower = true;
        f.is_followed_back = true;
        assert!(evaluate(&t, &f));

        let mut f = facts();
        f.followers_count = 1500;
        assert!(evaluate(&t, &f));

        let f = facts();
        assert!(!evaluate(&t, &f));
    }

    #[test]
    fn is_mutual_requires_both_directions() {
        let t = one_group(vec![c(T::IsMutual, ConditionOperator::Eq, json!(true))]);
        let mut f = facts();
        f.is_follower = true;
        assert!(!evaluate(&t, &f));
        f.is_followed_back = true;
        assert!(evaluate(&t, &f));
    }

    #[test]
    fn between_inclusive() {
        let mut cond = c(T::AccountAgeDays, ConditionOperator::Between, json!(30));
        cond.value_end = Some(json!(365));
        let t = one_group(vec![cond]);

        let mut f = facts();
        f.bsky_created_at = Some(chrono::Utc::now() - Duration::days(30));
        assert!(evaluate(&t, &f));
        f.bsky_created_at = Some(chrono::Utc::now() - Duration::days(365));
        assert!(evaluate(&t, &f));
        f.bsky_created_at = Some(chrono::Utc::now() - Duration::days(366));
        assert!(!evaluate(&t, &f));
    }

    #[test]
    fn handle_regex() {
        let t = one_group(vec![c(
            T::Handle,
            ConditionOperator::Regex,
            json!(r"^[a-z]+\.bsky\.social$"),
        )]);
        let mut f = facts();
        f.handle = "alice.bsky.social".into();
        assert!(evaluate(&t, &f));
        f.handle = "alice.example.com".into();
        assert!(!evaluate(&t, &f));
    }

    #[test]
    fn description_contains_case_insensitive() {
        let t = one_group(vec![c(
            T::Description,
            ConditionOperator::Contains,
            json!("rolelogic"),
        )]);
        let mut f = facts();
        f.description = Some("I'm a RoleLogic fan!".into());
        assert!(evaluate(&t, &f));
        f.description = Some("nothing here".into());
        assert!(!evaluate(&t, &f));
    }

    #[test]
    fn handle_domain_in_list() {
        let t = one_group(vec![c(
            T::HandleDomain,
            ConditionOperator::In,
            json!(["bsky.social", "blacksky.community"]),
        )]);
        let mut f = facts();
        f.handle_domain = Some("bsky.social".into());
        assert!(evaluate(&t, &f));
        f.handle_domain = Some("example.com".into());
        assert!(!evaluate(&t, &f));
    }

    #[test]
    fn is_on_list_with_memberships() {
        let t = one_group(vec![c(
            T::IsOnList,
            ConditionOperator::Eq,
            json!("at://did:plc:owner/app.bsky.graph.list/abc"),
        )]);
        let f = facts();
        let mut m = Memberships::default();
        m.list_uris
            .insert("at://did:plc:owner/app.bsky.graph.list/abc".into());
        assert!(evaluate_with_memberships(&t, &f, &m));
        let m_empty = Memberships::default();
        assert!(!evaluate_with_memberships(&t, &f, &m_empty));
    }

    #[test]
    fn realistic_loyal_follower_rule() {
        // (follower AND followed >= 30 days) OR (mutual) OR (on starter pack)
        let t = or_groups(vec![
            vec![
                c(T::IsFollower, ConditionOperator::Eq, json!(true)),
                c(T::FollowAgeDays, ConditionOperator::Gte, json!(30)),
            ],
            vec![c(T::IsMutual, ConditionOperator::Eq, json!(true))],
            vec![c(
                T::IsOnStarterPack,
                ConditionOperator::Eq,
                json!("at://did:plc:owner/app.bsky.graph.starterpack/xyz"),
            )],
        ]);

        // Long follower
        let mut f = facts();
        f.is_follower = true;
        f.followed_at = Some(chrono::Utc::now() - Duration::days(45));
        assert!(evaluate(&t, &f));

        // Mutual
        let mut f = facts();
        f.is_follower = true;
        f.is_followed_back = true;
        assert!(evaluate(&t, &f));

        // On starter pack
        let mut m = Memberships::default();
        m.starter_pack_uris
            .insert("at://did:plc:owner/app.bsky.graph.starterpack/xyz".into());
        let f = facts();
        assert!(evaluate_with_memberships(&t, &f, &m));

        // No relation
        let f = facts();
        assert!(!evaluate(&t, &f));
    }
}
