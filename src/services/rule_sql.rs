//! SQL WHERE-clause builder for bulk per-role-link sync.
//!
//! Pushes the same DNF semantics as [services::condition_eval::evaluate] down
//! into Postgres so `sync_for_role_link` filters server-side instead of
//! loading every viewer's facts into memory.
//!
//! Required SQL context (caller supplies aliases):
//!   * `bu`  — bsky_users
//!   * `ar`  — account_relations (LEFT JOINed; columns may be NULL)
//!
//! For list / starter-pack membership the SQL emits an `EXISTS (SELECT 1
//! FROM bsky_list_members lm WHERE lm.list_uri = $N AND lm.member_did = bu.did)`
//! subquery — keeps everything in a single query and reuses the existing
//! per-DID index on the memberships tables.

use crate::models::condition::{Condition, ConditionOperator, ConditionTarget};
use crate::models::rule::RuleTree;

#[derive(Debug, Clone)]
pub enum Bind {
    Bool(bool),
    Int(i64),
    Text(String),
    TextArray(Vec<String>),
}

pub fn build_rule_where(tree: &RuleTree, bind_offset: usize) -> (String, Vec<Bind>) {
    if tree.grant_on_any_relation {
        return ("TRUE".to_string(), vec![]);
    }
    if tree.groups.is_empty() {
        return ("FALSE".to_string(), vec![]);
    }

    let mut binds: Vec<Bind> = Vec::new();
    let mut group_clauses: Vec<String> = Vec::new();

    for group in &tree.groups {
        if group.conditions.is_empty() {
            group_clauses.push("FALSE".to_string());
            continue;
        }
        let mut cond_clauses: Vec<String> = Vec::new();
        for c in &group.conditions {
            cond_clauses.push(build_condition(c, bind_offset, &mut binds));
        }
        group_clauses.push(format!("({})", cond_clauses.join(" AND ")));
    }

    (format!("({})", group_clauses.join(" OR ")), binds)
}

/// SQL expression for a target.
fn target_expr(target: ConditionTarget) -> Option<&'static str> {
    use ConditionTarget::*;
    Some(match target {
        // -- account_relations (LEFT JOINed; COALESCE) --
        IsFollower => "COALESCE(ar.is_follower, false)",
        FollowAgeDays => "FLOOR(EXTRACT(EPOCH FROM (now() - ar.followed_at)) / 86400)",
        IsFollowedBack => "COALESCE(ar.is_followed_back, false)",
        IsMutual => "(COALESCE(ar.is_follower, false) AND COALESCE(ar.is_followed_back, false))",
        LikedPostsCount => "COALESCE(ar.liked_posts_count, 0)",
        RepostedPostsCount => "COALESCE(ar.reposted_posts_count, 0)",
        RepliedPostsCount => "COALESCE(ar.replied_posts_count, 0)",
        // -- bsky_users --
        AccountAgeDays => "FLOOR(EXTRACT(EPOCH FROM (now() - bu.bsky_created_at)) / 86400)",
        PostsCount => "bu.posts_count",
        FollowersCount => "bu.followers_count",
        FollowsCount => "bu.follows_count",
        Handle => "bu.handle",
        HandleDomain => "bu.handle_domain",
        HasCustomDomain => "COALESCE(bu.has_custom_domain, false)",
        DisplayName => "bu.display_name",
        Description => "bu.description",
        HasAvatar => "COALESCE(bu.has_avatar, false)",
        HasBanner => "COALESCE(bu.has_banner, false)",
        PdsHost => "bu.pds_host",
        // List / starter-pack membership doesn't map to a single column;
        // build_condition handles them specially.
        IsOnList | IsOnStarterPack => return None,
    })
}

fn build_condition(c: &Condition, bind_offset: usize, binds: &mut Vec<Bind>) -> String {
    use ConditionOperator::*;
    use ConditionTarget::*;

    let next = |binds: &Vec<Bind>| bind_offset + binds.len() + 1;

    // Special-case list / starter-pack membership.
    if matches!(c.target, IsOnList | IsOnStarterPack) {
        // Only `Eq` makes sense — validator enforces this.
        let uri = c.value.as_str().unwrap_or("");
        if uri.is_empty() || !matches!(c.operator, Eq) {
            return "FALSE".to_string();
        }
        let i = next(binds);
        binds.push(Bind::Text(uri.to_string()));
        let (mtable, ucol) = match c.target {
            IsOnList => ("bsky_list_members", "list_uri"),
            IsOnStarterPack => ("bsky_starter_pack_members", "pack_uri"),
            _ => unreachable!(),
        };
        return format!(
            "EXISTS (SELECT 1 FROM {mtable} m WHERE m.{ucol} = ${i} AND m.member_did = bu.did)"
        );
    }

    let expr = target_expr(c.target).expect("non-list target has an expression");

    match c.operator {
        Eq => {
            if let Some(b) = c.value.as_bool() {
                let i = next(binds);
                binds.push(Bind::Bool(b));
                format!("{expr} = ${i}")
            } else if let Some(n) = c.value.as_i64() {
                let i = next(binds);
                binds.push(Bind::Int(n));
                format!("{expr} = ${i}")
            } else {
                let i = next(binds);
                binds.push(Bind::Text(c.value.as_str().unwrap_or("").to_string()));
                format!("{expr} = ${i}")
            }
        }
        Neq => {
            if let Some(n) = c.value.as_i64() {
                let i = next(binds);
                binds.push(Bind::Int(n));
                format!("{expr} <> ${i}")
            } else {
                let i = next(binds);
                binds.push(Bind::Text(c.value.as_str().unwrap_or("").to_string()));
                format!("{expr} IS DISTINCT FROM ${i}")
            }
        }
        Gt | Gte | Lt | Lte => {
            let n = c.value.as_i64().unwrap_or(0);
            let i = next(binds);
            binds.push(Bind::Int(n));
            let op = match c.operator {
                Gt => ">",
                Gte => ">=",
                Lt => "<",
                Lte => "<=",
                _ => unreachable!(),
            };
            format!("({expr}) {op} ${i}")
        }
        Between => {
            let lo = c.value.as_i64().unwrap_or(0);
            let hi = c.value_end.as_ref().and_then(|v| v.as_i64()).unwrap_or(lo);
            let ia = next(binds);
            binds.push(Bind::Int(lo));
            let ib = next(binds);
            binds.push(Bind::Int(hi));
            format!("(({expr}) >= ${ia} AND ({expr}) <= ${ib})")
        }
        Contains => {
            let v = c.value.as_str().unwrap_or("");
            let i = next(binds);
            binds.push(Bind::Text(format!("%{}%", escape_like(v))));
            format!("LOWER({expr}) LIKE LOWER(${i})")
        }
        Regex => {
            let v = c.value.as_str().unwrap_or("");
            let i = next(binds);
            binds.push(Bind::Text(v.to_string()));
            format!("{expr} ~ ${i}")
        }
        In => {
            let arr = str_array(c);
            if arr.is_empty() {
                return "FALSE".to_string();
            }
            let i = next(binds);
            binds.push(Bind::TextArray(arr));
            format!("{expr} = ANY(${i}::text[])")
        }
        NotIn => {
            let arr = str_array(c);
            if arr.is_empty() {
                return "TRUE".to_string();
            }
            let i = next(binds);
            binds.push(Bind::TextArray(arr));
            format!("({expr} IS NOT NULL AND {expr} <> ALL(${i}::text[]))")
        }
    }
}

fn str_array(c: &Condition) -> Vec<String> {
    c.value
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn escape_like(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::condition::{Condition, ConditionOperator as Op, ConditionTarget as T};
    use crate::models::rule::{ConditionGroup, RuleTree};
    use serde_json::json;

    fn cond(t: T, op: Op, v: serde_json::Value) -> Condition {
        Condition {
            target: t,
            operator: op,
            value: v,
            value_end: None,
        }
    }

    #[test]
    fn grant_on_any_is_true() {
        let t = RuleTree {
            grant_on_any_relation: true,
            groups: vec![],
        };
        let (sql, binds) = build_rule_where(&t, 2);
        assert_eq!(sql, "TRUE");
        assert!(binds.is_empty());
    }

    #[test]
    fn empty_is_false() {
        let t = RuleTree::default();
        let (sql, _) = build_rule_where(&t, 2);
        assert_eq!(sql, "FALSE");
    }

    #[test]
    fn single_group_ands() {
        let t = RuleTree {
            grant_on_any_relation: false,
            groups: vec![ConditionGroup {
                conditions: vec![
                    cond(T::IsFollower, Op::Eq, json!(true)),
                    cond(T::FollowAgeDays, Op::Gte, json!(30)),
                ],
            }],
        };
        let (sql, binds) = build_rule_where(&t, 2);
        assert!(sql.contains(" AND "));
        assert!(sql.contains("ar.is_follower"));
        assert_eq!(binds.len(), 2);
    }

    #[test]
    fn mutual_uses_compound_expression() {
        let t = RuleTree {
            grant_on_any_relation: false,
            groups: vec![ConditionGroup {
                conditions: vec![cond(T::IsMutual, Op::Eq, json!(true))],
            }],
        };
        let (sql, _) = build_rule_where(&t, 0);
        assert!(sql.contains("is_follower"));
        assert!(sql.contains("is_followed_back"));
    }

    #[test]
    fn is_on_list_emits_exists() {
        let t = RuleTree {
            grant_on_any_relation: false,
            groups: vec![ConditionGroup {
                conditions: vec![cond(
                    T::IsOnList,
                    Op::Eq,
                    json!("at://did:plc:owner/app.bsky.graph.list/abc"),
                )],
            }],
        };
        let (sql, binds) = build_rule_where(&t, 2);
        assert!(sql.contains("EXISTS"));
        assert!(sql.contains("bsky_list_members"));
        assert_eq!(binds.len(), 1);
    }

    #[test]
    fn is_on_starter_pack_emits_exists() {
        let t = RuleTree {
            grant_on_any_relation: false,
            groups: vec![ConditionGroup {
                conditions: vec![cond(
                    T::IsOnStarterPack,
                    Op::Eq,
                    json!("at://did:plc:owner/app.bsky.graph.starterpack/xyz"),
                )],
            }],
        };
        let (sql, _binds) = build_rule_where(&t, 0);
        assert!(sql.contains("bsky_starter_pack_members"));
        assert!(sql.contains("pack_uri"));
    }

    #[test]
    fn handle_domain_in_list_uses_text_array() {
        let t = RuleTree {
            grant_on_any_relation: false,
            groups: vec![ConditionGroup {
                conditions: vec![cond(
                    T::HandleDomain,
                    Op::In,
                    json!(["bsky.social", "blacksky.community"]),
                )],
            }],
        };
        let (sql, binds) = build_rule_where(&t, 2);
        assert!(sql.contains("= ANY($3::text[])"));
        assert!(matches!(&binds[0], Bind::TextArray(v) if v.len() == 2));
    }

    #[test]
    fn description_contains_case_insensitive() {
        let t = RuleTree {
            grant_on_any_relation: false,
            groups: vec![ConditionGroup {
                conditions: vec![cond(T::Description, Op::Contains, json!("rolelogic"))],
            }],
        };
        let (sql, _binds) = build_rule_where(&t, 0);
        assert!(sql.contains("LOWER("));
    }

    #[test]
    fn between_emits_two_binds() {
        let mut c = cond(T::AccountAgeDays, Op::Between, json!(30));
        c.value_end = Some(json!(365));
        let t = RuleTree {
            grant_on_any_relation: false,
            groups: vec![ConditionGroup {
                conditions: vec![c],
            }],
        };
        let (sql, binds) = build_rule_where(&t, 0);
        assert!(sql.contains(">= $1") && sql.contains("<= $2"));
        assert_eq!(binds.len(), 2);
    }
}
