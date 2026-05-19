//! Condition target / operator types used in the rule tree.
//!
//! - `ConditionTarget` names a fact we can read from a (viewer, bsky-account) pair.
//! - `ConditionOperator` names a comparison.
//! - Validity of an (target, operator) combination is enforced at save time
//!   in [services::rule_validator] using each target's `kind()`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    Bool,
    Int,
    String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionTarget {
    // -- viewer × bsky-account facts (read from account_relations) --
    IsFollower,
    FollowAgeDays,
    IsFollowedBack,
    IsMutual,
    LikedPostsCount,
    RepostedPostsCount,
    RepliedPostsCount,

    // -- list / starter-pack membership (read from bsky_list_members /
    //    bsky_starter_pack_members; the rule's `value` carries the URI to
    //    check against) --
    IsOnList,
    IsOnStarterPack,

    // -- viewer account facts (read from bsky_users) --
    AccountAgeDays,
    PostsCount,
    FollowersCount,
    FollowsCount,
    Handle,
    HandleDomain,
    HasCustomDomain,
    DisplayName,
    Description,
    HasAvatar,
    HasBanner,
    PdsHost,
}

impl ConditionTarget {
    pub fn kind(self) -> TargetKind {
        use ConditionTarget::*;
        match self {
            IsFollower | IsFollowedBack | IsMutual | HasCustomDomain | HasAvatar | HasBanner => {
                TargetKind::Bool
            }
            FollowAgeDays | LikedPostsCount | RepostedPostsCount | RepliedPostsCount
            | AccountAgeDays | PostsCount | FollowersCount | FollowsCount => TargetKind::Int,
            // List / starter-pack membership: the operator is always Eq and
            // the value is a string (the URI). Treated as String for
            // validation, but the SQL builder special-cases them.
            IsOnList | IsOnStarterPack => TargetKind::String,
            Handle | HandleDomain | DisplayName | Description | PdsHost => TargetKind::String,
        }
    }

    pub fn as_str(self) -> &'static str {
        use ConditionTarget::*;
        match self {
            IsFollower => "is_follower",
            FollowAgeDays => "follow_age_days",
            IsFollowedBack => "is_followed_back",
            IsMutual => "is_mutual",
            LikedPostsCount => "liked_posts_count",
            RepostedPostsCount => "reposted_posts_count",
            RepliedPostsCount => "replied_posts_count",
            IsOnList => "is_on_list",
            IsOnStarterPack => "is_on_starter_pack",
            AccountAgeDays => "account_age_days",
            PostsCount => "posts_count",
            FollowersCount => "followers_count",
            FollowsCount => "follows_count",
            Handle => "handle",
            HandleDomain => "handle_domain",
            HasCustomDomain => "has_custom_domain",
            DisplayName => "display_name",
            Description => "description",
            HasAvatar => "has_avatar",
            HasBanner => "has_banner",
            PdsHost => "pds_host",
        }
    }

    pub fn from_key(s: &str) -> Option<Self> {
        use ConditionTarget::*;
        Some(match s {
            "is_follower" => IsFollower,
            "follow_age_days" => FollowAgeDays,
            "is_followed_back" => IsFollowedBack,
            "is_mutual" => IsMutual,
            "liked_posts_count" => LikedPostsCount,
            "reposted_posts_count" => RepostedPostsCount,
            "replied_posts_count" => RepliedPostsCount,
            "is_on_list" => IsOnList,
            "is_on_starter_pack" => IsOnStarterPack,
            "account_age_days" => AccountAgeDays,
            "posts_count" => PostsCount,
            "followers_count" => FollowersCount,
            "follows_count" => FollowsCount,
            "handle" => Handle,
            "handle_domain" => HandleDomain,
            "has_custom_domain" => HasCustomDomain,
            "display_name" => DisplayName,
            "description" => Description,
            "has_avatar" => HasAvatar,
            "has_banner" => HasBanner,
            "pds_host" => PdsHost,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionOperator {
    Eq,
    Neq,
    Gt,
    Gte,
    Lt,
    Lte,
    Between,
    Contains,
    Regex,
    In,
    NotIn,
}

impl ConditionOperator {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Eq => "eq",
            Self::Neq => "neq",
            Self::Gt => "gt",
            Self::Gte => "gte",
            Self::Lt => "lt",
            Self::Lte => "lte",
            Self::Between => "between",
            Self::Contains => "contains",
            Self::Regex => "regex",
            Self::In => "in",
            Self::NotIn => "not_in",
        }
    }

    pub fn from_key(s: &str) -> Option<Self> {
        Some(match s {
            "eq" => Self::Eq,
            "neq" => Self::Neq,
            "gt" => Self::Gt,
            "gte" => Self::Gte,
            "lt" => Self::Lt,
            "lte" => Self::Lte,
            "between" => Self::Between,
            "contains" => Self::Contains,
            "regex" => Self::Regex,
            "in" => Self::In,
            "not_in" => Self::NotIn,
            _ => return None,
        })
    }

    pub fn valid_for(self, kind: TargetKind) -> bool {
        use ConditionOperator::*;
        match kind {
            TargetKind::Bool => matches!(self, Eq),
            TargetKind::Int => matches!(self, Eq | Neq | Gt | Gte | Lt | Lte | Between),
            TargetKind::String => matches!(self, Eq | Neq | Contains | Regex | In | NotIn),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Condition {
    pub target: ConditionTarget,
    pub operator: ConditionOperator,
    pub value: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_end: Option<Value>,
}
