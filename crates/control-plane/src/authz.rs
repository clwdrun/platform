//! Per-request authorization (#12): the decision point, and the list of what
//! it is decided from.
//!
//! The gateway caches allow decisions; [`crate::relay`] tells it when one may
//! be stale. Both rest on [`INPUTS`]: every table the decision statement reads,
//! each of which carries the database's invalidation triggers. A test holds
//! the statement's plan, the triggers in `pg_trigger` and this list to one
//! another, so a table added to the decision without its triggers fails the
//! gate rather than becoming a revocation that never reaches a gateway.

use shared::authz::{Decision, Reason};

use crate::ids::{AppId, OrgId, UserId};

/// One decision input: a table, and the kind of [`shared::authz::Tag`] its
/// changes invalidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Input {
    pub table: &'static str,
    pub kind: &'static str,
}

/// Every table `queries/authz_check.sql` reads, as the migration's
/// `authz_watch` calls set them up. The single source for the trigger check
/// (the relay's, and the gate's) and for the staleness tests' cases.
pub const INPUTS: &[Input] = &[
    Input {
        table: "app_sessions",
        kind: "app_session",
    },
    Input {
        table: "sessions",
        kind: "session",
    },
    Input {
        table: "users",
        kind: "user",
    },
    Input {
        table: "apps",
        kind: "app",
    },
    Input {
        table: "orgs",
        kind: "org",
    },
    Input {
        table: "org_members",
        kind: "user",
    },
    Input {
        table: "app_subjects",
        kind: "user",
    },
];

/// The triggers each input carries, by name. All must exist and be enabled
/// (`tgenabled = 'O'`) for the cache to be trusted.
pub const TRIGGERS: &[&str] = &["authz_ins", "authz_upd", "authz_del", "authz_truncate"];

/// Who is asking. #14 adds group memberships.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Principal {
    pub user_id: UserId,
}

impl Principal {
    #[must_use]
    pub const fn user(user_id: UserId) -> Self {
        Self { user_id }
    }
}

/// What they want to do. Only `view` exists before #14.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Action {
    View,
}

/// What they want to do it to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Resource {
    App { app_id: AppId, org_id: OrgId },
}

/// The facts a policy decides from, loaded by the same statement as the
/// principal. #14's Cedar entities replace this with grants and groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Context {
    /// Whether the principal is a member of the resource's org.
    pub member_of_org: bool,
}

impl Context {
    #[must_use]
    pub const fn new(member_of_org: bool) -> Self {
        Self { member_of_org }
    }
}

/// One authorization question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Request {
    pub principal: Principal,
    pub action: Action,
    pub resource: Resource,
    pub context: Context,
}

impl Request {
    #[must_use]
    pub const fn new(
        principal: Principal,
        action: Action,
        resource: Resource,
        context: Context,
    ) -> Self {
        Self {
            principal,
            action,
            resource,
            context,
        }
    }
}

/// The decision point. A pure function of the request: everything it needs is
/// loaded before it is called, so a policy is tested without a database and
/// can never add a query to the request path. #14's Cedar evaluation
/// implements this.
pub trait Authorize: Send + Sync {
    fn decide(&self, request: &Request) -> Decision;
}

/// The interim rule until #14: members of the app's org may view it.
#[derive(Debug, Clone, Copy, Default)]
pub struct OrgMemberRule;

impl Authorize for OrgMemberRule {
    fn decide(&self, request: &Request) -> Decision {
        match request.action {
            Action::View if request.context.member_of_org => Decision::allow(Reason::OrgMember),
            Action::View => Decision::deny(Reason::NotAMember),
        }
    }
}

/// The policy in force. #14 replaces it.
pub const POLICY: &dyn Authorize = &OrgMemberRule;

#[cfg(test)]
mod tests {
    use super::*;

    fn request(member: bool) -> Request {
        Request::new(
            Principal::user(UserId::new()),
            Action::View,
            Resource::App {
                app_id: AppId::new(),
                org_id: OrgId::new(),
            },
            Context::new(member),
        )
    }

    #[test]
    fn the_interim_rule_allows_members_and_only_members() {
        assert_eq!(
            OrgMemberRule.decide(&request(true)),
            Decision::allow(Reason::OrgMember)
        );
        assert_eq!(
            OrgMemberRule.decide(&request(false)),
            Decision::deny(Reason::NotAMember)
        );
    }

    #[test]
    fn every_input_names_a_known_tag_kind() {
        for input in INPUTS {
            assert!(
                shared::authz::Tag::from_kind(input.kind, uuid::Uuid::nil()).is_some(),
                "{input:?}"
            );
        }
    }
}
