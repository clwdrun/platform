//! Authorization's wire types (#12): the decision, and the invalidation stream
//! the control plane relays to every gateway.
//!
//! The database numbers every committed change to a decision input (one
//! [`Seq`] per transaction, gap-free, in commit order) and names what it
//! touched as [`Tag`]s. The control plane relays those as [`Message`]s; a
//! gateway applies them in order, and treats a gap, a reconnect or a silent
//! stream as "everything may be stale". `docs/decisions/0003-authorization-cache.md`
//! states the guarantee this carries.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// How long a gateway may serve cached decisions after the control plane last
/// renewed its lease. The worst-case revoke latency, and the bound for changes
/// made outside the API.
pub const LEASE: Duration = Duration::from_secs(3);

/// How often the relay heartbeats, and so how often a gateway renews its lease.
pub const HEARTBEAT: Duration = Duration::from_secs(1);

/// The longest any cached decision lives, whatever the stream says: the bound
/// that holds even if invalidation itself is wrong.
pub const MAX_AGE: Duration = Duration::from_secs(60);

/// A position in the invalidation stream: one per committed transaction that
/// changed a decision input. Gap-free and in commit order, so a missing number
/// is a lost message, never a rolled-back write.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Seq(u64);

impl Seq {
    /// Before any change.
    pub const ZERO: Self = Self(0);

    #[must_use]
    pub const fn new(n: u64) -> Self {
        Self(n)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// The number that must come next for nothing to have been missed.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }

    /// From Postgres's `bigint`. `None` for a negative value, which the
    /// counter's check constraint rules out.
    #[must_use]
    pub fn from_db(n: i64) -> Option<Self> {
        u64::try_from(n).ok().map(Self)
    }

    /// For a `bigint` parameter. Saturates: no counter reaches `i64::MAX`.
    #[must_use]
    pub fn to_db(self) -> i64 {
        i64::try_from(self.0).unwrap_or(i64::MAX)
    }
}

impl std::fmt::Display for Seq {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Something a cached decision was derived from. A change to it invalidates
/// every decision carrying the tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum Tag {
    AppSession(Uuid),
    Session(Uuid),
    User(Uuid),
    App(Uuid),
    Org(Uuid),
}

impl Tag {
    /// From an outbox row's `kind`. `None` for `all`, which is a flush rather
    /// than a tag, and for anything unknown.
    #[must_use]
    pub fn from_kind(kind: &str, id: Uuid) -> Option<Self> {
        Some(match kind {
            "app_session" => Self::AppSession(id),
            "session" => Self::Session(id),
            "user" => Self::User(id),
            "app" => Self::App(id),
            "org" => Self::Org(id),
            _ => return None,
        })
    }
}

/// One line of the invalidation stream (newline-delimited JSON).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Message {
    /// The first line: where the stream starts. A gateway flushes and takes
    /// this as its position; history is never replayed.
    Hello { seq: Seq },
    /// One committed transaction. `flush` means every cached decision.
    Event {
        seq: Seq,
        flush: bool,
        tags: Vec<Tag>,
    },
    /// The relay is alive and has relayed everything through `seq`. Sent only
    /// while the relay is healthy, so silence means "stop trusting the cache".
    Heartbeat { seq: Seq },
}

impl Message {
    #[must_use]
    pub fn seq(&self) -> Seq {
        match self {
            Self::Hello { seq } | Self::Event { seq, .. } | Self::Heartbeat { seq } => *seq,
        }
    }
}

/// A gateway's acknowledgement: everything through `applied` is applied. A
/// successful ack also renews the gateway's lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ack {
    pub gateway: Uuid,
    pub applied: Seq,
}

/// Why a request was allowed or denied. Its code is what a denial's envelope
/// is chosen from. #14 adds reasons.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Reason {
    /// The interim rule: the visitor is a member of the app's org.
    OrgMember,
    /// Signed in, but not a member of the app's org.
    NotAMember,
}

impl Reason {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::OrgMember => "org_member",
            Self::NotAMember => "not_a_member",
        }
    }
}

/// Allow or deny, and why. Nothing reaches app code without an
/// [`Decision::is_allow`].
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "effect", content = "reason", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Decision {
    Allow(Reason),
    Deny(Reason),
}

impl Decision {
    pub const fn allow(reason: Reason) -> Self {
        Self::Allow(reason)
    }

    pub const fn deny(reason: Reason) -> Self {
        Self::Deny(reason)
    }

    #[must_use]
    pub const fn is_allow(self) -> bool {
        matches!(self, Self::Allow(_))
    }

    #[must_use]
    pub const fn reason(self) -> Reason {
        match self {
            Self::Allow(reason) | Self::Deny(reason) => reason,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_round_trip_as_one_json_line_each() {
        let id = Uuid::now_v7();
        for message in [
            Message::Hello { seq: Seq::new(7) },
            Message::Event {
                seq: Seq::new(8),
                flush: false,
                tags: vec![Tag::Session(id), Tag::User(id)],
            },
            Message::Heartbeat { seq: Seq::new(8) },
        ] {
            let line = serde_json::to_string(&message).expect("serializes");
            assert!(!line.contains('\n'));
            assert_eq!(
                serde_json::from_str::<Message>(&line).expect("parses"),
                message
            );
        }
    }

    #[test]
    fn a_negative_counter_is_not_a_seq() {
        assert_eq!(Seq::from_db(-1), None);
        assert_eq!(Seq::from_db(3), Some(Seq::new(3)));
        assert_eq!(Seq::new(3).next(), Seq::new(4));
    }
}
