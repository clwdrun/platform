//! Identifiers that cannot be swapped for one another.
//!
//! Every row here is keyed by a UUID, so before this module a function taking
//! `(Uuid, Uuid)` accepted its arguments in either order and compiled either
//! way. `add_org_member(org_id, user_id)` and `add_org_member(user_id, org_id)`
//! are the same signature to the compiler and opposite meanings to the
//! database, which catches it only if a foreign key happens to disagree —
//! and `app_versions.id` versus `app_versions.app_id` have no constraint
//! between them at all.
//!
//! The same split was made in `clwdrun/clwd#56` for `SubjectId` and `OrgId`,
//! for the same reason and at a smaller call-site count than this one.
//!
//! # Why these are not in `shared`
//!
//! They are control-plane domain types, not wire contract. `gateway` and
//! `builder` have no rows and no reason to name a `VersionId`. `shared` holds
//! what crosses between components — the error envelope, the upload ceiling —
//! and stays small precisely so depending on it costs nothing.
//!
//! # The property, as a test rather than a claim
//!
//! Passing one kind of identifier where another belongs must not compile:
//!
//! ```compile_fail
//! use control_plane::ids::{AppId, VersionId};
//! fn takes_app(_: AppId) {}
//! takes_app(VersionId::new());
//! ```
//!
//! This lives in the module documentation rather than beside the unit tests
//! because rustdoc does not collect doc tests from inside `#[cfg(test)]`. An
//! earlier version put it there and it ran zero tests while looking present —
//! the failure `docs/development.md` names as a check that passes without
//! checking. If a `From<VersionId> for AppId` is ever added, this stops
//! failing and the build says so.

use std::fmt;

use uuid::Uuid;

/// Declares an identifier newtype over [`Uuid`].
///
/// Generated rather than hand-written four times so they cannot drift: the
/// point of the type is that `AppId` and `VersionId` behave identically and
/// are still not interchangeable, and four hand-written copies eventually
/// disagree about one derive.
///
/// `#[sqlx(transparent)]` makes the wrapper invisible to the driver, so a
/// column typed `uuid` decodes into it directly and `query_as!` keeps its
/// compile-time checking.
macro_rules! id {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash,
            serde::Serialize, serde::Deserialize, sqlx::Type,
        )]
        #[sqlx(transparent)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// A fresh identifier.
            ///
            /// UUIDv7, so it sorts by creation time: rows from one incident
            /// cluster in an index, and inserts append rather than scatter.
            /// Minted here rather than by the database because the caller
            /// needs the value before the `INSERT` — idempotent publish claims
            /// a key it must already be able to name.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            /// The underlying UUID.
            ///
            /// Deliberately a method rather than a public field or a `Deref`:
            /// unwrapping should be a visible act, because the moment two of
            /// these are bare `Uuid`s again they are interchangeable again.
            #[must_use]
            pub fn as_uuid(&self) -> Uuid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl From<Uuid> for $name {
            fn from(id: Uuid) -> Self {
                Self(id)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl std::str::FromStr for $name {
            type Err = uuid::Error;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                s.parse::<Uuid>().map(Self)
            }
        }
    };
}

id! {
    /// An organisation.
    OrgId
}

id! {
    /// A person.
    UserId
}

id! {
    /// An app. Distinct from [`VersionId`]: `app_versions` holds both, and no
    /// constraint stops one being written where the other belongs.
    AppId
}

id! {
    /// One published version of an app.
    VersionId
}

id! {
    /// An API token's row — never its secret.
    ///
    /// Safe to log, return and put in a URL: knowing it grants nothing, which
    /// is exactly why the secret lives in a different type.
    TokenId
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_sort_by_creation_order() {
        let first = VersionId::new();
        let second = VersionId::new();
        assert!(
            first < second,
            "UUIDv7 should order by time: {first} then {second}"
        );
    }

    #[test]
    fn display_and_parse_round_trip() {
        let id = AppId::new();
        let parsed: AppId = id.to_string().parse().expect("its own Display parses");
        assert_eq!(id, parsed);
    }

    #[test]
    fn the_inner_uuid_survives_the_wrapper() {
        let raw = Uuid::now_v7();
        assert_eq!(AppId::from(raw).as_uuid(), raw);
    }
}
