//! The wire error every platform component emits.
//!
//! # One contract, two repositories
//!
//! This mirrors the envelope `clwd` publishes in `docs/error-codes.md`, field
//! for field, so a caller learns one error contract rather than two:
//!
//! ```json
//! {"code":"…","message":"…","hint":null,"retryable":false,"request_id":"…"}
//! ```
//!
//! `request_id` is the one field the CLI's envelope does not carry, and it goes
//! **last** so the shared prefix is byte-identical for an equivalent error. That
//! is asserted against a literal in the tests rather than by re-serialising —
//! comparing two serialisations of the same struct proves only that `serde` is
//! deterministic.
//!
//! `hint` is always present and never omitted: a consumer indexes the key
//! unconditionally. Every code this crate emits carries one — a null hint is a
//! dead end for the caller least able to work out what to do — but the field
//! stays nullable in the shape, so a consumer written against the CLI's
//! envelope keeps working.
//!
//! # The prefix names the subsystem that decided
//!
//! Codes are `<component>.<condition>`, lowercase. A caller told
//! `bundle.member_digest_mismatch` can rebuild their bundle; one told
//! `control-plane.internal` learns only that something, somewhere, went wrong.
//! That is why `Bundle` is a **delegating** variant whose `code()` returns its
//! source's string unchanged, exactly as `clwd_runtime::Error` does for the same
//! reason.

use std::fmt;

use serde::Serialize;

/// Declares `Error`, its `code()`, its HTTP `status()`, and the list of codes
/// this crate owns — all from one input, so a variant cannot ship without any
/// of them.
///
/// # Two non-obvious properties of the attribute handling
///
/// **`#[error(transparent)]` is written by this macro rather than accepted from
/// the invocation.** An attribute passed through a `$(#[$a:meta])*` fragment
/// carries the macro's hygiene context, so `thiserror` resolves `transparent` as
/// an identifier in *this* scope and fails with ``cannot find value
/// `transparent` ``. It is also the better contract: a delegating variant is
/// transparent by construction, so making it an input offers a choice with one
/// correct answer.
///
/// **No attributes are forwarded to the generated `match` arms.** Both sections
/// accept attributes and both put them on the *variant* only, which is the only
/// place they are valid.
///
/// `#[error]` on a match arm fails with ``cannot find attribute `error` `` — it
/// is a `thiserror` variant attribute. A doc comment on a match arm is an
/// unused-doc warning, which `-D warnings` turns into a build failure; that is
/// what an earlier version of this macro did, forwarding the delegating
/// variant's doc comment onto four arms at once.
///
/// `clwdrun/clwd`'s equivalent macro *does* forward, because its delegating
/// variant sits behind `#[cfg(feature = "run")]` and the gate has to reach the
/// arms or they name a variant that does not exist. Nothing here is
/// feature-gated, so forwarding would buy nothing and cost the doc comment.
/// **If a variant here ever needs a `#[cfg]`, copy that pattern rather than
/// re-deriving it: the gate goes to the arms, and the prose moves to the module.**
macro_rules! define_error {
    (
        // Braced so the two repetitions are bounded: without a delimiter the
        // parser cannot tell the `owned` keyword from another variant name.
        delegating {
            $(
                $(#[$dattr:meta])*
                $dvariant:ident { source: $dty:ty } => $dstatus:expr;
            )*
        }
        owned {
            $(
                $(#[$attr:meta])*
                $variant:ident { $($field:tt)* } => $code:literal, $status:expr, $retry:literal,
                    meaning: $meaning:literal, hint: $hint:literal;
            )*
        }
    ) => {
        #[derive(Debug, thiserror::Error)]
        #[non_exhaustive]
        pub enum Error {
            $( $(#[$dattr])* #[error(transparent)] $dvariant { source: $dty }, )*
            $( $(#[$attr])* $variant { $($field)* }, )*
        }

        impl Error {
            /// The stable code for this failure.
            ///
            /// A delegating variant returns its source's code **unchanged** —
            /// see the module documentation.
            pub fn code(&self) -> &'static str {
                match self {
                    $( Self::$dvariant { source } => source.code(), )*
                    $( Self::$variant { .. } => $code, )*
                }
            }

            /// The HTTP status this failure is reported with.
            ///
            /// Generated from the same invocation as `code()`, so a variant
            /// cannot ship without one. A hand-kept mapping beside the enum
            /// would let a new variant default to 500 silently, and 500 is the
            /// one status that should never be a default — it says "our fault"
            /// about something that may well be the caller's.
            pub fn status(&self) -> u16 {
                match self {
                    $( Self::$dvariant { .. } => $dstatus, )*
                    $( Self::$variant { .. } => $status, )*
                }
            }

            /// Whether retrying the same request unchanged could plausibly
            /// succeed.
            ///
            /// Spelled per variant with no default arm, so adding one forces a
            /// decision rather than inheriting `false`.
            pub fn retryable(&self) -> bool {
                match self {
                    // `clwd_bundle::Error::retryable` is `false` for its whole
                    // catalogue and says so: a malformed bundle does not become
                    // well formed on a second attempt. Forwarded rather than
                    // restated, so it stays true if that ever changes.
                    $( Self::$dvariant { source } => source.retryable(), )*
                    $( Self::$variant { .. } => $retry, )*
                }
            }

            /// What to do about it: a short, actionable next step.
            ///
            /// Never absent. `meaning` and `hint` are required literals in the
            /// invocation, so a code cannot ship without either.
            pub fn hint(&self) -> &'static str {
                match self {
                    // `clwd_bundle::Error` has `code()` and `retryable()` but no
                    // `hint()`, so there is nothing to forward. This points at
                    // the published table rather than restating 38 entries here,
                    // where they would drift from it.
                    //
                    // That is papering over an absence, not a design: the text
                    // belongs with the crate that owns the code, and
                    // `clwdrun/clwd#63` is the fix.
                    $( Self::$dvariant { .. } => DELEGATED_HINT, )*
                    $( Self::$variant { .. } => $hint, )*
                }
            }

            /// What the failure means, in a sentence a caller can act on.
            pub fn meaning(&self) -> &'static str {
                match self {
                    $( Self::$dvariant { .. } => DELEGATED_MEANING, )*
                    $( Self::$variant { .. } => $meaning, )*
                }
            }
        }

        /// Every code this crate owns, generated from the same input as the
        /// enum.
        ///
        /// Delegated codes are deliberately absent: they belong to the crate
        /// that defines them and are catalogued there.
        pub const OWNED_CODES: &[&str] = &[$($code),*];

        /// Every owned code with its status, retryability, meaning and hint,
        /// generated from the same input as the enum.
        ///
        /// Public because two consumers need the table without constructing an
        /// error: the envelope probe, which asserts every response's status is
        /// the one its code declares, and the OpenAPI document (#3), which
        /// publishes it.
        pub const CATALOGUE: &[Code] = &[$(Code {
            code: $code,
            status: $status,
            retryable: $retry,
            meaning: $meaning,
            hint: $hint,
        }),*];
    };
}

/// What a delegated error offers in place of a hint of its own.
///
/// A real next step rather than a null. The table it points at is generated from
/// the code, so this cannot drift from it the way a restatement would.
pub const DELEGATED_HINT: &str =
    "see docs/error-codes.md in clwdrun/clwd for this code's meaning and how to recover";

/// What a delegated `bundle.*` error means, in place of per-code text this crate
/// cannot see — `clwd_bundle` does not expose its codes or their meanings yet.
pub const DELEGATED_MEANING: &str = "The uploaded bundle was rejected by the bundle format. The code, `bundle.*`, names the specific defect.";

/// One owned code, as the catalogue publishes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Code {
    /// The stable `<component>.<condition>` identifier a caller branches on.
    pub code: &'static str,
    /// The HTTP status it is reported with.
    pub status: u16,
    /// Whether retrying the same request unchanged could succeed.
    pub retryable: bool,
    /// What the failure means.
    pub meaning: &'static str,
    /// What to do about it.
    pub hint: &'static str,
}

define_error! {
    delegating {
        /// A bundle the caller supplied was rejected by the format.
        ///
        /// 400, because these arrive from bytes a caller just uploaded — their
        /// bundle is malformed and they can fix it. Decoding bytes *already in
        /// storage* is a different situation and must not use this variant: that
        /// is a server-side integrity failure and maps to
        /// `control-plane.artifact_corrupt` at 500. See the comments on
        /// `platform#6` and `platform#23`.
        Bundle { source: clwd_bundle::Error } => 400;
    }

    owned {
        /// A request body or parameter the API would not accept.
        #[error("invalid request: {what}")]
        InvalidRequest { what: String } => "control-plane.invalid_request", 400, false,
            meaning: "A request body or parameter was not acceptable. The message says which part and why.",
            hint: "check the request against the OpenAPI schema at /openapi.json";

        /// A request body larger than the endpoint accepts.
        ///
        /// 413 rather than 400, because the distinction is actionable: a client
        /// or proxy can retry a 400 with a corrected body, and cannot retry a
        /// 413 with the same one. The message carries the limit so the caller
        /// learns it from the response rather than from documentation.
        #[error("{what}")]
        PayloadTooLarge { what: String } => "control-plane.payload_too_large", 413, false,
            meaning: "The request body is larger than this endpoint accepts. The message states the limit.",
            hint: "reduce the upload below the stated limit";

        /// The path exists, but not for this method.
        ///
        /// Not retryable: a `DELETE` sent to a `POST`-only route gets this answer
        /// forever. The methods that would work are in the response's `Allow`
        /// header, which HTTP requires on a 405 and the router already sets.
        #[error("method not allowed on this path")]
        MethodNotAllowed {} => "control-plane.method_not_allowed", 405, false,
            meaning: "The path exists, but not for this HTTP method.",
            hint: "use one of the methods named in the Allow header";

        /// The request carries no valid credential.
        ///
        /// No header, a malformed one, an unknown token and a revoked token
        /// are all this one value, deliberately. Distinguishing "revoked" from
        /// "never existed" would tell whoever holds a leaked token that it was
        /// once real.
        ///
        /// `identity.*` rather than `control-plane.*`: the prefix names the
        /// subsystem that decided, and authentication decisions belong to
        /// identity whichever process makes them — the control plane today,
        /// `identity` (#9) and the gateway (#11) later.
        #[error("authentication required")]
        Unauthenticated {} => "identity.unauthenticated", 401, false,
            meaning: "The request carries no valid credential: the Authorization header is missing or malformed, or the token is unknown or revoked. These are deliberately indistinguishable.",
            hint: "supply a valid, unrevoked API token as `Authorization: Bearer <token>`";

        /// The caller is authenticated but not permitted to do this: a token
        /// lacking the route's scope, a session member who is not the one
        /// allowed to make the change, or a session request that did not come
        /// from the control plane's own origin.
        ///
        /// Only for a resource the caller may see. A resource outside the
        /// token's org or app binding is `control-plane.not_found`, because a
        /// 403 there would confirm the resource exists.
        #[error("not permitted: {what}")]
        Forbidden { what: String } => "identity.forbidden", 403, false,
            meaning: "The caller is authenticated but not permitted to do this: a token without the scope the operation requires, a signed-in user who is not the one allowed to make this change, or a browser request from another origin. The message says which.",
            hint: "act on what the message names: a token with that scope, the permitted user, or a request from the control plane's own pages";

        /// A named resource does not exist, or the caller may not see it.
        ///
        /// Deliberately does not distinguish the two. Telling an unauthorised
        /// caller that a thing exists is an enumeration oracle.
        #[error("not found: {what}")]
        NotFound { what: String } => "control-plane.not_found", 404, false,
            meaning: "The resource does not exist, or it is outside what this token can reach — another org, or another app when the token is bound to one. These are deliberately indistinguishable.",
            hint: "check the identifier, and that the token's org, and its app if it is bound to one, cover this resource";

        /// The request conflicts with the current state — a slug already taken,
        /// a version already published under a different digest.
        #[error("conflict: {what}")]
        Conflict { what: String } => "control-plane.conflict", 409, false,
            meaning: "The request conflicts with the resource's current state.",
            hint: "re-read the resource and retry with the current state";

        /// A bundle whose manifest grants outbound network access.
        ///
        /// Refused until the platform can filter egress by address (#11's
        /// follow-up). The runtime enforces egress by host name only, and a
        /// name that resolves to loopback, link-local or a private range would
        /// reach the host, the cloud metadata service and anything internal.
        /// The worker refuses such a bundle at spawn as well; this refusal is
        /// the early one, so a developer finds out at deploy.
        #[error("outbound network access is not supported yet: the manifest grants egress to {hosts}")]
        EgressNotSupported { hosts: String } => "control-plane.egress_not_supported", 400, false,
            meaning: "The bundle's manifest grants outbound network access (`capabilities.egress`), which deployed apps cannot use yet. Nothing was published.",
            hint: "remove the hosts from `capabilities.egress` in clwd.toml, rebuild, and publish again";

        /// A stored artifact could not be decoded.
        ///
        /// **Not a `bundle.*` code, deliberately.** The bytes passed validation
        /// when they were ingested, so failing to decode them now means storage
        /// corruption, a truncated write, or a bad restore. Delegating here would
        /// return 400 and blame the caller for our own integrity failure, and
        /// would file a real incident under client errors where nobody looks.
        #[error("stored artifact {digest} could not be read")]
        ArtifactCorrupt { digest: String } => "control-plane.artifact_corrupt", 500, false,
            meaning: "A stored artifact could not be decoded. This is a server-side integrity failure, not a problem with the request.",
            hint: "this is a server-side integrity failure; the artifact must be rebuilt and republished";

        /// A dependency did not answer in time.
        ///
        /// Retryable, and the reason `retryable` is worth carrying at all: a
        /// field that is uniformly `false` is decorative, and nobody notices
        /// when it is wired wrong.
        #[error("timed out talking to {dependency}")]
        Timeout { dependency: String } => "control-plane.timeout", 504, true,
            meaning: "The request exceeded its time budget, or a dependency did not answer in time.",
            hint: "retry; if it persists the dependency is down rather than slow";

        /// This token has used its request budget.
        ///
        /// Retryable, and separate from `identity.forbidden` for exactly that
        /// reason: a caller that cannot tell "retry in a moment" from "you may
        /// not do this" either hammers or gives up. The wait is in the message
        /// and, for a client that reads headers rather than bodies, in
        /// `Retry-After`.
        #[error("rate limit exceeded; retry in {retry_after_secs}s")]
        RateLimited { retry_after_secs: u64 } => "control-plane.rate_limited", 429, true,
            meaning: "This token has used its request budget. The message and the Retry-After header say how long to wait.",
            hint: "retry after the number of seconds in the Retry-After header";

        /// Last resort only, never where a specific variant fits.
        #[error("internal error")]
        Internal {
            #[source]
            source: anyhow::Error,
        } => "control-plane.internal", 500, false,
            meaning: "An unexpected failure inside the service.",
            hint: "this is a defect; report it with the request id";
    }
}

/// Correlates a response with the log lines it produced.
///
/// Accepted from the client when it is well formed, generated otherwise. See
/// [`RequestId::sanitize`] for what "well formed" means and why it is checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestId(String);

impl RequestId {
    /// The longest client-supplied id accepted.
    ///
    /// Long enough for a UUID or a trace id with room to spare, short enough
    /// that it cannot be used to pad a log line into something expensive.
    pub const MAX_LEN: usize = 128;

    /// A fresh id.
    pub fn generate() -> Self {
        Self(uuid::Uuid::now_v7().to_string())
    }

    /// Accept a client-supplied id, or `None` if it is not usable.
    ///
    /// **This validates rather than trusts.** The id reaches log lines, and an
    /// unvalidated client string in a log line is log injection: a CR or LF lets
    /// a caller forge whole log entries, and a non-printable byte can corrupt a
    /// terminal or a downstream parser. So: ASCII visible characters only, no
    /// control bytes of any kind, and bounded length.
    ///
    /// Rejecting is silent — the caller gets a generated id rather than an
    /// error, because a malformed correlation header should not fail a request
    /// that is otherwise fine.
    pub fn sanitize(candidate: &str) -> Option<Self> {
        if candidate.is_empty() || candidate.len() > Self::MAX_LEN {
            return None;
        }
        // `is_ascii_graphic` is exactly "visible ASCII, no space, no control".
        if !candidate.bytes().all(|b| b.is_ascii_graphic()) {
            return None;
        }
        Some(Self(candidate.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The wire error, as serialized.
///
/// Field order is part of the contract: `code, message, hint, retryable` matches
/// the CLI's envelope byte for byte, and `request_id` follows.
#[derive(Debug, Serialize)]
pub struct Envelope<'a> {
    pub code: &'a str,
    pub message: String,
    pub hint: Option<&'a str>,
    pub retryable: bool,
    pub request_id: &'a str,
}

impl<'a> Envelope<'a> {
    pub fn new(error: &'a Error, request_id: &'a RequestId) -> Self {
        Self {
            code: error.code(),
            message: error.to_string(),
            hint: Some(error.hint()),
            retryable: error.retryable(),
            request_id: request_id.as_str(),
        }
    }
}

impl From<clwd_bundle::Error> for Error {
    fn from(source: clwd_bundle::Error) -> Self {
        Self::Bundle { source }
    }
}

/// One realistic instance of every owned code, in declaration order.
///
/// These are what the OpenAPI document shows as each code's example, serialised
/// through [`Envelope`] exactly as the wire carries them, and what the tests use
/// to prove the catalogue and the enum agree. A variant missing here fails
/// `owned_codes_are_exhaustive_over_variants`.
#[must_use]
pub fn owned_samples() -> Vec<Error> {
    vec![
        Error::InvalidRequest {
            what: "token request: missing field `name` at line 1 column 25".into(),
        },
        Error::PayloadTooLarge {
            what: format!(
                "request body exceeds the {} byte limit",
                crate::MAX_BUNDLE_BYTES
            ),
        },
        Error::MethodNotAllowed {},
        Error::Unauthenticated {},
        Error::Forbidden {
            what: "this route needs the `publish` scope".into(),
        },
        Error::NotFound {
            what: "app 0198f0c1-8b3e-7000-8000-0000000000a2".into(),
        },
        Error::Conflict {
            what: "slug acme is already taken".into(),
        },
        Error::ArtifactCorrupt {
            digest: format!("blake3:{}", "5f".repeat(32)),
        },
        Error::EgressNotSupported {
            hosts: "api.example.com".into(),
        },
        Error::Timeout {
            dependency: "the database".into(),
        },
        Error::RateLimited {
            retry_after_secs: 3,
        },
        Error::Internal {
            source: anyhow::anyhow!("an unexpected failure"),
        },
    ]
}

/// One realistic delegated error: a bundle whose member does not match its
/// recorded digest. Shown as the example for the `bundle.*` family.
#[must_use]
pub fn bundle_sample() -> Error {
    Error::from(clwd_bundle::Error::MemberDigestMismatch {
        path: "app.wasm".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// The namespaces this crate may declare codes in.
    ///
    /// `identity` is here because authentication decisions are identity's
    /// whichever process makes them; see `Error::Unauthenticated`. Widening
    /// this list is a deliberate act, so it is a list rather than a pattern.
    const OWNED_NAMESPACES: &[&str] = &["control-plane", "identity"];

    /// The two authentication codes, pinned as strings: `#3` publishes them,
    /// and a caller branches on them.
    #[test]
    fn authentication_codes_are_identity_codes() {
        assert_eq!(Error::Unauthenticated {}.code(), "identity.unauthenticated");
        assert_eq!(Error::Unauthenticated {}.status(), 401);
        let forbidden = Error::Forbidden { what: "x".into() };
        assert_eq!(forbidden.code(), "identity.forbidden");
        assert_eq!(forbidden.status(), 403);
    }

    /// A rate limit is the second retryable code, and must stay retryable:
    /// a caller told to stop rather than wait gives up on a working token.
    #[test]
    fn a_rate_limit_is_retryable_and_says_how_long() {
        let err = Error::RateLimited {
            retry_after_secs: 7,
        };
        assert_eq!(err.code(), "control-plane.rate_limited");
        assert_eq!(err.status(), 429);
        assert!(err.retryable());
        assert!(err.to_string().contains('7'), "the wait is in the message");
    }

    /// Every code carries real text in both fields, and they say different
    /// things: what happened, and what to do.
    #[test]
    fn every_code_has_a_meaning_and_a_hint() {
        for entry in CATALOGUE {
            assert!(
                entry.meaning.len() > 20,
                "{} has no real meaning",
                entry.code
            );
            assert!(entry.hint.len() > 10, "{} has no real hint", entry.code);
            assert_ne!(
                entry.meaning, entry.hint,
                "{}: one text for two purposes",
                entry.code
            );
        }
        for sample in owned_samples() {
            let entry = CATALOGUE.iter().find(|e| e.code == sample.code());
            assert_eq!(
                entry.map(|e| e.hint),
                Some(sample.hint()),
                "{}",
                sample.code()
            );
            assert_eq!(
                entry.map(|e| e.meaning),
                Some(sample.meaning()),
                "{}",
                sample.code()
            );
        }
    }

    #[test]
    fn owned_codes_are_unique() {
        let unique: BTreeSet<&str> = OWNED_CODES.iter().copied().collect();
        assert_eq!(unique.len(), OWNED_CODES.len(), "duplicate code");
    }

    #[test]
    fn owned_codes_are_exhaustive_over_variants() {
        let produced: BTreeSet<&str> = owned_samples().iter().map(Error::code).collect();
        let declared: BTreeSet<&str> = OWNED_CODES.iter().copied().collect();
        assert_eq!(
            produced, declared,
            "a variant is missing from `owned_samples()` or from the enum"
        );
    }

    #[test]
    fn owned_codes_are_namespaced_and_lowercase() {
        for code in OWNED_CODES {
            let (ns, rest) = code
                .split_once('.')
                .unwrap_or_else(|| panic!("{code} is not namespaced"));
            assert!(
                !ns.is_empty() && !rest.is_empty(),
                "{code} has an empty half"
            );
            assert_eq!(*code, code.to_lowercase(), "{code} is not lowercase");
            assert!(
                OWNED_NAMESPACES.contains(&ns),
                "{code} is not in a namespace this crate owns"
            );
        }
    }

    /// The status table, enforced rather than documented.
    #[test]
    fn every_owned_code_has_a_sane_status() {
        for &Code { code, status, .. } in CATALOGUE {
            assert!(
                (400..=599).contains(&status),
                "{code} maps to {status}, which is not an error status"
            );
        }
    }

    /// A variant's declared status must be what `status()` actually returns —
    /// the table and the code cannot drift because they are one input.
    #[test]
    fn status_matches_the_declared_table() {
        for err in owned_samples() {
            let declared = CATALOGUE
                .iter()
                .find(|entry| entry.code == err.code())
                .map(|entry| entry.status)
                .unwrap_or_else(|| panic!("{} is not in the catalogue", err.code()));
            assert_eq!(err.status(), declared, "for {}", err.code());
        }
    }

    /// **At least one code must be retryable.** A field that is uniformly
    /// `false` is decorative, and nobody notices when it is wired wrong.
    #[test]
    fn at_least_one_code_is_retryable() {
        let retryable: Vec<&str> = owned_samples()
            .iter()
            .filter(|e| e.retryable())
            .map(|e| e.code())
            .collect();
        assert!(
            !retryable.is_empty(),
            "no code is retryable, so the field carries no signal"
        );
        assert!(
            retryable.contains(&"control-plane.timeout"),
            "a timeout is the archetypal retryable failure; got {retryable:?}"
        );
    }

    /// All 38 `bundle.*` codes report 400: the bytes came from the caller in
    /// the same request, so a decode failure is theirs to fix.
    #[test]
    fn a_delegated_bundle_code_passes_through_verbatim_at_400() {
        let err = Error::from(clwd_bundle::Error::MemberDigestMismatch {
            path: "app.wasm".into(),
        });
        assert_eq!(err.code(), "bundle.member_digest_mismatch");
        assert_eq!(err.status(), 400);
        assert!(!err.retryable(), "a malformed bundle stays malformed");
        assert_eq!(err.hint(), DELEGATED_HINT);
    }

    /// Reading a *stored* artifact that will not decode is our failure, not the
    /// caller's, and must not borrow a `bundle.*` code.
    #[test]
    fn a_corrupt_stored_artifact_is_ours_not_the_callers() {
        let err = Error::ArtifactCorrupt {
            digest: "blake3:abc".into(),
        };
        assert_eq!(err.code(), "control-plane.artifact_corrupt");
        assert_eq!(err.status(), 500, "blaming the caller here would be a lie");
    }

    /// The envelope is byte-identical to the CLI's for the shared fields, with
    /// `request_id` last.
    ///
    /// Compared against a literal rather than a re-serialization: serializing
    /// the same struct twice proves only that `serde` is deterministic.
    #[test]
    fn the_envelope_matches_the_cli_byte_for_byte() {
        let err = Error::NotFound {
            what: "app dashboard".into(),
        };
        let id = RequestId::sanitize("req-42").expect("well formed");
        let json = serde_json::to_string(&Envelope::new(&err, &id)).expect("serializes");

        assert_eq!(
            json,
            r#"{"code":"control-plane.not_found","message":"not found: app dashboard","hint":"check the identifier, and that the token's org, and its app if it is bound to one, cover this resource","retryable":false,"request_id":"req-42"}"#
        );
    }

    /// `hint` is present as `null`, never omitted, so a consumer can index it
    /// unconditionally.
    #[test]
    fn a_none_hint_serializes_as_null_rather_than_being_dropped() {
        // No code this crate emits has a null hint any more, so the shape is
        // exercised directly: the field stays nullable for consumers of the
        // CLI's envelope, and `null` must still be present rather than dropped.
        let value: serde_json::Value = serde_json::to_value(Envelope {
            code: "cli.not_found",
            message: "x".into(),
            hint: None,
            retryable: false,
            request_id: "r",
        })
        .expect("serializes");
        let object = value.as_object().expect("an object");

        assert!(object.contains_key("hint"), "the key must be present");
        assert!(object["hint"].is_null());
    }

    #[test]
    fn a_well_formed_request_id_is_accepted() {
        for candidate in ["req-42", "0198f0c1-8b3e-7000-8000-000000000000", "a"] {
            assert!(
                RequestId::sanitize(candidate).is_some(),
                "{candidate:?} should be accepted"
            );
        }
    }

    /// **Log injection is the reason this validates rather than trusts.** A CR
    /// or LF in a client-supplied id lets a caller forge whole log entries.
    #[test]
    fn a_malformed_request_id_is_rejected() {
        let too_long = "a".repeat(RequestId::MAX_LEN + 1);
        for candidate in [
            "",
            "req\nINFO forged log line",
            "req\rrewritten",
            "req 42",
            "req\u{0}nul",
            "réq",
            too_long.as_str(),
        ] {
            assert!(
                RequestId::sanitize(candidate).is_none(),
                "{candidate:?} should be rejected"
            );
        }
    }

    #[test]
    fn a_generated_request_id_is_itself_well_formed() {
        let id = RequestId::generate();
        assert!(
            RequestId::sanitize(id.as_str()).is_some(),
            "we must not generate an id we would reject: {id}"
        );
    }
}
