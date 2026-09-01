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
//! `hint` is always present and may be `null`. It is never omitted: a consumer
//! indexes the key unconditionally.
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
                $variant:ident { $($field:tt)* } => $code:literal, $status:expr, $retry:literal, $hint:expr;
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

            /// A short, actionable next step, or `None`.
            pub fn hint(&self) -> Option<&'static str> {
                match self {
                    // `clwd_bundle::Error` has `code()` and `retryable()` but no
                    // `hint()`, so there is nothing to forward. This points at
                    // the published table rather than restating 38 entries here,
                    // where they would drift from it.
                    //
                    // That is papering over an absence, not a design: the text
                    // belongs with the crate that owns the code, and
                    // `clwdrun/clwd#63` is the fix.
                    $( Self::$dvariant { .. } => Some(DELEGATED_HINT), )*
                    $( Self::$variant { .. } => $hint, )*
                }
            }
        }

        /// Every code this crate owns, generated from the same input as the
        /// enum.
        ///
        /// Delegated codes are deliberately absent: they belong to the crate
        /// that defines them and are catalogued there.
        pub const OWNED_CODES: &[&str] = &[$($code),*];

        /// One sample per owned variant, for the exhaustiveness test. Generated,
        /// so a variant cannot be added and forgotten.
        #[cfg(test)]
        const OWNED_STATUSES: &[(&str, u16, bool)] = &[$(($code, $status, $retry)),*];
    };
}

/// What a delegated error offers in place of a hint of its own.
///
/// A real next step rather than a null. The table it points at is generated from
/// the code, so this cannot drift from it the way a restatement would.
const DELEGATED_HINT: &str =
    "see docs/error-codes.md in clwdrun/clwd for this code's meaning and how to recover";

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
            Some("check the request against the OpenAPI schema at /openapi.json");

        /// The caller is not authenticated.
        #[error("authentication required")]
        Unauthenticated {} => "control-plane.unauthenticated", 401, false,
            Some("supply a bearer token in the Authorization header");

        /// The caller is authenticated but not permitted.
        #[error("not permitted: {what}")]
        Forbidden { what: String } => "control-plane.forbidden", 403, false,
            Some("ask an owner of the organisation to grant access");

        /// A named resource does not exist, or the caller may not see it.
        ///
        /// Deliberately does not distinguish the two. Telling an unauthorised
        /// caller that a thing exists is an enumeration oracle.
        #[error("not found: {what}")]
        NotFound { what: String } => "control-plane.not_found", 404, false, None;

        /// The request conflicts with the current state — a slug already taken,
        /// a version already published under a different digest.
        #[error("conflict: {what}")]
        Conflict { what: String } => "control-plane.conflict", 409, false,
            Some("re-read the resource and retry with the current state");

        /// A stored artifact could not be decoded.
        ///
        /// **Not a `bundle.*` code, deliberately.** The bytes passed validation
        /// when they were ingested, so failing to decode them now means storage
        /// corruption, a truncated write, or a bad restore. Delegating here would
        /// return 400 and blame the caller for our own integrity failure, and
        /// would file a real incident under client errors where nobody looks.
        #[error("stored artifact {digest} could not be read")]
        ArtifactCorrupt { digest: String } => "control-plane.artifact_corrupt", 500, false,
            Some("this is a server-side integrity failure; the artifact must be rebuilt and republished");

        /// A dependency did not answer in time.
        ///
        /// The one retryable code today, and the reason `retryable` is worth
        /// carrying at all: a field that is uniformly `false` is decorative, and
        /// nobody notices when it is wired wrong.
        #[error("timed out talking to {dependency}")]
        Timeout { dependency: String } => "control-plane.timeout", 504, true,
            Some("retry; if it persists the dependency is down rather than slow");

        /// Last resort only, never where a specific variant fits.
        #[error("internal error")]
        Internal {
            #[source]
            source: anyhow::Error,
        } => "control-plane.internal", 500, false,
            Some("this is a defect; report it with the request id");
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
            hint: error.hint(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn owned_samples() -> Vec<Error> {
        vec![
            Error::InvalidRequest { what: "x".into() },
            Error::Unauthenticated {},
            Error::Forbidden { what: "x".into() },
            Error::NotFound { what: "x".into() },
            Error::Conflict { what: "x".into() },
            Error::ArtifactCorrupt { digest: "x".into() },
            Error::Timeout {
                dependency: "x".into(),
            },
            Error::Internal {
                source: anyhow::anyhow!("x"),
            },
        ]
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
            assert_eq!(
                ns, "control-plane",
                "{code} is not in this crate's namespace"
            );
        }
    }

    /// The status table, enforced rather than documented.
    #[test]
    fn every_owned_code_has_a_sane_status() {
        for (code, status, _) in OWNED_STATUSES {
            assert!(
                (400..=599).contains(status),
                "{code} maps to {status}, which is not an error status"
            );
        }
    }

    /// A variant's declared status must be what `status()` actually returns —
    /// the table and the code cannot drift because they are one input.
    #[test]
    fn status_matches_the_declared_table() {
        for err in owned_samples() {
            let (_, declared, _) = OWNED_STATUSES
                .iter()
                .find(|(c, _, _)| *c == err.code())
                .unwrap_or_else(|| panic!("{} is not in the status table", err.code()));
            assert_eq!(err.status(), *declared, "for {}", err.code());
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
        assert_eq!(err.hint(), Some(DELEGATED_HINT));
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
            r#"{"code":"control-plane.not_found","message":"not found: app dashboard","hint":null,"retryable":false,"request_id":"req-42"}"#
        );
    }

    /// `hint` is present as `null`, never omitted, so a consumer can index it
    /// unconditionally.
    #[test]
    fn a_none_hint_serializes_as_null_rather_than_being_dropped() {
        let err = Error::NotFound { what: "x".into() };
        let id = RequestId::sanitize("r").expect("well formed");
        let value: serde_json::Value =
            serde_json::to_value(Envelope::new(&err, &id)).expect("serializes");
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
