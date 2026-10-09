//! The OIDC flow and ID-token verification.
//!
//! Verification is the whole point of this crate: the ID token Google returns
//! is only worth what its checks are worth. [`verify_id_token`] runs the real
//! [`openidconnect`] verifier — signature against Google's JWKS, issuer,
//! audience, expiry, and the `nonce` — and every one of those is exercised by a
//! "rejects not-X" test beside a "accepts X". The negative cases are the ones
//! that matter: a happy-path-only test passes against a verifier that accepts
//! everything, which is the exact failure this code exists to prevent.

use openidconnect::core::{
    CoreGenderClaim, CoreIdTokenVerifier, CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
};
use openidconnect::{AdditionalClaims, IdToken, IdTokenClaims, Nonce};
use serde::{Deserialize, Serialize};

/// Google's stable, opaque identifier for a person.
///
/// A newtype, not a `String`, because a Google subject, a user id, a session
/// id, a `state` value and a nonce are a family where a mix-up is a
/// vulnerability rather than a type error — the same reason `control-plane`'s
/// `ids` module splits its UUIDs. This is the value `#10` keys a user on: it
/// never changes for an account and is never reused, which `email` is not.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GoogleSubject(String);

impl GoogleSubject {
    /// The subject string, for storing against a user.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The Google-specific claims that are not part of standard OIDC.
///
/// `hd` (hosted domain) is present only for a Workspace account and is what
/// `#10` uses to map a sign-in to an org. It is not a standard claim, so it
/// rides here in the additional-claims slot rather than on `StandardClaims`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoogleClaims {
    /// The Google Workspace hosted domain, when the account has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hd: Option<String>,
}

impl AdditionalClaims for GoogleClaims {}

/// An ID token carrying Google's `hd` claim.
///
/// The `CoreIdToken` alias fixes the additional-claims type to
/// `EmptyAdditionalClaims`, which would silently drop `hd`; this alias swaps in
/// [`GoogleClaims`] so the hosted domain survives deserialization.
pub type GoogleIdToken = IdToken<
    GoogleClaims,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;

/// The claims inside a [`GoogleIdToken`], parameterized so `hd` is reachable.
pub type GoogleIdTokenClaims = IdTokenClaims<GoogleClaims, CoreGenderClaim>;

/// What a verified sign-in yields.
///
/// Only what a verified token proves: the subject, the email **iff** Google
/// marked it verified, and the hosted domain. Nothing here is a credential, so
/// it carries a normal `Debug`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifiedIdentity {
    /// Google's stable identifier for the person. Always present.
    pub subject: GoogleSubject,
    /// The email, present **only** when `email_verified` was true. An
    /// unverified email is an unproven claim and is dropped, not trusted.
    pub email: Option<String>,
    /// The Workspace hosted domain (`hd`), when present. Consumed by `#10` for
    /// org mapping; not trusted for anything here.
    pub hosted_domain: Option<String>,
}

/// Why a token was not accepted.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VerifyError {
    /// The token failed verification: a bad signature, wrong issuer, wrong
    /// audience, an expired token, or a `nonce` that did not match. The reason
    /// is for the log, never the caller — every case is one denial to them.
    #[error("the ID token was rejected: {0}")]
    TokenRejected(String),
}

/// Verify a Google ID token against `verifier`, requiring `nonce` to match.
///
/// The single call `token.claims(verifier, nonce)` runs every check —
/// signature against the verifier's JWKS, issuer, audience, expiry, and the
/// nonce — so there is one place a check can be skipped and one place they are
/// all enforced.
///
/// # Errors
///
/// [`VerifyError::TokenRejected`] when any verification check fails.
pub fn verify_id_token(
    token: &GoogleIdToken,
    verifier: &CoreIdTokenVerifier,
    nonce: &Nonce,
) -> Result<VerifiedIdentity, VerifyError> {
    // The one call that runs every check: signature against the verifier's
    // JWKS, issuer, audience, expiry, and the nonce. A failure of any is one
    // denial to the caller.
    let claims = token
        .claims(verifier, nonce)
        .map_err(|e| VerifyError::TokenRejected(e.to_string()))?;

    let subject = GoogleSubject(claims.subject().as_str().to_owned());

    // The email is trusted only when Google marked it verified. `email_verified`
    // absent or false means the address is an unproven claim, so it is dropped
    // rather than carried as if it were confirmed.
    let email = match claims.email_verified() {
        Some(true) => claims.email().map(|e| e.as_str().to_owned()),
        _ => None,
    };

    let hosted_domain = claims.additional_claims().hd.clone();

    Ok(VerifiedIdentity {
        subject,
        email,
        hosted_domain,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use openidconnect::core::{CoreJsonWebKeySet, CoreRsaPrivateSigningKey};
    use openidconnect::{
        Audience, ClientId, ClientSecret, EndUserEmail, IssuerUrl, PrivateSigningKey,
        StandardClaims, SubjectIdentifier,
    };
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const ISSUER: &str = "https://accounts.google.com";
    const CLIENT_ID: &str = "test-client-id.apps.googleusercontent.com";
    const CLIENT_SECRET: &str = "test-client-secret";

    /// One knob per verification axis, so a negative test perturbs exactly one.
    struct Token {
        issuer: String,
        audience: String,
        /// `iat`, seconds since the epoch. `exp` is this plus one hour.
        issued_at: i64,
        nonce: Nonce,
        subject: String,
        email: Option<String>,
        email_verified: Option<bool>,
        hd: Option<String>,
        /// When false, a valid signature by a *different* key is produced, so
        /// the verifier's JWKS cannot vouch for it.
        sign_with_trusted_key: bool,
    }

    impl Token {
        fn valid(nonce: &Nonce) -> Self {
            Self {
                issuer: ISSUER.to_owned(),
                audience: CLIENT_ID.to_owned(),
                issued_at: 1_700_000_000,
                nonce: nonce.clone(),
                subject: "google-subject-123".to_owned(),
                email: Some("person@example.com".to_owned()),
                email_verified: Some(true),
                hd: Some("example.com".to_owned()),
                sign_with_trusted_key: true,
            }
        }

        /// Build and serialize the token, then parse it back as a
        /// [`GoogleIdToken`] — exactly the round trip the callback performs.
        fn build(&self) -> GoogleIdToken {
            let signing_key = if self.sign_with_trusted_key {
                trusted_key()
            } else {
                untrusted_key()
            };
            let mut standard = StandardClaims::new(SubjectIdentifier::new(self.subject.clone()));
            if let Some(email) = &self.email {
                standard = standard.set_email(Some(EndUserEmail::new(email.clone())));
            }
            standard = standard.set_email_verified(self.email_verified);

            let claims = GoogleIdTokenClaims::new(
                IssuerUrl::new(self.issuer.clone()).expect("issuer url"),
                vec![Audience::new(self.audience.clone())],
                utc(self.issued_at + 3600),
                utc(self.issued_at),
                standard,
                GoogleClaims {
                    hd: self.hd.clone(),
                },
            )
            .set_nonce(Some(self.nonce.clone()));

            let token = GoogleIdToken::new(
                claims,
                &signing_key,
                CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
                None,
                None,
            )
            .expect("sign the token");

            let json = serde_json::to_value(&token).expect("serialize");
            serde_json::from_value(json).expect("parse as GoogleIdToken")
        }
    }

    fn utc(secs: i64) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(secs, 0).expect("valid timestamp")
    }

    /// Generate a fresh PKCS#1 RSA private key as PEM. Done at runtime, and
    /// never written to disk, so no key material lives in the repository —
    /// where `*.pem` is ignored and gitleaks would flag an inline one anyway.
    fn generate_pkcs1_pem() -> String {
        use rsa::pkcs1::EncodeRsaPrivateKey as _;
        let mut rng = rand::thread_rng();
        let key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("generate a test RSA key");
        key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .expect("encode PKCS#1 PEM")
            .to_string()
    }

    /// The key the verifier's JWKS trusts. Generated once per test run.
    fn trusted_key() -> CoreRsaPrivateSigningKey {
        static PEM: OnceLock<String> = OnceLock::new();
        CoreRsaPrivateSigningKey::from_pem(PEM.get_or_init(generate_pkcs1_pem), None)
            .expect("trusted test key parses")
    }

    /// A second, unrelated key. A token signed with it is well-formed but the
    /// verifier's JWKS (the trusted key) cannot vouch for it.
    fn untrusted_key() -> CoreRsaPrivateSigningKey {
        static PEM: OnceLock<String> = OnceLock::new();
        CoreRsaPrivateSigningKey::from_pem(PEM.get_or_init(generate_pkcs1_pem), None)
            .expect("untrusted test key parses")
    }

    /// A verifier that trusts only the trusted key's JWKS, with a fixed clock
    /// so expiry is deterministic. `now` is seconds since the epoch.
    fn verifier(now: i64) -> CoreIdTokenVerifier<'static> {
        build_verifier(now, false, false)
    }

    /// Same as [`verifier`], but with individual checks disabled. Used only to
    /// prove a negative test's teeth: a token that the secure verifier rejects
    /// must *verify* once the single check under test is disabled, which shows
    /// the rejection is caused by that check and not by some incidental defect
    /// in the crafted token (an expiry mismatch masking a bad signature, say).
    fn build_verifier(
        now: i64,
        disable_signature: bool,
        ignore_audience: bool,
    ) -> CoreIdTokenVerifier<'static> {
        let jwks = CoreJsonWebKeySet::new(vec![trusted_key().as_verification_key()]);
        let clock = AtomicUsize::new(usize::try_from(now).expect("non-negative"));
        let mut v = CoreIdTokenVerifier::new_confidential_client(
            ClientId::new(CLIENT_ID.to_owned()),
            ClientSecret::new(CLIENT_SECRET.to_owned()),
            IssuerUrl::new(ISSUER.to_owned()).expect("issuer url"),
            jwks,
        )
        .set_time_fn(move || utc(clock.load(Ordering::Relaxed) as i64));
        if disable_signature {
            v = v.insecure_disable_signature_check();
        }
        if ignore_audience {
            v = v.require_audience_match(false);
        }
        v
    }

    /// A time inside the token's validity window (issued_at .. issued_at+3600).
    const DURING_VALIDITY: i64 = 1_700_001_000;

    #[test]
    fn a_valid_token_yields_the_subject_email_and_hosted_domain() {
        let nonce = Nonce::new_random();
        let token = Token::valid(&nonce).build();

        let identity = verify_id_token(&token, &verifier(DURING_VALIDITY), &nonce)
            .expect("a validly signed, unexpired, matching token verifies");

        assert_eq!(identity.subject.as_str(), "google-subject-123");
        assert_eq!(identity.email.as_deref(), Some("person@example.com"));
        assert_eq!(identity.hosted_domain.as_deref(), Some("example.com"));
    }

    // --- rejects not-X: one negative per verification axis ---
    //
    // Each perturbs exactly one field of an otherwise-valid token and asserts
    // the verifier rejects it. A happy-path-only harness passes against a
    // verifier that accepts everything; these are what make the checks
    // load-bearing.

    #[test]
    fn a_token_signed_by_an_untrusted_key_is_rejected() {
        let nonce = Nonce::new_random();
        let token = Token {
            sign_with_trusted_key: false,
            ..Token::valid(&nonce)
        }
        .build();

        let result = verify_id_token(&token, &verifier(DURING_VALIDITY), &nonce);

        assert!(result.is_err(), "a wrong signature must be rejected");

        // Teeth: the same token verifies once signature checking is disabled,
        // so the rejection above is the signature check, not a stray defect.
        let disabled = build_verifier(DURING_VALIDITY, true, false);
        assert!(
            verify_id_token(&token, &disabled, &nonce).is_ok(),
            "with signature checking off, this token is otherwise valid"
        );
    }

    #[test]
    fn a_token_from_the_wrong_issuer_is_rejected() {
        let nonce = Nonce::new_random();
        let token = Token {
            issuer: "https://accounts.evil.example".to_owned(),
            ..Token::valid(&nonce)
        }
        .build();

        let result = verify_id_token(&token, &verifier(DURING_VALIDITY), &nonce);

        assert!(result.is_err(), "a wrong issuer must be rejected");
    }

    #[test]
    fn a_token_for_the_wrong_audience_is_rejected() {
        let nonce = Nonce::new_random();
        let token = Token {
            audience: "some-other-client.apps.googleusercontent.com".to_owned(),
            ..Token::valid(&nonce)
        }
        .build();

        let result = verify_id_token(&token, &verifier(DURING_VALIDITY), &nonce);

        assert!(
            result.is_err(),
            "a token for another audience must be rejected"
        );

        // Teeth: verifies once audience matching is disabled, so the rejection
        // is the audience check.
        let disabled = build_verifier(DURING_VALIDITY, false, true);
        assert!(
            verify_id_token(&token, &disabled, &nonce).is_ok(),
            "with audience matching off, this token is otherwise valid"
        );
    }

    #[test]
    fn an_expired_token_is_rejected() {
        let nonce = Nonce::new_random();
        let token = Token::valid(&nonce).build();
        // The token's exp is issued_at + 3600 = 1_700_003_600; verify well past it.
        let after_expiry = 1_700_010_000;

        let result = verify_id_token(&token, &verifier(after_expiry), &nonce);

        assert!(result.is_err(), "an expired token must be rejected");
    }

    #[test]
    fn a_token_with_a_mismatched_nonce_is_rejected() {
        let token_nonce = Nonce::new_random();
        let token = Token::valid(&token_nonce).build();
        let expected_nonce = Nonce::new_random();
        assert_ne!(token_nonce.secret(), expected_nonce.secret());

        // The verifier is given the nonce we expected, not the one in the token
        // — the replay case, where a captured token carries a stale nonce.
        let result = verify_id_token(&token, &verifier(DURING_VALIDITY), &expected_nonce);

        assert!(result.is_err(), "a mismatched nonce must be rejected");
    }

    #[test]
    fn an_unverified_email_is_dropped_not_trusted() {
        let nonce = Nonce::new_random();
        let token = Token {
            email: Some("person@example.com".to_owned()),
            email_verified: Some(false),
            ..Token::valid(&nonce)
        }
        .build();

        let identity = verify_id_token(&token, &verifier(DURING_VALIDITY), &nonce)
            .expect("the token itself is valid; only the email claim is unverified");

        assert_eq!(
            identity.email, None,
            "an unverified email must not be carried as if confirmed"
        );
        assert_eq!(
            identity.subject.as_str(),
            "google-subject-123",
            "the rest of the identity is still trusted"
        );
    }
}
