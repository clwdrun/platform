//! What an API token is: its format, its scopes, and its digest.
//!
//! No I/O. Verification and issuance live in [`crate::auth`]; this module is
//! only the bytes, so every property here is a unit test away.
//!
//! # The format
//!
//! ```text
//! clwd_tok_ + 64 lowercase hex characters   (32 bytes from the system CSPRNG)
//! ```
//!
//! **The prefix** makes a leaked token greppable in logs and recognisable to
//! secret scanners, and costs nothing. `tok` rather than `pat` because a token
//! belongs to an org, not a person.
//!
//! **Hex** rather than base64url: base64url's `-` and `_` break double-click
//! selection and word-boundary regexes, which are how people and scanners find
//! these, and hex needs no dependency.
//!
//! # What is stored
//!
//! [`TokenSecret::digest`]: SHA-256 of the whole token string. See the
//! `api_tokens` migration for why a fast hash is correct for a token and would
//! be wrong for a password.

use std::fmt;
use std::str::FromStr;

use sha2::{Digest as _, Sha256};

/// The prefix every token carries.
pub const PREFIX: &str = "clwd_tok_";

/// Random bytes in a token.
const SECRET_BYTES: usize = 32;

/// The length of a well-formed token, in bytes.
pub const LEN: usize = PREFIX.len() + SECRET_BYTES * 2;

/// SHA-256 of a token string: what the database holds.
pub type TokenDigest = [u8; 32];

/// A token's full text, held only between minting it and returning it.
///
/// **Its `Debug` redacts, and it has no `Display` and no `Serialize`.** The
/// realistic leak is a `{:?}` reaching a log line, and this makes that print
/// `TokenSecret(<redacted>)`. Reading the value is [`TokenSecret::expose`],
/// which is greppable and says what it does.
///
/// Not `secrecy`, and not zeroed on drop. Zeroing this copy would be false
/// assurance: the same bytes sit in the response body buffer and, on the way
/// in, in a `HeaderValue`'s `Bytes`, and neither of those is ever zeroed.
pub struct TokenSecret(String);

impl TokenSecret {
    /// Mint a token from the system CSPRNG.
    ///
    /// # Errors
    ///
    /// When the operating system's random source fails. There is no fallback,
    /// deliberately: a token from a weaker source is worse than no token.
    pub fn generate() -> Result<Self, getrandom::Error> {
        const HEX: &[u8; 16] = b"0123456789abcdef";

        let mut bytes = [0u8; SECRET_BYTES];
        getrandom::fill(&mut bytes)?;

        let mut text = String::with_capacity(LEN);
        text.push_str(PREFIX);
        for byte in bytes {
            text.push(char::from(HEX[usize::from(byte >> 4)]));
            text.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        Ok(Self(text))
    }

    /// The token text. Shown to the caller once, at issuance, and nowhere else.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// What the database stores for this token.
    #[must_use]
    pub fn digest(&self) -> TokenDigest {
        Sha256::digest(self.0.as_bytes()).into()
    }
}

impl fmt::Debug for TokenSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TokenSecret(<redacted>)")
    }
}

/// The digest of a presented token, or `None` if it is not well formed.
///
/// A malformed token is rejected here, before anything touches the database,
/// so a flood of garbage costs a string comparison. That reveals nothing: the
/// format is public, and what it rejects is only what could never match.
#[must_use]
pub fn digest_presented(presented: &str) -> Option<TokenDigest> {
    let hex = presented.strip_prefix(PREFIX)?;
    let well_formed = hex.len() == SECRET_BYTES * 2
        && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    well_formed.then(|| Sha256::digest(presented.as_bytes()).into())
}

/// One thing a token may do.
///
/// Independent, not hierarchical: `admin` does not imply `publish`. Hierarchy
/// is convenient and makes "what can this token do" a derivation rather than a
/// list, and that question is the one asked after a token leaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Read resources.
    Read,
    /// Create apps and change their metadata (#108).
    Write,
    /// Publish a version of an app.
    Publish,
    /// Issue and revoke tokens.
    Admin,
}

impl Scope {
    /// Every scope, in canonical order.
    pub const ALL: [Self; 4] = [Self::Read, Self::Write, Self::Publish, Self::Admin];

    /// The name stored in the database and used on the wire.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Publish => "publish",
            Self::Admin => "admin",
        }
    }

    fn bit(self) -> u8 {
        1 << (self as u8)
    }
}

/// A scope name that is not one of the four.
#[derive(Debug, thiserror::Error)]
#[error("unknown scope {0:?}; expected read, write, publish or admin")]
pub struct UnknownScope(String);

impl FromStr for Scope {
    type Err = UnknownScope;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|scope| scope.as_str() == s)
            .ok_or_else(|| UnknownScope(s.to_owned()))
    }
}

/// A set of scopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Scopes(u8);

impl Scopes {
    /// Parse scope names. Duplicates collapse; order does not matter.
    ///
    /// # Errors
    ///
    /// The first name that is not a scope.
    pub fn parse_all<I>(names: I) -> Result<Self, UnknownScope>
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        names
            .into_iter()
            .map(|name| name.as_ref().parse::<Scope>())
            .collect()
    }

    #[must_use]
    pub fn contains(self, scope: Scope) -> bool {
        self.0 & scope.bit() != 0
    }

    #[must_use]
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The scopes in `self` that `holder` does not have.
    ///
    /// Empty exactly when `self` is a subset of `holder`, which is the rule a
    /// token issuing another token must satisfy.
    #[must_use]
    pub fn missing_from(self, holder: Self) -> Self {
        Self(self.0 & !holder.0)
    }

    /// The scopes, in canonical order.
    pub fn iter(self) -> impl Iterator<Item = Scope> {
        Scope::ALL.into_iter().filter(move |s| self.contains(*s))
    }

    /// The names, in canonical order, as the database column holds them.
    #[must_use]
    pub fn to_names(self) -> Vec<String> {
        self.iter().map(|s| s.as_str().to_owned()).collect()
    }
}

impl FromIterator<Scope> for Scopes {
    fn from_iter<T: IntoIterator<Item = Scope>>(iter: T) -> Self {
        Self(iter.into_iter().fold(0, |bits, s| bits | s.bit()))
    }
}

impl fmt::Display for Scopes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, scope) in self.iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            f.write_str(scope.as_str())?;
        }
        Ok(())
    }
}

impl serde::Serialize for Scopes {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.iter().map(Scope::as_str))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn a_generated_token_is_well_formed() {
        let token = TokenSecret::generate().expect("the system has randomness");
        assert_eq!(token.expose().len(), LEN);
        assert!(token.expose().starts_with(PREFIX));
        assert_eq!(
            digest_presented(token.expose()),
            Some(token.digest()),
            "a token we mint must be one we accept"
        );
    }

    #[test]
    fn two_generated_tokens_differ() {
        let a = TokenSecret::generate().expect("randomness");
        let b = TokenSecret::generate().expect("randomness");
        assert_ne!(a.expose(), b.expose());
    }

    /// The digest is SHA-256 of the whole string, pinned against a value
    /// computed outside Rust (`printf %s … | sha256sum`), so a change to what
    /// is hashed — dropping the prefix, hashing decoded bytes — fails here
    /// rather than silently invalidating every stored token.
    #[test]
    fn the_digest_is_sha256_of_the_whole_token() {
        let token = format!("{PREFIX}{}", "ab".repeat(32));
        let digest = digest_presented(&token).expect("well formed");
        assert_eq!(
            hex(&digest),
            "74ea8048f09db2332fa8c8a778b687311a172b3b27e0b74fb7108ab3d4c91880"
        );
    }

    #[test]
    fn debug_does_not_print_the_token() {
        let token = TokenSecret::generate().expect("randomness");
        let debug = format!("{token:?}");
        assert!(
            !debug.contains(token.expose()) && !debug.contains(&token.expose()[PREFIX.len()..]),
            "Debug leaked the token: {debug}"
        );
        assert_eq!(debug, "TokenSecret(<redacted>)");
    }

    #[test]
    fn malformed_tokens_are_rejected() {
        let hex64 = "0".repeat(64);
        for candidate in [
            String::new(),
            PREFIX.to_owned(),
            hex64.clone(),
            format!("clwd_pat_{hex64}"),
            format!("{PREFIX}{}", "0".repeat(63)),
            format!("{PREFIX}{}", "0".repeat(65)),
            format!("{PREFIX}{}", "A".repeat(64)),
            format!("{PREFIX}{}", "g".repeat(64)),
            format!(" {PREFIX}{hex64}"),
            format!("{PREFIX}{hex64} "),
        ] {
            assert!(
                digest_presented(&candidate).is_none(),
                "{candidate:?} should be rejected"
            );
        }
    }

    #[test]
    fn scopes_parse_and_collapse_duplicates() {
        let scopes = Scopes::parse_all(["publish", "read", "publish"]).expect("valid");
        assert_eq!(scopes.to_names(), ["read", "publish"]);
        assert_eq!(scopes.to_string(), "read, publish");
        assert!(Scopes::parse_all(["root"]).is_err());
        assert!(Scopes::parse_all(["Read"]).is_err(), "names are exact");
    }

    #[test]
    fn scopes_are_independent_not_hierarchical() {
        let admin = Scopes::parse_all(["admin"]).expect("valid");
        assert!(admin.contains(Scope::Admin));
        for other in [Scope::Read, Scope::Write, Scope::Publish] {
            assert!(!admin.contains(other), "admin must not imply {other:?}");
        }
    }

    #[test]
    fn missing_from_is_the_subset_rule() {
        let holder = Scopes::parse_all(["admin", "publish"]).expect("valid");
        let narrower = Scopes::parse_all(["publish"]).expect("valid");
        let broader = Scopes::parse_all(["publish", "write"]).expect("valid");

        assert!(narrower.missing_from(holder).is_empty());
        assert_eq!(broader.missing_from(holder).to_names(), ["write"]);
    }
}
