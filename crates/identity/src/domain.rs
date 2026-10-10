//! Domain names as the org boundary sees them.
//!
//! Two domains are the same domain only after normalisation: `Acme.com`,
//! `acme.com.` and `acme.com` must compare equal, or the one-verified-org-per-
//! domain rule is bypassed by spelling. [`normalize`] is the single place that
//! happens, and every domain type here is built through it, so no comparison
//! or stored value ever sees an unnormalised spelling.
//!
//! [`HostedDomain`] is the type the sign-in path produces from Google's `hd`
//! claim. It is deliberately not interchangeable with any other domain — an
//! email's domain above all. Mistaking the email domain for `hd` is exactly
//! the error that lets a consumer account registered as `bob@acme.com` into
//! Acme's org: Google verified that address once, at account creation, and
//! "ownership of the third party email account may have since changed".

use std::fmt;

/// The longest name DNS can carry, in presentation form without the root dot.
const MAX_NAME: usize = 253;
/// The longest single label.
const MAX_LABEL: usize = 63;

/// Why a string is not a usable domain name.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DomainError {
    /// Not convertible to an ASCII (punycode) name under IDNA.
    #[error("not a valid internationalised domain name")]
    Idna,
    /// Not an LDH host name of at least two labels within DNS length limits.
    #[error("not a valid domain name")]
    Shape,
}

/// Normalise `raw` to the one spelling a domain is compared and stored in:
/// one trailing root dot removed, IDNA-converted to punycode, lowercase.
///
/// The result has at least two labels, each 1–63 LDH characters with no
/// leading or trailing hyphen, and is at most 253 characters — the same rule
/// the database's `CHECK` constraints hold, so a value this accepts is one the
/// schema accepts.
///
/// # Errors
///
/// [`DomainError::Idna`] if IDNA conversion fails; [`DomainError::Shape`] if
/// the converted name is not a multi-label LDH host name.
pub fn normalize(raw: &str) -> Result<String, DomainError> {
    let trimmed = raw.strip_suffix('.').unwrap_or(raw);
    // `domain_to_ascii` lowercases and punycode-encodes; it also accepts some
    // things a host name cannot be (underscores, empty labels), which the
    // shape check below refuses.
    let ascii = idna::domain_to_ascii(trimmed).map_err(|_| DomainError::Idna)?;
    let labels: Vec<&str> = ascii.split('.').collect();
    let well_formed = ascii.len() <= MAX_NAME
        && labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= MAX_LABEL
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        });
    if well_formed {
        Ok(ascii)
    } else {
        Err(DomainError::Shape)
    }
}

/// A Google Workspace hosted domain: the `hd` claim of a verified ID token,
/// normalised.
///
/// # What it proves, per Google
///
/// `hd` is "provided only if the user belongs to a Google Cloud organization",
/// and "the absence of this claim indicates that the account does not belong
/// to a Google hosted domain". It sits inside the signed token, so unlike the
/// `hd` *request parameter* (a UI hint a client can edit) it can be trusted.
///
/// It proves membership of a Workspace tenant for this domain. It does **not**
/// prove the person administers that tenant, or that any org on this platform
/// should own the domain — that takes a DNS-verified claim.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HostedDomain(String);

impl HostedDomain {
    /// Normalise and wrap an `hd` value.
    ///
    /// # Errors
    ///
    /// As [`normalize`].
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        normalize(raw).map(Self)
    }

    /// The normalised domain.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for HostedDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spellings_of_one_domain_normalise_to_one_value() {
        for raw in ["acme.com", "Acme.COM", "acme.com.", "ACME.com."] {
            assert_eq!(normalize(raw).as_deref(), Ok("acme.com"), "{raw}");
        }
    }

    #[test]
    fn an_internationalised_name_becomes_punycode() {
        assert_eq!(normalize("bücher.de").as_deref(), Ok("xn--bcher-kva.de"));
        assert_eq!(normalize("BÜCHER.de.").as_deref(), Ok("xn--bcher-kva.de"));
    }

    #[test]
    fn what_is_not_a_host_name_is_refused() {
        for raw in [
            "",
            ".",
            "com",
            "acme..com",
            "-acme.com",
            "acme-.com",
            "ac_me.com",
            "acme.com..",
            "acme com",
            &format!("{}.com", "a".repeat(64)),
        ] {
            assert!(normalize(raw).is_err(), "{raw:?} must be refused");
        }
    }
}
