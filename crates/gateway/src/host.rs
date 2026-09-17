//! Parsing an inbound `Host` / SNI name into the org and app it addresses.
//!
//! App traffic is served on `{app}.{org}.clwd.run` (#18). This module owns the
//! single definition of that shape: an app host has exactly two DNS labels —
//! the app, then the org — in front of the platform apex. Everything else
//! (`clwd.run`, `api.clwd.run`, a bare `{org}.clwd.run`, a foreign domain) is
//! deliberately *not* an app host, and the gateway answers those with a 404
//! rather than routing them.
//!
//! [`OrgSlug`] and [`AppName`] are distinct newtypes on purpose: a slug is
//! reserved, immutable and certificate-bearing where an app name is mutable and
//! org-local, and the two must never be passed to the wrong place.

use std::fmt;

use thiserror::Error;

// The org slug and its DNS-label rule live in `shared` (they key the shared
// certificate store); re-exported here so the routing parser and its callers
// keep using `host::OrgSlug`.
pub use shared::cert::{MAX_LABEL_LEN, OrgSlug, is_valid_label};

/// An app name: the `{app}` in `{app}.{org}.clwd.run`. Same DNS-label rule as a
/// slug, but mutable and unique only within its org (#18), so it carries no
/// reserved-word list.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct AppName(String);

/// An inbound host successfully resolved to the app-on-org it addresses. This
/// is the only value the router treats as "a request for an app"; producing one
/// is the sole gate between a request and app routing.
#[derive(Clone, PartialEq, Eq, Hash)]
#[must_use]
pub struct AppHost {
    /// The app half. Owned so the value outlives the borrowed header it came from.
    pub app: AppName,
    /// The org half.
    pub org: OrgSlug,
}

/// Why a host is not a routable `{app}.{org}.{apex}` app host.
///
/// Every variant maps to the same outward response — a 404 — so a caller does
/// not branch on it; it exists so logs and tests can tell the cases apart. It
/// is `#[non_exhaustive]` because new non-routable shapes may be recognised
/// later without that being a breaking change.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum HostError {
    /// The host does not end in the platform apex (e.g. `example.com`).
    #[error("host is not under the platform apex")]
    ForeignApex,
    /// The host is under the apex but not `label.label.apex`: the apex itself,
    /// a bare `{org}.apex`, or a deeper name like `a.b.c.apex`.
    #[error("host is not of the form {{app}}.{{org}}.<apex>")]
    NotAppHost,
    /// A label is present but is not a valid DNS label (empty, too long, bad
    /// character, or a leading/trailing hyphen).
    #[error("host contains an invalid DNS label")]
    InvalidLabel,
}

impl AppName {
    /// Parse a single DNS label as an app name, applying the `apps.name` rule.
    ///
    /// # Errors
    /// Returns [`HostError::InvalidLabel`] if `label` is not a valid DNS label.
    pub fn parse(label: &str) -> Result<Self, HostError> {
        if is_valid_label(label) {
            Ok(Self(label.to_owned()))
        } else {
            Err(HostError::InvalidLabel)
        }
    }

    /// The name as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AppName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AppName({})", self.0)
    }
}

impl fmt::Debug for AppHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.app.0, self.org.as_str())
    }
}

/// Resolve an inbound host to the app host it addresses, if any.
///
/// `host` is the raw `Host` header or SNI name; an `:port` suffix, a trailing
/// dot, and upper-case letters are all tolerated and normalised. `apex` is the
/// platform apex (`clwd.run` in production, overridable for tests and dev).
///
/// Returns [`AppHost`] only for exactly `{app}.{org}.{apex}`. The apex itself, a
/// bare `{org}.{apex}`, deeper names, and foreign domains all return an error —
/// the caller renders every error as a 404.
///
/// # Errors
/// See [`HostError`].
pub fn parse_host(host: &str, apex: &str) -> Result<AppHost, HostError> {
    // Normalise: drop a port, drop a single trailing dot (FQDN root),
    // lower-case. DNS is case-insensitive and a browser may send either.
    let host = host.split(':').next().unwrap_or(host);
    let host = host.strip_suffix('.').unwrap_or(host);
    let host = host.to_ascii_lowercase();
    let apex = apex.to_ascii_lowercase();

    let remainder = host.strip_suffix(&apex).ok_or(HostError::ForeignApex)?;
    let prefix = match remainder.strip_suffix('.') {
        Some(prefix) => prefix,
        // Empty remainder means the host *is* the apex (`clwd.run`) — under the
        // apex, just not an app host. A non-empty remainder with no trailing dot
        // is the apex appearing as a non-boundary substring (`notclwd.run`).
        None if remainder.is_empty() => return Err(HostError::NotAppHost),
        None => return Err(HostError::ForeignApex),
    };

    // Exactly two labels in front of the apex: app, then org.
    let mut labels = prefix.split('.');
    let (Some(app), Some(org), None) = (labels.next(), labels.next(), labels.next()) else {
        return Err(HostError::NotAppHost);
    };

    Ok(AppHost {
        app: AppName::parse(app)?,
        // OrgSlug lives in `shared` and returns its own label error; the routing
        // layer reports every bad label as HostError::InvalidLabel.
        org: OrgSlug::parse(org).map_err(|_| HostError::InvalidLabel)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const APEX: &str = "clwd.run";

    #[test]
    fn parses_a_well_formed_app_host() {
        let h = parse_host("dashboard.acme.clwd.run", APEX).expect("valid app host");
        assert_eq!(h.app.as_str(), "dashboard");
        assert_eq!(h.org.as_str(), "acme");
    }

    #[test]
    fn normalises_case_port_and_trailing_dot() {
        let h = parse_host("Dashboard.ACME.clwd.run.:443", APEX).expect("valid after normalise");
        assert_eq!(h.app.as_str(), "dashboard");
        assert_eq!(h.org.as_str(), "acme");
    }

    #[test]
    fn single_character_labels_are_valid() {
        // The DB regex permits a one-character label; so must this.
        let h = parse_host("a.b.clwd.run", APEX).expect("single-char labels ok");
        assert_eq!(h.app.as_str(), "a");
        assert_eq!(h.org.as_str(), "b");
    }

    #[test]
    fn apex_itself_is_not_an_app_host() {
        assert_eq!(parse_host("clwd.run", APEX), Err(HostError::NotAppHost));
    }

    #[test]
    fn bare_org_root_is_not_an_app_host() {
        // acme.clwd.run is the org root, not an app — one label short.
        assert_eq!(
            parse_host("acme.clwd.run", APEX),
            Err(HostError::NotAppHost)
        );
    }

    #[test]
    fn deeper_names_are_not_app_hosts() {
        assert_eq!(
            parse_host("a.b.c.clwd.run", APEX),
            Err(HostError::NotAppHost)
        );
    }

    #[test]
    fn foreign_apex_is_rejected() {
        assert_eq!(
            parse_host("dashboard.acme.example.com", APEX),
            Err(HostError::ForeignApex)
        );
    }

    #[test]
    fn apex_as_substring_is_not_a_match() {
        // "notclwd.run" ends with "clwd.run" as text but not on a label
        // boundary; the leading-dot strip is what rejects it.
        assert_eq!(
            parse_host("dashboard.acme.notclwd.run", APEX),
            Err(HostError::ForeignApex)
        );
    }

    #[test]
    fn invalid_labels_are_rejected() {
        for bad in [
            "-app.acme.clwd.run", // leading hyphen
            "app-.acme.clwd.run", // trailing hyphen
            "app.acme-.clwd.run", // trailing hyphen in org
            "ap_p.acme.clwd.run", // underscore
            "app.ACME_.clwd.run", // underscore in org
            ".acme.clwd.run",     // empty app label
            "app..clwd.run",      // empty org label
        ] {
            assert_eq!(
                parse_host(bad, APEX),
                Err(HostError::InvalidLabel),
                "expected InvalidLabel for {bad}"
            );
        }
    }

    #[test]
    fn over_long_label_is_rejected() {
        let long = "a".repeat(MAX_LABEL_LEN + 1);
        let host = format!("{long}.acme.clwd.run");
        assert_eq!(parse_host(&host, APEX), Err(HostError::InvalidLabel));
        // The boundary value itself is accepted.
        let exact = "a".repeat(MAX_LABEL_LEN);
        let ok = format!("{exact}.acme.clwd.run");
        assert!(parse_host(&ok, APEX).is_ok());
    }

    #[test]
    fn label_rule_matches_the_db_check_constraint() {
        // Parity with `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$` from
        // migrations/20260828115934_core_schema.sql. A representative table
        // rather than a second regex, so the two cannot silently diverge.
        for (label, valid) in [
            ("a", true),
            ("a1", true),
            ("a-b", true),
            ("0", true),
            ("a--b", true),
            ("", false),
            ("-a", false),
            ("a-", false),
            ("A", false), // upper-case is normalised before this, never reaches here raw
            ("a.b", false),
            ("a_b", false),
        ] {
            assert_eq!(is_valid_label(label), valid, "label {label:?}");
        }
    }

    #[test]
    fn a_dev_apex_can_be_substituted() {
        let h = parse_host("dashboard.acme.clwd.test", "clwd.test").expect("valid under dev apex");
        assert_eq!(h.org.as_str(), "acme");
    }
}
