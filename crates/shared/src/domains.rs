//! The platform's two domains, as two types (#62).
//!
//! Apps run untrusted code, so they are served from a registrable domain of
//! their own — never the control plane's. Two domains on one registrable
//! domain are *same-site* to a browser: an app's page can then plant cookies
//! the control plane reads, share its renderer process, and drag its
//! reputation down with one phishing page. Keeping them apart is the whole
//! decision, and one `BASE_DOMAIN` used for both is how it would quietly be
//! undone.
//!
//! So they are distinct types: an app host can only be built from an
//! [`AppsDomain`], and [`AppsDomain::separate_from`] refuses a pair that share
//! a registrable domain. Both are configuration, read once at startup.

use std::fmt;

use crate::cert::{OrgSlug, is_valid_label};

/// Why a domain is not usable as configured.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DomainError {
    /// Not a lowercase, multi-label LDH host name.
    #[error("`{0}` is not a lowercase multi-label host name")]
    Malformed(String),
    /// The two domains share a registrable domain, which makes every app
    /// same-site with the control plane.
    #[error(
        "the apps domain `{apps}` and the control-plane domain `{control_plane}` share a \
         registrable domain; apps must be served from a separate one (#62)"
    )]
    NotSeparate { apps: String, control_plane: String },
}

fn parse_host_name(raw: &str) -> Result<String, DomainError> {
    let labels: Vec<&str> = raw.split('.').collect();
    if labels.len() >= 2 && raw.len() <= 253 && labels.iter().all(|l| is_valid_label(l)) {
        Ok(raw.to_owned())
    } else {
        Err(DomainError::Malformed(raw.to_owned()))
    }
}

/// The host the control plane is served on (e.g. `api.clwd.run`). Its session
/// cookie is host-only here, and cookie-authenticated state changes are
/// accepted only from its origin.
#[derive(Clone, PartialEq, Eq)]
pub struct ControlPlaneDomain(String);

impl ControlPlaneDomain {
    /// # Errors
    ///
    /// [`DomainError::Malformed`] unless `raw` is a lowercase multi-label host.
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        parse_host_name(raw).map(Self)
    }

    /// The host name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The control plane's origin, `https://<host>`.
    #[must_use]
    pub fn origin(&self) -> String {
        format!("https://{}", self.0)
    }
}

impl fmt::Debug for ControlPlaneDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ControlPlaneDomain({})", self.0)
    }
}

/// The registrable domain apps are served under: `{app}.{org}.<apps domain>`.
/// Never the control plane's (see the module docs).
#[derive(Clone, PartialEq, Eq)]
pub struct AppsDomain(String);

impl AppsDomain {
    /// # Errors
    ///
    /// [`DomainError::Malformed`] unless `raw` is a lowercase multi-label host.
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        parse_host_name(raw).map(Self)
    }

    /// The domain.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The host an app is served on: `{app}.{org}.<apps domain>`. The only
    /// place an app host is built.
    #[must_use]
    pub fn app_host(&self, app: &str, org: &OrgSlug) -> String {
        format!("{app}.{}.{}", org.as_str(), self.0)
    }

    /// An org's wildcard certificate name: `*.{org}.<apps domain>`.
    #[must_use]
    pub fn org_wildcard(&self, org: &OrgSlug) -> String {
        format!("*.{}.{}", org.as_str(), self.0)
    }

    /// Refuse an apps domain that shares a registrable domain with the
    /// control plane's.
    ///
    /// ponytail: "registrable domain" is approximated by the last two labels,
    /// without the Public Suffix List. That errs toward refusing: two hosts
    /// under `co.uk` are refused even when the PSL would call them separate.
    /// Load the PSL here if a real deployment ever needs such a pair.
    ///
    /// # Errors
    ///
    /// [`DomainError::NotSeparate`] when the two share their last two labels.
    pub fn separate_from(&self, control_plane: &ControlPlaneDomain) -> Result<(), DomainError> {
        let last_two = |host: &str| {
            let labels: Vec<&str> = host.rsplitn(3, '.').take(2).collect();
            labels.join(".")
        };
        if last_two(&self.0) == last_two(control_plane.as_str()) {
            Err(DomainError::NotSeparate {
                apps: self.0.clone(),
                control_plane: control_plane.as_str().to_owned(),
            })
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for AppsDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AppsDomain({})", self.0)
    }
}

impl fmt::Display for AppsDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cp(raw: &str) -> ControlPlaneDomain {
        ControlPlaneDomain::parse(raw).expect("control-plane domain")
    }

    fn apps(raw: &str) -> AppsDomain {
        AppsDomain::parse(raw).expect("apps domain")
    }

    #[test]
    fn apps_on_the_control_planes_registrable_domain_are_refused() {
        for (a, c) in [
            ("clwd.run", "api.clwd.run"),
            ("apps.clwd.run", "api.clwd.run"),
            ("clwd.run", "clwd.run"),
            ("apps.clwd.test", "clwd.test"),
        ] {
            assert!(
                matches!(
                    apps(a).separate_from(&cp(c)),
                    Err(DomainError::NotSeparate { .. })
                ),
                "{a} beside {c}"
            );
        }
    }

    #[test]
    fn a_separate_registrable_domain_is_accepted() {
        assert_eq!(
            apps("clwd-apps.test").separate_from(&cp("api.clwd.test")),
            Ok(())
        );
        assert_eq!(
            apps("clwdusercontent.net").separate_from(&cp("api.clwd.run")),
            Ok(())
        );
    }

    #[test]
    fn hosts_are_built_only_under_the_apps_domain() {
        let org = OrgSlug::parse("acme").expect("slug");
        let a = apps("clwd-apps.test");
        assert_eq!(a.app_host("notes", &org), "notes.acme.clwd-apps.test");
        assert_eq!(a.org_wildcard(&org), "*.acme.clwd-apps.test");
    }

    #[test]
    fn malformed_domains_are_refused() {
        for raw in [
            "",
            "test",
            "Clwd.run",
            "clwd..run",
            "-a.run",
            "a_b.run",
            "clwd.run.",
        ] {
            assert!(AppsDomain::parse(raw).is_err(), "{raw:?}");
            assert!(ControlPlaneDomain::parse(raw).is_err(), "{raw:?}");
        }
    }
}
