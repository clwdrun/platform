//! The serving binary's configuration, read once from the environment (#48).
//!
//! Every setting is validated here, before anything binds or connects, and a
//! failure names the variable. Nothing below this module reads the
//! environment.
//!
//! # Variables
//!
//! | variable | required | validation |
//! |---|---|---|
//! | `DATABASE_URL` | yes | non-empty; redacted in `Debug` |
//! | `CLWD_PUBLIC_LISTEN` | yes | `ip:port`, loopback or private, never unspecified ([`private_only`]) |
//! | `CLWD_PUBLIC_LISTEN_ALLOW_PUBLIC` | no | `1` lets the public listener bind a public address |
//! | `CLWD_INTERNAL_LISTEN` | yes | as `CLWD_PUBLIC_LISTEN` |
//! | `CLWD_INTERNAL_LISTEN_ALLOW_PUBLIC` | no | as `CLWD_PUBLIC_LISTEN_ALLOW_PUBLIC` |
//! | `CLWD_OPS_LISTEN` | yes | as `CLWD_PUBLIC_LISTEN` |
//! | `CLWD_OPS_LISTEN_ALLOW_PUBLIC` | no | as `CLWD_INTERNAL_LISTEN_ALLOW_PUBLIC` |
//! | `CLWD_INTERNAL_SECRET` | yes | at least 32 bytes |
//! | `CLWD_SESSION_KEY` | yes | at least 32 bytes ([`CookieKey::from_secret`]) |
//! | `CLWD_GOOGLE_CLIENT_ID` | yes | non-empty |
//! | `CLWD_GOOGLE_CLIENT_SECRET` | yes | non-empty; redacted |
//! | `CLWD_GOOGLE_REDIRECT_URI` | yes | `https://<CLWD_CONTROL_PLANE_DOMAIN>/…` |
//! | `CLWD_OIDC_ISSUER` | no, `https://accounts.google.com` | `https://` |
//! | `CLWD_ALLOW_INSECURE_ISSUER` | no | `1` allows `http://` for the issuer and redirect URI, and any redirect host; tests only |
//! | `CLWD_CONTROL_PLANE_DOMAIN` | yes | host name |
//! | `CLWD_APPS_DOMAIN` | yes | host name, separate registrable domain from the control plane's |
//! | `CLWD_ARTIFACT_ROOT` | yes | an existing directory |
//! | `CLWD_DB_MAX_CONNECTIONS` | no, 20 | 1–80; every connection is opened before ready |
//! | `CLWD_DB_ACQUIRE_TIMEOUT` | no, `2s` | a duration with a unit, under the gateway's 5 s |
//! | `CLWD_PRE_STOP_DELAY` | no, `5s` | a duration with a unit, at most 10 s |
//! | `CLWD_CERT_RECONCILER` | yes | `on` or `off`; no default |
//! | `CLWD_ACME_ACCOUNT_FILE` | with `on` | the account credentials JSON |
//! | `CLWD_ACME_CA_ROOT` | no | a PEM root to trust for the ACME directory (Pebble in tests) |
//! | `CLWD_CERT_DIR` | with `on` | where certificates are written |
//! | `CLWD_CLOUDFLARE_TOKEN` | with `on` | redacted |
//! | `CLWD_CLOUDFLARE_ZONE_ID` | with `on` | non-empty |
//! | `CLWD_CLOUDFLARE_NAMESERVERS` | with `on` | comma-separated host names |
//!
//! What is deliberately *not* configurable, and why, is in decision record
//! 0004: the drain deadline (equal to the request timeout), the header read
//! timeout, the statement and idle-in-transaction timeouts, and the pool's
//! idle and lifetime limits (off).

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use shared::domains::{AppsDomain, ControlPlaneDomain};

use crate::signin::{CookieKey, MIN_COOKIE_KEY_BYTES};

/// Google's issuer, the default for `CLWD_OIDC_ISSUER`.
pub const GOOGLE_ISSUER: &str = "https://accounts.google.com";

/// The gateway gives up on the control plane after this long, so a pool wait
/// must end before it does: a shortage then fails as `control-plane.timeout`
/// rather than as a gateway timeout (#48's comment from #12).
pub const GATEWAY_TIMEOUT: Duration = Duration::from_secs(5);

/// A ceiling on one instance's serving pool, to catch a typo rather than to
/// size anything. The real constraint is the budget in decision record 0004:
/// `(serving + relay's 5) × instances` must fit under the server's
/// `max_connections` less its reserved slots.
pub const MAX_POOL: u32 = 80;

/// The longest pre-stop delay accepted: with the 30 s drain it keeps the whole
/// shutdown inside the 45 s kill grace #84 is asked for.
pub const MAX_PRE_STOP: Duration = Duration::from_secs(10);

/// The ACME group: set together when the reconciler is on, none of them when
/// it is off.
const ACME_REQUIRED: [&str; 5] = [
    "CLWD_ACME_ACCOUNT_FILE",
    "CLWD_CERT_DIR",
    "CLWD_CLOUDFLARE_TOKEN",
    "CLWD_CLOUDFLARE_ZONE_ID",
    "CLWD_CLOUDFLARE_NAMESERVERS",
];
const ACME_OPTIONAL: [&str; 1] = ["CLWD_ACME_CA_ROOT"];

/// Why the configuration was refused. Every variant names the variable.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// A required variable is unset or empty.
    #[error("{var} is required: {what}")]
    Missing {
        var: &'static str,
        what: &'static str,
    },
    /// A variable is set to something unusable.
    #[error("{var}: {why}")]
    Invalid { var: &'static str, why: String },
}

fn invalid(var: &'static str, why: impl fmt::Display) -> ConfigError {
    ConfigError::Invalid {
        var,
        why: why.to_string(),
    }
}

/// A secret read from configuration. `Debug` and `Display` never print it.
#[derive(Clone)]
pub struct Secret(String);

impl Secret {
    /// The secret itself, for the one place that needs it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

/// The address the public router binds: reachable by the gateway, which
/// forwards the platform's own hosts to it (#95). Private by policy like the
/// other two: it serves plain HTTP, so a reachable bind would expose sign-in
/// and the OAuth callback without TLS and without the gateway. A distinct
/// type from the other two, so the addresses cannot be swapped by position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicListen(pub SocketAddr);

/// The address the internal router binds: the gateways' session checks, the
/// handshake exchange and the authorization stream. Private by policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InternalListen(pub SocketAddr);

/// The address `/livez` and `/readyz` bind. Private by policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpsListen(pub SocketAddr);

/// A duration read with an explicit unit: `500ms` or `5s`. A bare number is
/// refused, because `5` read as milliseconds by one reader and seconds by the
/// next is how a two-second timeout becomes a two-thousand-second one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnitDuration(pub Duration);

impl std::str::FromStr for UnitDuration {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let (digits, scale): (&str, fn(u64) -> Duration) = if let Some(d) = raw.strip_suffix("ms") {
            (d, Duration::from_millis)
        } else if let Some(d) = raw.strip_suffix('s') {
            (d, Duration::from_secs)
        } else {
            return Err(format!(
                "{raw:?} has no unit; write it as milliseconds (`500ms`) or seconds (`5s`)"
            ));
        };
        digits
            .parse::<u64>()
            .map(|n| Self(scale(n)))
            .map_err(|_| format!("{raw:?} is not a whole number of ms or s"))
    }
}

/// The serving pool, as configured. The rest of its shape is fixed in
/// [`crate::serve`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PoolSettings {
    /// Connections held, all opened before the instance is ready.
    pub max_connections: u32,
    /// How long a request waits for a connection.
    pub acquire_timeout: Duration,
}

/// Google sign-in, as configured.
#[derive(Debug)]
#[non_exhaustive]
pub struct Oidc {
    pub client_id: String,
    pub client_secret: Secret,
    pub redirect_uri: String,
    pub issuer: String,
}

impl Oidc {
    /// The `identity` crate's configuration type.
    #[must_use]
    pub fn to_identity(&self) -> identity::OidcConfig {
        identity::OidcConfig::new(
            self.client_id.clone(),
            self.client_secret.expose(),
            self.redirect_uri.clone(),
            self.issuer.clone(),
        )
    }
}

/// The certificate reconciler, switched explicitly (#48): a deploy that forgot
/// the ACME settings must fail to start, not silently never issue. Two
/// states, deliberately exhaustive: there is no third answer to "on or off".
#[derive(Debug)]
pub enum Reconciler {
    Off,
    On(Acme),
}

/// What the reconciler needs.
#[derive(Debug)]
#[non_exhaustive]
pub struct Acme {
    pub account_file: PathBuf,
    pub ca_root: Option<PathBuf>,
    pub cert_dir: PathBuf,
    pub cloudflare_token: Secret,
    pub cloudflare_zone_id: String,
    pub cloudflare_nameservers: Vec<String>,
}

/// Everything the serving binary is configured with.
#[derive(Debug)]
#[non_exhaustive]
pub struct Config {
    pub database_url: Secret,
    pub public: PublicListen,
    pub internal: InternalListen,
    pub ops: OpsListen,
    pub internal_secret: Secret,
    pub session_key: CookieKey,
    pub oidc: Oidc,
    pub control_plane_domain: ControlPlaneDomain,
    pub apps_domain: AppsDomain,
    pub artifact_root: PathBuf,
    pub pool: PoolSettings,
    pub pre_stop: Duration,
    pub reconciler: Reconciler,
}

impl Config {
    /// Read and validate the process environment.
    ///
    /// # Errors
    ///
    /// The first [`ConfigError`] found, naming its variable.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|var| std::env::var(var).ok())
    }

    /// Read and validate configuration from `lookup`, which maps a variable
    /// name to its value. An empty value counts as unset.
    ///
    /// # Errors
    ///
    /// The first [`ConfigError`] found, naming its variable.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let get = |var: &str| lookup(var).filter(|v| !v.is_empty());
        let require = |var: &'static str, what: &'static str| {
            get(var).ok_or(ConfigError::Missing { var, what })
        };
        let flag = |var: &'static str| match get(var).as_deref() {
            None | Some("0") => Ok(false),
            Some("1") => Ok(true),
            Some(other) => Err(invalid(var, format!("{other:?} is not `1` or `0`"))),
        };
        let address = |var: &'static str| {
            require(var, "the address to listen on, as ip:port")?
                .parse::<SocketAddr>()
                .map_err(|e| invalid(var, format!("not an ip:port: {e}")))
        };
        let duration = |var: &'static str, default: Duration| {
            get(var).map_or(Ok(default), |raw| {
                raw.parse::<UnitDuration>()
                    .map(|d| d.0)
                    .map_err(|e| invalid(var, e))
            })
        };

        let database_url = Secret(require("DATABASE_URL", "the control plane's database")?);

        let public = address("CLWD_PUBLIC_LISTEN")?;
        private_only(public, flag("CLWD_PUBLIC_LISTEN_ALLOW_PUBLIC")?)
            .map_err(|why| invalid("CLWD_PUBLIC_LISTEN", why))?;
        let public = PublicListen(public);
        let internal = address("CLWD_INTERNAL_LISTEN")?;
        private_only(internal, flag("CLWD_INTERNAL_LISTEN_ALLOW_PUBLIC")?)
            .map_err(|why| invalid("CLWD_INTERNAL_LISTEN", why))?;
        let internal = InternalListen(internal);
        let ops = address("CLWD_OPS_LISTEN")?;
        private_only(ops, flag("CLWD_OPS_LISTEN_ALLOW_PUBLIC")?)
            .map_err(|why| invalid("CLWD_OPS_LISTEN", why))?;
        let ops = OpsListen(ops);
        for (var, addr) in [
            ("CLWD_INTERNAL_LISTEN", internal.0),
            ("CLWD_OPS_LISTEN", ops.0),
        ] {
            if addr == public.0 {
                return Err(invalid(var, "must differ from CLWD_PUBLIC_LISTEN"));
            }
        }
        if internal.0 == ops.0 {
            return Err(invalid(
                "CLWD_OPS_LISTEN",
                "must differ from CLWD_INTERNAL_LISTEN",
            ));
        }

        let internal_secret = require(
            "CLWD_INTERNAL_SECRET",
            "the credential platform services present to internal routes",
        )?;
        if internal_secret.len() < MIN_COOKIE_KEY_BYTES {
            return Err(invalid(
                "CLWD_INTERNAL_SECRET",
                format!(
                    "needs at least {MIN_COOKIE_KEY_BYTES} bytes; this one has {}",
                    internal_secret.len()
                ),
            ));
        }
        let session_key = CookieKey::from_secret(
            require(
                "CLWD_SESSION_KEY",
                "the key session and sign-in cookies are signed with",
            )?
            .as_bytes(),
        )
        .map_err(|e| invalid("CLWD_SESSION_KEY", e))?;

        let control_plane_domain = ControlPlaneDomain::parse(&require(
            "CLWD_CONTROL_PLANE_DOMAIN",
            "the host the control plane is served on",
        )?)
        .map_err(|e| invalid("CLWD_CONTROL_PLANE_DOMAIN", e))?;
        let apps_domain = AppsDomain::parse(&require(
            "CLWD_APPS_DOMAIN",
            "the domain apps are served under",
        )?)
        .map_err(|e| invalid("CLWD_APPS_DOMAIN", e))?;
        apps_domain
            .separate_from(&control_plane_domain)
            .map_err(|e| invalid("CLWD_APPS_DOMAIN", e))?;

        let insecure = flag("CLWD_ALLOW_INSECURE_ISSUER")?;
        let issuer = get("CLWD_OIDC_ISSUER").unwrap_or_else(|| GOOGLE_ISSUER.to_owned());
        https_unless(&issuer, insecure).map_err(|e| invalid("CLWD_OIDC_ISSUER", e))?;
        let redirect_uri = require(
            "CLWD_GOOGLE_REDIRECT_URI",
            "the sign-in callback URL registered with Google",
        )?;
        let redirect = https_unless(&redirect_uri, insecure)
            .map_err(|e| invalid("CLWD_GOOGLE_REDIRECT_URI", e))?;
        if !insecure && redirect.host_str() != Some(control_plane_domain.as_str()) {
            return Err(invalid(
                "CLWD_GOOGLE_REDIRECT_URI",
                format!(
                    "its host must be CLWD_CONTROL_PLANE_DOMAIN ({}), because the session cookie is set there",
                    control_plane_domain.as_str()
                ),
            ));
        }
        let oidc = Oidc {
            client_id: require("CLWD_GOOGLE_CLIENT_ID", "the OAuth client id Google issued")?,
            client_secret: Secret(require(
                "CLWD_GOOGLE_CLIENT_SECRET",
                "the OAuth client secret Google issued",
            )?),
            redirect_uri,
            issuer,
        };

        let artifact_root = PathBuf::from(require(
            "CLWD_ARTIFACT_ROOT",
            "the directory publish stores artifacts in",
        )?);
        if !artifact_root.is_dir() {
            return Err(invalid(
                "CLWD_ARTIFACT_ROOT",
                format!("{} is not a directory", artifact_root.display()),
            ));
        }

        let max_connections = get("CLWD_DB_MAX_CONNECTIONS").map_or(Ok(20), |raw| {
            raw.parse::<u32>()
                .ok()
                .filter(|n| (1..=MAX_POOL).contains(n))
                .ok_or_else(|| {
                    invalid(
                        "CLWD_DB_MAX_CONNECTIONS",
                        format!("{raw:?} is not a whole number from 1 to {MAX_POOL}"),
                    )
                })
        })?;
        let acquire_timeout = duration("CLWD_DB_ACQUIRE_TIMEOUT", Duration::from_secs(2))?;
        if acquire_timeout.is_zero() || acquire_timeout >= GATEWAY_TIMEOUT {
            return Err(invalid(
                "CLWD_DB_ACQUIRE_TIMEOUT",
                format!(
                    "must be above zero and under the gateway's {} s, so a pool shortage is reported as \
                     control-plane.timeout rather than as a gateway timeout",
                    GATEWAY_TIMEOUT.as_secs()
                ),
            ));
        }
        let pre_stop = duration("CLWD_PRE_STOP_DELAY", Duration::from_secs(5))?;
        if pre_stop > MAX_PRE_STOP {
            return Err(invalid(
                "CLWD_PRE_STOP_DELAY",
                format!(
                    "at most {} s, so shutdown fits the kill grace",
                    MAX_PRE_STOP.as_secs()
                ),
            ));
        }

        let reconciler = reconciler(&get)?;

        Ok(Self {
            database_url,
            public,
            internal,
            ops,
            internal_secret: Secret(internal_secret),
            session_key,
            oidc,
            control_plane_domain,
            apps_domain,
            artifact_root,
            pool: PoolSettings {
                max_connections,
                acquire_timeout,
            },
            pre_stop,
            reconciler,
        })
    }
}

fn reconciler(get: &impl Fn(&str) -> Option<String>) -> Result<Reconciler, ConfigError> {
    const VAR: &str = "CLWD_CERT_RECONCILER";
    match get(VAR).as_deref() {
        None => Err(ConfigError::Missing {
            var: VAR,
            what: "`on` or `off`; there is no default, so a deploy that forgot the ACME settings fails here rather than never issuing certificates",
        }),
        Some("off") => {
            if let Some(var) = ACME_REQUIRED
                .iter()
                .chain(&ACME_OPTIONAL)
                .find(|var| get(var).is_some())
            {
                return Err(invalid(
                    VAR,
                    format!(
                        "is `off`, but {var} is set; set it to `on`, or unset the ACME settings"
                    ),
                ));
            }
            Ok(Reconciler::Off)
        }
        Some("on") => {
            let need = |var: &'static str| {
                get(var).ok_or(ConfigError::Missing {
                    var,
                    what: "the certificate reconciler is `on`, and it needs every ACME setting",
                })
            };
            let nameservers: Vec<String> = need("CLWD_CLOUDFLARE_NAMESERVERS")?
                .split(',')
                .map(|ns| ns.trim().to_owned())
                .collect();
            if nameservers.iter().any(String::is_empty) {
                return Err(invalid(
                    "CLWD_CLOUDFLARE_NAMESERVERS",
                    "a comma-separated list of host names, with none empty",
                ));
            }
            Ok(Reconciler::On(Acme {
                account_file: need("CLWD_ACME_ACCOUNT_FILE")?.into(),
                ca_root: get("CLWD_ACME_CA_ROOT").map(PathBuf::from),
                cert_dir: need("CLWD_CERT_DIR")?.into(),
                cloudflare_token: Secret(need("CLWD_CLOUDFLARE_TOKEN")?),
                cloudflare_zone_id: need("CLWD_CLOUDFLARE_ZONE_ID")?,
                cloudflare_nameservers: nameservers,
            }))
        }
        Some(other) => Err(invalid(VAR, format!("{other:?} is not `on` or `off`"))),
    }
}

/// Parse `raw` as a URL and require `https`, unless `insecure` allows `http`.
///
/// An issuer pointed at the wrong place is a total authentication bypass: it
/// signs whatever identity it likes. `https` is the floor; plain HTTP exists
/// only for the tests' mock issuer, behind an explicit switch.
fn https_unless(raw: &str, insecure: bool) -> Result<reqwest::Url, String> {
    let url = reqwest::Url::parse(raw).map_err(|e| format!("{raw:?} is not a URL: {e}"))?;
    match url.scheme() {
        "https" => Ok(url),
        "http" if insecure => Ok(url),
        "http" => Err(format!(
            "{raw:?} is plain HTTP; it must be https (CLWD_ALLOW_INSECURE_ISSUER=1 allows http, for tests only)"
        )),
        other => Err(format!("{raw:?} has scheme {other:?}; it must be https")),
    }
}

/// The bind policy for every listener: all three serve plain HTTP.
///
/// Never the unspecified address (`0.0.0.0`, `::`), with or without the
/// override: "every interface" includes the public one, and on a host that
/// gains an interface later, includes that too. Otherwise loopback or a
/// private range, unless `allow_public` says the operator means it.
///
/// # Errors
///
/// Why the address is refused.
pub fn private_only(addr: SocketAddr, allow_public: bool) -> Result<(), String> {
    let ip = addr.ip();
    if ip.is_unspecified() {
        return Err(format!(
            "{ip} listens on every interface, including public ones; name a private address"
        ));
    }
    let private = match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local(),
    };
    if private || allow_public {
        Ok(())
    } else {
        Err(format!(
            "{ip} is not loopback or a private range; set the matching _ALLOW_PUBLIC=1 if that is intended"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn base() -> HashMap<&'static str, String> {
        let root = std::env::temp_dir();
        [
            ("DATABASE_URL", "postgres://u:hunter2@db/clwd"),
            ("CLWD_PUBLIC_LISTEN", "10.0.0.5:8080"),
            ("CLWD_INTERNAL_LISTEN", "10.0.0.5:8081"),
            ("CLWD_OPS_LISTEN", "127.0.0.1:8082"),
            (
                "CLWD_INTERNAL_SECRET",
                "internal-secret-of-at-least-32-bytes!!",
            ),
            (
                "CLWD_SESSION_KEY",
                "session-key-of-at-least-thirty-two-bytes",
            ),
            ("CLWD_GOOGLE_CLIENT_ID", "client"),
            ("CLWD_GOOGLE_CLIENT_SECRET", "google-client-secret"),
            (
                "CLWD_GOOGLE_REDIRECT_URI",
                "https://api.clwd.run/auth/google/callback",
            ),
            ("CLWD_CONTROL_PLANE_DOMAIN", "api.clwd.run"),
            ("CLWD_APPS_DOMAIN", "clwd.app"),
            ("CLWD_ARTIFACT_ROOT", root.to_str().expect("utf-8 temp dir")),
            ("CLWD_CERT_RECONCILER", "off"),
        ]
        .into_iter()
        .map(|(k, v)| (k, v.to_owned()))
        .collect()
    }

    fn load(vars: &HashMap<&'static str, String>) -> Result<Config, ConfigError> {
        Config::from_lookup(|var| vars.get(var).cloned())
    }

    fn with(changes: &[(&'static str, &str)]) -> Result<Config, ConfigError> {
        let mut vars = base();
        for (k, v) in changes {
            vars.insert(k, (*v).to_owned());
        }
        load(&vars)
    }

    fn err_of(result: Result<Config, ConfigError>) -> String {
        match result {
            Ok(_) => panic!("expected the configuration to be refused"),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn a_complete_configuration_loads_with_the_documented_defaults() {
        let config = load(&base()).expect("complete");
        assert_eq!(config.pool.max_connections, 20);
        assert_eq!(config.pool.acquire_timeout, Duration::from_secs(2));
        assert_eq!(config.pre_stop, Duration::from_secs(5));
        assert_eq!(config.oidc.issuer, GOOGLE_ISSUER);
        assert!(matches!(config.reconciler, Reconciler::Off));
    }

    #[test]
    fn every_required_variable_is_named_when_missing() {
        for var in base().keys().copied() {
            let mut vars = base();
            vars.remove(var);
            let err = err_of(load(&vars));
            assert!(err.starts_with(var), "missing {var} reported as: {err}");
        }
        // Empty is unset.
        let err = err_of(with(&[("CLWD_INTERNAL_SECRET", "")]));
        assert!(err.starts_with("CLWD_INTERNAL_SECRET is required"), "{err}");
    }

    /// Mutation 14: a default for the switch turns this red.
    #[test]
    fn the_reconciler_switch_has_no_default() {
        let mut vars = base();
        vars.remove("CLWD_CERT_RECONCILER");
        let err = err_of(load(&vars));
        assert!(err.starts_with("CLWD_CERT_RECONCILER is required"), "{err}");
        let err = err_of(with(&[("CLWD_CERT_RECONCILER", "yes")]));
        assert!(err.contains("is not `on` or `off`"), "{err}");
    }

    #[test]
    fn the_reconciler_on_needs_every_acme_setting_and_off_refuses_any() {
        let full = [
            ("CLWD_CERT_RECONCILER", "on"),
            ("CLWD_ACME_ACCOUNT_FILE", "/run/secrets/acme.json"),
            ("CLWD_CERT_DIR", "/var/lib/clwd/certs"),
            ("CLWD_CLOUDFLARE_TOKEN", "cf-token"),
            ("CLWD_CLOUDFLARE_ZONE_ID", "zone"),
            (
                "CLWD_CLOUDFLARE_NAMESERVERS",
                "a.ns.cloudflare.com, b.ns.cloudflare.com",
            ),
        ];
        let config = with(&full).expect("complete ACME group");
        let Reconciler::On(acme) = config.reconciler else {
            panic!("expected the reconciler on");
        };
        assert_eq!(
            acme.cloudflare_nameservers,
            ["a.ns.cloudflare.com", "b.ns.cloudflare.com"]
        );
        assert!(
            !format!("{acme:?}").contains("cf-token"),
            "the token is redacted"
        );

        for missing in ACME_REQUIRED {
            let partial: Vec<_> = full
                .iter()
                .copied()
                .filter(|(k, _)| *k != missing)
                .collect();
            let err = err_of(with(&partial));
            assert!(err.starts_with(missing), "on without {missing}: {err}");
        }
        for set in ACME_REQUIRED.iter().chain(&ACME_OPTIONAL) {
            let err = err_of(with(&[(set, "x")]));
            assert!(
                err.starts_with("CLWD_CERT_RECONCILER") && err.contains(set),
                "off with {set}: {err}"
            );
        }
    }

    /// Mutation 15: accepting `http://` without the override turns this red.
    #[test]
    fn the_issuer_and_redirect_must_be_https_unless_insecure_is_explicit() {
        let err = err_of(with(&[("CLWD_OIDC_ISSUER", "http://issuer.test")]));
        assert!(
            err.starts_with("CLWD_OIDC_ISSUER") && err.contains("plain HTTP"),
            "{err}"
        );
        let err = err_of(with(&[(
            "CLWD_GOOGLE_REDIRECT_URI",
            "http://api.clwd.run/cb",
        )]));
        assert!(err.starts_with("CLWD_GOOGLE_REDIRECT_URI"), "{err}");
        let err = err_of(with(&[(
            "CLWD_GOOGLE_REDIRECT_URI",
            "https://evil.example/cb",
        )]));
        assert!(err.contains("CLWD_CONTROL_PLANE_DOMAIN"), "{err}");

        let config = with(&[
            ("CLWD_ALLOW_INSECURE_ISSUER", "1"),
            ("CLWD_OIDC_ISSUER", "http://127.0.0.1:9/"),
            (
                "CLWD_GOOGLE_REDIRECT_URI",
                "http://127.0.0.1:8080/auth/google/callback",
            ),
        ])
        .expect("explicitly insecure");
        assert_eq!(config.oidc.issuer, "http://127.0.0.1:9/");
        let err = err_of(with(&[("CLWD_ALLOW_INSECURE_ISSUER", "yes")]));
        assert!(err.starts_with("CLWD_ALLOW_INSECURE_ISSUER"), "{err}");
    }

    #[test]
    fn private_listeners_refuse_public_and_unspecified_addresses() {
        for var in [
            "CLWD_PUBLIC_LISTEN",
            "CLWD_INTERNAL_LISTEN",
            "CLWD_OPS_LISTEN",
        ] {
            let allow = match var {
                "CLWD_PUBLIC_LISTEN" => "CLWD_PUBLIC_LISTEN_ALLOW_PUBLIC",
                "CLWD_INTERNAL_LISTEN" => "CLWD_INTERNAL_LISTEN_ALLOW_PUBLIC",
                _ => "CLWD_OPS_LISTEN_ALLOW_PUBLIC",
            };
            let err = err_of(with(&[(var, "203.0.113.7:9000")]));
            assert!(
                err.starts_with(var) && err.contains("_ALLOW_PUBLIC"),
                "{err}"
            );
            with(&[(var, "203.0.113.7:9000"), (allow, "1")]).expect("public, explicitly allowed");
            for unspecified in ["0.0.0.0:9000", "[::]:9000"] {
                let err = err_of(with(&[(var, unspecified), (allow, "1")]));
                assert!(err.contains("every interface"), "{unspecified}: {err}");
            }
            with(&[(var, "[::1]:9000")]).expect("loopback v6");
            with(&[(var, "[fd00::1]:9000")]).expect("unique local v6");
            with(&[(var, "192.168.1.4:9000")]).expect("private v4");
        }
        let err = err_of(with(&[("CLWD_OPS_LISTEN", "10.0.0.5:8081")]));
        assert!(
            err.contains("must differ from CLWD_INTERNAL_LISTEN"),
            "{err}"
        );
        let err = err_of(with(&[("CLWD_INTERNAL_LISTEN", "10.0.0.5:8080")]));
        assert!(err.contains("must differ from CLWD_PUBLIC_LISTEN"), "{err}");
    }

    #[test]
    fn secrets_are_long_enough_and_never_printed() {
        let err = err_of(with(&[("CLWD_INTERNAL_SECRET", "short")]));
        assert!(
            err.starts_with("CLWD_INTERNAL_SECRET") && err.contains("32"),
            "{err}"
        );
        let err = err_of(with(&[("CLWD_SESSION_KEY", "short")]));
        assert!(
            err.starts_with("CLWD_SESSION_KEY") && err.contains("32"),
            "{err}"
        );

        let printed = format!("{:?}", load(&base()).expect("complete"));
        for secret in [
            "hunter2",
            "internal-secret-of-at-least-32-bytes",
            "session-key-of-at-least",
            "google-client-secret",
        ] {
            assert!(
                !printed.contains(secret),
                "{secret} leaked into Debug: {printed}"
            );
        }
    }

    #[test]
    fn durations_need_a_unit_and_stay_inside_their_bounds() {
        let err = err_of(with(&[("CLWD_DB_ACQUIRE_TIMEOUT", "2")]));
        assert!(
            err.starts_with("CLWD_DB_ACQUIRE_TIMEOUT") && err.contains("no unit"),
            "{err}"
        );
        let config = with(&[
            ("CLWD_DB_ACQUIRE_TIMEOUT", "1500ms"),
            ("CLWD_PRE_STOP_DELAY", "0s"),
        ])
        .expect("units");
        assert_eq!(config.pool.acquire_timeout, Duration::from_millis(1500));
        assert_eq!(config.pre_stop, Duration::ZERO);
        for over in ["5s", "5000ms", "0ms"] {
            let err = err_of(with(&[("CLWD_DB_ACQUIRE_TIMEOUT", over)]));
            assert!(err.contains("gateway"), "{over}: {err}");
        }
        let err = err_of(with(&[("CLWD_PRE_STOP_DELAY", "11s")]));
        assert!(err.starts_with("CLWD_PRE_STOP_DELAY"), "{err}");
        for bad in ["0", "81", "many"] {
            let err = err_of(with(&[("CLWD_DB_MAX_CONNECTIONS", bad)]));
            assert!(err.starts_with("CLWD_DB_MAX_CONNECTIONS"), "{bad}: {err}");
        }
    }

    #[test]
    fn the_apps_domain_must_be_separate_from_the_control_plane() {
        let err = err_of(with(&[("CLWD_APPS_DOMAIN", "apps.clwd.run")]));
        assert!(
            err.starts_with("CLWD_APPS_DOMAIN") && err.contains("registrable"),
            "{err}"
        );
        let err = err_of(with(&[(
            "CLWD_ARTIFACT_ROOT",
            "/nonexistent/clwd/artifacts",
        )]));
        assert!(err.starts_with("CLWD_ARTIFACT_ROOT"), "{err}");
    }
}
