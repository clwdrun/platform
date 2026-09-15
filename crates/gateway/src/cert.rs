//! Per-org certificate storage and SNI-time selection.
//!
//! One wildcard certificate per org — `*.{slug}.clwd.run` — covers every
//! `{app}.{slug}.clwd.run` host (#5, #18). At handshake time the SNI names the
//! full host; this module extracts the org and finds its certificate.
//!
//! Two seams, deliberately separated:
//!
//! - [`CertStore`] — where certificates live. #22 (the secret broker) inherits
//!   this trait; its Postgres + `age`-encrypted-key implementation sits behind
//!   it and changes no caller. The trait shape is what survives, so it is what
//!   matters here.
//! - [`CertResolver`] — the selection logic (SNI → org → certificate), kept out
//!   of the pingora `TlsAccept` callback so it is testable without a handshake.
//!
//! Every outcome other than "served" is a client-visible handshake failure that
//! looks identical to an outage from outside, so each is counted in
//! [`HandshakeMetrics`] and logged — the same visibility a silent renewal
//! failure would need.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use thiserror::Error;

use crate::host::{OrgSlug, parse_host};

/// A stored certificate chain and its private key, as PEM bytes.
///
/// Bytes rather than parsed TLS types on purpose: the store and the selection
/// logic stay decoupled from the TLS backend and testable without it, and the
/// key is parsed only at the moment the handshake needs it.
#[derive(Clone)]
pub struct StoredCert {
    /// The certificate (chain) in PEM.
    pub cert_pem: Vec<u8>,
    /// The private key in PEM. Never logged, never serialized — see the `Debug`
    /// impl, which redacts it.
    pub key_pem: Vec<u8>,
}

impl fmt::Debug for StoredCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The private key must never reach a log line or an error message.
        f.debug_struct("StoredCert")
            .field("cert_pem", &format_args!("{} bytes", self.cert_pem.len()))
            .field("key_pem", &"<redacted>")
            .finish()
    }
}

/// Where per-org certificates live, keyed by org slug.
///
/// #22 inherits this trait. Implementations must be cheap to share (`Arc`ed and
/// called per handshake).
#[async_trait]
pub trait CertStore: Send + Sync {
    /// The certificate for `org`, or `None` if none is stored yet (unissued, or
    /// issuance not complete).
    ///
    /// # Errors
    /// [`CertStoreError`] if the store cannot be reached.
    async fn cert_for(&self, org: &OrgSlug) -> Result<Option<StoredCert>, CertStoreError>;
}

/// Why a certificate store lookup could not be answered.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CertStoreError {
    /// The store could not be reached. A handshake with no cached alternative
    /// must fail closed, not serve a wrong or absent certificate.
    #[error("certificate store unavailable: {0}")]
    Unavailable(String),
}

/// The outcome of resolving an SNI name to a certificate.
#[derive(Debug)]
#[must_use]
pub enum Selection {
    /// A certificate for the org was found; serve it.
    Serve(StoredCert),
    /// The SNI is not a `{app}.{org}.<apex>` host, so no per-org certificate
    /// applies. The handshake cannot be completed for it here.
    NotAppHost,
    /// The org has no certificate yet — unissued, or issuance incomplete.
    NoCert,
    /// The certificate store could not be reached.
    Unavailable,
}

/// Counters for SNI certificate selection, so a miss is observable.
///
/// A non-`Serve` outcome fails the handshake, which a client cannot tell from
/// an outage, so it must be visible here as well as in the logs.
#[derive(Default)]
pub struct HandshakeMetrics {
    /// Handshakes for which a certificate was found.
    pub served: AtomicU64,
    /// SNI names that were not `{app}.{org}.<apex>` hosts.
    pub not_app_host: AtomicU64,
    /// Orgs with no certificate stored (unissued or issuance incomplete).
    pub no_cert: AtomicU64,
    /// Store lookups that could not be answered.
    pub unavailable: AtomicU64,
}

impl HandshakeMetrics {
    /// Read a counter. For tests and, later, metric export.
    #[must_use]
    pub fn get(counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }
}

/// Selects a certificate for an SNI name against a [`CertStore`].
///
/// The selection logic lives here, apart from the pingora `TlsAccept` callback,
/// so it can be tested without a TLS handshake.
pub struct CertResolver {
    store: Arc<dyn CertStore>,
    apex: String,
    metrics: Arc<HandshakeMetrics>,
}

impl CertResolver {
    /// A resolver over `store`, treating SNI names under `apex` (e.g. `clwd.run`).
    #[must_use]
    pub fn new(store: Arc<dyn CertStore>, apex: impl Into<String>) -> Self {
        Self {
            store,
            apex: apex.into(),
            metrics: Arc::new(HandshakeMetrics::default()),
        }
    }

    /// The shared metrics, for export and for asserting a miss was counted.
    #[must_use]
    pub fn metrics(&self) -> Arc<HandshakeMetrics> {
        Arc::clone(&self.metrics)
    }

    /// Resolve an SNI name to a [`Selection`], counting and logging every
    /// outcome. A missing SNI (`None`) is treated as not-an-app-host.
    pub async fn select(&self, sni: Option<&str>) -> Selection {
        let Some(sni) = sni else {
            self.metrics.not_app_host.fetch_add(1, Ordering::Relaxed);
            tracing::warn!("TLS handshake with no SNI; no per-org certificate applies");
            return Selection::NotAppHost;
        };

        let org = match parse_host(sni, &self.apex) {
            Ok(app_host) => app_host.org,
            Err(_) => {
                self.metrics.not_app_host.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    sni,
                    "SNI is not an app host; no per-org certificate applies"
                );
                return Selection::NotAppHost;
            }
        };

        match self.store.cert_for(&org).await {
            Ok(Some(cert)) => {
                self.metrics.served.fetch_add(1, Ordering::Relaxed);
                Selection::Serve(cert)
            }
            Ok(None) => {
                self.metrics.no_cert.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    org = org.as_str(),
                    "no certificate for org; handshake will fail (issuance pending?)"
                );
                Selection::NoCert
            }
            Err(error) => {
                self.metrics.unavailable.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    org = org.as_str(),
                    %error,
                    "certificate store unreachable; handshake will fail"
                );
                Selection::Unavailable
            }
        }
    }
}

/// A file-backed [`CertStore`] for development ONLY, until #22's secret broker
/// exists: it reads `{dir}/{org}/cert.pem` and `{dir}/{org}/key.pem`.
///
/// **This must not become the production answer.** It stores unencrypted private
/// keys as plaintext files on the gateway host — and the gateway is the shared,
/// multi-tenant case that clwd#71 says a file store is explicitly wrong for (a
/// file store is right for a dev laptop and nothing shared). It exists behind
/// the [`CertStore`] trait purely so per-org selection can be built and tested
/// before issuance and storage land; **#22 (the secret broker: `age` at rest,
/// keys off the host filesystem) replaces it**, and the trait means that swap
/// touches no caller. Do not deploy this to a shared gateway.
///
/// `org` is an [`OrgSlug`], already validated as a single DNS label, so it
/// cannot contain a path separator or `..` — no traversal.
pub struct DirCertStore {
    dir: std::path::PathBuf,
}

impl DirCertStore {
    /// A store rooted at `dir`.
    #[must_use]
    pub fn new(dir: impl Into<std::path::PathBuf>) -> Self {
        Self { dir: dir.into() }
    }
}

#[async_trait]
impl CertStore for DirCertStore {
    async fn cert_for(&self, org: &OrgSlug) -> Result<Option<StoredCert>, CertStoreError> {
        let base = self.dir.join(org.as_str());
        match tokio::fs::read(base.join("cert.pem")).await {
            Ok(cert_pem) => {
                // A cert with no key beside it is a store-integrity fault, not a
                // missing cert: surface it rather than silently reading as NoCert.
                let key_pem = tokio::fs::read(base.join("key.pem")).await.map_err(|e| {
                    CertStoreError::Unavailable(format!("key for {}: {e}", org.as_str()))
                })?;
                Ok(Some(StoredCert { cert_pem, key_pem }))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(CertStoreError::Unavailable(format!(
                "cert for {}: {e}",
                org.as_str()
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    /// An in-memory store, plus a switch to simulate the store being down.
    struct MapStore {
        certs: HashMap<String, StoredCert>,
        down: bool,
    }

    #[async_trait]
    impl CertStore for MapStore {
        async fn cert_for(&self, org: &OrgSlug) -> Result<Option<StoredCert>, CertStoreError> {
            if self.down {
                return Err(CertStoreError::Unavailable("test store is down".to_owned()));
            }
            Ok(self.certs.get(org.as_str()).cloned())
        }
    }

    fn cert() -> StoredCert {
        StoredCert {
            cert_pem: b"-----BEGIN CERTIFICATE-----".to_vec(),
            key_pem: b"-----BEGIN PRIVATE KEY-----".to_vec(),
        }
    }

    fn resolver(down: bool, orgs: &[&str]) -> CertResolver {
        let certs = orgs
            .iter()
            .map(|o| ((*o).to_owned(), cert()))
            .collect::<HashMap<_, _>>();
        CertResolver::new(Arc::new(MapStore { certs, down }), "clwd.run")
    }

    #[tokio::test]
    async fn a_known_org_is_served() {
        let r = resolver(false, &["acme"]);
        assert!(matches!(
            r.select(Some("dashboard.acme.clwd.run")).await,
            Selection::Serve(_)
        ));
        assert_eq!(HandshakeMetrics::get(&r.metrics().served), 1);
    }

    #[tokio::test]
    async fn an_org_without_a_cert_is_a_counted_no_cert() {
        let r = resolver(false, &[]); // store has no cert for acme
        assert!(matches!(
            r.select(Some("dashboard.acme.clwd.run")).await,
            Selection::NoCert
        ));
        assert_eq!(
            HandshakeMetrics::get(&r.metrics().no_cert),
            1,
            "a missing cert must be visible, not silent"
        );
    }

    #[tokio::test]
    async fn a_non_app_host_sni_and_a_missing_sni_are_counted() {
        let r = resolver(false, &["acme"]);
        assert!(matches!(
            r.select(Some("clwd.run")).await, // apex, not an app host
            Selection::NotAppHost
        ));
        assert!(matches!(r.select(None).await, Selection::NotAppHost));
        assert_eq!(HandshakeMetrics::get(&r.metrics().not_app_host), 2);
    }

    #[tokio::test]
    async fn a_store_outage_is_a_counted_unavailable() {
        let r = resolver(true, &["acme"]);
        assert!(matches!(
            r.select(Some("dashboard.acme.clwd.run")).await,
            Selection::Unavailable
        ));
        assert_eq!(HandshakeMetrics::get(&r.metrics().unavailable), 1);
    }

    #[test]
    fn debug_never_prints_the_private_key() {
        let rendered = format!("{:?}", cert());
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(
            !rendered.contains("PRIVATE KEY"),
            "the key must not appear: {rendered}"
        );
    }
}
