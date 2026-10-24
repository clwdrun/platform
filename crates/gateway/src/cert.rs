//! SNI-time certificate selection: mapping an inbound SNI name to the per-org
//! certificate that serves it.
//!
//! The certificate *store* ([`shared::cert::CertStore`], the two-sided interface
//! the control plane writes and the gateway reads) lives in `shared`. This
//! module is the gateway's read side: [`CertResolver`] turns an SNI name into a
//! [`Selection`], kept out of the pingora `TlsAccept` callback so it is testable
//! without a handshake. Every outcome other than "served" is a client-visible
//! handshake failure indistinguishable from an outage, so each is counted in
//! [`HandshakeMetrics`] and logged.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use shared::cert::{CertStore, StoredCert};
use shared::domains::{AppsDomain, ControlPlaneDomain};

use crate::host::parse_host;

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
    apps: AppsDomain,
    /// The control-plane domain and its certificate (#95), when configured.
    platform: Option<(ControlPlaneDomain, StoredCert)>,
    metrics: Arc<HandshakeMetrics>,
}

impl CertResolver {
    /// A resolver over `store`, treating SNI names under the apps domain.
    #[must_use]
    pub fn new(store: Arc<dyn CertStore>, apps: AppsDomain) -> Self {
        Self {
            store,
            apps,
            platform: None,
            metrics: Arc::new(HandshakeMetrics::default()),
        }
    }

    /// Also serve `cert` for the control-plane domain, which the gateway
    /// forwards to the control plane (#95). Without it, that SNI fails the
    /// handshake like any other host that is not an app's.
    #[must_use]
    pub fn with_platform(mut self, domain: ControlPlaneDomain, cert: StoredCert) -> Self {
        self.platform = Some((domain, cert));
        self
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

        if let Some((domain, cert)) = &self.platform
            && sni.eq_ignore_ascii_case(domain.as_str())
        {
            self.metrics.served.fetch_add(1, Ordering::Relaxed);
            return Selection::Serve(cert.clone());
        }

        let org = match parse_host(sni, self.apps.as_str()) {
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use async_trait::async_trait;
    use shared::cert::{CertStoreError, OrgSlug};

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
        async fn store(&self, _org: &OrgSlug, _cert: &StoredCert) -> Result<(), CertStoreError> {
            if self.down {
                return Err(CertStoreError::Unavailable("test store is down".to_owned()));
            }
            Ok(())
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
        CertResolver::new(
            Arc::new(MapStore { certs, down }),
            AppsDomain::parse("clwd-apps.test").expect("apps domain"),
        )
    }

    #[tokio::test]
    async fn a_known_org_is_served() {
        let r = resolver(false, &["acme"]);
        assert!(matches!(
            r.select(Some("dashboard.acme.clwd-apps.test")).await,
            Selection::Serve(_)
        ));
        assert_eq!(HandshakeMetrics::get(&r.metrics().served), 1);
    }

    #[tokio::test]
    async fn an_org_without_a_cert_is_a_counted_no_cert() {
        let r = resolver(false, &[]); // store has no cert for acme
        assert!(matches!(
            r.select(Some("dashboard.acme.clwd-apps.test")).await,
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
            r.select(Some("clwd-apps.test")).await, // apex, not an app host
            Selection::NotAppHost
        ));
        assert!(matches!(r.select(None).await, Selection::NotAppHost));
        assert_eq!(HandshakeMetrics::get(&r.metrics().not_app_host), 2);
    }

    /// The control-plane domain gets the platform certificate, in any case,
    /// and only that exact name: a sibling or a suffix of it does not.
    #[tokio::test]
    async fn the_control_plane_domain_is_served_the_platform_certificate() {
        let platform = StoredCert {
            cert_pem: b"platform".to_vec(),
            key_pem: b"platform-key".to_vec(),
        };
        let r = resolver(false, &["acme"]).with_platform(
            ControlPlaneDomain::parse("api.clwd.test").expect("domain"),
            platform,
        );
        for sni in ["api.clwd.test", "API.clwd.TEST"] {
            match r.select(Some(sni)).await {
                Selection::Serve(cert) => assert_eq!(cert.cert_pem, b"platform", "{sni}"),
                other => panic!("{sni}: {other:?}"),
            }
        }
        for sni in ["evil.clwd.test", "xapi.clwd.test", "api.clwd.test.evil"] {
            assert!(
                matches!(r.select(Some(sni)).await, Selection::NotAppHost),
                "{sni}"
            );
        }
        // Unconfigured, the control-plane domain is just another non-app host.
        assert!(matches!(
            resolver(false, &["acme"])
                .select(Some("api.clwd.test"))
                .await,
            Selection::NotAppHost
        ));
    }

    #[tokio::test]
    async fn a_store_outage_is_a_counted_unavailable() {
        let r = resolver(true, &["acme"]);
        assert!(matches!(
            r.select(Some("dashboard.acme.clwd-apps.test")).await,
            Selection::Unavailable
        ));
        assert_eq!(HandshakeMetrics::get(&r.metrics().unavailable), 1);
    }
}
