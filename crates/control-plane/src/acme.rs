//! ACME certificate issuance: one DNS-01 wildcard certificate per org
//! (`*.{slug}.clwd.run`, #5/#18), via `instant-acme`.
//!
//! `instant-acme` is transport-only — it hands out a challenge value but never
//! touches DNS. So DNS-01 validation is a collaboration: the ACME client gives
//! us the value, we publish it as a `_acme-challenge.{slug}.clwd.run` TXT
//! record, wait for it to propagate, tell the CA to validate, and clean up.
//! [`DnsProvider`] is the seam over whichever DNS API does that.
//!
//! A trait with one production implementation is the right shape here (#31 owns
//! the provider choice; Cloudflare is the recommendation): the ACME flow genuinely
//! calls into it, and a later swap is a new impl rather than a rewrite. The
//! Pebble test harness supplies a `challtestsrv`-backed implementation.
//!
//! The certificate issuer that drives `instant-acme` (account, order, challenge,
//! finalize, ARI-coordinated renewal) and stores the result via
//! [`crate::cert::CertStore`] is built on top of this seam.

use async_trait::async_trait;
use thiserror::Error;

/// Manages the `_acme-challenge` TXT records DNS-01 validation needs.
///
/// Implementations must be cheap to share and safe to call concurrently — org
/// creation and the renewal reconciler both drive issuance. For a per-org
/// wildcard the record is `_acme-challenge.{slug}.clwd.run`: a fixed one-label
/// depth under the apex, not arbitrary nesting.
#[async_trait]
pub trait DnsProvider: Send + Sync {
    /// Publish (create or replace) the TXT record at `name` with `value`.
    ///
    /// # Errors
    /// [`DnsError::Provider`] if the DNS API rejects or fails the write.
    async fn upsert_txt(&self, name: &str, value: &str) -> Result<(), DnsError>;

    /// Remove the TXT record at `name`. Cleanup after validation; callers treat
    /// a failure here as non-fatal (a stale challenge record is harmless), but
    /// it is still reported.
    ///
    /// # Errors
    /// [`DnsError::Provider`] if the DNS API rejects or fails the delete.
    async fn remove_txt(&self, name: &str) -> Result<(), DnsError>;

    /// Block until `value` is observable at `name`, or return
    /// [`DnsError::Timeout`].
    ///
    /// The caller MUST NOT tell the CA to validate before this returns `Ok`: the
    /// CA queries authoritative DNS, and validating against a record that has
    /// not propagated fails the challenge and burns an authorization attempt
    /// (Let's Encrypt allows only five per identifier per hour).
    ///
    /// # Errors
    /// [`DnsError::Timeout`] if the record is not visible within the deadline;
    /// [`DnsError::Provider`] if the lookup itself fails.
    async fn await_propagation(&self, name: &str, value: &str) -> Result<(), DnsError>;
}

/// Why a DNS provider operation did not succeed.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DnsError {
    /// The DNS API rejected or failed the request.
    #[error("DNS provider request failed: {0}")]
    Provider(String),
    /// A record did not become visible within the propagation deadline.
    #[error("DNS record did not propagate within the deadline")]
    Timeout,
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;

    /// A trivial in-memory provider: proves the trait is object-safe and usable
    /// as `Arc<dyn DnsProvider>`, and gives the issuer's tests something to drive
    /// without a real DNS API. Propagation is immediate.
    #[derive(Default)]
    struct MemoryDns {
        records: Mutex<HashMap<String, String>>,
    }

    #[async_trait]
    impl DnsProvider for MemoryDns {
        async fn upsert_txt(&self, name: &str, value: &str) -> Result<(), DnsError> {
            self.records
                .lock()
                .map_err(|_| DnsError::Provider("lock poisoned".to_owned()))?
                .insert(name.to_owned(), value.to_owned());
            Ok(())
        }
        async fn remove_txt(&self, name: &str) -> Result<(), DnsError> {
            self.records
                .lock()
                .map_err(|_| DnsError::Provider("lock poisoned".to_owned()))?
                .remove(name);
            Ok(())
        }
        async fn await_propagation(&self, name: &str, value: &str) -> Result<(), DnsError> {
            let seen = self
                .records
                .lock()
                .map_err(|_| DnsError::Provider("lock poisoned".to_owned()))?
                .get(name)
                .is_some_and(|v| v == value);
            if seen { Ok(()) } else { Err(DnsError::Timeout) }
        }
    }

    #[tokio::test]
    async fn upsert_then_propagate_then_remove() {
        let dns: std::sync::Arc<dyn DnsProvider> = std::sync::Arc::new(MemoryDns::default());
        let name = "_acme-challenge.acme.clwd.run";
        dns.upsert_txt(name, "token-value").await.expect("upsert");
        dns.await_propagation(name, "token-value")
            .await
            .expect("propagates immediately in the memory provider");
        dns.remove_txt(name).await.expect("remove");
        assert!(
            matches!(
                dns.await_propagation(name, "token-value").await,
                Err(DnsError::Timeout)
            ),
            "after removal the record is gone"
        );
    }
}
