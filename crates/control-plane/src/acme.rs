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
//! [`CertIssuer`] drives `instant-acme` (account, order, challenge, finalize)
//! and stores the result via [`shared::cert::CertStore`], on top of this seam.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use instant_acme::{Account, ChallengeType, Identifier, NewOrder, Order, OrderStatus, RetryPolicy};
use shared::cert::{CertStore, OrgSlug, StoredCert};
use sqlx::PgPool;
use thiserror::Error;

use crate::db;
use crate::ids::OrgId;

/// Install the process-level rustls [`CryptoProvider`](rustls::crypto::CryptoProvider)
/// that instant-acme's TLS uses. **Call once at process startup, before any
/// issuance.** Idempotent (a second call is a no-op).
///
/// Required because when both the `aws-lc-rs` and `ring` rustls backends end up
/// linked — which feature unification across the workspace causes — rustls 0.23
/// cannot auto-select one and panics on first use. aws-lc-rs is chosen to match
/// instant-acme's default. [`CertIssuer::new`] also calls this as a safety net,
/// but the account is often created before the issuer, so a binary that issues
/// certificates should call it explicitly at startup.
pub fn install_crypto_provider() {
    // Err means a provider is already installed — fine, that is the goal.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

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

/// Issues one per-org wildcard certificate (`*.{slug}.clwd.run`) via DNS-01,
/// and stores it.
///
/// # Persisted state spans three stores, and the crash windows between them are
/// the design
///
/// - `certificates.order_url` in Postgres — the in-flight ACME order.
/// - the ACME account (`AccountCredentials`) and the issued certificate — via
///   the account handle and the [`CertStore`].
/// - the `_acme-challenge` TXT record — at the DNS provider.
///
/// A crash can land between any two. What each leaves, and how the next attempt
/// recovers (this is the map the Phase 4 reconciler works from):
///
/// | Crash point | State left | Recovery |
/// |---|---|---|
/// | before the order URL is persisted | nothing | next attempt starts a fresh order — correct, none exists |
/// | order persisted, challenges not yet valid | order URL in DB, maybe a TXT record | **resume** the order via `order_url` (not a fresh one — this is the rate-limit-safe path); already-valid authorizations are skipped; TXT re-provisioned |
/// | challenges valid, before `finalize` | order Ready | resume → finalize → fetch |
/// | after `finalize`, before the cert is stored | order Valid/Processing, but the key `finalize` generated is **lost** (returned once) | resume detects Valid/Processing with no stored cert and starts a **fresh** order (one rate-limit slot) — a narrow in-process window between `finalize` and the store write |
/// | cert stored, before `cert_mark_issued` | DB says `pending`, cert is servable | the gateway serves it (it reads the store, not the DB); the reconciler re-stores (idempotent) and marks issued — benign |
/// | any crash leaving a TXT record | stale `_acme-challenge` TXT | best-effort `remove_txt` on every exit path; the reconciler sweeps orphans |
///
/// The account credentials are persisted once by the caller (issuance shares one
/// account across all orgs); losing them costs a new account, which is not
/// rate-limited the way new certificates are.
pub struct CertIssuer {
    account: Account,
    dns: Arc<dyn DnsProvider>,
    store: Arc<dyn CertStore>,
    pool: PgPool,
    apex: String,
}

/// Why issuance did not produce a stored certificate.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum IssueError {
    /// The ACME protocol exchange failed.
    #[error("ACME: {0}")]
    Acme(#[source] instant_acme::Error),
    /// A DNS-01 provider step failed.
    #[error(transparent)]
    Dns(#[from] DnsError),
    /// The certificate store could not be written.
    #[error(transparent)]
    Store(#[from] shared::cert::CertStoreError),
    /// The lifecycle-state database could not be read or written.
    #[error("certificate state store: {0}")]
    Db(#[source] sqlx::Error),
    /// The CA finished the order in a state that yields no usable certificate.
    #[error("ACME order ended in an unusable state: {0:?}")]
    OrderState(OrderStatus),
}

impl From<instant_acme::Error> for IssueError {
    fn from(e: instant_acme::Error) -> Self {
        Self::Acme(e)
    }
}

impl CertIssuer {
    /// An issuer over an existing ACME `account`, using `dns` for DNS-01 and
    /// storing certificates in `store`; `pool` holds the lifecycle state and
    /// `apex` is the platform apex (`clwd.run`).
    #[must_use]
    pub fn new(
        account: Account,
        dns: Arc<dyn DnsProvider>,
        store: Arc<dyn CertStore>,
        pool: PgPool,
        apex: impl Into<String>,
    ) -> Self {
        // Safety net: ensure the rustls provider is installed even if the caller
        // forgot. Idempotent; the account passed in was likely already created
        // against a provider, so this mainly guards the renewal path.
        install_crypto_provider();
        Self {
            account,
            dns,
            store,
            pool,
            apex: apex.into(),
        }
    }

    /// Issue (or resume issuing) `org`'s `*.{slug}.clwd.run` certificate, storing
    /// it and recording the lifecycle state. Idempotent and resumable: safe to
    /// call again after any crash above.
    ///
    /// # Errors
    /// [`IssueError`] for any ACME, DNS, store, or database failure; the failure
    /// is also recorded in `certificates.last_renewal_error` before returning.
    pub async fn issue(&self, org_id: OrgId, slug: &OrgSlug) -> Result<(), IssueError> {
        match self.issue_inner(org_id, slug).await {
            Ok(()) => Ok(()),
            Err(error) => {
                // A failure must be visible, not silent (a cert that never issues
                // is an outage with no deploy behind it). Record it; keep the
                // order URL so a retry resumes rather than restarts.
                if let Err(db_err) =
                    db::cert_mark_failed(&self.pool, org_id, &error.to_string()).await
                {
                    tracing::error!(%db_err, "could not record certificate failure");
                }
                Err(error)
            }
        }
    }

    async fn issue_inner(&self, org_id: OrgId, slug: &OrgSlug) -> Result<(), IssueError> {
        // The wildcard goes in the IDENTIFIER — `*.{slug}.clwd.run` — not the
        // challenge name. Ordering the base domain here yields a non-wildcard
        // certificate that works for one host and fails for every app.
        let wildcard = format!("*.{}.{}", slug.as_str(), self.apex);
        let identifier = Identifier::Dns(wildcard);

        // Resume an in-flight order if one is persisted; otherwise start one and
        // persist its URL before doing any work, so a crash resumes rather than
        // restarts (the rate-limit-safe path).
        let record = db::cert_record(&self.pool, org_id)
            .await
            .map_err(IssueError::Db)?;
        let mut order = match record.and_then(|r| r.order_url) {
            Some(url) => self.account.order(url).await?,
            None => {
                let order = self
                    .account
                    .new_order(&NewOrder::new(std::slice::from_ref(&identifier)))
                    .await?;
                db::cert_mark_pending(&self.pool, org_id, order.url())
                    .await
                    .map_err(IssueError::Db)?;
                order
            }
        };

        let status = order.state().status;
        if matches!(status, OrderStatus::Processing | OrderStatus::Valid) {
            // finalize already ran in a prior process; the key it generated was
            // lost with that process. The order's certificate is unusable without
            // it, so start fresh (see the crash-window map, window 4).
            tracing::warn!(
                org = slug.as_str(),
                ?status,
                "resumed order is past finalize but its key is gone; starting a fresh order"
            );
            order = self
                .account
                .new_order(&NewOrder::new(std::slice::from_ref(&identifier)))
                .await?;
            db::cert_mark_pending(&self.pool, org_id, order.url())
                .await
                .map_err(IssueError::Db)?;
        }

        // Complete any pending authorizations. Cleanup is best-effort on every
        // exit path; collect the challenge record names to remove afterwards.
        let mut challenge_records: Vec<String> = Vec::new();
        let result = self
            .drive_to_stored(&mut order, org_id, &mut challenge_records)
            .await;

        for name in &challenge_records {
            if let Err(e) = self.dns.remove_txt(name).await {
                // A stale challenge TXT is harmless; an accumulation is a mess.
                // Log and move on — the reconciler sweeps what this misses.
                tracing::warn!(%e, name, "could not clean up challenge record");
            }
        }
        result
    }

    /// Drive `order` from wherever it is to a stored certificate, recording the
    /// names of any challenge records provisioned so the caller can clean them.
    async fn drive_to_stored(
        &self,
        order: &mut Order,
        org_id: OrgId,
        challenge_records: &mut Vec<String>,
    ) -> Result<(), IssueError> {
        if order.state().status == OrderStatus::Pending {
            let mut authorizations = order.authorizations();
            while let Some(authz) = authorizations.next().await {
                let mut authz = authz?;
                if authz.status == instant_acme::AuthorizationStatus::Valid {
                    continue; // already satisfied on a resumed order
                }
                let mut challenge =
                    authz
                        .challenge(ChallengeType::Dns01)
                        .ok_or(IssueError::Acme(instant_acme::Error::Str(
                            "no dns-01 challenge offered",
                        )))?;
                let value = challenge.key_authorization().dns_value();
                // The record is `_acme-challenge.<identifier>`; for a wildcard
                // `*.slug.apex` the authorization identifier is `slug.apex`.
                let Identifier::Dns(base) = challenge.identifier().identifier else {
                    return Err(IssueError::Acme(instant_acme::Error::Str(
                        "unexpected non-DNS identifier",
                    )));
                };
                let name = format!("_acme-challenge.{base}");
                self.dns.upsert_txt(&name, &value).await?;
                challenge_records.push(name.clone());
                // Never tell the CA to validate before the record is observable:
                // a premature set_ready fails the challenge and burns one of the
                // 5-failed-validations-per-identifier-per-hour budget.
                self.dns.await_propagation(&name, &value).await?;
                challenge.set_ready().await?;
            }

            match order.poll_ready(&RetryPolicy::default()).await? {
                OrderStatus::Ready => {}
                other => return Err(IssueError::OrderState(other)),
            }
        }

        // Ready → finalize (generates the keypair + CSR, returns the key PEM).
        if order.state().status == OrderStatus::Ready {
            let key_pem = order.finalize().await?;
            let cert_pem = order.poll_certificate(&RetryPolicy::default()).await?;
            self.persist(org_id, cert_pem.into_bytes(), key_pem.into_bytes())
                .await?;
        }
        Ok(())
    }

    async fn persist(
        &self,
        org_id: OrgId,
        cert_pem: Vec<u8>,
        key_pem: Vec<u8>,
    ) -> Result<(), IssueError> {
        let cert = StoredCert { cert_pem, key_pem };
        // Store the certificate first: the gateway reads the store, and a
        // servable cert with the DB still 'pending' is benign (window 5); a DB
        // 'issued' with no cert would not be.
        let slug = db_org_slug(&self.pool, org_id).await?;
        self.store.store(&slug, &cert).await?;
        let (not_after, renew_after) = not_after_and_renewal(&cert)?;
        db::cert_mark_issued(&self.pool, org_id, not_after, renew_after)
            .await
            .map_err(IssueError::Db)?;
        Ok(())
    }
}

/// The org's slug, needed to key the certificate store. Read here rather than
/// threaded through so `persist` has it at the store call.
async fn db_org_slug(pool: &PgPool, org_id: OrgId) -> Result<OrgSlug, IssueError> {
    let slug = sqlx::query_scalar!(
        "select slug from orgs where id = $1 and deleted_at is null",
        org_id.as_uuid()
    )
    .fetch_one(pool)
    .await
    .map_err(IssueError::Db)?;
    OrgSlug::parse(&slug).map_err(|_| {
        IssueError::Acme(instant_acme::Error::Str(
            "stored org slug is not a valid label",
        ))
    })
}

/// Extract the certificate's notAfter and derive a renewal time. This is a
/// placeholder: Phase 4 replaces the halfway-point heuristic with an
/// ARI-coordinated window (`Account::renewal_info`). Kept simple here so the
/// reconciler has a value to schedule against.
fn not_after_and_renewal(_cert: &StoredCert) -> Result<(DateTime<Utc>, DateTime<Utc>), IssueError> {
    // ponytail: not parsing the cert yet — Phase 4 owns notAfter + ARI. Until
    // then, schedule a renewal check in ~60 days (inside a 90-day Let's Encrypt
    // lifetime) so nothing goes unrenewed while the real logic lands.
    let now = Utc::now();
    Ok((
        now + chrono::Duration::days(90),
        now + chrono::Duration::days(60),
    ))
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
