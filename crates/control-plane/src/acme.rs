//! ACME certificate issuance: one DNS-01 wildcard certificate per org
//! (`*.{slug}.<apps domain>`, #5/#18), via `instant-acme`.
//!
//! `instant-acme` is transport-only — it hands out a challenge value but never
//! touches DNS. So DNS-01 validation is a collaboration: the ACME client gives
//! us the value, we publish it as a `_acme-challenge.{slug}.<apps domain>` TXT
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
use instant_acme::{
    Account, CertificateIdentifier, ChallengeType, Identifier, NewOrder, Order, OrderStatus,
    RetryPolicy,
};
use rustls_pki_types::CertificateDer;
use shared::cert::{CertStore, OrgSlug, StoredCert};
use shared::domains::AppsDomain;
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
/// wildcard the record is `_acme-challenge.{slug}.<apps domain>`: a fixed one-label
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

/// Issues one per-org wildcard certificate (`*.{slug}.<apps domain>`) via DNS-01,
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
/// | after `finalize`, before the cert is stored | order Valid/Processing, but the key `finalize` generated is **lost** (returned once) | resume detects an undrivable order and starts a **fresh** order (one rate-limit slot) — a narrow in-process window between `finalize` and the store write |
/// | order failed validation | order Invalid, URL kept for visibility | resume detects an undrivable order and starts a **fresh** order — resuming it would no-op to a false success, so the dead URL is never driven twice |
/// | cert stored, before `cert_mark_issued` | DB says `pending` (first issuance) or `renewing` (reconciler), cert is servable | the gateway serves it (it reads the store, not the DB); the next pass resumes via `order_url` and converges to `issued` — a benign extra order in a narrow window |
/// | any crash leaving a TXT record | stale `_acme-challenge` TXT | best-effort `remove_txt` on every exit path; a stale record is harmless (challenges are single-use values) and ages out by TTL |
///
/// The account credentials are persisted once by the caller (issuance shares one
/// account across all orgs); losing them costs a new account, which is not
/// rate-limited the way new certificates are.
pub struct CertIssuer {
    account: Account,
    dns: Arc<dyn DnsProvider>,
    store: Arc<dyn CertStore>,
    pool: PgPool,
    apps: AppsDomain,
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
    /// The issued certificate could not be parsed (for its validity or ARI id).
    #[error("parsing the issued certificate: {0}")]
    CertParse(String),
    /// Renewal was asked for an org that has no stored certificate to replace.
    #[error("no stored certificate to renew for this org")]
    NothingToRenew,
}

impl From<instant_acme::Error> for IssueError {
    fn from(e: instant_acme::Error) -> Self {
        Self::Acme(e)
    }
}

impl CertIssuer {
    /// An issuer over an existing ACME `account`, using `dns` for DNS-01 and
    /// storing certificates in `store`; `pool` holds the lifecycle state, and
    /// certificates are for `*.{org}.<apps>`.
    ///
    /// Certificates are only ever for the apps domain, so `dns` must be scoped
    /// to the apps zone alone. The control plane's zone is a different zone
    /// with its own token, and this issuer never needs it (#62): a leaked
    /// issuance token can then touch app DNS only.
    #[must_use]
    pub fn new(
        account: Account,
        dns: Arc<dyn DnsProvider>,
        store: Arc<dyn CertStore>,
        pool: PgPool,
        apps: AppsDomain,
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
            apps,
        }
    }

    /// Issue (or resume issuing) `org`'s `*.{slug}.<apps domain>` certificate, storing
    /// it and recording the lifecycle state. Idempotent and resumable: safe to
    /// call again after any crash above.
    ///
    /// # Errors
    /// [`IssueError`] for any ACME, DNS, store, or database failure; the failure
    /// is also recorded in `certificates.last_renewal_error` before returning.
    pub async fn issue(&self, org_id: OrgId, slug: &OrgSlug) -> Result<(), IssueError> {
        self.attempt(org_id, slug, None).await
    }

    /// Renew `org`'s certificate: issue a new one whose ACME order `replaces` the
    /// currently-stored certificate. The `replaces` link is what makes the
    /// renewal exempt from the 50-new-certificates-per-week rate limit
    /// (RFC 9773). A renewal for an org with no stored certificate is
    /// [`IssueError::NothingToRenew`].
    ///
    /// Direct callers must drive to completion: a crash between the order
    /// persist and `cert_mark_issued` leaves `pending`, which the reconciler
    /// claim does not cover — new callers go through the claim (see
    /// [`db::claim_due_for_renewal`]).
    ///
    /// # Errors
    /// [`IssueError`] as [`CertIssuer::issue`], plus [`IssueError::NothingToRenew`].
    pub async fn renew(&self, org_id: OrgId, slug: &OrgSlug) -> Result<(), IssueError> {
        // A store outage here must be recorded, not just returned: the claim
        // already cleared `last_renewal_error`, so returning bare would leave
        // the row `renewing` with no signal and retry on the stale tier
        // instead of the failed tier. (`NothingToRenew` stays unrecorded — it
        // is the reconciler's cue to issue instead, not a failure.)
        let current = match self.store.cert_for(slug).await {
            Ok(current) => current.ok_or(IssueError::NothingToRenew)?,
            Err(error) => {
                let error = IssueError::Store(error);
                if let Err(db_error) =
                    db::cert_mark_failed(&self.pool, org_id, &error.to_string()).await
                {
                    tracing::error!(%db_error, "could not record certificate failure");
                }
                return Err(error);
            }
        };
        // The DER of the current cert identifies what this renewal replaces. If
        // the stored PEM does not parse, there is no `CertificateIdentifier` to
        // put in `replaces` — so the order below counts against the
        // new-certificate bucket instead of being exempt. That is a silent
        // rate-limit consumer unless it is loud here, so this degrades to an
        // unlinked order with an error log rather than failing the renewal.
        let replaces_der = match first_cert_der(&current.cert_pem) {
            Ok(der) => Some(der),
            Err(error) => {
                tracing::error!(
                    org = slug.as_str(),
                    %error,
                    "stored certificate unparseable; renewing WITHOUT replaces \
                     (counts against the new-certificate rate-limit bucket)"
                );
                None
            }
        };
        self.attempt(org_id, slug, replaces_der).await
    }

    /// Shared issue/renew path with failure recording. `replaces_der` is the DER
    /// of the certificate a renewal replaces, or `None` for a first issuance.
    async fn attempt(
        &self,
        org_id: OrgId,
        slug: &OrgSlug,
        replaces_der: Option<Vec<u8>>,
    ) -> Result<(), IssueError> {
        match self
            .issue_inner(org_id, slug, replaces_der.as_deref())
            .await
        {
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

    async fn issue_inner(
        &self,
        org_id: OrgId,
        slug: &OrgSlug,
        replaces_der: Option<&[u8]>,
    ) -> Result<(), IssueError> {
        // The wildcard goes in the IDENTIFIER — `*.{slug}.<apps domain>` — not the
        // challenge name. Ordering the base domain here yields a non-wildcard
        // certificate that works for one host and fails for every app.
        let wildcard = self.apps.org_wildcard(slug);
        let identifier = Identifier::Dns(wildcard);

        // Resume an in-flight order if one is persisted and still drivable;
        // otherwise start fresh and persist its URL before doing any work, so a
        // crash resumes rather than restarts (the rate-limit-safe path).
        //
        // Only `Pending` (challenges to complete) and `Ready` (to finalize)
        // are drivable. Anything else — `Valid`/`Processing` (finalize already
        // ran and its key died with that process), `Invalid` (a failed
        // validation poisoned this URL; resuming it would no-op to a false
        // success), or an order the CA no longer knows (fetch error) — starts
        // fresh. A fresh order costs one rate-limit slot and is logged; a
        // resumed dead order costs the certificate with no signal, which is
        // strictly worse.
        let record = db::cert_record(&self.pool, org_id)
            .await
            .map_err(IssueError::Db)?;
        let mut order = match record.and_then(|r| r.order_url) {
            Some(url) => match self.account.order(url).await {
                Ok(mut resumed) => {
                    // `state` takes `&mut`, so the drivability check lives here
                    // in the body rather than in a match guard.
                    if matches!(
                        resumed.state().status,
                        OrderStatus::Pending | OrderStatus::Ready
                    ) {
                        resumed
                    } else {
                        tracing::warn!(
                            org = slug.as_str(),
                            status = ?resumed.state().status,
                            "resumed order is past driving; starting a fresh order"
                        );
                        self.fresh_order(org_id, slug, &identifier, replaces_der)
                            .await?
                    }
                }
                Err(error) => {
                    tracing::warn!(
                        org = slug.as_str(),
                        %error,
                        "persisted order is unreachable at the CA; starting a fresh order"
                    );
                    self.fresh_order(org_id, slug, &identifier, replaces_der)
                        .await?
                }
            },
            None => {
                self.fresh_order(org_id, slug, &identifier, replaces_der)
                    .await?
            }
        };

        // Complete any pending authorizations. Cleanup is best-effort on every
        // exit path; collect the challenge record names to remove afterwards.
        let mut challenge_records: Vec<String> = Vec::new();
        let result = self
            .drive_to_stored(&mut order, org_id, &mut challenge_records)
            .await;

        for name in &challenge_records {
            if let Err(e) = self.dns.remove_txt(name).await {
                // A stale challenge TXT is harmless (single-use value, short
                // TTL). Log and move on — nothing reaps these yet.
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
        let (not_after, renew_after) = self.capture_schedule(&cert.cert_pem).await?;
        db::cert_mark_issued(&self.pool, org_id, not_after, renew_after)
            .await
            .map_err(IssueError::Db)?;
        Ok(())
    }

    /// Start a fresh order and persist its URL before any challenge work, so a
    /// crash from here on resumes rather than restarts.
    async fn fresh_order(
        &self,
        org_id: OrgId,
        slug: &OrgSlug,
        identifier: &Identifier,
        replaces_der: Option<&[u8]>,
    ) -> Result<Order, IssueError> {
        let order = self.new_order(slug, identifier, replaces_der).await?;
        db::cert_mark_pending(&self.pool, org_id, order.url())
            .await
            .map_err(IssueError::Db)?;
        Ok(order)
    }

    /// Start a new ACME order for `identifier`, setting `replaces` when this is a
    /// renewal (the DER of the certificate being replaced). The `replaces` link
    /// is what makes a renewal rate-limit-exempt (RFC 9773); its absence on a
    /// renewal would make the renewal count against the new-certificate bucket.
    /// When the old certificate's DER yields no ARI identifier, the order goes
    /// out WITHOUT `replaces` — and loudly so (error log naming the bucket),
    /// because a quiet fallback here is a silent rate-limit consumer.
    async fn new_order(
        &self,
        slug: &OrgSlug,
        identifier: &Identifier,
        replaces_der: Option<&[u8]>,
    ) -> Result<Order, IssueError> {
        let identifiers = std::slice::from_ref(identifier);
        match replaces_der {
            Some(der) => {
                let cert_der = CertificateDer::from(der);
                // `into_owned` frees the order from borrowing the DER buffer.
                match CertificateIdentifier::try_from(&cert_der) {
                    Ok(replaces) => Ok(self
                        .account
                        .new_order(&NewOrder::new(identifiers).replaces(replaces.into_owned()))
                        .await?),
                    Err(error) => {
                        tracing::error!(
                            org = slug.as_str(),
                            %error,
                            "old certificate yields no ARI identifier; ordering WITHOUT \
                             replaces (counts against the new-certificate rate-limit bucket)"
                        );
                        Ok(self.account.new_order(&NewOrder::new(identifiers)).await?)
                    }
                }
            }
            None => Ok(self.account.new_order(&NewOrder::new(identifiers)).await?),
        }
    }

    /// From the just-issued certificate, capture its real `notAfter` and the time
    /// to renew after. The renewal time is the ARI-suggested window start
    /// (RFC 9773) when the CA offers ARI; when it does not (or the call fails),
    /// it falls back to two-thirds through the certificate's lifetime — the
    /// reconciler keeps renewing on the certificate's own clock rather than
    /// stalling because ARI is down. The fallback is logged as degraded.
    async fn capture_schedule(
        &self,
        cert_pem: &[u8],
    ) -> Result<(DateTime<Utc>, DateTime<Utc>), IssueError> {
        let der = first_cert_der(cert_pem)?;
        let (_, parsed) = x509_parser::parse_x509_certificate(&der)
            .map_err(|e| IssueError::CertParse(format!("x509: {e}")))?;
        let to_utc = |secs: i64| {
            DateTime::from_timestamp(secs, 0)
                .ok_or_else(|| IssueError::CertParse("certificate time out of range".to_owned()))
        };
        let not_after = to_utc(parsed.validity().not_after.timestamp())?;
        let not_before = to_utc(parsed.validity().not_before.timestamp())?;

        let cert_der = CertificateDer::from(der.as_slice());
        let renew_after = match CertificateIdentifier::try_from(&cert_der) {
            Ok(id) => match self.account.renewal_info(&id).await {
                Ok((info, _retry)) => to_utc(info.suggested_window.start.unix_timestamp())?,
                Err(error) => {
                    tracing::warn!(%error, "ARI unavailable; renewing at 2/3 lifetime (degraded)");
                    two_thirds(not_before, not_after)
                }
            },
            Err(error) => {
                tracing::warn!(%error, "no ARI cert id; renewing at 2/3 lifetime (degraded)");
                two_thirds(not_before, not_after)
            }
        };
        Ok((not_after, renew_after))
    }
}

/// The first certificate's DER from a PEM chain.
fn first_cert_der(cert_pem: &[u8]) -> Result<Vec<u8>, IssueError> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(cert_pem)
        .map_err(|e| IssueError::CertParse(format!("PEM: {e}")))?;
    Ok(pem.contents)
}

/// Two-thirds through `[not_before, not_after]` — the ARI-unavailable fallback
/// renewal time. Inside a typical lifetime with margin to retry before expiry.
fn two_thirds(not_before: DateTime<Utc>, not_after: DateTime<Utc>) -> DateTime<Utc> {
    not_before + (not_after - not_before) * 2 / 3
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
