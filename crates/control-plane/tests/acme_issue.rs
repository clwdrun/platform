//! End-to-end certificate issuance against a real ACME server (Pebble) with a
//! mock DNS server (challtestsrv). Run `just pebble-up` first.
//!
//! **Required, not optional.** If Pebble is unreachable this test fails RED — it
//! never skips. A test that quietly passed when its server was absent would be
//! green in exactly the environment where issuance was untested.
//!
//! # What it proves
//! - A full DNS-01 issuance: order, challenge published to challtestsrv,
//!   validated by Pebble, finalized, certificate fetched and stored.
//! - **Resumption**: an interrupted order (its URL persisted, its work
//!   unfinished) is *resumed* on the next attempt via `Account::order(url)`,
//!   not restarted with a fresh order — the property that keeps a retry during
//!   an outage from burning the new-certificate rate limit. Proven by asserting
//!   the persisted order itself reaches `Valid`, which a fresh-order path would
//!   leave abandoned in `Pending`.
//!
//! # What it does NOT prove (a local harness cannot)
//! - Real Let's Encrypt rate limits (Pebble enforces none).
//! - Real ARI scheduling (Pebble returns canned ARI; the client honoring the
//!   window is separate).
//! - Real DNS propagation latency (challtestsrv is synchronous and is the
//!   authoritative server Pebble queries, so there is no propagation gap).

use std::sync::Arc;

use async_trait::async_trait;
use control_plane::acme::{CertIssuer, DnsError, DnsProvider};
use control_plane::db;
use instant_acme::{Account, NewAccount};
use shared::cert::{CertStore, CertStoreError, DirCertStore, OrgSlug, StoredCert};
use sqlx::PgPool;

/// The apps domain certificates are issued under: a placeholder until the
/// real one is chosen (#62). Pebble and challtestsrv accept any name.
fn apps() -> shared::domains::AppsDomain {
    shared::domains::AppsDomain::parse("clwd-apps.test").expect("apps domain")
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_owned())
}

/// A [`DnsProvider`] backed by challtestsrv's HTTP management API. Records are
/// set and cleared synchronously; challtestsrv is the authoritative server
/// Pebble queries, so there is no propagation delay to wait on.
struct ChallTestSrvDns {
    mgmt: String,
    http: reqwest::Client,
}

impl ChallTestSrvDns {
    fn new() -> Self {
        Self {
            mgmt: env_or("CHALLTESTSRV", "http://localhost:8055"),
            http: reqwest::Client::new(),
        }
    }
    // challtestsrv keys records by fully-qualified name with a trailing dot.
    fn fqdn(name: &str) -> String {
        format!("{name}.")
    }
}

#[async_trait]
impl DnsProvider for ChallTestSrvDns {
    async fn upsert_txt(&self, name: &str, value: &str) -> Result<(), DnsError> {
        self.http
            .post(format!("{}/set-txt", self.mgmt))
            .json(&serde_json::json!({ "host": Self::fqdn(name), "value": value }))
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|e| DnsError::Provider(e.to_string()))?;
        Ok(())
    }
    async fn remove_txt(&self, name: &str) -> Result<(), DnsError> {
        self.http
            .post(format!("{}/clear-txt", self.mgmt))
            .json(&serde_json::json!({ "host": Self::fqdn(name) }))
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|e| DnsError::Provider(e.to_string()))?;
        Ok(())
    }
    async fn await_propagation(&self, _name: &str, _value: &str) -> Result<(), DnsError> {
        // challtestsrv set-txt is synchronous and it is the authoritative server
        // Pebble validates against, so the record is observable the moment
        // upsert_txt returns. A real provider queries authoritative DNS here.
        Ok(())
    }
}

/// Build an ACME account against Pebble, trusting Pebble's directory CA.
async fn pebble_account() -> Account {
    // instant-acme's rustls needs a CryptoProvider chosen before first use, or
    // it panics when both aws-lc-rs and ring are linked (as they are in the
    // workspace test build). Production startup calls this too.
    control_plane::acme::install_crypto_provider();
    let ca = env_or("PEBBLE_CA", ".pebble/pebble.minica.pem");
    let dir = env_or("PEBBLE_DIR", "https://localhost:14000/dir");
    let (account, _creds) = Account::builder_with_root(&ca)
        .unwrap_or_else(|e| panic!("Pebble CA at {ca} — is `just pebble-up` running? {e}"))
        .create(
            &NewAccount {
                contact: &[],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            dir.clone(),
            None,
        )
        .await
        .unwrap_or_else(|e| panic!("create ACME account at {dir} — is Pebble up? {e}"));
    account
}

// A store dir unique per test (`label`), not per process — the two tests run in
// parallel in one binary, and a per-process dir would have each test's cleanup
// delete the other's certificates.
fn store(label: &str) -> (DirCertStore, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("clwd-acme-store-{}-{label}", std::process::id()));
    (DirCertStore::new(&dir), dir)
}

#[sqlx::test(migrations = "../../migrations")]
async fn full_issuance_stores_a_certificate(pool: PgPool) {
    let org = db::create_org(&pool, "acme").await.expect("org");
    let slug = OrgSlug::parse("acme").expect("slug");
    let (cert_store, dir) = store(slug.as_str());
    let cert_store = Arc::new(cert_store);
    let issuer = CertIssuer::new(
        pebble_account().await,
        Arc::new(ChallTestSrvDns::new()),
        cert_store.clone(),
        pool.clone(),
        apps(),
    );

    issuer.issue(org.id, &slug).await.expect("issuance");

    // The certificate is in the store, and PEM-shaped.
    let stored = cert_store
        .cert_for(&slug)
        .await
        .expect("read")
        .expect("a certificate was stored");
    let pem = String::from_utf8(stored.cert_pem).expect("utf8");
    assert!(
        pem.contains("BEGIN CERTIFICATE"),
        "a PEM certificate: {}",
        &pem[..pem.len().min(64)]
    );

    // The lifecycle state says issued, and the in-flight order is cleared.
    let record = db::cert_record(&pool, org.id)
        .await
        .expect("read")
        .expect("row");
    assert_eq!(record.state, "issued");
    assert_eq!(record.order_url, None, "a completed order is cleared");

    let _ = std::fs::remove_dir_all(&dir);
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_interrupted_order_is_resumed_not_restarted(pool: PgPool) {
    // A different slug from the other test: challtestsrv records are global, so
    // distinct challenge names keep the tests from colliding in parallel.
    let org = db::create_org(&pool, "beta").await.expect("org");
    let slug = OrgSlug::parse("beta").expect("slug");
    let account = pebble_account().await;

    // Simulate a crash right after new_order: an order exists on the CA and its
    // URL is persisted, but no challenge work has happened.
    let identifier = instant_acme::Identifier::Dns("*.beta.clwd-apps.test".to_owned());
    let interrupted = account
        .new_order(&instant_acme::NewOrder::new(std::slice::from_ref(
            &identifier,
        )))
        .await
        .expect("new order");
    let resumed_url = interrupted.url().to_owned();
    db::cert_mark_pending(&pool, org.id, &resumed_url)
        .await
        .expect("persist order url");
    drop(interrupted);

    let (cert_store, dir) = store(slug.as_str());
    let cert_store = Arc::new(cert_store);
    let issuer = CertIssuer::new(
        account.clone(),
        Arc::new(ChallTestSrvDns::new()),
        cert_store.clone(),
        pool.clone(),
        apps(),
    );

    issuer.issue(org.id, &slug).await.expect("resumed issuance");

    // The proof of resumption: the SAME order whose URL was persisted reached
    // Valid. A fresh-order path would have left this one abandoned in Pending
    // and completed a different order instead.
    let mut same_order = account.order(resumed_url).await.expect("re-fetch order");
    assert_eq!(
        same_order.state().status,
        instant_acme::OrderStatus::Valid,
        "the persisted order itself completed — it was resumed, not restarted"
    );

    // And a certificate was stored.
    assert!(
        cert_store.cert_for(&slug).await.expect("read").is_some(),
        "the resumed issuance stored a certificate"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[sqlx::test(migrations = "../../migrations")]
async fn renewal_replaces_the_stored_certificate(pool: PgPool) {
    let org = db::create_org(&pool, "gamma").await.expect("org");
    let slug = OrgSlug::parse("gamma").expect("slug");
    let (cert_store, dir) = store(slug.as_str());
    let cert_store = std::sync::Arc::new(cert_store);
    let issuer = CertIssuer::new(
        pebble_account().await,
        std::sync::Arc::new(ChallTestSrvDns::new()),
        cert_store.clone(),
        pool.clone(),
        apps(),
    );

    // First issuance stores a cert and, via ARI (Pebble supports it), a real
    // not_after and renewal time.
    issuer.issue(org.id, &slug).await.expect("first issuance");
    let first = cert_store
        .cert_for(&slug)
        .await
        .expect("read")
        .expect("issued")
        .cert_pem;
    let before = db::cert_record(&pool, org.id)
        .await
        .expect("read")
        .expect("row");
    assert_eq!(before.state, "issued");

    // Renew: a new order that `replaces` the stored cert (RFC 9773, rate-limit
    // exempt). The stored certificate must change to the renewed one. That
    // `replaces` is on the wire, not just in the code, is proven by
    // `a_renewal_from_another_account_is_rejected` — without it the renewal
    // would succeed as an ordinary order from any account.
    issuer.renew(org.id, &slug).await.expect("renewal");
    let renewed = cert_store
        .cert_for(&slug)
        .await
        .expect("read")
        .expect("renewed")
        .cert_pem;
    assert_ne!(
        first, renewed,
        "renewal replaced the stored certificate with a new one"
    );
    let after = db::cert_record(&pool, org.id)
        .await
        .expect("read")
        .expect("row");
    assert_eq!(after.state, "issued");
    assert_eq!(
        after.order_url, None,
        "the renewal order is cleared once done"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_renewal_failure_is_recorded_not_silent(pool: PgPool) {
    let org = db::create_org(&pool, "delta").await.expect("org");
    let slug = OrgSlug::parse("delta").expect("slug");
    let (inner, dir) = store(slug.as_str());

    // A store that fails every write after the first: the first issuance
    // stores fine, the renewal's persist fails deterministically.
    //
    // Deliberately NOT a failing DNS provider. Pebble reuses a valid
    // authorization 50% of the time (its startup log says so), which lets a
    // renewal skip the challenge entirely and succeed despite a broken DNS
    // provider — a coin flip, not a test. The store write, by contrast, runs
    // on every renewal path, reused authorization or not.
    struct FailSecondWriteStore {
        inner: DirCertStore,
        writes: std::sync::atomic::AtomicUsize,
    }
    #[async_trait]
    impl CertStore for FailSecondWriteStore {
        async fn cert_for(&self, org: &OrgSlug) -> Result<Option<StoredCert>, CertStoreError> {
            self.inner.cert_for(org).await
        }
        async fn store(&self, org: &OrgSlug, cert: &StoredCert) -> Result<(), CertStoreError> {
            if self
                .writes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                == 0
            {
                self.inner.store(org, cert).await
            } else {
                Err(CertStoreError::Unavailable(
                    "simulated store outage".to_owned(),
                ))
            }
        }
    }
    let cert_store = std::sync::Arc::new(FailSecondWriteStore {
        inner,
        writes: std::sync::atomic::AtomicUsize::new(0),
    });
    let issuer = CertIssuer::new(
        pebble_account().await,
        std::sync::Arc::new(ChallTestSrvDns::new()),
        cert_store.clone(),
        pool.clone(),
        apps(),
    );
    issuer.issue(org.id, &slug).await.expect("first issuance");

    let result = issuer.renew(org.id, &slug).await;
    assert!(result.is_err(), "a failing store fails the renewal");

    // The failure is visible in the row, not silent — a certificate that fails
    // to renew must leave a signal, or it expires with no deploy behind it.
    let record = sqlx::query!(
        "select state, last_renewal_error from certificates where org_id = $1",
        org.id.as_uuid()
    )
    .fetch_one(&pool)
    .await
    .expect("row");
    assert_eq!(record.state, "failed");
    assert!(
        record
            .last_renewal_error
            .as_deref()
            .is_some_and(|e| e.contains("simulated store outage")),
        "the failure reason is recorded: {:?}",
        record.last_renewal_error
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A renewal from a different ACME account is rejected: `replaces` binds the
/// order to the account holding the replaced certificate, which is what makes
/// it the exempt path rather than an ordinary issuance any account may place.
///
/// This is also the test that proves `replaces` is on the wire, not just in
/// the code — without it this would succeed as a fresh order. Deleting
/// `.replaces(...)` from `new_order` must turn this green-success red.
#[sqlx::test(migrations = "../../migrations")]
async fn a_renewal_from_another_account_is_rejected(pool: PgPool) {
    let org = db::create_org(&pool, "zeta").await.expect("org");
    let slug = OrgSlug::parse("zeta").expect("slug");
    let (cert_store, dir) = store(slug.as_str());
    let cert_store = std::sync::Arc::new(cert_store);
    let issuer = CertIssuer::new(
        pebble_account().await,
        std::sync::Arc::new(ChallTestSrvDns::new()),
        cert_store.clone(),
        pool.clone(),
        apps(),
    );
    issuer.issue(org.id, &slug).await.expect("first issuance");

    let stranger = CertIssuer::new(
        pebble_account().await,
        std::sync::Arc::new(ChallTestSrvDns::new()),
        cert_store.clone(),
        pool.clone(),
        apps(),
    );
    let result = stranger.renew(org.id, &slug).await;
    assert!(
        result.is_err(),
        "a renewal from another account must be rejected, got success"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The reconciler's drive step end to end: a certificate whose ARI window has
/// passed is claimed and renewed by `reconcile_once`, and a second pass finds
/// nothing left to do.
///
/// **Required, not optional, like every test in this file:** if Pebble is
/// unreachable this fails RED — it never skips.
#[sqlx::test(migrations = "../../migrations")]
async fn the_reconciler_renews_a_due_certificate(pool: PgPool) {
    let org = db::create_org(&pool, "epsilon").await.expect("org");
    let slug = OrgSlug::parse("epsilon").expect("slug");
    let (cert_store, dir) = store(slug.as_str());
    let cert_store = std::sync::Arc::new(cert_store);
    let issuer = CertIssuer::new(
        pebble_account().await,
        std::sync::Arc::new(ChallTestSrvDns::new()),
        cert_store.clone(),
        pool.clone(),
        apps(),
    );
    issuer.issue(org.id, &slug).await.expect("first issuance");
    let first = cert_store
        .cert_for(&slug)
        .await
        .expect("read")
        .expect("issued")
        .cert_pem;

    // Force the ARI window into the past: the row is now due.
    sqlx::query!(
        "update certificates set ari_renewal_after = now() - interval '1 hour' \
          where org_id = $1",
        org.id.as_uuid(),
    )
    .execute(&pool)
    .await
    .expect("backdate the renewal window");

    let report = control_plane::reconcile::reconcile_once(&pool, &issuer).await;
    assert_eq!(
        report,
        control_plane::reconcile::ReconcileReport {
            claimed: 1,
            renewed: 1,
            failed: 0,
        },
        "one due row claimed and renewed, reported as counts"
    );

    let renewed = cert_store
        .cert_for(&slug)
        .await
        .expect("read")
        .expect("renewed")
        .cert_pem;
    assert_ne!(
        first, renewed,
        "the pass replaced the stored certificate with a new one"
    );
    let row = db::cert_record(&pool, org.id)
        .await
        .expect("read")
        .expect("row");
    assert_eq!(row.state, "issued");
    assert_eq!(
        row.order_url, None,
        "the renewal order is cleared once done"
    );

    // A second pass is quiet: nothing due, nothing claimed.
    let again = control_plane::reconcile::reconcile_once(&pool, &issuer).await;
    assert_eq!(
        again,
        control_plane::reconcile::ReconcileReport {
            claimed: 0,
            renewed: 0,
            failed: 0,
        },
        "rotation drained — a pass with nothing due claims nothing"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Counts every certificate written to the store. Each completed order writes
/// once, on every path — unlike a DNS write, which Pebble's 50% authorization
/// reuse can skip — so this is the count of orders that issued.
struct CountingStore {
    inner: DirCertStore,
    writes: std::sync::atomic::AtomicUsize,
}

#[async_trait]
impl CertStore for CountingStore {
    async fn cert_for(&self, org: &OrgSlug) -> Result<Option<StoredCert>, CertStoreError> {
        self.inner.cert_for(org).await
    }
    async fn store(&self, org: &OrgSlug, cert: &StoredCert) -> Result<(), CertStoreError> {
        self.writes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.store(org, cert).await
    }
}

/// Two reconcilers — two workers, each with its own ACME account — race for
/// one requested certificate. `SKIP LOCKED` hands it to one: the CA issues
/// exactly once, because every duplicate order spends the shared quota.
#[sqlx::test(migrations = "../../migrations")]
async fn two_reconcilers_issue_a_pending_certificate_once(pool: PgPool) {
    let org = db::create_org(&pool, "zeta").await.expect("org");
    let slug = OrgSlug::parse("zeta").expect("slug");
    control_plane::orgs::ensure_certificate_row(&pool, org.id)
        .await
        .expect("requested");
    let (inner, dir) = store(slug.as_str());
    let counting = Arc::new(CountingStore {
        inner,
        writes: std::sync::atomic::AtomicUsize::new(0),
    });
    let worker = |account| {
        CertIssuer::new(
            account,
            Arc::new(ChallTestSrvDns::new()),
            counting.clone(),
            pool.clone(),
            apps(),
        )
    };
    let (a, b) = (
        worker(pebble_account().await),
        worker(pebble_account().await),
    );

    let (first, second) = tokio::join!(
        control_plane::reconcile::reconcile_once(&pool, &a),
        control_plane::reconcile::reconcile_once(&pool, &b),
    );

    assert_eq!(first.claimed + second.claimed, 1, "{first:?} {second:?}");
    assert_eq!(first.renewed + second.renewed, 1, "{first:?} {second:?}");
    assert_eq!(
        counting.writes.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the CA issued exactly one certificate"
    );
    let row = db::cert_record(&pool, org.id)
        .await
        .expect("read")
        .expect("row");
    assert_eq!(row.state, "issued");

    let _ = std::fs::remove_dir_all(&dir);
}

/// A DNS provider that fails while `down` is set.
struct FlakyDns {
    inner: ChallTestSrvDns,
    down: std::sync::atomic::AtomicBool,
}

#[async_trait]
impl DnsProvider for FlakyDns {
    async fn upsert_txt(&self, name: &str, value: &str) -> Result<(), DnsError> {
        if self.down.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(DnsError::Provider("simulated DNS outage".to_owned()));
        }
        self.inner.upsert_txt(name, value).await
    }
    async fn remove_txt(&self, name: &str) -> Result<(), DnsError> {
        self.inner.remove_txt(name).await
    }
    async fn await_propagation(&self, name: &str, value: &str) -> Result<(), DnsError> {
        self.inner.await_propagation(name, value).await
    }
}

/// Org creation queues the certificate and never calls the CA, so issuance
/// being down cannot fail it. Here issuance *is* down: the reconciler records
/// the failure visibly, and issues once it recovers.
///
/// A fresh account and identifier, so Pebble has no authorization to reuse
/// and the outage cannot be skipped by luck.
#[sqlx::test(migrations = "../../migrations")]
async fn a_queued_certificate_issues_once_issuance_recovers(pool: PgPool) {
    let org = db::create_org(&pool, "eta").await.expect("org");
    let slug = OrgSlug::parse("eta").expect("slug");
    control_plane::orgs::ensure_certificate_row(&pool, org.id)
        .await
        .expect("org creation's hand-off");
    let (cert_store, dir) = store(slug.as_str());
    let dns = Arc::new(FlakyDns {
        inner: ChallTestSrvDns::new(),
        down: std::sync::atomic::AtomicBool::new(true),
    });
    let issuer = CertIssuer::new(
        pebble_account().await,
        dns.clone(),
        Arc::new(cert_store),
        pool.clone(),
        apps(),
    );
    let pass = || {
        control_plane::reconcile::reconcile_with(
            &pool,
            &issuer,
            10,
            std::time::Duration::from_secs(900),
            std::time::Duration::ZERO,
        )
    };

    let down = pass().await;
    assert_eq!((down.claimed, down.failed), (1, 1), "{down:?}");
    let row = db::cert_record(&pool, org.id)
        .await
        .expect("read")
        .expect("row");
    assert_eq!(row.state, "failed", "the outage is recorded, not silent");

    dns.down.store(false, std::sync::atomic::Ordering::SeqCst);
    // Past the zero retry backoff on the database clock.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let up = pass().await;
    assert_eq!((up.claimed, up.renewed), (1, 1), "{up:?}");
    let row = db::cert_record(&pool, org.id)
        .await
        .expect("read")
        .expect("row");
    assert_eq!(row.state, "issued");

    let _ = std::fs::remove_dir_all(&dir);
}
