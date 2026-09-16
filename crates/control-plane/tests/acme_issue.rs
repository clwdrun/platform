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
use shared::cert::{CertStore, DirCertStore, OrgSlug};
use sqlx::PgPool;

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
        "clwd.run",
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
    let identifier = instant_acme::Identifier::Dns("*.beta.clwd.run".to_owned());
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
        "clwd.run",
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
