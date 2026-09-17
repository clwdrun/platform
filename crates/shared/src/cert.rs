//! Per-org certificate storage, shared between the control plane (which issues
//! and writes certificates) and the gateway (which reads them to serve TLS).
//!
//! [`CertStore`] is a two-sided interface on purpose: it lives here in `shared`
//! so neither crate depends on the other — the control plane writes, the gateway
//! reads, both depend only on `shared`. [`OrgSlug`] lives here too because it is
//! the store's key and the identifier a per-org wildcard certificate
//! (`*.{slug}.clwd.run`, #5/#18) is issued for; the gateway's routing parser
//! (`gateway::host`) re-exports it.

use std::fmt;

use async_trait::async_trait;
use thiserror::Error;

/// Longest a single DNS label may be, per RFC 1035 and the `orgs.slug` /
/// `apps.name` CHECK constraints in `migrations/`.
pub const MAX_LABEL_LEN: usize = 63;

/// True when `label` satisfies the platform DNS-label rule, matching the regex
/// `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$` used by the `orgs.slug` and
/// `apps.name` CHECK constraints. Shared so the gateway's `AppName` and this
/// crate's [`OrgSlug`] apply one rule; a parity test pins it against the DB.
///
// ponytail: hand-rolled to avoid a regex dep; mirrors the DB CHECK verbatim.
#[must_use]
pub fn is_valid_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_LABEL_LEN {
        return false;
    }
    let is_ldh = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-';
    if !bytes.iter().all(|&b| is_ldh(b)) {
        return false;
    }
    bytes[0] != b'-' && bytes[bytes.len() - 1] != b'-'
}

/// A label that is not a valid DNS label.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("not a valid DNS label")]
pub struct InvalidLabel;

/// An org slug: the `{org}` in `{app}.{org}.clwd.run`, and the label a per-org
/// wildcard certificate (`*.{slug}.clwd.run`) is issued for and keyed by.
///
/// Construct only via [`OrgSlug::parse`], which enforces the same DNS-label rule
/// the `orgs.slug` column enforces. That validation is load-bearing for
/// [`DirCertStore`]: a slug cannot contain a path separator or `..`, so it is
/// safe to use as a path segment.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct OrgSlug(String);

impl OrgSlug {
    /// Parse a single DNS label as an org slug.
    ///
    /// # Errors
    /// [`InvalidLabel`] if `label` is not a valid DNS label.
    pub fn parse(label: &str) -> Result<Self, InvalidLabel> {
        if is_valid_label(label) {
            Ok(Self(label.to_owned()))
        } else {
            Err(InvalidLabel)
        }
    }

    /// The slug as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for OrgSlug {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OrgSlug({})", self.0)
    }
}

/// A stored certificate chain and its private key, as PEM bytes.
///
/// Bytes rather than parsed TLS types on purpose: the store and its callers stay
/// decoupled from the TLS backend, and the key is parsed only at the moment the
/// handshake needs it.
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

/// Where per-org certificates live, keyed by org slug. The control plane writes
/// (issuance, renewal); the gateway reads (handshake-time selection).
///
/// #22 (the secret broker) inherits this trait; its `age`-encrypted, off-host
/// implementation sits behind it and changes no caller. Implementations must be
/// cheap to share (`Arc`ed, called per handshake on the read side).
#[async_trait]
pub trait CertStore: Send + Sync {
    /// The certificate for `org`, or `None` if none is stored yet (unissued, or
    /// issuance not complete).
    ///
    /// # Errors
    /// [`CertStoreError`] if the store cannot be reached.
    async fn cert_for(&self, org: &OrgSlug) -> Result<Option<StoredCert>, CertStoreError>;

    /// Store (create or replace) the certificate for `org`. Called by the issuer
    /// when a certificate is first issued and by the renewal reconciler when it
    /// is renewed — a subsequent [`CertStore::cert_for`] must return exactly what
    /// was stored.
    ///
    /// # Errors
    /// [`CertStoreError`] if the store cannot be written.
    async fn store(&self, org: &OrgSlug, cert: &StoredCert) -> Result<(), CertStoreError>;
}

/// Why a certificate store operation could not be answered.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CertStoreError {
    /// The store could not be reached. A handshake with no cached alternative
    /// must fail closed, not serve a wrong or absent certificate.
    #[error("certificate store unavailable: {0}")]
    Unavailable(String),
}

/// A file-backed [`CertStore`] for development ONLY, until #22's secret broker
/// exists: it reads and writes `{dir}/{org}/cert.pem` and `{dir}/{org}/key.pem`.
///
/// **This must not become the production answer**, for two reasons:
///
/// 1. It stores unencrypted private keys as plaintext files — and the gateway is
///    the shared, multi-tenant case clwd#71 says a file store is explicitly wrong
///    for (right for a dev laptop, wrong for anything shared).
/// 2. It assumes the writer (control plane) and the reader (gateway) see the
///    **same filesystem** — i.e. co-location on one node. The moment issuance and
///    serving run on separate nodes, a certificate written by one is invisible to
///    the other. This is the assumption that breaks first in any multi-node
///    deployment.
///
/// It exists behind the [`CertStore`] trait purely so issuance and per-org
/// selection can be built and tested before real storage lands; **#22 (the
/// secret broker: `age` at rest, keys off the host filesystem, reachable from
/// every node) replaces it**, and the trait means that swap touches no caller.
///
/// `org` is an [`OrgSlug`], already validated as a single DNS label, so it cannot
/// contain a path separator or `..` — no traversal.
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

    async fn store(&self, org: &OrgSlug, cert: &StoredCert) -> Result<(), CertStoreError> {
        let base = self.dir.join(org.as_str());
        tokio::fs::create_dir_all(&base)
            .await
            .map_err(|e| CertStoreError::Unavailable(format!("mkdir {}: {e}", org.as_str())))?;
        // Key first, then cert: cert_for keys off cert.pem existing, so writing
        // the cert last means a reader never sees a cert without its key.
        tokio::fs::write(base.join("key.pem"), &cert.key_pem)
            .await
            .map_err(|e| CertStoreError::Unavailable(format!("write key {}: {e}", org.as_str())))?;
        tokio::fs::write(base.join("cert.pem"), &cert.cert_pem)
            .await
            .map_err(|e| {
                CertStoreError::Unavailable(format!("write cert {}: {e}", org.as_str()))
            })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_rule_matches_the_db_check_constraint() {
        // Parity with `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$` from
        // migrations/20260828115934_core_schema.sql.
        for (label, valid) in [
            ("a", true),
            ("a1", true),
            ("a-b", true),
            ("0", true),
            ("a--b", true),
            ("", false),
            ("-a", false),
            ("a-", false),
            ("A", false),
            ("a.b", false),
            ("a_b", false),
        ] {
            assert_eq!(is_valid_label(label), valid, "label {label:?}");
        }
        assert!(!is_valid_label(&"a".repeat(MAX_LABEL_LEN + 1)), "too long");
        assert!(
            is_valid_label(&"a".repeat(MAX_LABEL_LEN)),
            "boundary length"
        );
    }

    #[tokio::test]
    async fn dir_store_round_trips_and_reports_none_for_a_missing_org() {
        let dir = std::env::temp_dir().join(format!("clwd-certstore-{}", std::process::id()));
        let store = DirCertStore::new(&dir);
        let org = OrgSlug::parse("acme").expect("slug");

        assert!(
            store.cert_for(&org).await.expect("read").is_none(),
            "an org with nothing stored resolves to None"
        );
        // Distinct, byte-exact sentinels — not PEM-shaped, so the round-trip
        // fixture does not trip the private-key secrets scanner. The redaction
        // test below is where a key-shaped string is deliberately used.
        let cert = StoredCert {
            cert_pem: b"cert-bytes-acme".to_vec(),
            key_pem: b"key-bytes-acme".to_vec(),
        };
        store.store(&org, &cert).await.expect("store");
        let got = store.cert_for(&org).await.expect("read").expect("present");
        assert_eq!(got.cert_pem, cert.cert_pem, "cert round-trips byte-exact");
        assert_eq!(got.key_pem, cert.key_pem, "key round-trips byte-exact");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn debug_never_prints_the_private_key() {
        let rendered = format!(
            "{:?}",
            StoredCert {
                cert_pem: b"cert".to_vec(),
                key_pem: b"-----BEGIN PRIVATE KEY-----".to_vec(),
            }
        );
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(!rendered.contains("PRIVATE KEY"), "{rendered}");
    }
}
