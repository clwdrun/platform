//! The pingora TLS-accept callback: choose a per-org certificate by SNI.
//!
//! Deliberately thin. The selection logic and its metrics live in
//! [`crate::cert`] and are tested without a handshake; this only reads the SNI
//! name, asks the resolver, and applies the chosen certificate to the
//! in-progress handshake.
//!
//! # The no-certificate case
//!
//! When no certificate applies (unknown org, issuance pending, store down, or a
//! non-app-host SNI), this sets no certificate and the handshake fails.
//! pingora's callback returns `()` with **no channel to signal a TLS alert**
//! (its own source carries `// TODO: return error?`), so a client cannot be told
//! `unrecognized_name` — it sees a generic handshake failure indistinguishable
//! from a network fault. Since "this org's certificate is not issued yet" is a
//! routine onboarding state, not only a failure, the miss is made visible the
//! only way this pingora version allows: [`crate::cert::HandshakeMetrics`] plus a
//! warn log (done inside [`CertResolver::select`]). A cleaner client-facing
//! alert waits on pingora exposing a return path (or the rustls backend).

use std::any::Any;
use std::sync::Arc;

use async_trait::async_trait;
use pingora::listeners::{TlsAccept, TlsAcceptCallbacks};
use pingora::tls::error::ErrorStack;
use pingora::tls::ext;
use pingora::tls::pkey::PKey;
use pingora::tls::ssl::{NameType, SslRef};
use pingora::tls::x509::X509;

use shared::cert::StoredCert;

use crate::cert::{CertResolver, Selection};

/// The SNI a connection's handshake named, kept with the connection so each
/// request on it can be checked against its `Host` (#95). Read back from the
/// session's TLS digest with [`Sni::of`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sni(pub String);

impl Sni {
    /// The SNI recorded for `session`'s connection, if it was TLS and named one.
    #[must_use]
    pub fn of(session: &pingora::protocols::http::ServerSession) -> Option<&str> {
        session
            .digest()?
            .ssl_digest
            .as_ref()?
            .extension
            .get::<Self>()
            .map(|sni| sni.0.as_str())
    }
}

/// A pingora `TlsAccept` callback that serves each org its own certificate.
pub struct DynamicCert {
    resolver: CertResolver,
}

impl DynamicCert {
    /// Wrap a resolver.
    #[must_use]
    pub fn new(resolver: CertResolver) -> Self {
        Self { resolver }
    }

    /// Boxed for [`pingora::listeners::tls::TlsSettings::with_callbacks`].
    #[must_use]
    pub fn callbacks(resolver: CertResolver) -> TlsAcceptCallbacks {
        Box::new(Self::new(resolver))
    }
}

#[async_trait]
impl TlsAccept for DynamicCert {
    async fn certificate_callback(&self, ssl: &mut SslRef) {
        let sni = ssl.servername(NameType::HOST_NAME);
        if let Selection::Serve(cert) = self.resolver.select(sni).await
            && let Err(error) = apply(ssl, &cert)
        {
            // A stored certificate that will not parse is a store-integrity
            // fault, not the client's; leave the handshake to fail rather than
            // serve a broken certificate.
            tracing::error!(%error, "stored certificate did not parse; handshake will fail");
        }
        // Every non-serve outcome leaves no certificate set, which fails the
        // handshake. `select` has already counted and logged which outcome it
        // was (NotAppHost / NoCert / Unavailable).
    }

    /// Keep the SNI with the connection. A handshake only completes when a
    /// certificate was chosen for an SNI, so every request has one to check.
    async fn handshake_complete_callback(
        &self,
        ssl: &SslRef,
    ) -> Option<Arc<dyn Any + Send + Sync>> {
        ssl.servername(NameType::HOST_NAME)
            .map(|sni| Arc::new(Sni(sni.to_owned())) as Arc<dyn Any + Send + Sync>)
    }
}

/// Parse the stored PEM and hand the certificate and key to the handshake.
fn apply(ssl: &mut SslRef, cert: &StoredCert) -> Result<(), ErrorStack> {
    let x509 = X509::from_pem(&cert.cert_pem)?;
    let key = PKey::private_key_from_pem(&cert.key_pem)?;
    ext::ssl_use_certificate(ssl, &x509)?;
    ext::ssl_use_private_key(ssl, &key)?;
    Ok(())
}
