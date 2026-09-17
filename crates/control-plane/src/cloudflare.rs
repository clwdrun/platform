//! A Cloudflare-backed [`DnsProvider`](crate::acme::DnsProvider) for ACME
//! DNS-01: writes `_acme-challenge` TXT records via the Cloudflare API and
//! confirms propagation at the zone's authoritative nameservers.
//!
//! # Token blast radius — read before minting one
//!
//! Cloudflare API tokens scope only at **zone + permission group**; there is no
//! record-name restriction (confirmed against current Cloudflare docs). So the
//! narrowest token that can write these challenge records is `Zone:DNS:Edit`
//! scoped to the `clwd.run` zone — which is **full create/update/delete over
//! every record in the zone**: the apex `A`, `api.clwd.run`, every org
//! subdomain, MX, SPF. A leaked token is total DNS control of the platform's
//! primary domain, far wider than "write a challenge TXT".
//!
//! This is accepted as the interim posture (`#22` holds the token; the trait
//! makes it swappable). **acme-dns CNAME delegation (#58) is the least-privilege
//! answer** — challenge records in a separate zone the main credential cannot
//! touch — and replaces this before GA. The token minted for this provider must
//! be `Zone:DNS:Edit`, Zone Resources → Include → Specific zone → `clwd.run`,
//! and nothing else.

use std::time::Duration;

use async_trait::async_trait;
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::rdata::TXT;
use hickory_resolver::{Resolver, TokioResolver};
use serde::Deserialize;

use crate::acme::{DnsError, DnsProvider};

const API_BASE: &str = "https://api.cloudflare.com/client/v4";
/// TXT TTL: the Cloudflare minimum. A challenge record is short-lived, so the
/// lowest TTL minimises how long a stale one lingers in caches.
const CHALLENGE_TTL: u32 = 60;
/// How long to wait for a record to appear at the authoritative nameservers,
/// and the gap between polls.
const PROPAGATION_TIMEOUT: Duration = Duration::from_secs(60);
const PROPAGATION_POLL: Duration = Duration::from_secs(2);

/// Cloudflare DNS provider. Holds the API token; its `Debug` redacts it.
pub struct CloudflareDns {
    http: reqwest::Client,
    api_base: String,
    token: String,
    zone_id: String,
    /// The zone's authoritative nameserver hostnames (Cloudflare assigns two per
    /// zone, e.g. `ada.ns.cloudflare.com`). Propagation is confirmed against
    /// these, not a recursive resolver whose view lags.
    authoritative_ns: Vec<String>,
}

impl std::fmt::Debug for CloudflareDns {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The API token must never reach a log line.
        f.debug_struct("CloudflareDns")
            .field("api_base", &self.api_base)
            .field("token", &"<redacted>")
            .field("zone_id", &self.zone_id)
            .field("authoritative_ns", &self.authoritative_ns)
            .finish()
    }
}

impl CloudflareDns {
    /// A provider for `zone_id`, authenticating with `token` (a `Zone:DNS:Edit`
    /// token scoped to that zone — see the module docs on blast radius), and
    /// confirming propagation against `authoritative_ns` (the zone's Cloudflare
    /// nameserver hostnames).
    ///
    /// # Errors
    /// [`DnsError::Provider`] if the HTTP client cannot be built.
    pub fn new(
        token: impl Into<String>,
        zone_id: impl Into<String>,
        authoritative_ns: Vec<String>,
    ) -> Result<Self, DnsError> {
        // instant-acme and reqwest share the process rustls provider; ensure it
        // is installed so the HTTPS client to Cloudflare has one.
        crate::acme::install_crypto_provider();
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| DnsError::Provider(format!("building HTTP client: {e}")))?;
        Ok(Self {
            http,
            api_base: API_BASE.to_owned(),
            token: token.into(),
            zone_id: zone_id.into(),
            authoritative_ns,
        })
    }

    /// Override the API base URL (for tests pointing at a mock server).
    #[must_use]
    pub fn with_api_base(mut self, base: impl Into<String>) -> Self {
        self.api_base = base.into();
        self
    }

    fn records_url(&self) -> String {
        format!("{}/zones/{}/dns_records", self.api_base, self.zone_id)
    }

    /// The ids of TXT records at `name`, so upsert and remove can target them.
    async fn txt_record_ids(&self, name: &str) -> Result<Vec<String>, DnsError> {
        let response = self
            .http
            .get(self.records_url())
            .bearer_auth(&self.token)
            .query(&[("type", "TXT"), ("name", name)])
            .send()
            .await
            .map_err(|e| DnsError::Provider(format!("listing TXT {name}: {e}")))?;
        let records: Vec<DnsRecord> = parse(response).await?;
        Ok(records.into_iter().map(|r| r.id).collect())
    }
}

#[async_trait]
impl DnsProvider for CloudflareDns {
    async fn upsert_txt(&self, name: &str, value: &str) -> Result<(), DnsError> {
        let existing = self.txt_record_ids(name).await?;
        let payload = serde_json::json!({
            "type": "TXT", "name": name, "content": value, "ttl": CHALLENGE_TTL,
        });
        let response = match existing.first() {
            // Replace the first existing record in place.
            Some(id) => {
                self.http
                    .put(format!("{}/{id}", self.records_url()))
                    .bearer_auth(&self.token)
                    .json(&payload)
                    .send()
                    .await
            }
            None => {
                self.http
                    .post(self.records_url())
                    .bearer_auth(&self.token)
                    .json(&payload)
                    .send()
                    .await
            }
        }
        .map_err(|e| DnsError::Provider(format!("writing TXT {name}: {e}")))?;
        let _: ApiObject = parse(response).await?;

        // Remove any extra duplicates so exactly one value stands at the name.
        for id in existing.into_iter().skip(1) {
            self.delete_record(&id, name).await?;
        }
        Ok(())
    }

    async fn remove_txt(&self, name: &str) -> Result<(), DnsError> {
        for id in self.txt_record_ids(name).await? {
            self.delete_record(&id, name).await?;
        }
        Ok(())
    }

    async fn await_propagation(&self, name: &str, value: &str) -> Result<(), DnsError> {
        let resolver = self.authoritative_resolver().await?;
        let deadline = tokio::time::Instant::now() + PROPAGATION_TIMEOUT;
        loop {
            if let Ok(lookup) = resolver.txt_lookup(name).await {
                let present = lookup.answers().iter().any(|record| {
                    record.try_borrow::<TXT>().is_some_and(|txt| {
                        txt.data()
                            .txt_data
                            .iter()
                            .any(|chunk| chunk.as_ref() == value.as_bytes())
                    })
                });
                if present {
                    return Ok(());
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(DnsError::Timeout);
            }
            tokio::time::sleep(PROPAGATION_POLL).await;
        }
    }
}

impl CloudflareDns {
    async fn delete_record(&self, id: &str, name: &str) -> Result<(), DnsError> {
        let response = self
            .http
            .delete(format!("{}/{id}", self.records_url()))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| DnsError::Provider(format!("deleting TXT {name}: {e}")))?;
        let _: ApiObject = parse(response).await?;
        Ok(())
    }

    /// A resolver that queries the zone's authoritative nameservers directly.
    /// Their hostnames are resolved to IPs with the system resolver first, since
    /// a nameserver config is addressed by IP.
    async fn authoritative_resolver(&self) -> Result<TokioResolver, DnsError> {
        let system = Resolver::builder_tokio()
            .map_err(|e| DnsError::Provider(format!("system resolver: {e}")))?
            .build()
            .map_err(|e| DnsError::Provider(format!("system resolver build: {e}")))?;
        let mut servers: Vec<NameServerConfig> = Vec::new();
        for ns in &self.authoritative_ns {
            let looked_up = system
                .lookup_ip(ns.as_str())
                .await
                .map_err(|e| DnsError::Provider(format!("resolving nameserver {ns}: {e}")))?;
            for ip in looked_up.iter() {
                servers.push(NameServerConfig::udp_and_tcp(ip));
            }
        }
        if servers.is_empty() {
            return Err(DnsError::Provider(
                "no authoritative nameserver IPs resolved".to_owned(),
            ));
        }
        let config = ResolverConfig::from_parts(None, vec![], servers);
        Resolver::builder_with_config(config, TokioRuntimeProvider::default())
            .build()
            .map_err(|e| DnsError::Provider(format!("authoritative resolver build: {e}")))
    }
}

/// Read a Cloudflare API envelope, turning `success: false` into an error.
async fn parse<T: for<'de> Deserialize<'de>>(response: reqwest::Response) -> Result<T, DnsError> {
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| DnsError::Provider(format!("reading response body: {e}")))?;
    let envelope: ApiEnvelope<T> = serde_json::from_str(&body)
        .map_err(|e| DnsError::Provider(format!("HTTP {status}: unparsable response: {e}")))?;
    if !envelope.success {
        let detail = envelope
            .errors
            .iter()
            .map(|e| format!("{}: {}", e.code, e.message))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(DnsError::Provider(format!(
            "Cloudflare API error (HTTP {status}): {detail}"
        )));
    }
    envelope
        .result
        .ok_or_else(|| DnsError::Provider("Cloudflare API: success with no result".to_owned()))
}

#[derive(Deserialize)]
struct ApiEnvelope<T> {
    success: bool,
    #[serde(default)]
    errors: Vec<ApiError>,
    result: Option<T>,
}

#[derive(Deserialize)]
struct ApiError {
    code: i64,
    message: String,
}

#[derive(Deserialize)]
struct DnsRecord {
    id: String,
}

/// The `result` of create/update/delete is a single object we do not inspect.
#[derive(Deserialize)]
struct ApiObject {}
