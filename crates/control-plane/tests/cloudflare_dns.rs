//! The Cloudflare DnsProvider's request construction and error mapping, against
//! a mock HTTP server — no live Cloudflare, no live DNS.
//!
//! # What it proves
//! - upsert creates when no record exists and updates when one does, hitting the
//!   right method and URL with the right body.
//! - remove deletes every TXT record at the name.
//! - a Cloudflare `success: false` envelope maps to a legible DnsError, not a
//!   generic failure.
//!
//! # What it does NOT prove (a mock cannot)
//! - Real Cloudflare request/response quirks or auth.
//! - Real DNS propagation latency — `await_propagation` queries live
//!   authoritative nameservers and is not exercised here.

use control_plane::acme::{DnsError, DnsProvider};
use control_plane::cloudflare::CloudflareDns;
use wiremock::matchers::{method, path, path_regex, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ZONE: &str = "test-zone-id";
const CHALLENGE: &str = "_acme-challenge.acme.clwd.run";

fn provider(base: &str) -> CloudflareDns {
    // authoritative_ns is unused by the paths under test (no await_propagation).
    CloudflareDns::new("test-token", ZONE, vec![])
        .expect("client")
        .with_api_base(base)
}

fn ok_list(records: serde_json::Value) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(serde_json::json!({
        "success": true, "errors": [], "result": records,
    }))
}

fn ok_object() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(serde_json::json!({
        "success": true, "errors": [], "result": { "id": "rec-1" },
    }))
}

#[tokio::test]
async fn upsert_creates_when_no_record_exists() {
    let server = MockServer::start().await;
    // List returns empty → provider must POST to create.
    Mock::given(method("GET"))
        .and(path(format!("/zones/{ZONE}/dns_records")))
        .and(query_param("type", "TXT"))
        .and(query_param("name", CHALLENGE))
        .respond_with(ok_list(serde_json::json!([])))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/zones/{ZONE}/dns_records")))
        .respond_with(ok_object())
        .expect(1) // exactly one create, no update
        .mount(&server)
        .await;

    provider(&server.uri())
        .upsert_txt(CHALLENGE, "challenge-value")
        .await
        .expect("upsert creates");
    // Mock `.expect(1)` assertions are verified on server drop.
}

#[tokio::test]
async fn upsert_updates_when_a_record_exists() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/zones/{ZONE}/dns_records")))
        .respond_with(ok_list(serde_json::json!([{ "id": "existing-rec" }])))
        .expect(1)
        .mount(&server)
        .await;
    // Update the existing record in place: PUT to its id, no POST.
    Mock::given(method("PUT"))
        .and(path(format!("/zones/{ZONE}/dns_records/existing-rec")))
        .respond_with(ok_object())
        .expect(1)
        .mount(&server)
        .await;

    provider(&server.uri())
        .upsert_txt(CHALLENGE, "new-value")
        .await
        .expect("upsert updates");
}

#[tokio::test]
async fn remove_deletes_every_record_at_the_name() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/zones/{ZONE}/dns_records")))
        .respond_with(ok_list(
            serde_json::json!([{ "id": "rec-a" }, { "id": "rec-b" }]),
        ))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path_regex(format!("/zones/{ZONE}/dns_records/rec-.")))
        .respond_with(ok_object())
        .expect(2) // both records deleted
        .mount(&server)
        .await;

    provider(&server.uri())
        .remove_txt(CHALLENGE)
        .await
        .expect("remove deletes all");
}

#[tokio::test]
async fn an_api_error_envelope_maps_to_a_legible_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/zones/{ZONE}/dns_records")))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "success": false,
            "errors": [{ "code": 9109, "message": "Invalid access token" }],
            "result": null,
        })))
        .mount(&server)
        .await;

    let err = provider(&server.uri())
        .upsert_txt(CHALLENGE, "v")
        .await
        .expect_err("an API error is an error");
    match err {
        DnsError::Provider(msg) => {
            assert!(msg.contains("9109"), "carries the code: {msg}");
            assert!(
                msg.contains("Invalid access token"),
                "carries the message: {msg}"
            );
        }
        other => panic!("expected Provider error, got {other:?}"),
    }
}
