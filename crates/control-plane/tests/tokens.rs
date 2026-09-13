//! API tokens against a real Postgres, through the real router.
//!
//! Every status is asserted together with its code string, because the code is
//! what a caller branches on: `identity.unauthenticated` means "get a valid
//! token", `identity.forbidden` means "get a different one".

use std::num::NonZeroU32;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use control_plane::auth;
use control_plane::db;
use control_plane::http::AppState;
use control_plane::ids::{AppId, OrgId, TokenId};
use control_plane::token::{PREFIX, Scopes};
use sha2::{Digest as _, Sha256};
use sqlx::PgPool;
use tower::ServiceExt as _;

fn state(pool: &PgPool) -> AppState {
    let operator =
        opendal::Operator::new(opendal::services::Memory::default()).expect("in-memory operator");
    AppState::new(pool.clone(), builder::ArtifactStore::new(operator))
}

/// A token, issued the way the bootstrap subcommand issues one.
async fn token(
    pool: &PgPool,
    org: OrgId,
    app: Option<AppId>,
    scopes: &[&str],
) -> (TokenId, String) {
    let scopes = Scopes::parse_all(scopes).expect("known scopes");
    let issued = auth::issue(pool, org, app, "test", scopes)
        .await
        .expect("issuing a token");
    (issued.id, issued.secret.expose().to_owned())
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    json: serde_json::Value,
}

async fn send(state: &AppState, method: &str, uri: &str, token: Option<&str>, body: Body) -> Reply {
    let mut request = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let response = control_plane::http::router(state.clone())
        .oneshot(request.body(body).expect("a valid request"))
        .await
        .expect("the router answers");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body");
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    Reply {
        status,
        headers,
        json,
    }
}

/// A route that needs `admin`, does no work, and answers 404 for an unknown
/// id — so a 404 here means "authenticated and allowed", cheaply.
fn probe() -> String {
    format!("/v1/tokens/{}", TokenId::new())
}

async fn an_org_and_app(pool: &PgPool, slug: &str) -> (OrgId, AppId) {
    let org = db::create_org(pool, slug).await.expect("org");
    let app = db::create_app(pool, org.id, "one", "wasm")
        .await
        .expect("app");
    (org.id, app.id)
}

/// A real bundle, built the way `clwd build` builds one.
fn a_bundle(body: &[u8]) -> Body {
    const PREAMBLE: [u8; 8] = [0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00];
    let mut data = PREAMBLE.to_vec();
    data.extend_from_slice(body);
    let encoded = clwd_bundle::build(
        clwd_bundle::Runtime::Wasm,
        "app.wasm",
        clwd_bundle::Capabilities {
            version: 1,
            egress: vec![],
            secrets: vec![],
            storage_namespaces: vec![],
            limits: clwd_bundle::Limits {
                cpu_ms: 1_000,
                memory_mb: 64,
            },
        },
        vec![clwd_bundle::File {
            path: "app.wasm".into(),
            data,
            executable: false,
        }],
    )
    .expect("a well-formed bundle encodes");
    Body::from(encoded.bytes)
}

/// **A stored token value is unrecoverable from the database.**
///
/// Asserted rather than inferred from the column type: every row is rendered
/// as JSON — every column, whatever it is called — and searched for the token
/// and for its secret part. The positive control comes first: the stored
/// digest is SHA-256 of this exact token, so the row searched is the row that
/// token produced, not some other row that happens not to contain it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_stored_token_is_unrecoverable_from_the_database(pool: PgPool) {
    let (org, _) = an_org_and_app(&pool, "acme").await;
    let (id, full) = token(&pool, org, None, &["admin"]).await;

    let stored: Vec<u8> = sqlx::query_scalar!(
        "select secret_sha256 from api_tokens where id = $1",
        id.as_uuid()
    )
    .fetch_one(&pool)
    .await
    .expect("the row exists");
    assert_eq!(
        stored,
        Sha256::digest(full.as_bytes()).to_vec(),
        "positive control: this row is the one this token produced"
    );

    let rows: Vec<Option<String>> =
        sqlx::query_scalar!("select row_to_json(t)::text from api_tokens t")
            .fetch_all(&pool)
            .await
            .expect("rendering rows");
    assert_eq!(rows.len(), 1, "one token, one row");

    let hex_part = &full[PREFIX.len()..];
    for row in rows.iter().flatten() {
        assert!(!row.contains(full.as_str()), "the token is stored: {row}");
        assert!(!row.contains(hex_part), "the secret part is stored: {row}");
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_request_without_a_valid_token_is_401(pool: PgPool) {
    let (org, app) = an_org_and_app(&pool, "acme").await;
    let state = state(&pool);
    let uri = format!("/v1/apps/{app}/versions");

    // A well-formed token that is not in the database takes the lookup path;
    // the malformed cases never reach it. Both must give the same answer.
    let unknown = format!("{PREFIX}{}", "0".repeat(64));
    let (_, real) = token(&pool, org, None, &["publish"]).await;
    let uppercased = real.to_uppercase();

    for presented in [None, Some(unknown.as_str()), Some(uppercased.as_str())] {
        let reply = send(&state, "POST", &uri, presented, Body::empty()).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "for {presented:?}");
        assert_eq!(reply.json["code"], "identity.unauthenticated");
        assert_eq!(reply.json["retryable"], false);
        assert_eq!(reply.headers[header::WWW_AUTHENTICATE], "Bearer");
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_valid_token_without_the_scope_is_403(pool: PgPool) {
    let (org, app) = an_org_and_app(&pool, "acme").await;
    let state = state(&pool);
    let (_, reader) = token(&pool, org, None, &["read", "write"]).await;

    let reply = send(
        &state,
        "POST",
        &format!("/v1/apps/{app}/versions"),
        Some(&reader),
        Body::empty(),
    )
    .await;

    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(reply.json["code"], "identity.forbidden");
    assert!(
        reply.json["message"]
            .as_str()
            .is_some_and(|m| m.contains("publish")),
        "the caller must learn which scope to ask for: {}",
        reply.json
    );

    // And `admin` does not imply `publish`: scopes are independent.
    let (_, admin) = token(&pool, org, None, &["admin"]).await;
    let reply = send(
        &state,
        "POST",
        &format!("/v1/apps/{app}/versions"),
        Some(&admin),
        Body::empty(),
    )
    .await;
    assert_eq!(reply.json["code"], "identity.forbidden");
}

/// **Revocation takes effect on the next request.** There is no cache, so this
/// holds by construction — and this test is what keeps it holding if one is
/// ever added.
#[sqlx::test(migrations = "../../migrations")]
async fn revocation_takes_effect_on_the_next_request(pool: PgPool) {
    let (org, _) = an_org_and_app(&pool, "acme").await;
    let state = state(&pool);
    let (victim_id, victim) = token(&pool, org, None, &["admin"]).await;
    let (_, revoker) = token(&pool, org, None, &["admin"]).await;

    // The same state, and so the same router and limiter, throughout.
    let before = send(&state, "DELETE", &probe(), Some(&victim), Body::empty()).await;
    assert_eq!(
        before.status,
        StatusCode::NOT_FOUND,
        "positive control: the token works before it is revoked: {}",
        before.json
    );

    let revoke = send(
        &state,
        "DELETE",
        &format!("/v1/tokens/{victim_id}"),
        Some(&revoker),
        Body::empty(),
    )
    .await;
    assert_eq!(revoke.status, StatusCode::NO_CONTENT);

    let after = send(&state, "DELETE", &probe(), Some(&victim), Body::empty()).await;
    assert_eq!(after.status, StatusCode::UNAUTHORIZED);
    assert_eq!(after.json["code"], "identity.unauthenticated");

    // Revoking again is revoking once.
    let again = send(
        &state,
        "DELETE",
        &format!("/v1/tokens/{victim_id}"),
        Some(&revoker),
        Body::empty(),
    )
    .await;
    assert_eq!(again.status, StatusCode::NO_CONTENT);
}

/// An app outside the token's binding is 404, the same as an app that does
/// not exist. A 403 would confirm it is real.
#[sqlx::test(migrations = "../../migrations")]
async fn a_token_bound_to_one_app_cannot_see_another(pool: PgPool) {
    let (org, mine) = an_org_and_app(&pool, "acme").await;
    let other = db::create_app(&pool, org, "two", "wasm")
        .await
        .expect("a second app")
        .id;
    let state = state(&pool);
    let (_, bound) = token(&pool, org, Some(mine), &["publish"]).await;

    let to_other = send(
        &state,
        "POST",
        &format!("/v1/apps/{other}/versions"),
        Some(&bound),
        a_bundle(b"x"),
    )
    .await;
    let to_nowhere = send(
        &state,
        "POST",
        &format!("/v1/apps/{}/versions", AppId::new()),
        Some(&bound),
        a_bundle(b"x"),
    )
    .await;

    assert_eq!(to_other.status, StatusCode::NOT_FOUND);
    assert_eq!(to_other.json["code"], "control-plane.not_found");
    assert_eq!(
        (to_other.status, &to_other.json["code"]),
        (to_nowhere.status, &to_nowhere.json["code"]),
        "another app and no app must be indistinguishable"
    );

    // Positive control: the same token publishes to its own app.
    let to_mine = send(
        &state,
        "POST",
        &format!("/v1/apps/{mine}/versions"),
        Some(&bound),
        a_bundle(b"x"),
    )
    .await;
    assert_eq!(to_mine.status, StatusCode::CREATED, "{}", to_mine.json);
}

/// Another org's app is 404 — and leaves no version row behind, which is the
/// half a status code alone would not show.
#[sqlx::test(migrations = "../../migrations")]
async fn a_token_cannot_reach_another_orgs_app(pool: PgPool) {
    let (_, theirs) = an_org_and_app(&pool, "acme").await;
    let (mine, _) = an_org_and_app(&pool, "globex").await;
    let state = state(&pool);
    let (_, publisher) = token(&pool, mine, None, &["publish"]).await;

    let reply = send(
        &state,
        "POST",
        &format!("/v1/apps/{theirs}/versions"),
        Some(&publisher),
        a_bundle(b"x"),
    )
    .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert_eq!(reply.json["code"], "control-plane.not_found");

    let rows = sqlx::query_scalar!("select count(*) from app_versions")
        .fetch_one(&pool)
        .await
        .expect("counting");
    assert_eq!(rows, Some(0), "a cross-org publish must write nothing");

    // Nor may it revoke their tokens.
    let their_org = db::org_by_slug(&pool, "acme")
        .await
        .expect("lookup")
        .expect("the org exists")
        .id;
    let (their_token, _) = token(&pool, their_org, None, &["admin"]).await;
    let (_, my_admin) = token(&pool, mine, None, &["admin"]).await;
    let revoke = send(
        &state,
        "DELETE",
        &format!("/v1/tokens/{their_token}"),
        Some(&my_admin),
        Body::empty(),
    )
    .await;
    assert_eq!(revoke.status, StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "../../migrations")]
async fn issuance_returns_the_token_once_and_uncacheably(pool: PgPool) {
    let (org, _) = an_org_and_app(&pool, "acme").await;
    let state = state(&pool);
    let (_, admin) = token(&pool, org, None, &["admin", "publish"]).await;

    let reply = send(
        &state,
        "POST",
        &format!("/v1/orgs/{org}/tokens"),
        Some(&admin),
        Body::from(r#"{"name":"ci","scopes":["publish"]}"#),
    )
    .await;

    assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.json);
    assert_eq!(reply.headers[header::CACHE_CONTROL], "no-store");
    let issued = reply.json["token"].as_str().expect("the token is returned");
    assert!(issued.starts_with(PREFIX) && issued.len() == PREFIX.len() + 64);
    assert_eq!(reply.json["scopes"], serde_json::json!(["publish"]));

    // The issued token authenticates, and carries only what it was given.
    let reply = send(&state, "DELETE", &probe(), Some(issued), Body::empty()).await;
    assert_eq!(
        reply.json["code"], "identity.forbidden",
        "a publish token authenticates but may not administer"
    );
}

/// A token can only issue a token no stronger than itself.
#[sqlx::test(migrations = "../../migrations")]
async fn issuance_cannot_escalate(pool: PgPool) {
    let (org, app) = an_org_and_app(&pool, "acme").await;
    let state = state(&pool);
    let uri = format!("/v1/orgs/{org}/tokens");

    let (_, admin) = token(&pool, org, None, &["admin", "publish"]).await;
    let broader = send(
        &state,
        "POST",
        &uri,
        Some(&admin),
        Body::from(r#"{"name":"x","scopes":["publish","write"]}"#),
    )
    .await;
    assert_eq!(broader.status, StatusCode::FORBIDDEN);
    assert_eq!(broader.json["code"], "identity.forbidden");
    assert!(
        broader.json["message"]
            .as_str()
            .is_some_and(|m| m.contains("write")),
        "{}",
        broader.json
    );

    let (_, bound_admin) = token(&pool, org, Some(app), &["admin", "publish"]).await;
    let unbound = send(
        &state,
        "POST",
        &uri,
        Some(&bound_admin),
        Body::from(r#"{"name":"x","scopes":["publish"]}"#),
    )
    .await;
    assert_eq!(unbound.status, StatusCode::FORBIDDEN);
    assert_eq!(unbound.json["code"], "identity.forbidden");

    let same_app = send(
        &state,
        "POST",
        &uri,
        Some(&bound_admin),
        Body::from(format!(
            r#"{{"name":"x","scopes":["publish"],"app_id":"{app}"}}"#
        )),
    )
    .await;
    assert_eq!(
        same_app.status,
        StatusCode::CREATED,
        "positive control: narrowing to the same app is allowed: {}",
        same_app.json
    );

    let other_org = send(
        &state,
        "POST",
        &format!("/v1/orgs/{}/tokens", OrgId::new()),
        Some(&admin),
        Body::from(r#"{"name":"x","scopes":["publish"]}"#),
    )
    .await;
    assert_eq!(other_org.status, StatusCode::NOT_FOUND);
    assert_eq!(other_org.json["code"], "control-plane.not_found");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_malformed_issuance_request_is_an_envelope(pool: PgPool) {
    let (org, _) = an_org_and_app(&pool, "acme").await;
    let state = state(&pool);
    let (_, admin) = token(&pool, org, None, &["admin"]).await;

    for body in [
        "not json",
        r#"{"name":"x","scopes":["root"]}"#,
        r#"{"name":"x","scopes":[]}"#,
        r#"{"name":"","scopes":["admin"]}"#,
        r#"{"name":"x","scopes":["admin"],"extra":1}"#,
    ] {
        let reply = send(
            &state,
            "POST",
            &format!("/v1/orgs/{org}/tokens"),
            Some(&admin),
            Body::from(body),
        )
        .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "for {body}");
        assert_eq!(
            reply.json["code"], "control-plane.invalid_request",
            "for {body}"
        );
    }
}

/// A rate limit is 429, retryable, and says how long — per token, so one
/// caller exhausting its budget does not spend anyone else's.
#[sqlx::test(migrations = "../../migrations")]
async fn a_rate_limited_token_is_told_to_retry(pool: PgPool) {
    let (org, _) = an_org_and_app(&pool, "acme").await;
    let operator =
        opendal::Operator::new(opendal::services::Memory::default()).expect("in-memory operator");
    let quota = governor::Quota::per_minute(NonZeroU32::MIN);
    let state = AppState::with_quota(pool.clone(), builder::ArtifactStore::new(operator), quota);
    let (_, busy) = token(&pool, org, None, &["admin"]).await;
    let (_, quiet) = token(&pool, org, None, &["admin"]).await;

    let first = send(&state, "DELETE", &probe(), Some(&busy), Body::empty()).await;
    assert_eq!(first.status, StatusCode::NOT_FOUND, "the budget allows one");

    let second = send(&state, "DELETE", &probe(), Some(&busy), Body::empty()).await;
    assert_eq!(second.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(second.json["code"], "control-plane.rate_limited");
    assert_eq!(second.json["retryable"], true);
    let wait: u64 = second.headers[header::RETRY_AFTER]
        .to_str()
        .expect("ascii")
        .parse()
        .expect("Retry-After is whole seconds");
    assert!((1..=60).contains(&wait), "a usable wait, got {wait}");

    let other = send(&state, "DELETE", &probe(), Some(&quiet), Body::empty()).await;
    assert_eq!(
        other.status,
        StatusCode::NOT_FOUND,
        "another token's budget is untouched"
    );
}

/// The database, not the handler, guarantees a token's app is in its org.
#[sqlx::test(migrations = "../../migrations")]
async fn a_token_cannot_be_bound_to_another_orgs_app_even_by_hand(pool: PgPool) {
    let (_, theirs) = an_org_and_app(&pool, "acme").await;
    let (mine, _) = an_org_and_app(&pool, "globex").await;

    let err = sqlx::query!(
        "insert into api_tokens (id, org_id, app_id, name, secret_sha256, scopes)
         values ($1, $2, $3, 'x', $4, array['read'])",
        TokenId::new().as_uuid(),
        mine.as_uuid(),
        theirs.as_uuid(),
        &[0u8; 32][..],
    )
    .execute(&pool)
    .await
    .expect_err("a cross-org binding");

    let code = match err {
        sqlx::Error::Database(e) => e.code().map(|c| c.into_owned()),
        other => panic!("expected a database error, got {other:?}"),
    };
    assert_eq!(code.as_deref(), Some("23503"), "a foreign-key violation");
}
