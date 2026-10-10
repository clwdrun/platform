//! Session enforcement against a real Postgres.
//!
//! These cannot run against `sqlx`'s offline query cache, and that is the
//! point: what they prove is that the lookup *fails closed after a write* —
//! a revoke, an expiry, a delete — and the offline cache can only prove the
//! query compiles. Each asserts on the second authentication's verdict, never
//! on the column the write set: setting `revoked_at` tests the write;
//! rejecting the reuse tests the enforcement.

use axum::body::to_bytes;
use axum::http::{HeaderMap, HeaderValue, header};
use control_plane::http::render;
use control_plane::session::{self, COOKIE_NAME};
use control_plane::signin::CookieKey;
use control_plane::{db, ids::UserId};
use shared::{Error, RequestId};
use sqlx::PgPool;

fn key() -> CookieKey {
    CookieKey::from_secret(b"a-test-signing-secret-of-some-length")
}

/// The request headers a browser would send back for this `Set-Cookie`.
fn cookie_from(set_cookie: &str) -> HeaderMap {
    let pair = set_cookie.split(';').next().expect("a name=value pair");
    assert!(pair.starts_with(COOKIE_NAME));
    let mut h = HeaderMap::new();
    h.insert(header::COOKIE, HeaderValue::from_str(pair).expect("ascii"));
    h
}

async fn signed_in(pool: &PgPool) -> (UserId, session::Issued, HeaderMap) {
    let user = db::create_user(pool, "a@example.com").await.expect("user");
    let issued = session::issue(pool, &key(), user.id)
        .await
        .expect("issue")
        .expect("a live user gets a session");
    let cookie = cookie_from(&issued.set_cookie);
    (user.id, issued, cookie)
}

/// The full response a rejection renders to. The caller passes one request id
/// for every rejection, so two can be compared byte for byte.
async fn rendered(error: &Error, id: &RequestId) -> (u16, Vec<u8>) {
    let response = render(error, id);
    let status = response.status().as_u16();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (status, body.to_vec())
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_revoked_session_cookie_is_rejected_on_reuse(pool: PgPool) {
    let (user_id, issued, cookie) = signed_in(&pool).await;

    let first = session::authenticate(&pool, &key(), &cookie)
        .await
        .expect("a fresh session authenticates");
    assert_eq!(first.user_id, user_id);

    assert!(db::revoke_session(&pool, issued.id).await.expect("revoke"));

    // The same cookie, byte for byte: still validly signed, still unexpired.
    let err = session::authenticate(&pool, &key(), &cookie)
        .await
        .expect_err("a revoked session must not authenticate");
    assert_eq!(err.code(), "identity.unauthenticated");
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_expired_session_is_rejected_though_its_cookie_is_not(pool: PgPool) {
    let (_, issued, cookie) = signed_in(&pool).await;

    // The row ends; the cookie's own exp is untouched, so only the database
    // can be what refuses it.
    sqlx::query!(
        "update sessions set created_at = now() - interval '2 days',
                             expires_at = now() - interval '1 day'
         where id = $1",
        issued.id.as_uuid()
    )
    .execute(&pool)
    .await
    .expect("expire");

    let err = session::authenticate(&pool, &key(), &cookie)
        .await
        .expect_err("an expired session must not authenticate");
    assert_eq!(err.code(), "identity.unauthenticated");
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_unknown_session_is_rejected(pool: PgPool) {
    let (_, issued, cookie) = signed_in(&pool).await;
    sqlx::query!("delete from sessions where id = $1", issued.id.as_uuid())
        .execute(&pool)
        .await
        .expect("delete");

    let err = session::authenticate(&pool, &key(), &cookie)
        .await
        .expect_err("a session with no row must not authenticate");
    assert_eq!(err.code(), "identity.unauthenticated");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_deleted_users_session_is_rejected(pool: PgPool) {
    let (user_id, _, cookie) = signed_in(&pool).await;
    sqlx::query!(
        "update users set deleted_at = now() where id = $1",
        user_id.as_uuid()
    )
    .execute(&pool)
    .await
    .expect("delete user");

    let err = session::authenticate(&pool, &key(), &cookie)
        .await
        .expect_err("a deleted user's session must not authenticate");
    assert_eq!(err.code(), "identity.unauthenticated");
}

/// Revoked, expired and unknown are one answer to the caller: same status,
/// same code, same body. Each session gets its own database so the three
/// rejections are produced independently, then compared.
#[sqlx::test(migrations = "../../migrations")]
async fn revoked_expired_and_unknown_are_indistinguishable(pool: PgPool) {
    let mut rejections = Vec::new();
    let id = RequestId::generate();

    for (n, fate) in [
        "update sessions set revoked_at = now() where id = $1",
        "update sessions set created_at = now() - interval '2 days',
                             expires_at = now() - interval '1 day' where id = $1",
        "delete from sessions where id = $1",
    ]
    .into_iter()
    .enumerate()
    {
        let user = db::create_user(&pool, &format!("u{n}@example.com"))
            .await
            .expect("user");
        let issued = session::issue(&pool, &key(), user.id)
            .await
            .expect("issue")
            .expect("session");
        let cookie = cookie_from(&issued.set_cookie);
        session::authenticate(&pool, &key(), &cookie)
            .await
            .expect("live before its fate");

        sqlx::query(fate)
            .bind(issued.id.as_uuid())
            .execute(&pool)
            .await
            .expect("apply fate");

        let err = session::authenticate(&pool, &key(), &cookie)
            .await
            .expect_err("rejected after its fate");
        rejections.push(rendered(&err, &id).await);
    }

    assert_eq!(rejections[0].0, 401);
    assert_eq!(rejections[0], rejections[1], "revoked vs expired");
    assert_eq!(rejections[0], rejections[2], "revoked vs unknown");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_cookie_signed_by_another_key_is_rejected(pool: PgPool) {
    let (_, _, cookie) = signed_in(&pool).await;
    let other = CookieKey::from_secret(b"some-other-secret-entirely-different");

    let err = session::authenticate(&pool, &other, &cookie)
        .await
        .expect_err("another key's cookie must not authenticate");
    assert_eq!(err.code(), "identity.unauthenticated");
}

#[sqlx::test(migrations = "../../migrations")]
async fn no_cookie_is_rejected(pool: PgPool) {
    let err = session::authenticate(&pool, &key(), &HeaderMap::new())
        .await
        .expect_err("no cookie");
    assert_eq!(err.code(), "identity.unauthenticated");
}
