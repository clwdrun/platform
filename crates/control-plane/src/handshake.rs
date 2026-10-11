//! The app-host sign-in handshake and app-host sessions (#62).
//!
//! Apps are served from a registrable domain of their own, so the control
//! plane's host-only session cookie never reaches them. An app host gets its
//! own session — a child of the visitor's control-plane session — like this:
//!
//! 1. **Begin** (internal, from the gateway): the gateway records the app and
//!    the same-host path the visitor asked for, and gets back a state value.
//!    It sets that value as `__Host-clwd_state` on the app host and sends the
//!    visitor to `/authorize?state=…`.
//! 2. **Authorize** (public, `GET /authorize`): finds the handshake by its
//!    state, signs the visitor in first if they have no control-plane session,
//!    and issues a single-use code good for 60 seconds, bound to this handshake
//!    and that session. The visitor is sent to the app host's
//!    `/__clwd/callback` — a host built **from the handshake's app row**, never
//!    from the request. There is no redirect parameter to tamper with.
//! 3. **Exchange** (internal): the gateway, having matched the callback's
//!    `state` against the state cookie, trades code + state server-to-server
//!    for an app-host session secret. The handshake row is deleted in the same
//!    statement, so a code works once.
//! 4. **Check** (internal, every app request): one statement, looking the
//!    secret up *for the app being requested*, and requiring both it and its
//!    parent session to be live.
//!
//! Codes, states and session secrets are each their own type, with a redacted
//! `Debug`, and only their SHA-256 digests are stored. A code can never be
//! passed where a session secret belongs.

use std::fmt;

use axum::Extension;
use axum::body::Bytes;
use axum::extract::{RawQuery, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use shared::return_path::ReturnPath;
use shared::{Error, RequestId};
use sqlx::PgPool;

use crate::auth::unavailable;
use crate::http::{AppState, render};
use crate::ids::{AppId, AppSessionId, AppSubject, HandshakeId, OrgId};
use crate::openapi::{Body, Doc, Success};
use crate::session;

/// How long a begun handshake may take to reach `/authorize`, sign-in included.
const HANDSHAKE_TTL_SECS: i64 = 10 * 60;
/// How long an issued code may wait for its exchange.
const CODE_TTL_SECS: i64 = 60;
/// Bytes of randomness in a state, a code and a session secret.
const SECRET_BYTES: usize = 32;

/// Declare a 64-hex-character secret token with a redacted `Debug`.
macro_rules! secret_token {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, PartialEq, Eq)]
        pub struct $name(String);

        impl $name {
            fn generate() -> Result<Self, Error> {
                let mut bytes = [0u8; SECRET_BYTES];
                getrandom::fill(&mut bytes).map_err(|e| Error::Internal { source: e.into() })?;
                Ok(Self(bytes.iter().map(|b| format!("{b:02x}")).collect()))
            }

            /// Accept `raw` only in the exact shape this platform mints:
            /// 64 lowercase hex characters.
            #[must_use]
            pub fn parse(raw: &str) -> Option<Self> {
                (raw.len() == SECRET_BYTES * 2
                    && raw.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
                .then(|| Self(raw.to_owned()))
            }

            /// The token, for the one place it is sent.
            #[must_use]
            pub fn expose(&self) -> &str {
                &self.0
            }

            fn digest(&self) -> [u8; 32] {
                Sha256::digest(self.0.as_bytes()).into()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }
    };
}

secret_token! {
    /// A handshake's state: in the app host's `__Host-clwd_state` cookie and in
    /// the `/authorize` and callback URLs. Binds a callback to the browser that
    /// began the handshake.
    HandshakeState
}

secret_token! {
    /// A single-use, 60-second code, delivered through the browser to the app
    /// host's callback and exchanged server-to-server.
    HandshakeCode
}

secret_token! {
    /// An app-host session's secret: the value of `__Host-clwd_app_session`.
    AppSessionSecret
}

// ------------------------------------------------------------ begin ----

/// Record a handshake for `app_id` returning to `return_path`.
///
/// # Errors
///
/// `control-plane.not_found` if the app does not exist or is deleted;
/// [`unavailable`]'s mapping for a database failure.
pub async fn begin(
    pool: &PgPool,
    app_id: AppId,
    return_path: &ReturnPath,
) -> Result<HandshakeState, Error> {
    let state = HandshakeState::generate()?;
    let inserted = sqlx::query_scalar!(
        r#"insert into handshakes (id, state_sha256, app_id, return_path, expires_at)
           select $1, $2, a.id, $3, now() + ($4::bigint * interval '1 second')
             from apps a where a.id = $5 and a.deleted_at is null
           returning id as "id: HandshakeId""#,
        HandshakeId::new().as_uuid(),
        &state.digest()[..],
        return_path.as_str(),
        HANDSHAKE_TTL_SECS,
        app_id.as_uuid(),
    )
    .fetch_optional(pool)
    .await
    .map_err(unavailable)?;
    inserted.map(|_| state).ok_or_else(|| Error::NotFound {
        what: format!("app {app_id}"),
    })
}

// -------------------------------------------------------- exchange ----

/// What a successful exchange hands the gateway.
#[derive(Debug)]
#[non_exhaustive]
pub struct Exchanged {
    pub id: AppSessionId,
    pub app_id: AppId,
    pub secret: AppSessionSecret,
    pub expires_at: DateTime<Utc>,
    pub return_path: ReturnPath,
}

/// Trade a code and its state for an app-host session, once.
///
/// One statement: the handshake row is deleted (so the code cannot be used
/// again, even inside its 60 seconds), its parent session is required to be
/// live, and the child session is inserted with an expiry no later than the
/// parent's. `None` for any reason the pair is not good — unknown, used,
/// expired, mismatched, or a parent signed out meanwhile — all one answer.
///
/// # Errors
///
/// [`unavailable`]'s mapping for a database failure.
pub async fn exchange(
    pool: &PgPool,
    code: &HandshakeCode,
    state: &HandshakeState,
) -> Result<Option<Exchanged>, Error> {
    let secret = AppSessionSecret::generate()?;
    let row = sqlx::query!(
        r#"with h as (
               delete from handshakes
                where code_sha256 = $1 and state_sha256 = $2 and code_expires_at > now()
               returning app_id, parent_session_id, return_path
           ),
           parent as (
               select s.id, s.user_id, s.expires_at from sessions s
                 join h on s.id = h.parent_session_id
                where s.revoked_at is null and s.expires_at > now()
           ),
           -- The visitor's pairwise subject for this app, created on their
           -- first exchange and kept forever. A concurrent first exchange for
           -- the same pair meets this one on the primary key and does nothing,
           -- so both read back the one subject at their next check.
           subject as (
               insert into app_subjects (app_id, user_id)
               select h.app_id, parent.user_id from h, parent
               on conflict (app_id, user_id) do nothing
           )
           insert into app_sessions (id, parent_session_id, app_id, secret_sha256, expires_at)
           select $3, parent.id, h.app_id, $4,
                  least(now() + ($5::bigint * interval '1 second'), parent.expires_at)
             from h, parent
           returning id as "id: AppSessionId", app_id as "app_id: AppId", expires_at,
                     (select return_path from h) as "return_path!""#,
        &code.digest()[..],
        &state.digest()[..],
        AppSessionId::new().as_uuid(),
        &secret.digest()[..],
        session::TTL.num_seconds(),
    )
    .fetch_optional(pool)
    .await
    .map_err(unavailable)?;

    Ok(row.map(|row| Exchanged {
        id: row.id,
        app_id: row.app_id,
        secret,
        expires_at: row.expires_at,
        // Validated when written; re-validated so a bad row cannot become a
        // redirect anywhere but the app's root.
        return_path: ReturnPath::parse(&row.return_path).unwrap_or_else(|_| ReturnPath::root()),
    }))
}

// ----------------------------------------------------------- check ----

/// Who a live app-host session belongs to, as the app is allowed to see it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Checked {
    /// The visitor's pairwise subject for this app, never their user id.
    pub subject: AppSubject,
    /// Verified (#9 stores no other kind).
    pub email: String,
    /// The app's org.
    pub org_id: OrgId,
    /// Whether the visitor is a member of the app's org. The interim access
    /// rule until #12: a session for a non-member reaches no app code.
    pub member: bool,
}

/// The visitor behind `secret`, if it is a live app-host session **for
/// `app_id`**.
///
/// The per-request check, and the only query the session model adds to the
/// app request path: one statement, an index probe on `secret_sha256`. Both
/// the app-host session and its parent control-plane session must be live,
/// so the effective expiry is the earlier of the two, and signing out or
/// revoking the parent ends every child on its very next request. Nothing is
/// cached, so revocation latency is zero; #12's cache must keep that or argue
/// for a bound.
///
/// The same statement returns what the app is told (its pairwise subject,
/// the verified email, the app's org) and whether the visitor is a member of
/// the app's org: a left join, not a second query. **#12 replaces the
/// membership rule** with its policy; #15/#16 widen it to "a member, or holds a
/// grant on this app".
///
/// # Errors
///
/// [`unavailable`]'s mapping for a database failure.
pub async fn check(
    pool: &PgPool,
    secret: &AppSessionSecret,
    app_id: AppId,
) -> Result<Option<Checked>, Error> {
    let mut connection = crate::db::acquire_for(pool, "session check")
        .await
        .map_err(unavailable)?;
    let row = sqlx::query!(
        r#"select sub.subject as "subject: AppSubject",
                  u.email,
                  ap.org_id as "org_id: OrgId",
                  -- #12 replaces: interim org-member rule.
                  (m.user_id is not null) as "member!"
             from app_sessions a
             join sessions s on s.id = a.parent_session_id
             join users u on u.id = s.user_id
             join apps ap on ap.id = a.app_id
             join app_subjects sub on sub.app_id = a.app_id and sub.user_id = u.id
             left join org_members m on m.org_id = ap.org_id and m.user_id = u.id
            where a.secret_sha256 = $1
              and a.app_id = $2
              and a.expires_at > now()
              and s.revoked_at is null
              and s.expires_at > now()
              and u.deleted_at is null
              and ap.deleted_at is null"#,
        &secret.digest()[..],
        app_id.as_uuid(),
    )
    .fetch_optional(&mut *connection)
    .await
    .map_err(unavailable)?;
    Ok(row.map(|row| Checked {
        subject: row.subject,
        email: row.email,
        org_id: row.org_id,
        member: row.member,
    }))
}

// ------------------------------------------------------- authorize ----

/// The handshake `state` names, if it is live: its row and where its app is
/// served.
struct Pending {
    id: HandshakeId,
    app_host: String,
}

async fn pending(
    pool: &PgPool,
    state: &HandshakeState,
    apps: &shared::domains::AppsDomain,
) -> Result<Option<Pending>, Error> {
    let row = sqlx::query!(
        r#"select h.id as "id: HandshakeId", a.name, o.slug
             from handshakes h
             join apps a on a.id = h.app_id and a.deleted_at is null
             join orgs o on o.id = a.org_id and o.deleted_at is null
            where h.state_sha256 = $1 and h.expires_at > now()"#,
        &state.digest()[..],
    )
    .fetch_optional(pool)
    .await
    .map_err(unavailable)?;
    Ok(row.and_then(|row| {
        let slug = shared::cert::OrgSlug::parse(&row.slug).ok()?;
        Some(Pending {
            id: row.id,
            app_host: apps.app_host(&row.name, &slug),
        })
    }))
}

fn redirect(location: &str) -> Response {
    let mut response = StatusCode::SEE_OTHER.into_response();
    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(location) {
        headers.insert(header::LOCATION, value);
    }
    // The URL carries a code or a state. Neither may leak in a Referer, nor
    // be kept by a cache.
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn unknown_handshake() -> Error {
    Error::InvalidRequest {
        what: "this sign-in link has expired or was already used; open the app again".to_owned(),
    }
}

/// `GET /authorize?state=…`.
pub(crate) async fn authorize_route(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    match authorize(&state, query.as_deref().unwrap_or(""), &headers).await {
        Ok(response) => response,
        Err(error) => render(&error, &request_id),
    }
}

async fn authorize(
    app_state: &AppState,
    query: &str,
    headers: &HeaderMap,
) -> Result<Response, Error> {
    let not_configured = || Error::Internal {
        source: anyhow::anyhow!("app sign-in is not configured on this control plane"),
    };
    let signin = app_state.signin.as_deref().ok_or_else(not_configured)?;
    let apps = app_state.apps_domain.as_ref().ok_or_else(not_configured)?;

    // The state is the only input. Any other parameter — a host, a redirect
    // URI — is ignored: where the visitor goes is the handshake row's app.
    let state = form_urlencoded::parse(query.as_bytes())
        .find(|(name, _)| name == "state")
        .and_then(|(_, value)| HandshakeState::parse(&value))
        .ok_or_else(unknown_handshake)?;
    let pending = pending(&app_state.pool, &state, apps)
        .await?
        .ok_or_else(unknown_handshake)?;

    let parent = match session::authenticate(&app_state.pool, signin.key(), headers).await {
        Ok(live) => live.id,
        // Not signed in to the control plane: sign in first, then come back
        // here. The resume value is this state, re-validated on the way back.
        Err(Error::Unauthenticated {}) => {
            return Ok(redirect(&format!(
                "{}/auth/google?resume={}",
                signin.origin(),
                state.expose()
            )));
        }
        Err(other) => return Err(other),
    };

    let code = HandshakeCode::generate()?;
    let issued = sqlx::query_scalar!(
        r#"update handshakes
              set code_sha256 = $2, parent_session_id = $3,
                  code_expires_at = now() + ($4::bigint * interval '1 second')
            where id = $1 and expires_at > now()
           returning id as "id: HandshakeId""#,
        pending.id.as_uuid(),
        &code.digest()[..],
        parent.as_uuid(),
        CODE_TTL_SECS,
    )
    .fetch_optional(&app_state.pool)
    .await
    .map_err(unavailable)?;
    if issued.is_none() {
        return Err(unknown_handshake());
    }

    Ok(redirect(&format!(
        "https://{}/__clwd/callback?code={}&state={}",
        pending.app_host,
        code.expose(),
        state.expose()
    )))
}

pub(crate) fn authorize_doc() -> Doc {
    Doc {
        operation_id: "authorizeAppHost",
        summary: "Sign in to an app host",
        description: "The middle of the app-host sign-in handshake. The gateway sends a visitor \
                      here with the handshake's `state`. Signs the visitor in to the control plane \
                      first if needed, then redirects to the app's own `/__clwd/callback` with a \
                      single-use, 60-second code. The app host is taken from the handshake, never \
                      from this request: any other parameter is ignored.",
        params: &[],
        request: None,
        success: vec![Success {
            status: StatusCode::SEE_OTHER,
            description: "To the app host's callback with a code, or to sign-in first.",
            body: None,
        }],
        errors: &["control-plane.invalid_request"],
    }
}

// ---------------------------------------------------- internal routes ----

/// `POST /internal/handshakes`.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct BeginRequest {
    #[schema(value_type = String, format = Uuid)]
    app_id: AppId,
    return_path: String,
}

#[derive(Serialize, Deserialize, utoipa::ToSchema)]
pub(crate) struct BeginResponse {
    state: String,
}

/// `POST /internal/handshakes/exchange`.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExchangeRequest {
    code: String,
    state: String,
}

#[derive(Serialize, Deserialize, utoipa::ToSchema)]
pub(crate) struct ExchangeResponse {
    session: String,
    #[schema(value_type = String, format = Uuid)]
    app_id: AppId,
    max_age_secs: i64,
    return_path: String,
}

/// `POST /internal/app-sessions/check`.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct CheckRequest {
    session: String,
    #[schema(value_type = String, format = Uuid)]
    app_id: AppId,
}

#[derive(Serialize, Deserialize, utoipa::ToSchema)]
pub(crate) struct CheckResponse {
    /// The visitor's pairwise subject for this app.
    #[schema(value_type = String, format = Uuid)]
    subject: AppSubject,
    email: String,
    #[schema(value_type = String, format = Uuid)]
    org_id: OrgId,
    /// Whether the visitor is a member of the app's org (#12 replaces).
    member: bool,
}

fn parse_body<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, Error> {
    serde_json::from_slice(body).map_err(|e| Error::InvalidRequest {
        what: e.to_string(),
    })
}

pub(crate) async fn begin_route(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    body: Bytes,
) -> Response {
    let result = async {
        let request: BeginRequest = parse_body(&body)?;
        let return_path =
            ReturnPath::parse(&request.return_path).unwrap_or_else(|_| ReturnPath::root());
        begin(&state.pool, request.app_id, &return_path).await
    }
    .await;
    match result {
        Ok(handshake) => (
            StatusCode::CREATED,
            axum::Json(BeginResponse {
                state: handshake.expose().to_owned(),
            }),
        )
            .into_response(),
        Err(error) => render(&error, &request_id),
    }
}

pub(crate) async fn exchange_route(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    body: Bytes,
) -> Response {
    let result = async {
        let request: ExchangeRequest = parse_body(&body)?;
        let (Some(code), Some(handshake)) = (
            HandshakeCode::parse(&request.code),
            HandshakeState::parse(&request.state),
        ) else {
            return Err(Error::Unauthenticated {});
        };
        exchange(&state.pool, &code, &handshake)
            .await?
            .ok_or(Error::Unauthenticated {})
    }
    .await;
    match result {
        Ok(exchanged) => axum::Json(ExchangeResponse {
            session: exchanged.secret.expose().to_owned(),
            app_id: exchanged.app_id,
            max_age_secs: (exchanged.expires_at - Utc::now()).num_seconds().max(0),
            return_path: exchanged.return_path.as_str().to_owned(),
        })
        .into_response(),
        Err(error) => render(&error, &request_id),
    }
}

pub(crate) async fn check_route(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    body: Bytes,
) -> Response {
    let result = async {
        let request: CheckRequest = parse_body(&body)?;
        let secret = AppSessionSecret::parse(&request.session).ok_or(Error::Unauthenticated {})?;
        check(&state.pool, &secret, request.app_id)
            .await?
            .ok_or(Error::Unauthenticated {})
    }
    .await;
    match result {
        Ok(checked) => axum::Json(CheckResponse {
            subject: checked.subject,
            email: checked.email,
            org_id: checked.org_id,
            member: checked.member,
        })
        .into_response(),
        Err(error) => render(&error, &request_id),
    }
}

fn begin_request_example() -> serde_json::Result<serde_json::Value> {
    serde_json::to_value(BeginRequest {
        app_id: AppId::from(crate::openapi::EXAMPLE_APP),
        return_path: "/notes/42".to_owned(),
    })
}

fn begin_response_example() -> serde_json::Result<serde_json::Value> {
    serde_json::to_value(BeginResponse {
        state: "0".repeat(64),
    })
}

fn exchange_request_example() -> serde_json::Result<serde_json::Value> {
    serde_json::to_value(ExchangeRequest {
        code: "0".repeat(64),
        state: "0".repeat(64),
    })
}

fn exchange_response_example() -> serde_json::Result<serde_json::Value> {
    serde_json::to_value(ExchangeResponse {
        session: "0".repeat(64),
        app_id: AppId::from(crate::openapi::EXAMPLE_APP),
        max_age_secs: 86_400,
        return_path: "/notes/42".to_owned(),
    })
}

fn check_response_example() -> serde_json::Result<serde_json::Value> {
    Ok(serde_json::json!({
        "subject": "3f2a1c4e-9b7d-4e21-8c3a-5d6f7e8a9b0c",
        "email": "ada@example.com",
        "org_id": crate::openapi::EXAMPLE_ORG,
        "member": true,
    }))
}

fn check_request_example() -> serde_json::Result<serde_json::Value> {
    serde_json::to_value(CheckRequest {
        session: "0".repeat(64),
        app_id: AppId::from(crate::openapi::EXAMPLE_APP),
    })
}

pub(crate) fn begin_doc() -> Doc {
    Doc {
        operation_id: "beginHandshake",
        summary: "Begin an app-host sign-in handshake",
        description: "Gateway only. Records the app and the same-host path to return to, and returns the state to set on the app host and send to /authorize.",
        params: &[],
        request: Some(Body::json::<BeginRequest>(
            "The app and the return path.",
            begin_request_example,
        )),
        success: vec![Success {
            status: StatusCode::CREATED,
            description: "The handshake's state.",
            body: Some(Body::json::<BeginResponse>(
                "The state.",
                begin_response_example,
            )),
        }],
        errors: &["control-plane.invalid_request", "control-plane.not_found"],
    }
}

pub(crate) fn exchange_doc() -> Doc {
    Doc {
        operation_id: "exchangeHandshakeCode",
        summary: "Exchange a handshake code for an app-host session",
        description: "Gateway only, server-to-server. A code works once. Every failure is identity.unauthenticated.",
        params: &[],
        request: Some(Body::json::<ExchangeRequest>(
            "The code and the state.",
            exchange_request_example,
        )),
        success: vec![Success {
            status: StatusCode::OK,
            description: "The app-host session to set.",
            body: Some(Body::json::<ExchangeResponse>(
                "The session.",
                exchange_response_example,
            )),
        }],
        errors: &["control-plane.invalid_request"],
    }
}

pub(crate) fn check_doc() -> Doc {
    Doc {
        operation_id: "checkAppSession",
        summary: "Check an app-host session",
        description: "Gateway only, on every app request. 200 with the visitor's identity for this app if the session is live for this app and its parent control-plane session is live; identity.unauthenticated otherwise. `member` is false when the visitor is not a member of the app's org, and the gateway runs no app code for them.",
        params: &[],
        request: Some(Body::json::<CheckRequest>(
            "The session and the app requested.",
            check_request_example,
        )),
        success: vec![Success {
            status: StatusCode::OK,
            description: "The session is live for this app.",
            body: Some(Body::json::<CheckResponse>(
                "Who the visitor is, as the app may see them.",
                check_response_example,
            )),
        }],
        errors: &["control-plane.invalid_request"],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_redact_their_debug_and_parse_only_their_own_shape() {
        let code = HandshakeCode::generate().expect("random");
        assert_eq!(format!("{code:?}"), "HandshakeCode(<redacted>)");
        assert_eq!(HandshakeCode::parse(code.expose()), Some(code.clone()));
        for raw in ["", "abc", &"A".repeat(64), &"g".repeat(64), &"0".repeat(65)] {
            assert_eq!(HandshakeCode::parse(raw), None, "{raw}");
        }
        let state = HandshakeState::generate().expect("random");
        assert_eq!(format!("{state:?}"), "HandshakeState(<redacted>)");
        let secret = AppSessionSecret::generate().expect("random");
        assert_eq!(format!("{secret:?}"), "AppSessionSecret(<redacted>)");
    }
}
