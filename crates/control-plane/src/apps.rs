//! Creating an app (#108).
//!
//! # The host label is the app's address, for good
//!
//! An app's URL is `{host_label}.{org}.<apps domain>`. The label is chosen
//! once, here, and the database refuses to change it or to give it to another
//! app in the org, even after this one is deleted. A link shared to an app can
//! therefore never come to open a different one. The display name (`name`) is
//! separate and starts equal to the label.
//!
//! # Idempotent by label
//!
//! Creating a label that a live app in the org already holds returns that app
//! with `200` and `"created": false`, rather than a conflict: an agent retrying
//! after a dropped response must be able to learn the id it was given. A label
//! a deleted app held is `409`: never a new app under an old URL.
//!
//! # Who may
//!
//! A signed-in member of the org, or an API token of that org with the `write`
//! scope, through the decision interface (#12) like every authorization
//! question, so #14's policy replaces this rule too. A token bound to one app
//! may not create others. An org the caller cannot reach is `404`, the same as
//! one that does not exist.

use axum::Extension;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use shared::{Error, RequestId};

use crate::auth::Caller;
use crate::authz::{self, Action, Context, Principal, Resource};
use crate::db::{self, App, Ensured};
use crate::http::{AppState, render};
use crate::ids::{AppId, OrgId, UserId};
use crate::openapi::{Body, Doc, EXAMPLE_APP, EXAMPLE_ORG, Success};

/// The one runtime anything runs today.
const DEFAULT_RUNTIME: &str = "wasm";

/// The request body.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateAppRequest {
    /// The app's half of `{app}.{org}.<apps domain>`: lowercase letters,
    /// digits and hyphens, 1–63 characters, not starting or ending with a
    /// hyphen. Permanent: it can never be changed or reused in the org.
    #[schema(pattern = "^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")]
    pub host_label: String,
    /// `wasm`, the default and the only runtime available.
    #[serde(default)]
    pub runtime: Option<String>,
}

/// The app, and whether this call created it.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct AppResponse {
    #[schema(value_type = String, format = Uuid)]
    pub id: AppId,
    #[schema(value_type = String, format = Uuid)]
    pub org_id: OrgId,
    /// The permanent label in the app's URL.
    #[schema(pattern = "^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")]
    pub host_label: String,
    /// The display name. Starts equal to `host_label`.
    pub name: String,
    /// Where the app is served.
    pub url: String,
    /// `true` if this call created the app; `false` if a live app already held
    /// the label and this is that app.
    pub created: bool,
}

/// Whether `label` is a DNS label the apps table accepts: the same rule as its
/// `CHECK`, checked first so a bad label is a 400 that says why, not a
/// database error.
fn valid_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    (1..=63).contains(&bytes.len())
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
        && bytes.first() != Some(&b'-')
        && bytes.last() != Some(&b'-')
}

/// `POST /v1/orgs/{org_id}/apps`
pub(crate) async fn create_route(
    State(state): State<AppState>,
    Path(org): Path<String>,
    Extension(caller): Extension<Caller>,
    Extension(request_id): Extension<RequestId>,
    body: Bytes,
) -> Response {
    match create(&state, &org, &caller, &body).await {
        Ok((status, app)) => (status, axum::Json(app)).into_response(),
        Err(error) => render(&error, &request_id),
    }
}

async fn create(
    state: &AppState,
    org: &str,
    caller: &Caller,
    body: &[u8],
) -> Result<(StatusCode, AppResponse), Error> {
    let not_found = || Error::NotFound {
        what: format!("org {org}"),
    };
    let org_id = org.parse::<OrgId>().map_err(|_| not_found())?;
    let request: CreateAppRequest =
        serde_json::from_slice(body).map_err(|e| Error::InvalidRequest {
            what: format!("app: {e}"),
        })?;
    if !valid_label(&request.host_label) {
        return Err(Error::InvalidRequest {
            what: format!(
                "host_label {:?}: use 1-63 lowercase letters, digits and hyphens, not starting or ending with a hyphen",
                request.host_label
            ),
        });
    }
    let runtime = request.runtime.as_deref().unwrap_or(DEFAULT_RUNTIME);
    if runtime != DEFAULT_RUNTIME {
        return Err(Error::InvalidRequest {
            what: format!("runtime {runtime:?}: only `wasm` is available"),
        });
    }

    // Who is asking, and the one fact the interim rule decides from.
    let (principal, user) = match caller {
        Caller::Token(token) => {
            if token.app_id.is_some() {
                return Err(Error::Forbidden {
                    what: "a token bound to one app cannot create apps".to_owned(),
                });
            }
            (Principal::token(token.token_id, token.org_id), None)
        }
        Caller::Session(session) => (Principal::user(session.user_id), Some(session.user_id)),
    };
    let row = org_and_membership(&state.pool, org_id, user)
        .await
        .map_err(crate::auth::unavailable)?
        .ok_or_else(not_found)?;
    let member_of_org = match caller {
        Caller::Token(token) => token.org_id == org_id,
        Caller::Session(_) => row.member,
    };
    let decision = authz::POLICY.decide(&authz::Request::new(
        principal,
        Action::CreateApp,
        Resource::Org { org_id },
        Context::new(member_of_org),
    ));
    if !decision.is_allow() {
        return Err(not_found());
    }

    let (status, app, created) = match db::ensure_app(
        &state.pool,
        org_id,
        &request.host_label,
        runtime,
    )
    .await
    .map_err(crate::auth::unavailable)?
    {
        Ensured::Created(app) => (StatusCode::CREATED, app, true),
        Ensured::Existing(app) => (StatusCode::OK, app, false),
        Ensured::Retired => {
            return Err(Error::Conflict {
                what: format!(
                    "host_label {:?} belonged to a deleted app in this org, and labels are never reused; choose another",
                    request.host_label
                ),
            });
        }
        Ensured::NoOrg => return Err(not_found()),
    };
    Ok((status, response(state, &row.slug, app, created)?))
}

struct OrgRow {
    slug: String,
    member: bool,
}

/// The live org's slug, and whether `user` (if any) is a member of it.
async fn org_and_membership(
    pool: &sqlx::PgPool,
    org_id: OrgId,
    user: Option<UserId>,
) -> sqlx::Result<Option<OrgRow>> {
    sqlx::query_as!(
        OrgRow,
        r#"select o.slug,
                  exists (select 1 from org_members m
                           where m.org_id = o.id and m.user_id = $2) as "member!"
             from orgs o
            where o.id = $1 and o.deleted_at is null"#,
        org_id.as_uuid(),
        user.map(|u| u.as_uuid()),
    )
    .fetch_optional(pool)
    .await
}

fn response(state: &AppState, slug: &str, app: App, created: bool) -> Result<AppResponse, Error> {
    let apps = state.apps_domain.as_ref().ok_or_else(|| Error::Internal {
        source: anyhow::anyhow!("the apps domain is not configured on this control plane"),
    })?;
    let slug = shared::cert::OrgSlug::parse(slug).map_err(|e| Error::Internal {
        source: anyhow::anyhow!("stored org slug {slug:?} does not parse: {e}"),
    })?;
    Ok(AppResponse {
        url: format!("https://{}", apps.app_host(&app.host_label, &slug)),
        id: app.id,
        org_id: app.org_id,
        host_label: app.host_label,
        name: app.name,
        created,
    })
}

fn request_example() -> serde_json::Result<serde_json::Value> {
    Ok(serde_json::json!({ "host_label": "notes" }))
}

fn created_example() -> serde_json::Result<serde_json::Value> {
    serde_json::to_value(example(true))
}

fn existing_example() -> serde_json::Result<serde_json::Value> {
    serde_json::to_value(example(false))
}

fn example(created: bool) -> AppResponse {
    AppResponse {
        id: AppId::from(EXAMPLE_APP),
        org_id: OrgId::from(EXAMPLE_ORG),
        host_label: "notes".to_owned(),
        name: "notes".to_owned(),
        url: "https://notes.acme.example-apps.net".to_owned(),
        created,
    }
}

/// The documentation for `POST /v1/orgs/{org_id}/apps`.
pub(crate) fn create_doc() -> Doc {
    Doc {
        operation_id: "createApp",
        summary: "Create an app",
        description: "Creates an app in the org and returns its id and URL. Publish versions to it with `POST /v1/apps/{app_id}/versions`.\n\nThe `host_label` is the app's permanent address, `https://{host_label}.{org}.<apps domain>`: it can never be changed, and never reused in the org, even after the app is deleted, so a link to an app never comes to open another.\n\nIdempotent by label: if a live app in the org already has this `host_label`, that app is returned with 200 and `\"created\": false`, so a retry after a dropped response is always safe.",
        params: &[(
            "org_id",
            "The org to create the app in. The caller must be a member of it, or present a token of it; otherwise the answer is the same 404 as an org that does not exist.",
        )],
        request: Some(Body::json::<CreateAppRequest>(
            "The app's permanent host label, and optionally its runtime (`wasm`, the only one available).",
            request_example,
        )),
        success: vec![
            Success {
                status: StatusCode::CREATED,
                description: "This request created the app.",
                body: Some(Body::json::<AppResponse>("The new app.", created_example)),
            },
            Success {
                status: StatusCode::OK,
                description: "A live app in the org already has this host label: this is that app. Not an error.",
                body: Some(Body::json::<AppResponse>(
                    "The existing app.",
                    existing_example,
                )),
            },
        ],
        errors: &["control-plane.not_found", "control-plane.conflict"],
    }
}
