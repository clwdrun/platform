//! The gateway's host-resolution lookup: `{app}.{org}` → the live app.
//!
//! An [`Access::Internal`](crate::http::Access::Internal) route,
//! `GET /internal/orgs/{org}/apps/{app}`: only a platform service holding the
//! internal credential may call it. It answers whether an app exists so the
//! gateway can route a known host and 404 an unknown one; #11 extends the
//! gateway to proxy to the resolved app.

use axum::Json;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};

use shared::{Error, RequestId};

use crate::auth::unavailable;
use crate::db;
use crate::http::{AppState, render};
use crate::ids::{AppId, OrgId};
use crate::openapi::{Doc, Success};

/// What the gateway learns about a resolved host: the app, and the digest of
/// the version to run (the newest `ready` one; `null` until one is published).
#[derive(serde::Serialize)]
struct Resolution {
    app_id: AppId,
    org_id: OrgId,
    digest: Option<String>,
}

/// Resolve `{org}`/`{app}` to the live app, or 404 when there is none.
///
/// The three not-found cases — no such org, no such app, or the app is not that
/// org's — are one `control-plane.not_found`, deliberately indistinguishable.
/// Authentication has already run in [`crate::auth::require_internal`], layered
/// on this route; a caller without the internal credential never reaches here.
pub async fn resolve(
    State(state): State<AppState>,
    Path((org, app)): Path<(String, String)>,
    axum::Extension(request_id): axum::Extension<RequestId>,
) -> Response {
    let resolved = match db::acquire_for(&state.pool, "route resolve").await {
        Ok(mut connection) => db::resolve_live_app(&mut *connection, &org, &app).await,
        Err(source) => Err(source),
    };
    match resolved {
        Ok(Some(found)) => Json(Resolution {
            app_id: found.id,
            org_id: found.org_id,
            digest: found.digest,
        })
        .into_response(),
        Ok(None) => render(
            &Error::NotFound {
                what: format!("{app}.{org}"),
            },
            &request_id,
        ),
        Err(source) => render(&unavailable(source), &request_id),
    }
}

/// Documentation for the resolution route. It carries one — [`crate::http::Route::new`]
/// requires it and the envelope probe reads it to check the codes the route
/// produces — but it is not rendered into the public OpenAPI document, because
/// the route is [`Access::Internal`](crate::http::Access::Internal).
pub(crate) fn doc() -> Doc {
    Doc {
        operation_id: "resolve_host",
        summary: "Resolve an app host (internal)",
        description: "Maps `{app}.{org}` to the live app the gateway should serve. Internal: \
                      authenticated by the platform service credential, not a customer token.",
        params: &[
            (
                "org",
                "The org slug — the `{org}` label of `{app}.{org}.clwd.run`.",
            ),
            ("app", "The app name — the `{app}` label."),
        ],
        request: None,
        success: vec![Success {
            status: axum::http::StatusCode::OK,
            description: "The host resolves to a live app.",
            body: None,
        }],
        errors: &["control-plane.not_found"],
    }
}
