//! Publishing a bundle as a version of an app.
//!
//! # The ordering, and why it is this way round
//!
//! ```text
//! builder         validate(bytes)                    -> digest, no I/O
//! control-plane   claim (app_id, digest) 'pending'      atomic, one winner
//! builder         put(&validated)                       the expensive part
//! control-plane   mark ready
//! ```
//!
//! The digest is only known after decoding, so the row cannot be claimed until
//! validation has run. The artifact is written only after the claim, so a
//! crash leaves a **visible `pending` row** rather than an orphan artifact that
//! nothing references — the failure mode `#1`'s migration comment rejected this
//! ordering's alternative for.
//!
//! No transaction spans the artifact write. The whole point of claiming first
//! is that the expensive work happens outside the database.
//!
//! # Retrying never has to guess
//!
//! A retry of the same `(app_id, digest)` finds the row already claimed and
//! **cannot tell** whether another request is uploading right now or one died
//! an hour ago. It does not need to: the retry arrived with the same bytes, so
//! both readings lead to the same correct action — finish the work.
//!
//! That is only safe because `#6` made both halves idempotent. `put` no-ops on
//! an existing content-addressed key, and marking `ready` twice is marking it
//! once. So there is no lease, no timeout heuristic, and no window where the
//! right answer depends on which reading is true.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use shared::{Error, RequestId};

use crate::db::{self, AppVersion};
use crate::http::{AppState, render};
use crate::ids::AppId;

/// What a publish did, and the status it reports.
///
/// The distinction comes from whether the `INSERT` returned a row — never from
/// a prior `SELECT`, which would be a race. Carrying it as a type rather than a
/// bare status keeps the mapping in one place: error statuses are generated
/// beside their codes and cannot drift, and this is the success path's
/// equivalent.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Published {
    /// This request claimed the digest and stored the artifact.
    Created(AppVersion),
    /// The digest was already published. Not an error: with a content address
    /// the same bytes are the same version, so this is what a retry looks like.
    AlreadyExisted(AppVersion),
}

impl Published {
    /// **201** for a version this request created, **200** for one that was
    /// already there.
    ///
    /// Both are successes; they differ because the distinction is actionable —
    /// a caller, a proxy, or a deploy script can tell whether this call did the
    /// work.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        match self {
            Self::Created(_) => StatusCode::CREATED,
            Self::AlreadyExisted(_) => StatusCode::OK,
        }
    }

    /// The version, whichever way it went.
    #[must_use]
    pub fn version(&self) -> &AppVersion {
        match self {
            Self::Created(v) | Self::AlreadyExisted(v) => v,
        }
    }
}

impl IntoResponse for Published {
    fn into_response(self) -> Response {
        // No `created: bool` in the body. The status already carries it, and
        // two encodings of one fact eventually disagree.
        (self.status(), axum::Json(self.version().clone())).into_response()
    }
}

/// `POST /v1/apps/{app_id}/versions`
///
/// The body is the bundle, raw. The upload ceiling and its 413 envelope are
/// router-level layers from `#6`, so this route inherits both and needs
/// neither of its own.
///
/// # Errors
///
/// A malformed bundle returns its `bundle.*` code verbatim at 400 — the
/// caller's bytes are wrong and the code says how. An unknown or deleted app
/// is `control-plane.not_found` at 404, which is the other half of the
/// claim's ambiguous empty result and must not be confused with a conflict.
pub async fn publish(
    State(state): State<AppState>,
    Path(app_id): Path<AppId>,
    axum::Extension(request_id): axum::Extension<RequestId>,
    body: Bytes,
) -> Response {
    match publish_inner(&state, app_id, body).await {
        Ok(published) => published.into_response(),
        Err(error) => render(&error, &request_id),
    }
}

async fn publish_inner(state: &AppState, app_id: AppId, body: Bytes) -> Result<Published, Error> {
    // Before the claim, so an invalid bundle leaves no row at all.
    let validated = builder::validate(body)?;
    let digest = validated.digest().to_string();

    let claimed = db::claim_app_version(&state.pool, app_id, &digest)
        .await
        .map_err(internal)?;

    let Some(row) = claimed else {
        // Empty means *either* the conflict fired *or* no live app matched.
        // Disambiguate with a read — not a race, because this request is not
        // the one making progress and both answers are stable by now.
        let existing = db::app_version_by_digest(&state.pool, app_id, &digest)
            .await
            .map_err(internal)?;

        return match existing {
            // A conflict. Finish the work rather than assuming whoever holds
            // the row is still alive — see the module docs.
            Some(row) => {
                state.artifacts.put(&validated).await?;
                let ready = db::mark_app_version_ready(&state.pool, row.id)
                    .await
                    .map_err(internal)?;
                Ok(Published::AlreadyExisted(ready))
            }
            // No row, so the app is absent or deleted. A 404, never a 200:
            // reporting success for a publish that went nowhere is worse than
            // any error.
            None => Err(Error::NotFound {
                what: format!("app {app_id}"),
            }),
        };
    };

    state.artifacts.put(&validated).await?;
    let ready = db::mark_app_version_ready(&state.pool, row.id)
        .await
        .map_err(internal)?;
    Ok(Published::Created(ready))
}

/// A driver failure is ours, not the caller's.
fn internal(source: sqlx::Error) -> Error {
    Error::Internal {
        source: source.into(),
    }
}
