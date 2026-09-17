//! The renewal reconciler's drive step: claim what is due, renew it.
//!
//! One pass is [`reconcile_once`]: claim up to [`CLAIM_LIMIT`] rows with
//! [`db::claim_due_for_renewal`] (a single statement that commits before any
//! issuance runs), then drive each through [`CertIssuer::renew`]. The pass is
//! deliberately sequential — parallelism across workers comes from the claim's
//! `SKIP LOCKED`, not from driving concurrently inside a pass, so the per
//! identifier validation rate stays predictable and far under the
//! 5-failed-validations-per-hour budget.
//!
//! What each claimed row does:
//!
//! - A stored certificate exists → `renew`: a `replaces`-linked order (the
//!   rate-limit-exempt path), resuming `order_url` when a previous attempt left
//!   one.
//! - No stored certificate (a failed first issuance, or a crash before anything
//!   was stored) → `issue` instead. This is a new order and counts against the
//!   bucket — but a first issuance always does, so nothing is lost by trying.
//! - Either fails → the failure is already recorded visibly by the issuer
//!   (`cert_mark_failed`), and the row retries after [`FAILED_RETRY_AFTER`].
//!   A reconciler that stopped on failure would be an outage on a timer.
//!
//! Nothing here blocks on ARI: the schedule capture falls back to two-thirds
//! of lifetime when ARI is down (see [`CertIssuer`]), so a pass keeps renewing
//! on the certificates' own clocks.

use std::time::Duration;

use shared::cert::OrgSlug;

use crate::acme::{CertIssuer, IssueError};
use crate::db;

/// How long a `renewing` row may sit without progress before a pass reclaims
/// it. Must exceed the slowest healthy issuance (DNS propagation plus ACME
/// polling, minutes): reclaiming a merely-slow worker drives a duplicate order
/// — still safe, but it burns a validation and an order slot, so the interval
/// keeps that bounded and far under the 5-validations-per-hour budget.
pub const STALE_RENEWING_AFTER: Duration = Duration::from_secs(15 * 60);

/// How long after a recorded failure before the row is due again. An hour
/// means a persistently failing renewal burns at most one validation per hour
/// per identifier — inside the 5-per-hour budget with margin — while a
/// transient outage (DNS, CA) recovers without an operator.
pub const FAILED_RETRY_AFTER: Duration = Duration::from_secs(60 * 60);

/// The most rows one pass takes. A pass is sequential, so this bounds one
/// pass's slow work; anything still due waits for the next pass.
pub const CLAIM_LIMIT: i64 = 20;

/// What one reconciler pass did. Reported as counts, not just success: a pass
/// that claimed nothing and a pass that renewed ten must not look the same.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    /// Rows claimed (`renewing`) by this pass.
    pub claimed: usize,
    /// Of those, renewals (or fallback issuances) that completed.
    pub renewed: usize,
    /// Of those, renewals that failed (recorded visibly, retried later).
    pub failed: usize,
}

/// Run one renewal pass with the production intervals.
pub async fn reconcile_once(pool: &sqlx::PgPool, issuer: &CertIssuer) -> ReconcileReport {
    reconcile_with(
        pool,
        issuer,
        CLAIM_LIMIT,
        STALE_RENEWING_AFTER,
        FAILED_RETRY_AFTER,
    )
    .await
}

/// Run one renewal pass with explicit intervals (exists so tests drive the
/// stale and retry arms without waiting out the production ones).
pub async fn reconcile_with(
    pool: &sqlx::PgPool,
    issuer: &CertIssuer,
    limit: i64,
    stale_after: Duration,
    retry_after: Duration,
) -> ReconcileReport {
    let due = match db::claim_due_for_renewal(
        pool,
        limit,
        stale_after.as_secs() as i64,
        retry_after.as_secs() as i64,
    )
    .await
    {
        Ok(due) => due,
        Err(error) => {
            tracing::error!(%error, "renewal reconciler: claim failed; skipping this pass");
            return ReconcileReport::default();
        }
    };
    let mut report = ReconcileReport {
        // Sized from the slugs found, not the rows marked: an org deleted
        // between the mark and the read leaves a `renewing` row no pass drives
        // or reclaims — harmless, since nothing is served under its names.
        claimed: due.len(),
        ..ReconcileReport::default()
    };
    for cert in due {
        let slug = match OrgSlug::parse(&cert.slug) {
            Ok(slug) => slug,
            Err(error) => {
                // The orgs table normally forbids this (dns-label check), so a
                // failure here is a defect, not input — retire it visibly
                // rather than crashing the pass.
                tracing::error!(slug = cert.slug.as_str(), %error, "org slug is not a valid label; retiring this renewal visibly");
                if let Err(db_error) = db::cert_mark_failed(
                    pool,
                    cert.org_id,
                    &format!("stored org slug is not a valid label: {}", cert.slug),
                )
                .await
                {
                    tracing::error!(%db_error, "could not record the bad-slug failure");
                }
                report.failed += 1;
                continue;
            }
        };
        match issuer.renew(cert.org_id, &slug).await {
            Ok(()) => report.renewed += 1,
            Err(IssueError::NothingToRenew) => {
                tracing::info!(
                    org = slug.as_str(),
                    "no stored certificate; issuing instead of renewing"
                );
                match issuer.issue(cert.org_id, &slug).await {
                    Ok(()) => report.renewed += 1,
                    Err(error) => {
                        tracing::warn!(org = slug.as_str(), %error, "fallback issuance failed; recorded for retry");
                        report.failed += 1;
                    }
                }
            }
            Err(error) => {
                tracing::warn!(org = slug.as_str(), %error, "renewal failed; recorded for retry");
                report.failed += 1;
            }
        }
    }
    tracing::info!(
        claimed = report.claimed,
        renewed = report.renewed,
        failed = report.failed,
        "renewal reconciler pass complete"
    );
    report
}
