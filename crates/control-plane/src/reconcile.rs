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
    /// Of those, claims released unstarted because the process is stopping.
    pub released: usize,
    /// The claim itself failed, so nothing was attempted.
    pub claim_failed: bool,
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
    pass(pool, issuer, limit, stale_after, retry_after, None).await
}

/// One pass. With `stop`, checks it before each row: once it is set, the rows
/// not yet started are released (see [`db::cert_release_claims`]) rather than
/// left `renewing` for [`STALE_RENEWING_AFTER`], and the pass returns.
async fn pass(
    pool: &sqlx::PgPool,
    issuer: &CertIssuer,
    limit: i64,
    stale_after: Duration,
    retry_after: Duration,
    stop: Option<&tokio::sync::watch::Receiver<bool>>,
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
            return ReconcileReport {
                claim_failed: true,
                ..ReconcileReport::default()
            };
        }
    };
    let mut report = ReconcileReport {
        // Sized from the slugs found, not the rows marked: an org deleted
        // between the mark and the read leaves a `renewing` row no pass drives
        // or reclaims — harmless, since nothing is served under its names.
        claimed: due.len(),
        ..ReconcileReport::default()
    };
    for (index, cert) in due.iter().enumerate() {
        if stop.is_some_and(|stop| *stop.borrow()) {
            let unstarted: Vec<_> = due[index..].iter().map(|c| c.org_id).collect();
            match db::cert_release_claims(pool, &unstarted).await {
                Ok(released) => report.released = released,
                Err(error) => {
                    tracing::warn!(%error, "could not release unstarted renewals; they are reclaimed once stale")
                }
            }
            tracing::info!(
                released = report.released,
                "renewal reconciler stopping between rows"
            );
            break;
        }
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

/// How often the reconciler runs a pass.
pub const PASS_EVERY: Duration = Duration::from_secs(60);

/// The longest wait between attempts to set up the ACME account.
const ACCOUNT_MAX_RETRY: Duration = Duration::from_secs(300);

/// What the reconciler is doing, for `/readyz` (#48). Reported, never a
/// reason to be unready: certificates renew weeks ahead, and an instance
/// that cannot reach the CA can still serve every request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReconcilerState {
    /// `CLWD_CERT_RECONCILER=off`.
    Off,
    /// Setting up the ACME account.
    Starting,
    /// The last pass claimed and completed what was due.
    Running,
    /// The account could not be set up, or the last pass had failures.
    Failing,
    /// Stopped at shutdown.
    Stopped,
}

impl ReconcilerState {
    /// The name `/readyz` reports.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Failing => "failing",
            Self::Stopped => "stopped",
        }
    }
}

/// A [`ReconcilerState`] shared between the reconciler and readiness.
#[derive(Debug)]
pub struct StateCell(std::sync::Mutex<ReconcilerState>);

impl StateCell {
    #[must_use]
    pub fn new(state: ReconcilerState) -> Self {
        Self(std::sync::Mutex::new(state))
    }

    #[must_use]
    pub fn get(&self) -> ReconcilerState {
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn set(&self, state: ReconcilerState) {
        let mut current = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *current != state {
            tracing::info!(
                from = current.as_str(),
                to = state.as_str(),
                "certificate reconciler state changed"
            );
            *current = state;
        }
    }
}

async fn stopped(stop: &mut tokio::sync::watch::Receiver<bool>) {
    let _ = stop.wait_for(|stop| *stop).await;
}

/// Run the reconciler until `stop` is set: set up the issuer with `connect`
/// (retrying with backoff, since it reaches the CA), then a pass every
/// [`PASS_EVERY`]. A pass in progress when `stop` is set finishes its current
/// row and releases the rest.
pub async fn run<F, Fut>(
    pool: sqlx::PgPool,
    connect: F,
    state: std::sync::Arc<StateCell>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<CertIssuer, String>>,
{
    state.set(ReconcilerState::Starting);
    let mut wait = Duration::from_secs(1);
    let issuer = loop {
        match connect().await {
            Ok(issuer) => break issuer,
            Err(error) => {
                tracing::warn!(%error, retry_in_s = wait.as_secs(), "certificate reconciler: ACME account setup failed");
                state.set(ReconcilerState::Failing);
            }
        }
        tokio::select! {
            () = tokio::time::sleep(wait) => {}
            () = stopped(&mut stop) => {
                state.set(ReconcilerState::Stopped);
                return;
            }
        }
        wait = (wait * 2).min(ACCOUNT_MAX_RETRY);
    };
    loop {
        let report = pass(
            &pool,
            &issuer,
            CLAIM_LIMIT,
            STALE_RENEWING_AFTER,
            FAILED_RETRY_AFTER,
            Some(&stop),
        )
        .await;
        if *stop.borrow() {
            break;
        }
        state.set(if report.claim_failed || report.failed > 0 {
            ReconcilerState::Failing
        } else {
            ReconcilerState::Running
        });
        tokio::select! {
            () = tokio::time::sleep(PASS_EVERY) => {}
            () = stopped(&mut stop) => break,
        }
    }
    state.set(ReconcilerState::Stopped);
}
