//! The gateway-wide budget for request bodies held in memory at once (#95).
//!
//! Every request body the gateway forwards is read whole before it is sent on
//! — to an app over the worker hop, or to the control plane — and each is
//! capped at [`shared::MAX_BUNDLE_BYTES`]. A cap per body does not bound the
//! sum: nothing caps how many connections the gateway accepts (pingora has no
//! such limit, and the gateway sets none), so enough concurrent uploads would
//! exhaust its memory, and the kernel would kill the process that holds every
//! org's TLS key.
//!
//! So the bytes are counted against one semaphore, a permit per byte, taken
//! as each chunk arrives and released when the request is done. A chunk that
//! does not fit is refused **at once** rather than waited for: a waiting
//! upload holds the bytes it already has, so queueing would let a slow sender
//! pin the budget, and an answer now (`gateway.busy`, retryable) is one a
//! client can act on.

use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// What the gateway holds for request bodies at once, at most.
///
/// Sixteen bodies at the per-body cap. Typical bodies are far smaller (a
/// published `hello` bundle is about 55 KB), so this admits hundreds of
/// ordinary uploads in flight while keeping the worst case — every in-flight
/// request a maximum-size upload — at a size a gateway host must have to spare
/// anyway. It bounds request bodies only; responses are bounded per request
/// by their own caps.
pub const GATEWAY_BODY_BUDGET: usize = 16 * shared::MAX_BUNDLE_BYTES;

/// The shared budget. Cheap to clone; every clone draws on the same bytes.
#[derive(Clone)]
pub struct BodyBudget {
    bytes: Arc<Semaphore>,
    total: usize,
}

/// Why a body could not be buffered.
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    /// This body is larger than one request may send.
    TooLarge,
    /// The gateway holds too many bodies at once to take this one now.
    Busy,
}

impl BodyBudget {
    /// A budget of `total` bytes.
    ///
    /// # Panics
    ///
    /// If `total` is smaller than `per_body`: one body that the per-body cap
    /// allows could then never be admitted, a configuration error caught at
    /// startup rather than as a refused upload.
    #[must_use]
    pub fn new(total: usize, per_body: usize) -> Self {
        assert!(
            total >= per_body,
            "a body budget of {total} bytes cannot hold one body of {per_body}"
        );
        Self {
            bytes: Arc::new(Semaphore::new(total)),
            total,
        }
    }

    /// Bytes not held by any request now.
    #[must_use]
    pub fn available(&self) -> usize {
        self.bytes.available_permits()
    }

    /// The whole budget.
    #[must_use]
    pub fn total(&self) -> usize {
        self.total
    }

    /// Start counting one request's body against the budget.
    #[must_use]
    pub fn reserve(&self, per_body: usize) -> Reservation {
        Reservation {
            budget: self.bytes.clone(),
            held: None,
            len: 0,
            per_body,
        }
    }
}

/// One request's share of the budget. Its bytes go back when it is dropped.
pub struct Reservation {
    budget: Arc<Semaphore>,
    held: Option<OwnedSemaphorePermit>,
    len: usize,
    per_body: usize,
}

impl Reservation {
    /// Count `n` more bytes of this body.
    ///
    /// # Errors
    ///
    /// [`Refused::TooLarge`] past the per-body cap, [`Refused::Busy`] when the
    /// budget cannot take `n` more bytes now. Neither waits.
    pub fn grow(&mut self, n: usize) -> Result<(), Refused> {
        if self.len + n > self.per_body {
            return Err(Refused::TooLarge);
        }
        let n32 = u32::try_from(n).map_err(|_| Refused::TooLarge)?;
        let permit = self
            .budget
            .clone()
            .try_acquire_many_owned(n32)
            .map_err(|_| Refused::Busy)?;
        match &mut self.held {
            Some(held) => held.merge(permit),
            None => self.held = Some(permit),
        }
        self.len += n;
        Ok(())
    }

    /// Bytes counted so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether nothing has been counted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_go_back_when_the_request_is_done() {
        let budget = BodyBudget::new(100, 60);
        let mut one = budget.reserve(60);
        one.grow(40).expect("fits");
        one.grow(20).expect("fits");
        assert_eq!(budget.available(), 40);
        drop(one);
        assert_eq!(budget.available(), 100);
    }

    #[test]
    fn a_body_past_its_cap_is_too_large_whatever_the_budget() {
        let budget = BodyBudget::new(1000, 60);
        let mut one = budget.reserve(60);
        one.grow(60).expect("at the cap");
        assert_eq!(one.grow(1), Err(Refused::TooLarge));
    }

    #[test]
    fn a_chunk_that_does_not_fit_is_busy_at_once_and_holds_nothing_extra() {
        let budget = BodyBudget::new(100, 100);
        let mut first = budget.reserve(100);
        first.grow(90).expect("fits");
        let mut second = budget.reserve(100);
        assert_eq!(second.grow(20), Err(Refused::Busy));
        assert!(second.is_empty());
        assert_eq!(budget.available(), 10, "the refused chunk took nothing");
    }

    #[test]
    #[should_panic(expected = "cannot hold one body")]
    fn a_budget_smaller_than_one_body_is_refused_at_startup() {
        let _ = BodyBudget::new(10, 11);
    }

    /// Many concurrent large bodies: the bytes held never exceed the budget,
    /// some uploads are refused as busy rather than queued, every refused or
    /// finished upload gives its bytes back, and the budget ends whole.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn many_concurrent_large_bodies_never_exceed_the_budget() {
        const BODY: usize = 1024 * 1024;
        const CHUNK: usize = 16 * 1024;
        const UPLOADS: usize = 64;
        let budget = BodyBudget::new(4 * BODY, BODY);
        let peak = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        // Every upload holds its first chunk before any sends a second, so
        // all of them are in flight at once (64 first chunks fit in 4 MiB).
        let started = Arc::new(tokio::sync::Barrier::new(UPLOADS));
        let mut uploads = Vec::new();
        for _ in 0..UPLOADS {
            let (budget, peak, started) = (budget.clone(), peak.clone(), started.clone());
            uploads.push(tokio::spawn(async move {
                let mut held = budget.reserve(BODY);
                held.grow(CHUNK).expect("every first chunk fits");
                started.wait().await;
                for _ in 1..BODY / CHUNK {
                    held.grow(CHUNK)?;
                    let in_use = budget.total() - budget.available();
                    peak.fetch_max(in_use, std::sync::atomic::Ordering::SeqCst);
                    tokio::task::yield_now().await;
                }
                Ok::<usize, Refused>(held.len())
            }));
        }
        let (mut done, mut busy) = (0, 0);
        for upload in uploads {
            match upload.await.expect("no upload panicked") {
                Ok(len) => {
                    assert_eq!(len, BODY);
                    done += 1;
                }
                Err(Refused::Busy) => busy += 1,
                Err(Refused::TooLarge) => panic!("no body here is over its cap"),
            }
        }
        assert!(done >= 1, "some uploads finish");
        assert!(
            busy >= 1,
            "64 bodies of 1 MiB in flight together do not fit in 4 MiB"
        );
        assert!(
            peak.load(std::sync::atomic::Ordering::SeqCst) <= budget.total(),
            "the bytes held never exceeded the budget"
        );
        assert_eq!(budget.available(), budget.total(), "every byte came back");
    }
}
