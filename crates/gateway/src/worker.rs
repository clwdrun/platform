//! The production hop: the gateway's [`AppUpstream`] that sends a request to
//! the worker over a Unix socket and reads its answer (#11).
//!
//! # The worker is untrusted
//!
//! It runs app code, so it is the process an escape lands in, and a compromised
//! worker can send back any bytes it likes. Nothing it sends is trusted:
//!
//! - **Who is listening is checked before a byte is written.** The socket's
//!   peer must run as the worker's user (`SO_PEERCRED`). Otherwise any local
//!   process that bound the path first would receive every visitor's identity
//!   and request body.
//! - **Every length is capped before it is allocated for** — head, body,
//!   header count, header bytes — by [`shared::hop::read_frame`], the same caps
//!   the worker applies to what the gateway sends.
//! - **Filtering happens after the hop, in the gateway**: platform
//!   `Set-Cookie`s and hop-by-hop headers are removed in the edge, so a worker
//!   that skipped them changes nothing.
//! - **One connection per request**, so one compromised response cannot
//!   poison another request's stream.

use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use shared::hop::{self, AppId, HopRequestId, OrgId, RequestHead, ResponseHead};
use tokio::net::UnixStream;

use crate::upstream::{AppTarget, AppUpstream, UpstreamError, UpstreamRequest, UpstreamResponse};

/// How long one hop may take, end to end: the worker's own invoke deadline,
/// plus room for a cold spawn.
const HOP_TIMEOUT: Duration = Duration::from_secs(45);

/// Sends requests to the worker.
#[derive(Debug, Clone)]
pub struct WorkerUpstream {
    socket: PathBuf,
    worker_uid: u32,
}

impl WorkerUpstream {
    /// A hop to the worker listening on `socket`, which must run as
    /// `worker_uid`.
    #[must_use]
    pub fn new(socket: impl Into<PathBuf>, worker_uid: u32) -> Self {
        Self {
            socket: socket.into(),
            worker_uid,
        }
    }

    async fn hop(
        &self,
        target: &AppTarget,
        request: UpstreamRequest,
    ) -> Result<UpstreamResponse, UpstreamError> {
        let mut stream = UnixStream::connect(&self.socket)
            .await
            .map_err(|e| UpstreamError::Unreachable(format!("connecting to the worker: {e}")))?;
        let cred = stream.peer_cred().map_err(|e| {
            UpstreamError::Unreachable(format!("reading the worker's credentials: {e}"))
        })?;
        if cred.uid() != self.worker_uid {
            return Err(UpstreamError::Unreachable(format!(
                "the process on the worker socket runs as uid {}, not the worker's {}",
                cred.uid(),
                self.worker_uid
            )));
        }

        let head = RequestHead {
            v: hop::VERSION,
            request_id: HopRequestId::new(shared::RequestId::generate().as_str()),
            app_id: AppId::new(target.app_id()),
            org_id: OrgId::new(target.org_id()),
            digest: *target.digest(),
            caller: request.caller,
            method: request.method.as_str().to_owned(),
            path_and_query: request.path_and_query,
            headers: request
                .headers
                .iter()
                .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
                .collect(),
        };
        hop::write_frame(&mut stream, &head, &request.body)
            .await
            .map_err(|e| UpstreamError::Unreachable(format!("sending to the worker: {e}")))?;
        let (answer, body) = hop::read_frame::<_, ResponseHead>(&mut stream)
            .await
            .map_err(|e| {
                UpstreamError::Unreachable(format!("the worker's answer was refused: {e}"))
            })?;

        if let Some(code) = answer.error {
            return Err(UpstreamError::Reported(code));
        }
        let status = StatusCode::from_u16(answer.status).map_err(|_| {
            UpstreamError::Unreachable(format!("the worker sent status {}", answer.status))
        })?;
        let mut headers = HeaderMap::new();
        for (name, value) in answer.headers {
            // A header that is not valid HTTP is dropped, not forwarded: the
            // worker's output is filtered as untrusted.
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_bytes(&value),
            ) {
                headers.append(name, value);
            }
        }
        Ok(UpstreamResponse::new(status, headers, Bytes::from(body)))
    }
}

#[async_trait]
impl AppUpstream for WorkerUpstream {
    async fn forward(
        &self,
        target: &AppTarget,
        request: UpstreamRequest,
    ) -> Result<UpstreamResponse, UpstreamError> {
        tokio::time::timeout(HOP_TIMEOUT, self.hop(target, request))
            .await
            .map_err(|_| {
                UpstreamError::Unreachable("the worker did not answer in time".to_owned())
            })?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Method;
    use shared::hop::{AppSubject, Caller};
    use tokio::io::AsyncReadExt as _;

    fn my_uid() -> u32 {
        use std::os::unix::fs::MetadataExt as _;
        std::fs::metadata("/proc/self")
            .map(|m| m.uid())
            .unwrap_or(0)
    }

    /// A process that wins the socket path, running as anyone but the worker,
    /// receives nothing: not the caller, not a header, not a byte.
    #[tokio::test]
    async fn a_listener_under_the_wrong_uid_gets_no_request() {
        let socket = std::env::temp_dir().join(format!("gw-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&socket);
        let listener = tokio::net::UnixListener::bind(&socket).expect("bind");
        let received = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut got = Vec::new();
            let _ = stream.read_to_end(&mut got).await;
            got.len()
        });

        let hop = WorkerUpstream::new(&socket, my_uid().wrapping_add(1));
        let target = AppTarget::new(
            "a".into(),
            "o".into(),
            clwd_bundle::BundleRef::of_stream(b"x"),
        );
        let request = UpstreamRequest::new(
            Caller::new(
                AppSubject::new("s"),
                Some("ada@example.com".into()),
                OrgId::new("o"),
            ),
            Method::GET,
            "/".into(),
            HeaderMap::new(),
            Bytes::from_static(b"body"),
        );
        let error = hop.forward(&target, request).await.expect_err("refused");
        assert!(error.to_string().contains("not the worker's"), "{error}");
        assert_eq!(
            received.await.expect("listener"),
            0,
            "the impostor received bytes"
        );
        let _ = std::fs::remove_file(&socket);
    }
}
