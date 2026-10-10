//! The worker: runs app code for the gateway, in a process of its own (#11).
//!
//! # Why a separate process
//!
//! App code is untrusted, and wasmtime has shipped sandbox escapes. The gateway
//! holds every org's TLS private key and the internal credential; an escape in
//! its address space would hand an attacker all of them. The worker holds none
//! of that: read access to artifacts, and the requests in flight. An escape here
//! exposes other orgs' in-flight requests (cookies, bodies, caller emails) and
//! artifact bytes, which is why per-org workers are a follow-up and why secrets
//! must not reach this process until they exist. [`refuse_secrets`] makes the
//! binary refuse to start with the gateway's or the control plane's
//! credentials in its environment.
//!
//! # One request, one instance
//!
//! Every hop is spawn, invoke, stop, with the caller the gateway's session
//! check produced. Nothing about a caller outlives its request: no instance
//! reuse, no `Store` pool, nothing set at startup.
//!
//! # What runs is what was published
//!
//! The digest comes from the control plane, through the gateway, in the hop's
//! head. The artifact store verifies it on load ([`builder::ArtifactStore`]),
//! and the runtime verifies it again when it decodes. The capabilities enforced
//! are the bundle's sealed manifest's; nothing in the request can add one.
//!
//! # Egress is refused
//!
//! The runtime enforces egress by host name only, and a name that resolves to
//! loopback, link-local or a private address would reach the host, the cloud
//! metadata service and anything internal. Until egress is filtered by address,
//! a bundle whose manifest grants any is refused here, at spawn, before it
//! runs. Publish refuses it too; this is the authoritative refusal.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use builder::ArtifactStore;
use clwd_bundle::BundleRef;
use clwd_runtime::identity::{Caller, IdentityCtx, OrgId, Principal, SubjectId};
use clwd_runtime::wasm::{
    AppDataStore, AppId, AppIdRequired, BundleStore, SecretStore, WasmSandbox,
};
use clwd_runtime::{Deadline, InvokeOptions, RequestId, Sandbox, SpawnOptions};
use futures::FutureExt as _;
use futures::StreamExt as _;
use shared::hop::{self, RequestHead, ResponseHead};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;

/// How long one invocation may run, wall clock.
pub const INVOKE_DEADLINE: Duration = Duration::from_secs(30);
/// How long a spawn may take, compilation included.
pub const SPAWN_DEADLINE: Duration = Duration::from_secs(10);

/// Environment variables that name the gateway's or the control plane's
/// secrets. The worker refuses to start with any of them set.
pub const FORBIDDEN_ENV: &[&str] = &[
    "CLWD_INTERNAL_SECRET",
    "DATABASE_URL",
    "CLWD_CERT_DIR",
    "CLWD_COOKIE_KEY",
    "CLWD_GOOGLE_CLIENT_SECRET",
];

/// The worker refuses to start with a credential it must not hold.
#[derive(Debug, thiserror::Error)]
#[error(
    "refusing to start: {0} is set. The worker runs untrusted code and must hold no \
     gateway or control-plane secret; start it with a clean environment"
)]
pub struct HoldsASecret(String);

/// Fail if `vars` names any of [`FORBIDDEN_ENV`].
///
/// # Errors
///
/// [`HoldsASecret`] naming the first one found.
pub fn refuse_secrets<I: IntoIterator<Item = (String, String)>>(
    vars: I,
) -> Result<(), HoldsASecret> {
    match vars
        .into_iter()
        .find(|(name, _)| FORBIDDEN_ENV.contains(&name.as_str()))
    {
        Some((name, _)) => Err(HoldsASecret(name)),
        None => Ok(()),
    }
}

/// Runs app code, one hop at a time.
pub struct Worker {
    sandbox: WasmSandbox,
    artifacts: ArtifactStore,
    /// Whether a digest's manifest grants egress, decided once: a digest's
    /// manifest never changes.
    grants_egress: Mutex<HashMap<BundleRef, bool>>,
    invocations: AtomicU64,
    gateway_uid: u32,
}

impl Worker {
    /// A worker reading artifacts from `artifacts`, accepting hops only from a
    /// peer running as `gateway_uid`.
    ///
    /// # Errors
    ///
    /// The runtime's error if the engine cannot be built.
    pub fn new(artifacts: ArtifactStore, gateway_uid: u32) -> Result<Self, clwd_runtime::Error> {
        let sandbox = WasmSandbox::with_stores(
            Arc::new(Artifacts(artifacts.clone())),
            Arc::new(NoSecrets),
            Arc::new(NoAppData),
            // Every spawn names its app; a forgotten one is an error, never a
            // digest lookup (apps from one template share a digest).
            Arc::new(AppIdRequired),
        )?;
        Ok(Self {
            sandbox,
            artifacts,
            grants_egress: Mutex::new(HashMap::new()),
            invocations: AtomicU64::new(0),
            gateway_uid,
        })
    }

    /// How many times app code has been invoked. Tests assert that a refused
    /// request leaves this unchanged.
    #[must_use]
    pub fn invocations(&self) -> u64 {
        self.invocations.load(Ordering::SeqCst)
    }

    /// Accept hops on `listener` until the process ends.
    pub async fn serve(self: Arc<Self>, listener: UnixListener) {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let worker = Arc::clone(&self);
                    tokio::spawn(async move { worker.connection(stream).await });
                }
                Err(error) => tracing::warn!(%error, "accept failed"),
            }
        }
    }

    /// One hop: check who is on the other end, read one request, answer it.
    async fn connection(&self, mut stream: UnixStream) {
        // Anyone who can reach the socket could otherwise hand the worker a
        // caller of their choosing. The peer must be the gateway's user.
        match stream.peer_cred() {
            Ok(cred) if cred.uid() == self.gateway_uid => {}
            Ok(cred) => {
                tracing::warn!(
                    peer_uid = cred.uid(),
                    "refused a hop from a peer that is not the gateway"
                );
                return;
            }
            Err(error) => {
                tracing::warn!(%error, "could not read the peer's credentials; refused");
                return;
            }
        }
        let (head, body) = match hop::read_frame::<_, RequestHead>(&mut stream).await {
            Ok(frame) => frame,
            Err(error) => {
                tracing::warn!(%error, "refused a malformed hop");
                return;
            }
        };
        let (answer, body) = self.run(head, body).await;
        if let Err(error) = hop::write_frame(&mut stream, &answer, &body).await {
            tracing::warn!(%error, "could not answer a hop");
        }
    }

    /// Run one request. Never panics and never returns an error: a failure is
    /// a [`ResponseHead::failed`] with a stable code.
    pub async fn run(&self, head: RequestHead, body: Vec<u8>) -> (ResponseHead, Vec<u8>) {
        let request_id = head.request_id.clone();
        let app_id = head.app_id.clone();
        match self.egress_granted(&head.digest).await {
            Ok(false) => {}
            Ok(true) => {
                tracing::warn!(app_id = %app_id, request_id = %request_id, digest = %head.digest,
                    "refused a bundle that grants egress");
                return (
                    ResponseHead::failed("worker.egress_not_supported"),
                    Vec::new(),
                );
            }
            Err(code) => return (ResponseHead::failed(code), Vec::new()),
        }

        let mut principal = Principal::new(
            SubjectId::new(head.caller.subject.as_str()),
            OrgId::new(head.caller.org_id.as_str()),
        );
        principal.email = head.caller.email.clone();
        let identity = IdentityCtx::new(Caller::User(principal));

        let mut spawn = SpawnOptions::default();
        spawn.app = Some(AppId::new(head.app_id.as_str()));
        spawn.deadline = Some(Deadline::after(SPAWN_DEADLINE));
        let handle = match self.sandbox.spawn(head.digest, identity, spawn).await {
            Ok(handle) => handle,
            Err(error) => {
                tracing::warn!(app_id = %app_id, request_id = %request_id, code = error.code(),
                    error = %error, "spawn failed");
                return (ResponseHead::failed(error.code()), Vec::new());
            }
        };

        let result = self.invoke(&handle, head, body).await;
        if let Err(error) = self.sandbox.stop(handle).await {
            tracing::warn!(%error, "stop failed");
        }
        match result {
            Ok(answer) => answer,
            Err(error) => {
                tracing::info!(app_id = %app_id, request_id = %request_id, code = error.code(),
                    error = %error, "app failed");
                (ResponseHead::failed(error.code()), Vec::new())
            }
        }
    }

    async fn invoke(
        &self,
        handle: &clwd_runtime::Handle,
        head: RequestHead,
        body: Vec<u8>,
    ) -> Result<(ResponseHead, Vec<u8>), clwd_runtime::Error> {
        let request = request(&head, body)?;
        let mut logs = self.sandbox.logs_stream(handle).await?;
        let mut opts = InvokeOptions::default();
        opts.deadline = Some(Deadline::after(INVOKE_DEADLINE));
        opts.request_id = Some(RequestId::new(head.request_id.as_str()));

        self.invocations.fetch_add(1, Ordering::SeqCst);
        let response = self.sandbox.invoke(handle, request, opts).await;

        // App output is attacker-controlled: structured fields only, never
        // part of a format string. Its volume is capped per invocation by the
        // runtime (256 KiB a stream, then one marker line).
        while let Some(Some(Ok(line))) = logs.next().now_or_never() {
            tracing::info!(
                target: "app",
                app_id = %head.app_id,
                request_id = %head.request_id,
                stream = ?line.stream,
                message = %line.message,
            );
        }

        let response = response?;
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
            .collect();
        Ok((
            ResponseHead::answer(response.status().as_u16(), headers),
            response.into_body().into_bytes().to_vec(),
        ))
    }

    /// Whether `digest`'s sealed manifest grants egress. Reading it verifies
    /// the digest; a failure is the code to answer with.
    async fn egress_granted(&self, digest: &BundleRef) -> Result<bool, &'static str> {
        if let Some(known) = self.grants_egress.lock().await.get(digest) {
            return Ok(*known);
        }
        let bundle = self.artifacts.get(digest).await.map_err(|error| {
            tracing::warn!(%digest, code = error.code(), "artifact could not be loaded");
            "worker.artifact_unavailable"
        })?;
        let grants = !bundle.manifest.capabilities.egress.is_empty();
        self.grants_egress.lock().await.insert(*digest, grants);
        Ok(grants)
    }
}

/// The request as the app receives it: the client's headers as the gateway
/// filtered them, and nothing that names the caller.
fn request(
    head: &RequestHead,
    body: Vec<u8>,
) -> Result<clwd_runtime::Request, clwd_runtime::Error> {
    let host = head
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("host"))
        .and_then(|(_, value)| std::str::from_utf8(value).ok())
        .unwrap_or("app.invalid");
    let mut builder = http::Request::builder()
        .method(head.method.as_str())
        .uri(format!("https://{host}{}", head.path_and_query));
    for (name, value) in &head.headers {
        builder = builder.header(name.as_str(), value.as_slice());
    }
    builder
        .body(clwd_runtime::Body::from(body))
        .map_err(|e| clwd_runtime::Error::Internal {
            source: format!("building the app's request: {e}").into(),
        })
}

/// Artifacts, read from the store publish wrote them to.
struct Artifacts(ArtifactStore);

#[async_trait]
impl BundleStore for Artifacts {
    async fn fetch(&self, bundle: &BundleRef) -> clwd_runtime::Result<Vec<u8>> {
        self.0
            .get_bytes(bundle)
            .await
            .map(|bytes| bytes.to_vec())
            .map_err(|error| match error {
                shared::Error::NotFound { .. } => {
                    clwd_runtime::Error::BundleNotFound { bundle: *bundle }
                }
                other => clwd_runtime::Error::Internal {
                    source: other.to_string().into(),
                },
            })
    }
}

/// No secrets reach the worker until it is per org (M4 waits on that).
struct NoSecrets;

#[async_trait]
impl SecretStore for NoSecrets {
    async fn resolve(
        &self,
        _app: &AppId,
        _names: &[String],
    ) -> clwd_runtime::Result<Vec<(String, Vec<u8>)>> {
        Ok(Vec::new())
    }
}

/// App data is not wired yet (M4). Every operation fails loudly — the guest
/// sees `unavailable` — rather than succeeding into memory that vanishes.
struct NoAppData;

#[async_trait]
impl AppDataStore for NoAppData {
    async fn get(&self, _app: &AppId, _key: &str) -> clwd_runtime::Result<Option<Vec<u8>>> {
        Err(unavailable())
    }
    async fn set(&self, _app: &AppId, _key: &str, _value: Vec<u8>) -> clwd_runtime::Result<()> {
        Err(unavailable())
    }
    async fn delete(&self, _app: &AppId, _key: &str) -> clwd_runtime::Result<()> {
        Err(unavailable())
    }
}

fn unavailable() -> clwd_runtime::Error {
    clwd_runtime::Error::Internal {
        source: "app data is not available yet".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt as _;

    fn my_uid() -> u32 {
        use std::os::unix::fs::MetadataExt as _;
        std::fs::metadata("/proc/self")
            .map(|m| m.uid())
            .unwrap_or(0)
    }

    /// A peer that is not the gateway cannot hand the worker a caller: the
    /// connection is dropped before a frame is read, and nothing runs.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_peer_that_is_not_the_gateway_runs_nothing() {
        let operator =
            opendal::Operator::new(opendal::services::Memory::default()).expect("operator");
        let worker = Arc::new(
            Worker::new(ArtifactStore::new(operator), my_uid().wrapping_add(1)).expect("worker"),
        );
        let socket = std::env::temp_dir().join(format!("wk-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&socket);
        let listener = UnixListener::bind(&socket).expect("bind");
        tokio::spawn(Arc::clone(&worker).serve(listener));

        let mut stream = UnixStream::connect(&socket).await.expect("connect");
        let mut answer = Vec::new();
        let read = stream.read_to_end(&mut answer).await;
        assert!(
            read.is_err() || answer.is_empty(),
            "the worker answered an impostor"
        );
        assert_eq!(worker.invocations(), 0);
        let _ = std::fs::remove_file(&socket);
    }

    #[test]
    fn a_forbidden_variable_is_named_and_others_pass() {
        let env = |pairs: &[(&str, &str)]| {
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect::<Vec<_>>()
        };
        assert!(refuse_secrets(env(&[("PATH", "/bin"), ("CLWD_WORKER_SOCKET", "/run/x")])).is_ok());
        for name in FORBIDDEN_ENV {
            let err = refuse_secrets(env(&[("PATH", "/bin"), (name, "x")])).expect_err("refused");
            assert!(err.to_string().contains(name), "{err}");
        }
    }
}
