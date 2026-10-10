//! Warm-invoke latency (#11): the gateway's hop (connect, peer check, one
//! `shared::hop` frame each way, exactly what `WorkerUpstream` sends → worker →
//! spawn, invoke, stop → back) against a baseline of the same
//! spawn, invoke, stop in-process with no hop. Measures the cost the process
//! boundary adds; TLS and the session check are the same either way.
//!
//! `just fixture && cargo run --release -p worker --example hop_latency`

use std::sync::Arc;
use std::time::{Duration, Instant};

use clwd_runtime::identity::{Caller, IdentityCtx, OrgId, Principal, SubjectId};
use clwd_runtime::wasm::{AppId, MemoryBundleStore, WasmSandbox};
use clwd_runtime::{InvokeOptions, Sandbox, SpawnOptions};
use shared::hop;

const WHOAMI: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../target/fixtures/wasm32-wasip2/release/whoami.wasm"
));
const WARMUP: usize = 200;
const N: usize = 5_000;

fn bundle() -> (clwd_bundle::BundleRef, bytes::Bytes) {
    let encoded = clwd_bundle::build(
        clwd_bundle::Runtime::Wasm,
        "app.wasm",
        clwd_bundle::Capabilities {
            version: 1,
            egress: vec![],
            secrets: vec![],
            storage_namespaces: vec![],
            limits: clwd_bundle::Limits {
                cpu_ms: 5_000,
                memory_mb: 128,
            },
        },
        vec![clwd_bundle::File {
            path: "app.wasm".into(),
            data: WHOAMI.to_vec(),
            executable: false,
        }],
    )
    .expect("bundle");
    (encoded.digest, bytes::Bytes::from(encoded.bytes))
}

fn report(name: &str, mut samples: Vec<Duration>) {
    samples.sort();
    let at = |q: f64| samples[((samples.len() as f64 * q) as usize).min(samples.len() - 1)];
    println!(
        "{name:<10} n={} p50={:>7.1} µs  p99={:>7.1} µs",
        samples.len(),
        at(0.50).as_secs_f64() * 1e6,
        at(0.99).as_secs_f64() * 1e6
    );
}

fn head(digest: clwd_bundle::BundleRef) -> hop::RequestHead {
    hop::RequestHead {
        v: hop::VERSION,
        request_id: hop::HopRequestId::new("r"),
        app_id: hop::AppId::new("a"),
        org_id: hop::OrgId::new("o"),
        digest,
        caller: hop::Caller::new(
            hop::AppSubject::new("s"),
            Some("ada@example.com".into()),
            hop::OrgId::new("o"),
        ),
        method: "GET".into(),
        path_and_query: "/".into(),
        headers: vec![("host".into(), b"notes.test".to_vec())],
    }
}

fn me() -> u32 {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::metadata("/proc/self").expect("/proc/self").uid()
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let (digest, bytes) = bundle();

    // Baseline: the worker's per-request work, in process, no hop.
    let store = MemoryBundleStore::new();
    store.insert(&digest, bytes.to_vec());
    let sandbox = WasmSandbox::new(Arc::new(store)).expect("sandbox");
    let mut base = Vec::with_capacity(N);
    for i in 0..WARMUP + N {
        let start = Instant::now();
        let mut p = Principal::new(SubjectId::new("s"), OrgId::new("o"));
        p.email = Some("ada@example.com".into());
        let mut spawn = SpawnOptions::default();
        spawn.app = Some(AppId::new("a"));
        let h = sandbox
            .spawn(digest, IdentityCtx::new(Caller::User(p)), spawn)
            .await
            .expect("spawn");
        let req = http::Request::get("https://notes.test/")
            .body(clwd_runtime::Body::empty())
            .expect("req");
        let r = sandbox
            .invoke(&h, req, InvokeOptions::default())
            .await
            .expect("invoke");
        assert_eq!(r.status(), 200);
        sandbox.stop(h).await.expect("stop");
        if i >= WARMUP {
            base.push(start.elapsed());
        }
    }
    report("no hop", base);

    // Through the hop the gateway uses, to a worker on its own runtime.
    let operator = opendal::Operator::new(opendal::services::Memory::default()).expect("op");
    let artifacts = builder::ArtifactStore::new(operator);
    artifacts
        .put(&builder::validate(bytes).expect("valid"))
        .await
        .expect("put");
    let worker = Arc::new(worker::Worker::new(artifacts, me()).expect("worker"));
    // The worker's own per-request path, in process: its artifact store, its
    // checks, spawn, invoke, stop. The difference to "with hop" is the hop.
    let mut direct = Vec::with_capacity(N);
    for i in 0..WARMUP + N {
        let start = Instant::now();
        let (answer, _) = worker.run(head(digest), Vec::new()).await;
        assert_eq!(answer.status, 200, "{:?}", answer.error);
        if i >= WARMUP {
            direct.push(start.elapsed());
        }
    }
    report("worker", direct);

    let socket = format!("/tmp/clwd-lat-{}.sock", std::process::id());
    let _ = std::fs::remove_file(&socket);
    let (served, path) = (Arc::clone(&worker), socket.clone());
    let (ready, bound) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        tokio::runtime::Runtime::new()
            .expect("rt")
            .block_on(async move {
                let listener = tokio::net::UnixListener::bind(&path).expect("bind");
                let _ = ready.send(());
                served.serve(listener).await;
            });
    });
    bound.await.expect("bound");
    let mut hopped = Vec::with_capacity(N);
    for i in 0..WARMUP + N {
        let start = Instant::now();
        let mut stream = tokio::net::UnixStream::connect(&socket)
            .await
            .expect("connect");
        assert_eq!(stream.peer_cred().expect("cred").uid(), me());
        let head = head(digest);
        hop::write_frame(&mut stream, &head, b"")
            .await
            .expect("send");
        let (answer, _): (hop::ResponseHead, _) =
            hop::read_frame(&mut stream).await.expect("answer");
        assert_eq!(answer.status, 200, "{:?}", answer.error);
        if i >= WARMUP {
            hopped.push(start.elapsed());
        }
    }
    report("with hop", hopped);
    let _ = std::fs::remove_file(&socket);
}
