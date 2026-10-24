//! End-to-end: the real gateway binary forwards the control-plane domain to
//! the control plane's public listener (#95).
//!
//! The control plane here is a recording stand-in on plain HTTP, as the real
//! public listener is: it answers every request, keeps what it received, and
//! sets a cookie, so each test can say exactly what crossed the hop — and,
//! for the refusals, that nothing did.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{Request, State};
use axum::response::IntoResponse;
use boring::asn1::Asn1Time;
use boring::hash::MessageDigest;
use boring::pkey::PKey;
use boring::rsa::Rsa;
use boring::ssl::{SslConnector, SslMethod, SslVerifyMode};
use boring::x509::{X509, X509NameBuilder};

const APPS: &str = "clwd-apps.test";
const CONTROL_PLANE: &str = "api.clwd.test";
const APP_HOST: &str = "notes.acme.clwd-apps.test";

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);
    port
}

/// A self-signed certificate named `cn`, written as `cert.pem` and `key.pem`
/// under `dir`. Returns the certificate PEM.
fn write_cert(dir: &Path, cn: &str) -> Vec<u8> {
    let pkey = PKey::from_rsa(Rsa::generate(2048).expect("rsa")).expect("pkey");
    let mut name = X509NameBuilder::new().expect("name");
    name.append_entry_by_text("CN", cn).expect("cn");
    let name = name.build();
    let mut b = X509::builder().expect("builder");
    b.set_version(2).expect("version");
    b.set_subject_name(&name).expect("subject");
    b.set_issuer_name(&name).expect("issuer");
    b.set_pubkey(&pkey).expect("pubkey");
    b.set_not_before(&Asn1Time::days_from_now(0).expect("nbf"))
        .expect("nbf");
    b.set_not_after(&Asn1Time::days_from_now(1).expect("naf"))
        .expect("naf");
    b.sign(&pkey, MessageDigest::sha256()).expect("sign");
    let cert_pem = b.build().to_pem().expect("cert pem");
    std::fs::create_dir_all(dir).expect("dir");
    std::fs::write(dir.join("cert.pem"), &cert_pem).expect("cert");
    std::fs::write(
        dir.join("key.pem"),
        pkey.private_key_to_pem_pkcs8().expect("key pem"),
    )
    .expect("key");
    cert_pem
}

/// One request as the stand-in received it.
#[derive(Debug, Clone)]
struct Seen {
    path_and_query: String,
    headers: http::HeaderMap,
    body_len: usize,
}

/// The control plane's public listener, standing in: records every request,
/// answers 200 with a cookie of its own, and holds `/slow` for a second so
/// concurrent uploads overlap.
struct ControlPlane {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
    _runtime: tokio::runtime::Runtime,
}

impl ControlPlane {
    fn start() -> Self {
        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let listener = runtime
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        #[expect(
            clippy::disallowed_methods,
            reason = "a stand-in for the control plane's listener, not its router"
        )]
        let app = axum::Router::new()
            .fallback(record)
            .layer(axum::extract::DefaultBodyLimit::disable())
            .with_state(seen.clone());
        runtime.spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            addr,
            seen,
            _runtime: runtime,
        }
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().expect("lock").clone()
    }
}

async fn record(State(seen): State<Arc<Mutex<Vec<Seen>>>>, request: Request) -> impl IntoResponse {
    let (parts, body) = request.into_parts();
    let body: Bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .unwrap_or_default();
    let path_and_query = parts
        .uri
        .path_and_query()
        .map_or_else(String::new, |pq| pq.as_str().to_owned());
    if path_and_query == "/slow" {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    seen.lock().expect("lock").push(Seen {
        path_and_query: path_and_query.clone(),
        headers: parts.headers,
        body_len: body.len(),
    });
    (
        [(
            "set-cookie",
            "__Host-clwd_session=fresh; Path=/; Secure; HttpOnly; SameSite=Lax",
        )],
        format!("control plane saw {path_and_query}"),
    )
}

struct Gateway {
    child: Child,
    port: u16,
    platform_cert: Vec<u8>,
    dir: std::path::PathBuf,
}

impl Gateway {
    fn start(control_plane: SocketAddr, body_budget: Option<usize>) -> Self {
        let port = free_port();
        let dir = std::env::temp_dir().join(format!("clwd-gw-cp-{port}"));
        write_cert(&dir.join("certs/acme"), "acme-cert");
        let platform_cert = write_cert(&dir.join("platform"), "platform-cert");
        let mut command = Command::new(env!("CARGO_BIN_EXE_gateway"));
        command
            .env("CLWD_GATEWAY_LISTEN", format!("127.0.0.1:{port}"))
            .env("CLWD_APPS_DOMAIN", APPS)
            .env("CLWD_CONTROL_PLANE_DOMAIN", CONTROL_PLANE)
            // The internal listener: unreachable, so an app host gets a gateway
            // envelope and a test can tell the two hops apart.
            .env("CLWD_CONTROL_PLANE", "http://127.0.0.1:1")
            .env(
                "CLWD_CONTROL_PLANE_PUBLIC",
                format!("http://{control_plane}"),
            )
            .env("CLWD_INTERNAL_SECRET", "unused")
            .env("CLWD_CERT_DIR", dir.join("certs"))
            .env("CLWD_PLATFORM_CERT", dir.join("platform/cert.pem"))
            .env("CLWD_PLATFORM_KEY", dir.join("platform/key.pem"))
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(bytes) = body_budget {
            command.env("CLWD_GATEWAY_BODY_BUDGET", bytes.to_string());
        }
        let child = command.spawn().expect("spawn gateway");
        let deadline = Instant::now() + Duration::from_secs(20);
        while TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(Instant::now() < deadline, "the gateway never listened");
            std::thread::sleep(Duration::from_millis(25));
        }
        Self {
            child,
            port,
            platform_cert,
            dir,
        }
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A raw HTTP/1.1 request over TLS, with the SNI and the `Host` chosen
/// separately. Returns the served certificate and the raw response.
fn send(port: u16, sni: &str, request: &str) -> (Vec<u8>, String) {
    let mut builder = SslConnector::builder(SslMethod::tls()).expect("connector");
    builder.set_verify(SslVerifyMode::NONE);
    let connector = builder.build();
    let tcp = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    tcp.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let mut config = connector.configure().expect("configure");
    config.set_verify_hostname(false);
    let mut stream = config.connect(sni, tcp).expect("handshake");
    let served = stream
        .ssl()
        .peer_certificate()
        .expect("a certificate")
        .to_pem()
        .expect("pem");
    stream.write_all(request.as_bytes()).expect("write");
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    (served, String::from_utf8_lossy(&raw).into_owned())
}

fn status(response: &str) -> u16 {
    response
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn header<'a>(response: &'a str, name: &str) -> Vec<&'a str> {
    response
        .split("\r\n\r\n")
        .next()
        .unwrap_or_default()
        .lines()
        .filter_map(|line| line.split_once(':'))
        .filter(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim())
        .collect()
}

fn envelope(response: &str) -> serde_json::Value {
    serde_json::from_str(response.split("\r\n\r\n").nth(1).unwrap_or_default().trim())
        .unwrap_or(serde_json::Value::Null)
}

/// The control-plane domain reaches the public listener: its path and query,
/// its cookies unchanged, the gateway's request id in place of the client's,
/// no hop-by-hop header, and no forwarded header added. The answer comes back
/// with the control plane's own cookie, over the platform certificate.
#[test]
fn the_control_plane_domain_is_forwarded_as_sent() {
    let cp = ControlPlane::start();
    let gw = Gateway::start(cp.addr, None);
    let cookie = "__Host-clwd_session=abc; __Host-clwd_state=st; theme=dark";
    let (served, response) = send(
        gw.port,
        CONTROL_PLANE,
        &format!(
            "GET /openapi.json?probe=1 HTTP/1.1\r\nHost: {CONTROL_PLANE}\r\n\
             Cookie: {cookie}\r\nx-request-id: chosen-by-the-client\r\n\
             x-private: 1\r\nConnection: close, x-private\r\n\r\n"
        ),
    );
    assert_eq!(
        served, gw.platform_cert,
        "the platform certificate is served"
    );
    assert_eq!(status(&response), 200, "{response}");
    assert!(response.ends_with("control plane saw /openapi.json?probe=1"));
    assert_eq!(
        header(&response, "set-cookie"),
        ["__Host-clwd_session=fresh; Path=/; Secure; HttpOnly; SameSite=Lax"],
        "the control plane's cookie reaches the browser unchanged"
    );

    let seen = cp.seen();
    assert_eq!(seen.len(), 1, "{seen:?}");
    let got = &seen[0];
    assert_eq!(got.path_and_query, "/openapi.json?probe=1");
    assert_eq!(
        got.headers.get("cookie").and_then(|v| v.to_str().ok()),
        Some(cookie),
        "platform cookies reach the control plane unchanged on its own host"
    );
    let id = got
        .headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .expect("a request id");
    assert_ne!(
        id, "chosen-by-the-client",
        "the gateway's id, not the client's"
    );
    assert_eq!(
        header(&response, "x-request-id"),
        [id],
        "one id in both logs and in the answer"
    );
    assert!(!got.headers.contains_key("x-private"), "hop-by-hop dropped");
    assert!(
        !got.headers
            .keys()
            .any(|k| k.as_str().starts_with("x-forwarded") || k == "forwarded"),
        "no forwarded header: {:?}",
        got.headers
    );
}

/// A connection opened for one host cannot carry a request for the other, in
/// either direction: 421, and the control plane receives nothing.
#[test]
fn sni_and_host_must_name_the_same_host() {
    let cp = ControlPlane::start();
    let gw = Gateway::start(cp.addr, None);
    for (sni, host) in [(APP_HOST, CONTROL_PLANE), (CONTROL_PLANE, APP_HOST)] {
        let (_, response) = send(
            gw.port,
            sni,
            &format!("GET /openapi.json HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"),
        );
        assert_eq!(status(&response), 421, "SNI {sni}, Host {host}: {response}");
        assert_eq!(
            envelope(&response)["code"],
            "gateway.misdirected_request",
            "{response}"
        );
    }
    assert!(
        cp.seen().is_empty(),
        "nothing reached the control plane: {:?}",
        cp.seen()
    );
}

/// Many concurrent large uploads against a small budget: every answer is the
/// control plane's or a retryable `gateway.busy`, at least one is busy, a busy
/// upload never reaches the control plane, and the gateway still serves.
#[test]
fn concurrent_large_uploads_past_the_budget_are_busy_not_fatal() {
    const BODY: usize = 15 * 1024 * 1024;
    const UPLOADS: usize = 8;
    let cp = ControlPlane::start();
    let gw = Gateway::start(cp.addr, Some(32 * 1024 * 1024));
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .resolve(CONTROL_PLANE, SocketAddr::from(([127, 0, 0, 1], gw.port)))
        .no_proxy()
        .build()
        .expect("client");
    let url = format!("https://{CONTROL_PLANE}:{}/slow", gw.port);
    let answers: Vec<(u16, Option<String>, Option<String>)> = runtime.block_on(async {
        let uploads = (0..UPLOADS).map(|_| {
            let (client, url) = (client.clone(), url.clone());
            tokio::spawn(async move {
                let response = client
                    .post(url)
                    .body(vec![b'x'; BODY])
                    .send()
                    .await
                    .expect("an answer, not a dropped connection");
                let status = response.status().as_u16();
                let retry_after = response
                    .headers()
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned);
                let body: serde_json::Value = response.json().await.unwrap_or_default();
                (
                    status,
                    body["code"].as_str().map(str::to_owned),
                    retry_after,
                )
            })
        });
        let mut answers = Vec::new();
        for upload in uploads.collect::<Vec<_>>() {
            answers.push(upload.await.expect("no task panicked"));
        }
        answers
    });

    let busy = answers.iter().filter(|(s, _, _)| *s == 503).count();
    let forwarded = answers.iter().filter(|(s, _, _)| *s == 200).count();
    assert_eq!(busy + forwarded, UPLOADS, "only 200 or 503: {answers:?}");
    assert!(
        busy >= 1,
        "8 uploads of 15 MiB exceed a 32 MiB budget: {answers:?}"
    );
    for (status, code, retry_after) in &answers {
        if *status == 503 {
            assert_eq!(code.as_deref(), Some("gateway.busy"));
            assert_eq!(retry_after.as_deref(), Some("1"));
        }
    }
    let seen = cp.seen();
    assert_eq!(seen.len(), forwarded, "a busy upload never reached it");
    assert!(seen.iter().all(|s| s.body_len == BODY), "forwarded whole");

    // Still serving, with every byte returned to the budget.
    let after = runtime.block_on(async {
        client
            .post(url.replace("/slow", "/after"))
            .body(vec![b'x'; BODY])
            .send()
            .await
            .expect("an answer")
            .status()
            .as_u16()
    });
    assert_eq!(after, 200, "the gateway serves on, budget whole");
}
