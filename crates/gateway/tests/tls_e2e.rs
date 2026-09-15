//! End-to-end: the real gateway binary terminates TLS with a per-org
//! certificate chosen by SNI, and returns the platform envelope.
//!
//! The load-bearing case is **two orgs, each asserting it got its OWN
//! certificate** — a single-org test would pass against a resolver that ignores
//! SNI and serves the only cert it has. And the miss case asserts the handshake
//! **fails** for an org with no certificate (the counter side of the miss is
//! asserted in `cert.rs`'s in-process unit tests, which can read the resolver's
//! metrics; a subprocess cannot).
//!
//! "Control plane unreachable" and closed-port readiness follow the same hard
//! rules as the lookup tests: SIGKILL cleanup (pingora ignores SIGTERM's grace),
//! bind-and-release for a free port, poll for readiness, hermetic cert-gen via
//! the same BoringSSL the server links.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use boring::asn1::Asn1Time;
use boring::hash::MessageDigest;
use boring::pkey::PKey;
use boring::rsa::Rsa;
use boring::ssl::{SslConnector, SslMethod, SslVerifyMode};
use boring::x509::{X509, X509NameBuilder};

const APEX: &str = "clwd.run";

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener); // release so the gateway can bind it
    port
}

/// A self-signed cert with a distinct CN, so the client can tell one org's cert
/// from another's. Returns the certificate PEM (to compare against what the
/// server actually serves).
fn write_org_cert(dir: &Path, org: &str) -> Vec<u8> {
    let rsa = Rsa::generate(2048).expect("rsa");
    let pkey = PKey::from_rsa(rsa).expect("pkey");
    let mut name = X509NameBuilder::new().expect("name");
    name.append_entry_by_text("CN", &format!("{org}-cert"))
        .expect("cn");
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
    let cert = b.build();
    let cert_pem = cert.to_pem().expect("cert pem");

    let org_dir = dir.join(org);
    std::fs::create_dir_all(&org_dir).expect("org dir");
    std::fs::write(org_dir.join("cert.pem"), &cert_pem).expect("write cert");
    std::fs::write(
        org_dir.join("key.pem"),
        pkey.private_key_to_pem_pkcs8().expect("key pem"),
    )
    .expect("write key");
    cert_pem
}

struct Gateway(Child);
impl Drop for Gateway {
    fn drop(&mut self) {
        // SIGKILL, not SIGTERM: pingora ignores the grace window, so a polite
        // wait hangs for the full shutdown timeout and reads as a CI flake.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn await_ready(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("gateway never accepted connections on {port}");
}

/// Handshake to the gateway presenting `sni`. `Ok((served_cert_pem, response))`
/// on success; `Err(reason)` when the TLS handshake fails — the reason is what a
/// real client observes.
fn tls_request(port: u16, sni: &str) -> Result<(Vec<u8>, String), String> {
    let mut builder = SslConnector::builder(SslMethod::tls()).expect("connector");
    builder.set_verify(SslVerifyMode::NONE); // self-signed; termination is the point
    let connector = builder.build();
    let tcp = TcpStream::connect(("127.0.0.1", port)).map_err(|e| format!("connect: {e}"))?;
    tcp.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let mut config = connector.configure().expect("configure");
    config.set_verify_hostname(false);
    let mut stream = config
        .connect(sni, tcp)
        .map_err(|e| format!("handshake: {e}"))?;

    let served = stream
        .ssl()
        .peer_certificate()
        .ok_or("no peer certificate")?
        .to_pem()
        .map_err(|e| format!("peer cert pem: {e}"))?;

    stream
        .write_all(format!("GET / HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n").as_bytes())
        .map_err(|e| format!("write: {e}"))?;
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    Ok((served, String::from_utf8_lossy(&raw).into_owned()))
}

#[test]
fn sni_selects_each_orgs_own_certificate_and_a_missing_cert_fails_the_handshake() {
    let port = free_port();
    let dir = std::env::temp_dir().join(format!("clwd-gw-tls-{port}"));
    std::fs::create_dir_all(&dir).expect("dir");
    let acme_cert = write_org_cert(&dir, "acme");
    let other_cert = write_org_cert(&dir, "other");
    // "ghost" deliberately gets no cert directory.
    assert_ne!(
        acme_cert, other_cert,
        "the two orgs must have distinct certs"
    );

    let child = Command::new(env!("CARGO_BIN_EXE_gateway"))
        .env("CLWD_GATEWAY_LISTEN", format!("127.0.0.1:{port}"))
        .env("CLWD_APEX", APEX)
        .env("CLWD_CONTROL_PLANE", "http://127.0.0.1:1") // unreachable; HTTP body is a gateway envelope regardless
        .env("CLWD_INTERNAL_SECRET", "unused")
        .env("CLWD_CERT_DIR", &dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn gateway");
    let _gateway = Gateway(child);
    await_ready(port);

    // Each org's SNI is served that org's OWN certificate — the assertion a
    // resolver that ignored SNI could not pass.
    let (served, response) =
        tls_request(port, "app.acme.clwd.run").expect("acme handshake succeeds");
    assert_eq!(
        served, acme_cert,
        "acme host must be served acme's certificate"
    );
    assert!(
        response
            .lines()
            .next()
            .unwrap_or_default()
            .contains("HTTP/1.1"),
        "a well-formed HTTP response over TLS: {:?}",
        response.lines().next()
    );
    let body = response.split("\r\n\r\n").nth(1).unwrap_or_default();
    let envelope: serde_json::Value =
        serde_json::from_str(body.trim()).expect("an envelope body over TLS");
    assert!(
        envelope["code"]
            .as_str()
            .is_some_and(|c| c.starts_with("gateway.")),
        "a gateway-namespaced envelope: {body}"
    );

    let (served_other, _) =
        tls_request(port, "app.other.clwd.run").expect("other handshake succeeds");
    assert_eq!(
        served_other, other_cert,
        "other host must be served other's certificate, not acme's"
    );
    assert_ne!(
        served, served_other,
        "the two orgs were served different certs"
    );

    // An org with no certificate: the handshake FAILS. (The counter side of this
    // miss — no_cert incremented — is asserted in cert.rs's unit tests, which can
    // read the resolver's metrics; a subprocess cannot.)
    let miss = tls_request(port, "app.ghost.clwd.run");
    assert!(
        miss.is_err(),
        "an org with no certificate must fail the handshake, got {miss:?}"
    );
    // What a real client observes for a not-yet-issued org (recorded, since
    // pingora's callback cannot send a specific TLS alert):
    println!("no-cert client observation: {}", miss.unwrap_err());

    let _ = std::fs::remove_dir_all(&dir);
}
