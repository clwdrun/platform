//! The gateway binary: a pingora service that terminates TLS and routes by
//! host to the edge application ([`gateway::edge::Edge`]).
//!
//! Sync `main`, not `#[tokio::main]`: pingora's [`Server`] owns and manages its
//! own runtimes, so it must run on a plain thread. Configuration comes from the
//! environment. This is binary-edge glue, so `anyhow`; the library crates use
//! `thiserror`.

use std::env;
use std::sync::Arc;

use anyhow::Context as _;
use gateway::edge::Edge;
use gateway::lookup::RouteLookup;
use pingora::apps::http_app::HttpServer;
use pingora::server::Server;
use pingora::services::listening::Service;

fn main() -> anyhow::Result<()> {
    shared::telemetry::init();

    let listen = env::var("CLWD_GATEWAY_LISTEN").unwrap_or_else(|_| "0.0.0.0:8443".to_owned());
    let apex = env::var("CLWD_APEX").unwrap_or_else(|_| "clwd.run".to_owned());
    let control_plane = env::var("CLWD_CONTROL_PLANE")
        .context("CLWD_CONTROL_PLANE must be the internal control-plane base URL")?;
    let internal_secret =
        env::var("CLWD_INTERNAL_SECRET").context("CLWD_INTERNAL_SECRET must be set")?;
    let cert = env::var("CLWD_TLS_CERT").context("CLWD_TLS_CERT must name the certificate PEM")?;
    let key = env::var("CLWD_TLS_KEY").context("CLWD_TLS_KEY must name the private-key PEM")?;

    tracing::info!(%listen, %apex, "gateway serving");
    let lookup = Arc::new(RouteLookup::new(control_plane, internal_secret)?);
    let edge = Edge::new(lookup, apex);

    let mut server = Server::new(None).map_err(|e| anyhow::anyhow!("pingora server: {e}"))?;
    server.bootstrap();

    let mut service = Service::new("gateway-edge".to_owned(), HttpServer::new_app(edge));
    service
        .add_tls(&listen, &cert, &key)
        .map_err(|e| anyhow::anyhow!("TLS listener on {listen}: {e}"))?;
    server.add_service(service);

    server.run_forever();
}
