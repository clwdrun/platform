//! Wildcard subdomain routing (org-scoped: myapp.acme.clwd.run), TLS via
//! DNS-01 wildcard certs, identity header injection, cold-start hold.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    shared::telemetry::init();
    tracing::info!("gateway starting");
    Ok(())
}
