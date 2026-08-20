//! Apps, orgs, versions, share grants.
//! `runtime: Wasm | MicroVM` is stored as a single field here and never
//! branched on above clwd-runtime.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    shared::telemetry::init();
    tracing::info!("control-plane starting");
    Ok(())
}
