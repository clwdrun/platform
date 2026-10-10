//! The worker binary. Configuration comes from the environment, and the
//! environment must hold no gateway or control-plane secret: the worker refuses
//! to start if it does. Binary-edge glue, so `anyhow`.
//!
//! - `CLWD_WORKER_SOCKET`: the Unix socket to listen on. Keep it short; a
//!   socket path is limited to 108 bytes. The directory should belong to the
//!   worker's user, group the gateway's, mode 0750.
//! - `CLWD_ARTIFACT_ROOT`: the directory publish stores artifacts in, read-only.
//! - `CLWD_GATEWAY_UID`: the only peer user a hop is accepted from.

use std::env;
use std::os::unix::fs::PermissionsExt as _;
use std::sync::Arc;

use anyhow::Context as _;

fn main() -> anyhow::Result<()> {
    worker::refuse_secrets(env::vars())?;
    shared::telemetry::init();

    let socket =
        env::var("CLWD_WORKER_SOCKET").context("CLWD_WORKER_SOCKET must name the socket")?;
    let root = env::var("CLWD_ARTIFACT_ROOT")
        .context("CLWD_ARTIFACT_ROOT must name the artifact directory")?;
    let gateway_uid: u32 = env::var("CLWD_GATEWAY_UID")
        .context("CLWD_GATEWAY_UID must name the gateway's user id")?
        .parse()
        .context("CLWD_GATEWAY_UID must be a number")?;

    let operator = opendal::Operator::new(opendal::services::Fs::default().root(&root))
        .context("artifact store")?;
    let worker = Arc::new(worker::Worker::new(
        builder::ArtifactStore::new(operator),
        gateway_uid,
    )?);

    tokio::runtime::Runtime::new()?.block_on(async move {
        // A socket left by a previous run would make bind fail.
        let _ = std::fs::remove_file(&socket);
        let listener =
            tokio::net::UnixListener::bind(&socket).with_context(|| format!("binding {socket}"))?;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o660))?;
        tracing::info!(%socket, %root, gateway_uid, "worker serving");
        worker.serve(listener).await;
        Ok(())
    })
}
