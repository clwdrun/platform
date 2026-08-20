//! Wire types shared across platform crates, plus tracing/otel setup.

pub mod telemetry {
    pub fn init() {
        tracing_subscriber::fmt::init();
    }
}
