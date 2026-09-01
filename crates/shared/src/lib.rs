//! Wire types shared across platform crates, plus tracing/otel setup.

pub mod error;

pub use error::{Envelope, Error, RequestId};

pub mod telemetry {
    pub fn init() {
        tracing_subscriber::fmt::init();
    }
}
