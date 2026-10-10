//! Wire types shared across platform crates, plus tracing/otel setup.

pub mod cert;
pub mod cookie;
pub mod domains;
pub mod error;
pub mod limits;

pub use error::{Envelope, Error, RequestId};
pub use limits::MAX_BUNDLE_BYTES;

pub mod telemetry {
    pub fn init() {
        tracing_subscriber::fmt::init();
    }
}
