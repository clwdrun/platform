//! clwd gateway: wildcard-subdomain routing, TLS termination and (later)
//! identity injection for `{app}.{org}.<apps domain>`.
//!
//! The binary (`src/main.rs`) is a thin entry point; the routing and TLS logic
//! lives here in the library so it can be unit-tested without standing up a
//! listener.

pub mod authz;
pub mod cert;
pub mod edge;
pub mod host;
pub mod logship;
pub mod lookup;
pub mod signin;
pub mod tls;
pub mod upstream;
pub mod worker;
