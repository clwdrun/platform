//! clwd gateway: wildcard-subdomain routing, TLS termination and (later)
//! identity injection for `{app}.{org}.clwd.run`.
//!
//! The binary (`src/main.rs`) is a thin entry point; the routing and TLS logic
//! lives here in the library so it can be unit-tested without standing up a
//! listener.

pub mod edge;
pub mod host;
pub mod lookup;
