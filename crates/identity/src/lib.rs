//! SSO in, per-app authz out. Share grants ("viewer/editor/owner on app X")
//! modeled as Cedar entities.
//!
//! # What this crate owns
//!
//! The OIDC authorization-code-with-PKCE flow against Google, and the
//! verification that turns Google's ID token into a [`VerifiedIdentity`]. The
//! *pure* half of sign-in lives here — no database, no HTTP router, no cookies
//! — so every security property (a wrong signature is rejected, a replayed
//! nonce is rejected) is a unit test away from the code that enforces it.
//!
//! Session storage, the session cookie, and the two sign-in routes live in
//! `control-plane`, which owns the router, the pool, and the schema. It depends
//! on this crate for the flow and the verification.

pub mod flow;
pub mod oidc;

pub use flow::{Authorization, Flow, FlowError, OidcConfig};
pub use oidc::{GoogleClaims, GoogleIdToken, GoogleSubject, VerifiedIdentity, VerifyError};
