//! Validating bytes a caller just uploaded.
//!
//! This is the half of the builder where a `bundle.*` code delegates verbatim:
//! the bytes arrived in this request, so a decode failure is the caller's
//! bundle being wrong and they can fix it. Reading bytes back out of storage is
//! a different situation entirely and lives in [`crate::store`], which cannot
//! reach this module's error mapping.

use bytes::Bytes;
use clwd_bundle::{Bundle, BundleRef, Manifest};
use shared::Error;

use crate::key::ArtifactKey;

/// The largest bundle this platform accepts, in bytes.
///
/// **A memory bound, not a format bound.** `clwd-bundle` exposes no streaming
/// API — [`clwd_bundle::decode`] and [`BundleRef::of_stream`] both take a
/// slice — so a bundle must be held whole to be validated or digested at all.
/// Whatever ceiling is chosen is therefore a statement about how much memory
/// one upload may occupy, and the constraint is recorded upstream as
/// `clwdrun/clwd#74`.
///
/// The format's own ceiling is far higher: 8 GiB − 1 per member, from the tar
/// size field's octal encoding (spec §3.4.3). Inheriting that would let a
/// single upload exhaust a control-plane node, so it is deliberately not
/// inherited.
///
/// # Why 16 MiB
///
/// Sized against the app this product is *for*, not against the smallest thing
/// that compiles. The `clwd` templates measure 23.5 KB, 64.0 KB and 68.9 KB
/// stripped, but those are a bare handler, a notes app and a webhook — they
/// establish a floor, not a target. Reading the ceiling as a multiple of them
/// invites cutting it.
///
/// The realistic case is an app carrying its own frontend: an embedded HTML
/// page, a web font, and a handful of images alongside the component. That is
/// plausibly 2–5 MiB of assets, and it is an ordinary app rather than an
/// extreme one. 16 MiB leaves roughly threefold headroom above the top of that
/// range, while still bounding one upload at a size a node survives many of
/// concurrently.
///
/// The number that made this urgent is axum's: its `DefaultBodyLimit` is
/// **2 MiB**, which sits *below* a realistic asset-carrying app. Left at the
/// default, a legitimate upload would be refused by a limit stated nowhere in
/// this repository, and this constant would never apply. `control-plane`'s
/// router overrides it with this value for that reason.
///
/// Raise it when a real app needs more, not pre-emptively.
pub const MAX_BUNDLE_BYTES: usize = 16 * 1024 * 1024;

/// Axum's `DefaultBodyLimit`, which applies to any route that reads a body
/// unless a router overrides it.
const AXUM_DEFAULT_BODY_LIMIT: usize = 2 * 1024 * 1024;

/// The ceiling must exceed axum's default, or the override is pointless and a
/// realistic asset-carrying app is refused by a limit nothing states.
///
/// A compile-time assertion rather than a test: this is a property of two
/// constants, so there is nothing to run and no reason to wait for a test
/// binary to discover it. Lowering `MAX_BUNDLE_BYTES` past 2 MiB fails the
/// build, at the line that explains why.
const _: () = assert!(MAX_BUNDLE_BYTES > AXUM_DEFAULT_BODY_LIMIT);

/// A bundle that has passed every check in spec §8.
///
/// The type exists so [`crate::store::ArtifactStore::put`] cannot be handed
/// bytes that were never validated, and so the digest cannot be recomputed —
/// and possibly differ — between validating and storing. It owns the canonical
/// stream because storing is what happens next and copying it again would be a
/// second pass over megabytes for nothing.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Validated {
    bundle: Bundle,
    bytes: Bytes,
}

impl Validated {
    /// The bundle digest, computed by `clwd-bundle` over the canonical stream.
    #[must_use]
    pub fn digest(&self) -> &BundleRef {
        &self.bundle.digest
    }

    /// The validated manifest.
    #[must_use]
    pub fn manifest(&self) -> &Manifest {
        &self.bundle.manifest
    }

    /// Where this artifact belongs in storage.
    #[must_use]
    pub fn key(&self) -> ArtifactKey {
        ArtifactKey::bundle(self.digest())
    }

    /// The canonical, uncompressed stream. This is what the digest addresses.
    #[must_use]
    pub fn canonical_bytes(&self) -> &Bytes {
        &self.bytes
    }
}

/// Validate an uploaded bundle.
///
/// Runs every check in spec §8, in the spec's order, by calling
/// [`clwd_bundle::decode`] once and adding nothing. The order is normative
/// precisely so that a bundle which is both malformed *and* tampered with
/// reports the same code on every implementation — imposing our own order here
/// would break the comparability the spec exists to provide.
///
/// `expected` is deliberately [`None`]. A caller-supplied digest checked
/// against bytes from the same request proves the caller can hash, not that the
/// bundle is the one anyone wanted. The digest comes *out* of this call.
///
/// # Errors
///
/// [`Error::InvalidRequest`] when the upload exceeds [`MAX_BUNDLE_BYTES`], and
/// the underlying `bundle.*` code **verbatim** for anything the format rejects.
pub fn validate(bytes: Bytes) -> Result<Validated, Error> {
    if bytes.len() > MAX_BUNDLE_BYTES {
        return Err(Error::InvalidRequest {
            what: format!(
                "bundle is {} bytes; the limit is {MAX_BUNDLE_BYTES}",
                bytes.len()
            ),
        });
    }

    // `?` on `clwd_bundle::Error` goes through `From` to the delegating
    // variant, which returns the source's code unchanged. That is the whole
    // point of this call site.
    let bundle = clwd_bundle::decode(&bytes, None)?;

    Ok(Validated { bundle, bytes })
}
