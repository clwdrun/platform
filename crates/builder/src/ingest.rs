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
/// Re-exported from [`shared::limits`], which owns it because both this crate
/// and the HTTP layer need the number and neither owns the other. See that
/// module for why 16 MiB and why it does not live here.
pub use shared::limits::MAX_BUNDLE_BYTES;

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
