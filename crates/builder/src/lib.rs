//! Bundle to content-addressed artifact.
//!
//! The builder **validates** bundles; it never authors them. `clwd build`
//! creates a bundle and this crate decides whether to accept it, what its
//! address is, and where the bytes go.
//!
//! # Two calls, not one
//!
//! [`ingest::validate`] and [`store::ArtifactStore::put`] are separate because
//! `platform#7` needs to run a database write *between* them:
//!
//! ```text
//! builder         validate(bytes)                  -> digest, no I/O
//! control-plane   INSERT (app_id, digest) 'pending'   claims the digest
//! builder         put(&validated)                     stores the artifact
//! control-plane   mark ready
//! ```
//!
//! The digest is only known after decoding, so the row cannot be claimed until
//! validation has run — and the artifact should not be written until the claim
//! is won. A single `ingest_and_store` would make that ordering impossible to
//! express.
//!
//! [`ingest::Validated`] is what connects them: [`store::ArtifactStore::put`]
//! takes one, so it cannot be handed bytes that were never validated, and the
//! digest cannot be recomputed — and possibly differ — between the two calls.
//!
//! This crate takes no database handle and knows nothing about apps, orgs or
//! versions. Idempotent publish is `platform#7`'s; artifact lifecycle and
//! garbage collection are `platform#23`'s; placement is `platform#24`'s.
//!
//! # Two error paths that must not be confused
//!
//! | bytes from | function | code | status |
//! | ---------- | -------- | ---- | ------ |
//! | this request | [`ingest::validate`] | `bundle.*` **verbatim** | 400 |
//! | storage | [`store::ArtifactStore::get`] | `control-plane.artifact_corrupt` | 500 |
//!
//! Both decode with the same library. They are deliberately different calls in
//! different modules rather than one shared helper, so the storage path cannot
//! inherit the ingest mapping by accident — which would return 400 and blame a
//! caller for a corrupt write of ours.

pub mod ingest;
pub mod key;
pub mod store;

pub use ingest::{MAX_BUNDLE_BYTES, Validated, validate};
pub use key::ArtifactKey;
pub use store::ArtifactStore;
