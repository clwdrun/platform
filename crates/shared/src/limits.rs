//! Bounds the API enforces on what a caller may send.
//!
//! # Why this lives in `shared` rather than beside the code that uses it
//!
//! A request size limit is a wire contract: the HTTP layer enforces it and the
//! ingest path re-checks it, so both need the number and neither should own it.
//!
//! It was briefly `builder::MAX_BUNDLE_BYTES`, and `control-plane` took a
//! dependency on `builder` to read it. That is a 39-crate dependency — the
//! whole `opendal` stack, `zstd`, a TLS implementation — pulled into the
//! control plane to import one `usize`. `shared` is the crate that exists for
//! exactly this: contract values both sides need, with a dependency footprint
//! small enough that depending on it costs nothing.
//!
//! The rule the mistake broke: **a constant is not a reason to take a
//! dependency.** If two crates need a value and neither owns the other, the
//! value belongs in the crate they already share.

/// The largest request body the API accepts, in bytes.
///
/// **A memory bound, not a format bound.** `clwd-bundle` exposes no streaming
/// API — `decode` and `BundleRef::of_stream` both take a slice — so a bundle
/// must be held whole to be validated or digested at all. Whatever ceiling is
/// chosen is therefore a statement about how much memory one upload may
/// occupy; the constraint is recorded upstream as `clwdrun/clwd#74`.
///
/// The bundle format's own ceiling is far higher: 8 GiB - 1 per member, from
/// the tar size field's octal encoding (spec §3.4.3). Inheriting that would let
/// a single upload exhaust a control-plane node, so it is not inherited.
///
/// # Why 16 MiB
///
/// Sized against the app this product is for, not the smallest thing that
/// compiles. The `clwd` templates measure 23.5 KB, 64.0 KB and 68.9 KB
/// stripped — a bare handler, a notes app, a webhook. They establish a floor,
/// not a target, and reading the ceiling as a multiple of them invites cutting
/// it.
///
/// The realistic case is an app carrying its own frontend: an embedded HTML
/// page, a web font, a handful of images beside the component. Plausibly 2-5
/// MiB of assets, and an ordinary app rather than an extreme one. 16 MiB leaves
/// roughly threefold headroom over that while bounding one upload at a size a
/// node survives many of concurrently.
///
/// The number that made stating it urgent is axum's: its `DefaultBodyLimit` is
/// 2 MiB, which sits *below* a realistic asset-carrying app. Left at the
/// default, a legitimate upload would be refused by a limit stated nowhere.
///
/// Raise it when a real app needs more, not pre-emptively.
pub const MAX_BUNDLE_BYTES: usize = 16 * 1024 * 1024;

/// Axum's `DefaultBodyLimit`, which applies to any route reading a body unless
/// a router overrides it.
const AXUM_DEFAULT_BODY_LIMIT: usize = 2 * 1024 * 1024;

/// The ceiling must exceed axum's default, or the override is pointless and a
/// realistic asset-carrying app is refused by a limit nothing states.
///
/// A compile-time assertion rather than a test: this is a property of two
/// constants, so there is nothing to run. Lowering [`MAX_BUNDLE_BYTES`] past
/// 2 MiB fails the build, at the line that explains why.
const _: () = assert!(MAX_BUNDLE_BYTES > AXUM_DEFAULT_BODY_LIMIT);
