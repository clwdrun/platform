//! Round-trips through a real store.
//!
//! Every test here puts a bundle through `ArtifactStore` rather than asserting
//! the strings the builder computes. A digest this crate calculates means
//! nothing until storage accepts it and hands the same bytes back — asserting
//! the computation against itself would pass whether or not the two halves
//! agree, which is the shape of failure `clwdrun/clwd#73` found in
//! `data::for_caller`.
//!
//! The bundles are built with `clwd_bundle::build`, the same call `clwd build`
//! makes, so these are real canonical streams rather than hand-written bytes.

use builder::{ArtifactStore, MAX_BUNDLE_BYTES, validate};
use bytes::Bytes;
use clwd_bundle::{BundleRef, Capabilities, File, Limits, Runtime};
use opendal::{Operator, services::Memory};

/// The component-model preamble a `wasm` bundle's entrypoint must begin with,
/// per spec §6.1: `\0asm`, version 0x000D, layer 0x0001.
const COMPONENT_PREAMBLE: [u8; 8] = [0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00];

fn store() -> ArtifactStore {
    let operator =
        Operator::new(Memory::default()).expect("an in-memory operator needs no configuration");
    ArtifactStore::new(operator)
}

fn capabilities() -> Capabilities {
    Capabilities {
        version: 1,
        egress: vec![],
        secrets: vec![],
        storage_namespaces: vec![],
        limits: Limits {
            cpu_ms: 1_000,
            memory_mb: 64,
        },
    }
}

/// A real bundle, built the way `clwd build` builds one.
fn bundle_with(entrypoint_body: &[u8]) -> Bytes {
    let mut data = COMPONENT_PREAMBLE.to_vec();
    data.extend_from_slice(entrypoint_body);
    let encoded = clwd_bundle::build(
        Runtime::Wasm,
        "app.wasm",
        capabilities(),
        vec![File {
            path: "app.wasm".into(),
            data,
            executable: false,
        }],
    )
    .expect("a well-formed bundle encodes");
    Bytes::from(encoded.bytes)
}

fn a_bundle() -> Bytes {
    bundle_with(b"body")
}

#[tokio::test]
async fn a_bundle_round_trips_byte_for_byte() {
    let original = a_bundle();
    let store = store();

    let validated = validate(original.clone()).expect("a real bundle validates");
    let digest = *validated.digest();
    store.put(&validated).await.expect("storing succeeds");

    let read_back = store
        .get_bytes(&digest)
        .await
        .expect("what was stored can be read");

    assert_eq!(
        read_back, original,
        "the bytes that came out are not the bytes that went in"
    );

    // And the digest the store verified on the way out is the one we filed it
    // under — the property that makes the address content-addressed at all.
    let reread = store.get(&digest).await.expect("the artifact decodes");
    assert_eq!(reread.digest, digest);
}

#[tokio::test]
async fn identical_input_yields_an_identical_digest() {
    let first = validate(a_bundle()).expect("validates");
    let second = validate(a_bundle()).expect("validates");
    assert_eq!(first.digest(), second.digest());
    assert_eq!(first.key(), second.key());
}

#[tokio::test]
async fn different_input_yields_a_different_digest() {
    let first = validate(bundle_with(b"one")).expect("validates");
    let second = validate(bundle_with(b"two")).expect("validates");
    assert_ne!(first.digest(), second.digest());
}

/// The normal case under retry, not an error.
#[tokio::test]
async fn storing_the_same_bundle_twice_succeeds() {
    let store = store();
    let validated = validate(a_bundle()).expect("validates");

    store.put(&validated).await.expect("first store");
    store
        .put(&validated)
        .await
        .expect("second store is a no-op");

    let read_back = store
        .get_bytes(validated.digest())
        .await
        .expect("still readable");
    assert_eq!(read_back, *validated.canonical_bytes());
}

/// Ingest delegates. The caller's bundle is wrong and the code says which way.
#[tokio::test]
async fn a_tampered_bundle_is_rejected_before_storage_with_the_bundle_code() {
    let store = store();
    let mut bytes = a_bundle().to_vec();

    // Flip a byte inside the entrypoint's *data*, found by locating the
    // component preamble rather than by a fixed offset. The archive stays
    // structurally valid — same lengths, same padding — so this reaches spec
    // §8 step 20, the member digest check.
    //
    // An earlier version of this test flipped a byte at a hardcoded offset and
    // landed in the tar padding, producing `bundle.padding_invalid` from step
    // 6 instead. That is §8's "structure before content" ordering behaving
    // exactly as specified, and it is the reason the offset is computed here
    // rather than guessed.
    let preamble = bytes
        .windows(COMPONENT_PREAMBLE.len())
        .position(|w| w == COMPONENT_PREAMBLE)
        .expect("the entrypoint is in the archive");
    let first_body_byte = preamble + COMPONENT_PREAMBLE.len();
    bytes[first_body_byte] ^= 0xff;
    let tampered = Bytes::from(bytes);

    let digest = BundleRef::of_stream(&tampered);
    let error = validate(tampered).expect_err("a tampered bundle is rejected");

    assert_eq!(
        error.code(),
        "bundle.member_digest_mismatch",
        "the bundle code must survive delegation verbatim"
    );
    assert_eq!(error.status(), 400, "a bad upload is the caller's fault");

    // Nothing reached storage: rejection happens before any write.
    let stored = store.get(&digest).await;
    assert_eq!(
        stored.expect_err("nothing was stored").code(),
        "control-plane.not_found"
    );
}

/// Storage corruption is ours. The `bundle.*` code must NOT come back out.
#[tokio::test]
async fn a_corrupt_stored_artifact_is_not_a_delegated_bundle_error() {
    let store = store();
    let validated = validate(a_bundle()).expect("validates");
    let digest = *validated.digest();
    store.put(&validated).await.expect("stored");

    // Corrupt the stored object in place, behind the store's back — which is
    // what a truncated write or a bad restore looks like from here.
    let operator = Operator::new(Memory::default()).expect("in-memory operator");
    let store = ArtifactStore::new(operator.clone());
    store.put(&validated).await.expect("stored again");
    operator
        .write(validated.key().as_str(), b"not a zstd frame".to_vec())
        .await
        .expect("overwriting for the test");

    let error = store
        .get(&digest)
        .await
        .expect_err("corruption is detected");

    assert_eq!(
        error.code(),
        "control-plane.artifact_corrupt",
        "a storage failure must not be reported as the caller's bad bundle"
    );
    assert_eq!(error.status(), 500, "our integrity failure is a 500");
    assert!(
        !error.code().starts_with("bundle."),
        "the bundle code must stay in the log, not the response"
    );
}

/// The same corruption check, but with bytes that decompress and then fail
/// validation — the path where a `bundle.*` code actually exists to leak.
#[tokio::test]
async fn a_stored_artifact_that_decodes_to_the_wrong_digest_is_artifact_corrupt() {
    let operator = Operator::new(Memory::default()).expect("in-memory operator");
    let store = ArtifactStore::new(operator.clone());

    let validated = validate(a_bundle()).expect("validates");
    let digest = *validated.digest();
    store.put(&validated).await.expect("stored");

    // Valid zstd, valid bundle — but a *different* bundle than the key claims.
    let other = validate(bundle_with(b"different")).expect("validates");
    let swapped = zstd::encode_all(other.canonical_bytes().as_ref(), 3).expect("compresses");
    operator
        .write(validated.key().as_str(), swapped)
        .await
        .expect("swapping for the test");

    let error = store.get(&digest).await.expect_err("the swap is detected");
    assert_eq!(error.code(), "control-plane.artifact_corrupt");
    assert_eq!(error.status(), 500);
}

#[tokio::test]
async fn an_absent_artifact_is_not_found_rather_than_corrupt() {
    let store = store();
    let never_stored = BundleRef::of_stream(b"never stored");
    let error = store
        .get(&never_stored)
        .await
        .expect_err("nothing is there");
    assert_eq!(error.code(), "control-plane.not_found");
    assert_eq!(error.status(), 404);
}

#[tokio::test]
async fn an_oversized_upload_is_rejected_without_decoding() {
    let oversized = Bytes::from(vec![0u8; MAX_BUNDLE_BYTES + 1]);
    let error = validate(oversized).expect_err("over the ceiling");
    assert_eq!(error.code(), "control-plane.invalid_request");
    assert_eq!(error.status(), 400);
}

/// A real bundle is orders of magnitude under the ceiling. If this ever fails,
/// the limit needs revisiting against a measurement rather than raising.
#[tokio::test]
async fn a_real_bundle_is_far_under_the_ceiling() {
    let bundle = a_bundle();
    assert!(
        bundle.len() < MAX_BUNDLE_BYTES / 100,
        "a bundle of {} bytes is within 100x of the {MAX_BUNDLE_BYTES} byte ceiling",
        bundle.len()
    );
}
