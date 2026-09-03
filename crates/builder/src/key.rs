//! Where an artifact lives, derived from what it is.

use clwd_bundle::BundleRef;

/// The storage path of an artifact.
///
/// A newtype rather than a `String` because a digest, an app id and a storage
/// key are all 32-byte-ish identifiers that must never be interchangeable in a
/// signature. This is the only place the layout is spelled out; #23 and
/// [`platform#44`] both depend on it, so it having one definition matters more
/// than the definition being short.
///
/// # Layout
///
/// ```text
/// artifacts/blake3/<aa>/<bb>/<hex>/bundle.clwd.zst
/// ```
///
/// - `blake3/` names the algorithm. A future digest change is a new prefix
///   rather than two incompatible things sharing a namespace.
/// - `<aa>/<bb>` are the first two byte-pairs of the hex digest. Fan-out is
///   free on object storage and load-bearing on a filesystem backend, where a
///   flat directory of every artifact eventually stops being listable. It
///   costs nothing now and cannot be added later without moving every object.
/// - **A directory per digest, not a file per digest.** The trailing
///   `bundle.clwd.zst` looks redundant until something else needs to live
///   beside it. [`platform#44`] will put a precompiled artifact at
///   `…/<hex>/precompiled/<wasmtime-version>-<config-fp>.cwasm`; with a file
///   per digest there is nowhere to put it and retrofitting means rewriting
///   every key in the store.
/// - `.zst` is a storage detail. The digest addresses the *uncompressed*
///   canonical stream — see [`crate::store`].
///
/// [`platform#44`]: https://github.com/clwdrun/platform/issues/44
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ArtifactKey(String);

const HEX: &[u8; 16] = b"0123456789abcdef";

impl ArtifactKey {
    /// The key holding the canonical bundle stream for `digest`.
    #[must_use]
    pub fn bundle(digest: &BundleRef) -> Self {
        let hex = hex_encode(digest.as_bytes());
        // Indexing is sound by construction: `hex_encode` produces exactly 64
        // characters from a fixed 32-byte array, so both slices exist. Written
        // as slices rather than `char` arithmetic so the shape of the layout is
        // visible in the code.
        let (aa, bb) = (&hex[0..2], &hex[2..4]);
        Self(format!("artifacts/blake3/{aa}/{bb}/{hex}/bundle.clwd.zst"))
    }

    /// The key as `opendal` wants it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ArtifactKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Lowercase hex, matching the spec's §4.1 digest spelling.
///
/// Hand-rolled rather than pulled from a crate: it is six lines, and
/// `write!` into a `String` returns a `Result` that cannot fail, which would
/// mean either an `unwrap` or a discarded error in the one place the layout is
/// decided.
fn hex_encode(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_key_fans_out_on_the_first_two_byte_pairs() {
        let digest = BundleRef::of_stream(b"");
        let key = ArtifactKey::bundle(&digest);
        // BLAKE3 of the empty input, per spec §4.2.
        let hex = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
        assert_eq!(
            key.as_str(),
            format!("artifacts/blake3/af/13/{hex}/bundle.clwd.zst")
        );
    }

    #[test]
    fn hex_is_lowercase_and_64_characters() {
        let hex = hex_encode(BundleRef::of_stream(b"anything").as_bytes());
        assert_eq!(hex.len(), 64);
        assert_eq!(hex, hex.to_lowercase());
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// The layout's whole purpose: something else can live beside the bundle.
    #[test]
    fn a_second_artifact_can_share_the_digest_directory() {
        let key = ArtifactKey::bundle(&BundleRef::of_stream(b"x"));
        let dir = key
            .as_str()
            .strip_suffix("/bundle.clwd.zst")
            .expect("the key ends with the bundle filename");
        assert!(dir.starts_with("artifacts/blake3/"));
    }
}
