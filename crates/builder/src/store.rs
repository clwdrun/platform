//! Putting artifacts somewhere and getting them back.

use bytes::Bytes;
use clwd_bundle::{Bundle, BundleRef};
use opendal::Operator;
use shared::Error;

use crate::ingest::Validated;
use crate::key::ArtifactKey;

/// zstd level 3, the library default.
///
/// Compression is a storage and transport detail that sits **outside** the
/// digest (spec §2.1), which is what makes this level a free parameter: it can
/// change, or be removed entirely, without moving a single artifact. Were it
/// inside the digest, a level change would silently rewrite every address in
/// the system — every idempotency key would miss and every stored artifact
/// would be orphaned behind a name nothing computes any more.
const ZSTD_LEVEL: i32 = 3;

/// Content-addressed artifact storage.
///
/// Backend-agnostic by construction: it holds an [`Operator`], so the same code
/// runs against memory in a test and object storage in production. A test that
/// asserted the bytes it was about to write would prove only that the test can
/// build a string.
#[derive(Debug, Clone)]
pub struct ArtifactStore {
    operator: Operator,
}

impl ArtifactStore {
    /// Wrap a configured [`Operator`].
    #[must_use]
    pub fn new(operator: Operator) -> Self {
        Self { operator }
    }

    /// Store a validated bundle, compressed, at its content address.
    ///
    /// Storing something already present is a **success, not a conflict**. With
    /// a content address, identical bytes at an existing key is what a retried
    /// publish looks like, and it is the normal case rather than an error —
    /// `platform#7` builds idempotent publish on exactly that.
    ///
    /// # Concurrency
    ///
    /// The existence check and the write are not atomic, so two concurrent
    /// publishes of the same digest can both write. That is harmless **here and
    /// only here**: the key is derived from a digest of the bytes, so both
    /// writers are writing the same bytes. Do not copy this pattern to a
    /// mutable key, where the same race is a lost update.
    ///
    /// # Errors
    ///
    /// [`Error::Internal`] if the backend rejects the read or write.
    pub async fn put(&self, validated: &Validated) -> Result<(), Error> {
        let key = validated.key();

        if self.exists(&key).await? {
            tracing::debug!(key = %key, "artifact already stored");
            return Ok(());
        }

        let compressed = zstd::encode_all(validated.canonical_bytes().as_ref(), ZSTD_LEVEL)
            .map_err(|source| Error::Internal {
                source: source.into(),
            })?;

        self.operator
            .write(key.as_str(), compressed)
            .await
            .map_err(|source| Error::Internal {
                source: source.into(),
            })?;

        tracing::info!(key = %key, digest = %validated.digest(), "artifact stored");
        Ok(())
    }

    /// Read an artifact back and re-validate it.
    ///
    /// # This is not the ingest path, and its errors say so
    ///
    /// These bytes passed every check in spec §8 when they were stored. If they
    /// fail now, the caller did nothing wrong — the store did. So a `bundle.*`
    /// code is **not** delegated here: it becomes
    /// [`Error::ArtifactCorrupt`] at 500, with the underlying code kept in the
    /// log rather than returned in the response.
    ///
    /// Delegating instead would return 400 and blame the caller for our
    /// integrity failure, and would file a real incident under client errors
    /// where nobody looks for it.
    ///
    /// `expected` is [`Some`] here, unlike at ingest: we know which artifact we
    /// asked for, so there is no reason to parse untrusted structure before
    /// confirming this is it. That makes spec §8 step 0 the first thing to run.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] when no artifact is stored under `digest`,
    /// [`Error::ArtifactCorrupt`] when the stored bytes no longer decode, and
    /// [`Error::Internal`] if the backend itself fails.
    pub async fn get(&self, digest: &BundleRef) -> Result<Bundle, Error> {
        Ok(self.read(digest).await?.0)
    }

    /// The canonical, uncompressed bytes of a stored artifact.
    ///
    /// What a caller handing the stream onward needs — the validated model does
    /// not carry it, and re-encoding from the model would be a second
    /// serialization and a chance to differ from what was stored.
    ///
    /// # Errors
    ///
    /// As [`Self::get`].
    pub async fn get_bytes(&self, digest: &BundleRef) -> Result<Bytes, Error> {
        Ok(self.read(digest).await?.1)
    }

    /// One read, one decompression, one validation.
    ///
    /// [`Self::get`] and [`Self::get_bytes`] both want a different half of the
    /// same work, so it happens once here rather than twice at two call sites.
    async fn read(&self, digest: &BundleRef) -> Result<(Bundle, Bytes), Error> {
        let key = ArtifactKey::bundle(digest);

        if !self.exists(&key).await? {
            return Err(Error::NotFound {
                what: format!("artifact {digest}"),
            });
        }

        let compressed =
            self.operator
                .read(key.as_str())
                .await
                .map_err(|source| Error::Internal {
                    source: source.into(),
                })?;

        let bytes = zstd::decode_all(compressed.to_bytes().as_ref()).map_err(|source| {
            tracing::error!(key = %key, %digest, %source, "stored artifact failed to decompress");
            Error::ArtifactCorrupt {
                digest: digest.to_string(),
            }
        })?;

        let bundle = clwd_bundle::decode(&bytes, Some(*digest)).map_err(|source| {
            // The `bundle.*` code goes here and no further.
            tracing::error!(
                key = %key,
                %digest,
                bundle_code = source.code(),
                %source,
                "stored artifact failed to validate",
            );
            Error::ArtifactCorrupt {
                digest: digest.to_string(),
            }
        })?;

        Ok((bundle, Bytes::from(bytes)))
    }

    async fn exists(&self, key: &ArtifactKey) -> Result<bool, Error> {
        self.operator
            .exists(key.as_str())
            .await
            .map_err(|source| Error::Internal {
                source: source.into(),
            })
    }
}
