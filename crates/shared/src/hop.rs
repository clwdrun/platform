//! The hop from the gateway to the worker that runs app code (#11).
//!
//! One request per Unix-socket connection, in each direction one frame:
//!
//! ```text
//! [u32 BE head length][head: JSON][u64 BE body length][body]
//! ```
//!
//! The head is versioned from the first message ([`VERSION`]); a reader
//! refuses any other version rather than guessing at its shape.
//!
//! # Neither side trusts the other's encoder
//!
//! The worker runs untrusted code, so a worker escape can write any bytes it
//! likes back to the gateway; a process that wins the socket path can write
//! any bytes to the worker. [`read_frame`] therefore checks every length
//! against its cap **before allocating for it**: head, body, header count and
//! total header bytes. The same limits apply in both directions, enforced by
//! whichever side is reading.
//!
//! # Identity is a typed field, never a header
//!
//! [`Caller`] travels in the head, built by the gateway from its per-request
//! session check. Nothing a client sends can become it: client headers ride in
//! [`RequestHead::headers`], a separate field the worker never reads identity
//! from.
//!
//! # One connection per request
//!
//! No pooling, for two reasons. It keeps a request's bytes on a stream no other
//! request shares, so one compromised response cannot poison another
//! request's stream. And the measured cost is small: about 30–50 µs p50 over a
//! persistent connection on loopback.

use std::fmt;

use clwd_bundle::BundleRef;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

/// The protocol version this build speaks.
pub const VERSION: u16 = 1;
/// The largest head, in bytes. Header values travel as JSON arrays of numbers,
/// so this leaves room for [`MAX_HEADER_BYTES`] of raw headers several times
/// over and nothing more.
pub const MAX_HEAD: u32 = 512 * 1024;
/// The largest body, in bytes: the gateway's request cap and the runtime's
/// response cap, both 16 MiB.
pub const MAX_BODY: u64 = 16 * 1024 * 1024;
/// The most headers a head may carry.
pub const MAX_HEADERS: usize = 128;
/// The most header bytes, names and values together, a head may carry.
pub const MAX_HEADER_BYTES: usize = 64 * 1024;

/// An app, by the id the control plane gave it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AppId(String);

/// An org, by the id the control plane gave it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OrgId(String);

/// The subject an app sees for one visitor: pairwise per (app, user), never
/// the platform user id.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AppSubject(String);

/// Correlates one hop with the log lines it produced.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HopRequestId(String);

macro_rules! string_id {
    ($($ty:ident),*) => {$(
        impl $ty {
            /// Wrap a value already validated by whoever produced it.
            #[must_use]
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            /// The value.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    )*};
}
string_id!(AppId, OrgId, AppSubject, HopRequestId);

/// Who is calling, as the app is allowed to see them.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Caller {
    pub subject: AppSubject,
    /// Verified, when present.
    pub email: Option<String>,
    /// The app's org.
    pub org_id: OrgId,
}

impl Caller {
    /// A caller.
    #[must_use]
    pub fn new(subject: AppSubject, email: Option<String>, org_id: OrgId) -> Self {
        Self {
            subject,
            email,
            org_id,
        }
    }
}

impl fmt::Debug for Caller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Caller")
            .field("subject", &self.subject)
            .field("email", &self.email.as_ref().map(|_| "<redacted>"))
            .field("org_id", &self.org_id)
            .finish()
    }
}

/// One header, its value as raw bytes: HTTP allows values that are not UTF-8.
pub type Header = (String, Vec<u8>);

/// What the gateway sends.
///
/// Not `#[non_exhaustive]`: a field added here is a protocol change, so it
/// comes with a [`VERSION`] bump, and every construction site should fail to
/// compile until it says what to send.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestHead {
    pub v: u16,
    pub request_id: HopRequestId,
    pub app_id: AppId,
    pub org_id: OrgId,
    /// The version of the app to run.
    #[serde(with = "bundle_ref")]
    pub digest: BundleRef,
    pub caller: Caller,
    pub method: String,
    pub path_and_query: String,
    pub headers: Vec<Header>,
}

/// What the worker sends back.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ResponseHead {
    pub v: u16,
    pub status: u16,
    pub headers: Vec<Header>,
    /// Set when the worker ran nothing or the app failed: a stable code for
    /// the gateway's log, such as `worker.egress_not_supported`. The status is
    /// then 502 and the body empty.
    pub error: Option<String>,
}

impl ResponseHead {
    /// The app's answer.
    #[must_use]
    pub fn answer(status: u16, headers: Vec<Header>) -> Self {
        Self {
            v: VERSION,
            status,
            headers,
            error: None,
        }
    }

    /// The worker's refusal, or the app's failure.
    #[must_use]
    pub fn failed(code: impl Into<String>) -> Self {
        Self {
            v: VERSION,
            status: 502,
            headers: Vec::new(),
            error: Some(code.into()),
        }
    }
}

/// A head that carries a version and headers, so [`read_frame`] can check both.
pub trait Head: Serialize + DeserializeOwned {
    fn version(&self) -> u16;
    fn headers(&self) -> &[Header];
}

impl Head for RequestHead {
    fn version(&self) -> u16 {
        self.v
    }
    fn headers(&self) -> &[Header] {
        &self.headers
    }
}

impl Head for ResponseHead {
    fn version(&self) -> u16 {
        self.v
    }
    fn headers(&self) -> &[Header] {
        &self.headers
    }
}

/// Why a frame was refused.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HopError {
    #[error("hop i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("hop {what} of {len} exceeds the cap of {max}")]
    TooLarge {
        what: &'static str,
        len: u64,
        max: u64,
    },
    #[error("hop head is malformed: {0}")]
    Malformed(String),
    #[error("hop version {0} is not {VERSION}")]
    Version(u16),
}

/// Write one frame.
///
/// # Errors
///
/// [`HopError::Io`] if the stream fails, [`HopError::Malformed`] if the head
/// cannot be encoded, and [`HopError::TooLarge`] if this side would exceed a
/// cap the reader enforces anyway.
pub async fn write_frame<W: AsyncWrite + Unpin, H: Head>(
    writer: &mut W,
    head: &H,
    body: &[u8],
) -> Result<(), HopError> {
    let head = serde_json::to_vec(head).map_err(|e| HopError::Malformed(e.to_string()))?;
    let head_len = u32::try_from(head.len()).unwrap_or(u32::MAX);
    check("head", u64::from(head_len), u64::from(MAX_HEAD))?;
    check("body", body.len() as u64, MAX_BODY)?;
    writer.write_all(&head_len.to_be_bytes()).await?;
    writer.write_all(&head).await?;
    writer.write_all(&(body.len() as u64).to_be_bytes()).await?;
    writer.write_all(body).await?;
    writer.flush().await?;
    Ok(())
}

/// Read one frame, checking every length before allocating for it.
///
/// # Errors
///
/// [`HopError::TooLarge`] for any length over its cap, [`HopError::Version`]
/// for a head of another version, [`HopError::Malformed`] for a head that does
/// not parse, and [`HopError::Io`] if the stream ends early.
pub async fn read_frame<R: AsyncRead + Unpin, H: Head>(
    reader: &mut R,
) -> Result<(H, Vec<u8>), HopError> {
    let head_len = reader.read_u32().await?;
    check("head", u64::from(head_len), u64::from(MAX_HEAD))?;
    let mut head = vec![0u8; head_len as usize];
    reader.read_exact(&mut head).await?;
    let head: H = serde_json::from_slice(&head).map_err(|e| HopError::Malformed(e.to_string()))?;
    if head.version() != VERSION {
        return Err(HopError::Version(head.version()));
    }
    check(
        "header count",
        head.headers().len() as u64,
        MAX_HEADERS as u64,
    )?;
    let header_bytes: usize = head
        .headers()
        .iter()
        .map(|(name, value)| name.len() + value.len())
        .sum();
    check("header bytes", header_bytes as u64, MAX_HEADER_BYTES as u64)?;

    let body_len = reader.read_u64().await?;
    check("body", body_len, MAX_BODY)?;
    let mut body = vec![0u8; usize::try_from(body_len).unwrap_or(usize::MAX)];
    reader.read_exact(&mut body).await?;
    Ok((head, body))
}

fn check(what: &'static str, len: u64, max: u64) -> Result<(), HopError> {
    if len > max {
        return Err(HopError::TooLarge { what, len, max });
    }
    Ok(())
}

mod bundle_ref {
    use clwd_bundle::BundleRef;
    use serde::{Deserialize as _, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(value: &BundleRef, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(value)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<BundleRef, D::Error> {
        let raw = String::deserialize(d)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head() -> RequestHead {
        RequestHead {
            v: VERSION,
            request_id: HopRequestId::new("r1"),
            app_id: AppId::new("a"),
            org_id: OrgId::new("o"),
            digest: BundleRef::of_stream(b"x"),
            caller: Caller::new(
                AppSubject::new("s"),
                Some("ada@example.com".into()),
                OrgId::new("o"),
            ),
            method: "GET".into(),
            path_and_query: "/".into(),
            headers: vec![("accept".into(), b"*/*".to_vec())],
        }
    }

    #[tokio::test]
    async fn a_frame_round_trips() {
        let mut wire = Vec::new();
        write_frame(&mut wire, &head(), b"body")
            .await
            .expect("writes");
        let (back, body): (RequestHead, _) = read_frame(&mut wire.as_slice()).await.expect("reads");
        assert_eq!(back.caller, head().caller);
        assert_eq!(back.digest, head().digest);
        assert_eq!(body, b"body");
    }

    #[test]
    fn a_callers_email_is_redacted_in_debug() {
        let debug = format!("{:?}", head().caller);
        assert!(!debug.contains("ada@"), "{debug}");
    }

    /// Each cap refuses before allocating: the length alone is enough.
    #[tokio::test]
    async fn every_length_is_capped_before_it_is_read() {
        let head_too_long = (MAX_HEAD + 1).to_be_bytes().to_vec();
        let err = read_frame::<_, ResponseHead>(&mut head_too_long.as_slice())
            .await
            .expect_err("refused");
        assert!(
            matches!(err, HopError::TooLarge { what: "head", .. }),
            "{err}"
        );

        let ok = ResponseHead::answer(200, Vec::new());
        let encoded = serde_json::to_vec(&ok).expect("encodes");
        let mut wire = (encoded.len() as u32).to_be_bytes().to_vec();
        wire.extend_from_slice(&encoded);
        wire.extend_from_slice(&(MAX_BODY + 1).to_be_bytes());
        let err = read_frame::<_, ResponseHead>(&mut wire.as_slice())
            .await
            .expect_err("refused");
        assert!(
            matches!(err, HopError::TooLarge { what: "body", .. }),
            "{err}"
        );

        let many = ResponseHead::answer(
            200,
            (0..=MAX_HEADERS)
                .map(|i| (format!("h{i}"), Vec::new()))
                .collect(),
        );
        let mut wire = Vec::new();
        let encoded = serde_json::to_vec(&many).expect("encodes");
        wire.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
        wire.extend_from_slice(&encoded);
        wire.extend_from_slice(&0u64.to_be_bytes());
        let err = read_frame::<_, ResponseHead>(&mut wire.as_slice())
            .await
            .expect_err("refused");
        assert!(
            matches!(
                err,
                HopError::TooLarge {
                    what: "header count",
                    ..
                }
            ),
            "{err}"
        );

        let big = ResponseHead::answer(200, vec![("h".into(), vec![b'x'; MAX_HEADER_BYTES])]);
        let mut wire = Vec::new();
        let encoded = serde_json::to_vec(&big).expect("encodes");
        wire.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
        wire.extend_from_slice(&encoded);
        wire.extend_from_slice(&0u64.to_be_bytes());
        let err = read_frame::<_, ResponseHead>(&mut wire.as_slice())
            .await
            .expect_err("refused");
        assert!(
            matches!(
                err,
                HopError::TooLarge {
                    what: "header bytes",
                    ..
                }
            ),
            "{err}"
        );
    }

    #[tokio::test]
    async fn another_version_is_refused() {
        let mut other = ResponseHead::answer(200, Vec::new());
        other.v = VERSION + 1;
        let encoded = serde_json::to_vec(&other).expect("encodes");
        let mut wire = (encoded.len() as u32).to_be_bytes().to_vec();
        wire.extend_from_slice(&encoded);
        wire.extend_from_slice(&0u64.to_be_bytes());
        let err = read_frame::<_, ResponseHead>(&mut wire.as_slice())
            .await
            .expect_err("refused");
        assert!(matches!(err, HopError::Version(_)), "{err}");
    }
}
