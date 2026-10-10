//! Where a visitor returns to after the app-host sign-in handshake (#62).
//!
//! The gateway records the path a visitor asked for before sending them to
//! the control plane, and sends them back to it afterwards. A redirect target
//! taken from a request is how an open redirect is built, so a
//! [`ReturnPath`] can only hold a path on the *same host*: it starts with a
//! single `/`, never `//` or `/\` (both of which browsers read as "another
//! host"), carries no scheme, and no control or non-ASCII bytes. It is stored
//! server-side between the two halves of the handshake and never read back
//! from a query string.

use std::fmt;

/// The longest path accepted. Longer is refused rather than truncated.
const MAX_LEN: usize = 2048;

/// A same-host path to return to. Construct with [`ReturnPath::parse`].
#[derive(Clone, PartialEq, Eq)]
pub struct ReturnPath(String);

/// Why a path is not a safe return target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("not a same-host path")]
pub struct NotSameHost;

impl ReturnPath {
    /// Accept `raw` only as a same-host path (see the module docs).
    ///
    /// # Errors
    ///
    /// [`NotSameHost`] for anything else.
    pub fn parse(raw: &str) -> Result<Self, NotSameHost> {
        let bytes = raw.as_bytes();
        let same_host = bytes.first() == Some(&b'/')
            && !matches!(bytes.get(1), Some(b'/' | b'\\'))
            && bytes.len() <= MAX_LEN
            // Visible ASCII only: no control bytes (a tab or newline lets a
            // browser re-read `/\t/evil` as `//evil`), no spaces, nothing
            // non-ASCII to normalise into a separator.
            && bytes.iter().all(|b| (0x21..=0x7e).contains(b))
            && !bytes.contains(&b'\\');
        // A scheme inside a path that starts with `/` is still only a path,
        // but there is no reason to carry one, and refusing it keeps the rule
        // obvious to a reader.
        let lower = raw.to_ascii_lowercase();
        let has_scheme = ["http:", "https:", "javascript:", "data:"]
            .iter()
            .any(|scheme| lower.contains(scheme));
        if same_host && !has_scheme {
            Ok(Self(raw.to_owned()))
        } else {
            Err(NotSameHost)
        }
    }

    /// The root path, `/`.
    #[must_use]
    pub fn root() -> Self {
        Self("/".to_owned())
    }

    /// The path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ReturnPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ReturnPath({})", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_host_paths_are_accepted() {
        for raw in [
            "/",
            "/notes",
            "/notes/42?tab=history#top",
            "/a/b/c?x=%2F%2Fevil",
        ] {
            assert_eq!(ReturnPath::parse(raw).map(|p| p.0), Ok(raw.to_owned()));
        }
    }

    #[test]
    fn anything_that_could_leave_the_host_is_refused() {
        for raw in [
            "",
            "notes",
            "//evil.example",
            "/\\evil.example",
            "\\\\evil.example",
            "https://evil.example/",
            "/redirect?to=https://evil.example",
            "javascript:alert(1)",
            "/\tevil",
            "/\n/evil",
            "/\r\n/evil",
            "/ space",
            "/caf\u{e9}",
            "/x\\y",
        ] {
            assert_eq!(ReturnPath::parse(raw), Err(NotSameHost), "{raw:?}");
        }
        assert_eq!(
            ReturnPath::parse(&format!("/{}", "a".repeat(MAX_LEN))),
            Err(NotSameHost)
        );
    }
}
