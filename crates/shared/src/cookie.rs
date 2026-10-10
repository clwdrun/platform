//! Reading platform cookies from a `Cookie` header: the one parser the
//! platform uses for its own cookies (#62).
//!
//! # Why not the `cookie` crate
//!
//! `cookie` 0.18 (`Cookie::parse`, `Cookie::split_parse` and their encoded
//! variants) is written to be forgiving, which is the wrong property for a
//! cookie that names a session:
//!
//! - it trims Unicode whitespace from names, so `__Host-clwd_session\u{2000}`
//!   and `\u{3000}__Host-clwd_session` both come back as `__Host-clwd_session`.
//!   A browser does not treat either as `__Host-`-prefixed — the name does not
//!   start with the prefix — so it lets a sibling host set one with `Domain=`,
//!   and the forgiving parser then hands the control plane a planted session;
//! - it keeps every duplicate, leaving the caller to pick one — and picking is
//!   letting whoever planted the second one choose the session.
//!
//! `clippy.toml` therefore disallows those functions workspace-wide and points
//! here. This parser matches **bytes**: pairs are split on `;`, only SP and
//! HTAB around a whole pair are trimmed (the header's own separator
//! whitespace — nothing between a name and its `=`), a pair without
//! `=` is skipped (it is a nameless cookie, which cannot be ours), and a name
//! matches only if it is byte-for-byte the name asked for. Anything else —
//! another case, padding, non-ASCII — is a different cookie and is ignored,
//! never repaired into ours.
//!
//! # What no server can see
//!
//! A browser that accepts a nameless cookie whose value is
//! `__Host-clwd_session=v` sends it as `__Host-clwd_session=v`, byte-identical
//! to the real one. RFC 6265bis (§5.7, step 22) has browsers reject those; on
//! one that does not, refusing duplicates ([`Found::Duplicate`]) is the only
//! server-side defence, and it protects only a visitor who already holds the
//! real cookie.

/// What a `Cookie` header holds under one name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Found<'h> {
    /// No cookie of exactly this name.
    Absent,
    /// Exactly one, with this value. A value that is not UTF-8 is reported as
    /// [`Found::Absent`]: no platform cookie carries one.
    One(&'h str),
    /// More than one. Refused, never resolved: a second one is what a planted
    /// cookie looks like, and choosing either lets the planter choose.
    Duplicate,
}

/// The pairs of one `Cookie` header value, as `(name, value)` byte slices,
/// after splitting on `;` and trimming SP and HTAB around each pair. Pairs
/// with no `=` are dropped. Nothing between a name and its `=` is trimmed: a
/// browser trims names when it stores them, so padding there never comes
/// from a cookie a browser holds under our name.
fn pairs(header: &[u8]) -> impl Iterator<Item = (&[u8], &[u8])> {
    header.split(|b| *b == b';').filter_map(|pair| {
        let pair = trim_ows(pair);
        let at = pair.iter().position(|b| *b == b'=')?;
        Some((&pair[..at], &pair[at + 1..]))
    })
}

/// Trim the header's optional whitespace — SP and HTAB, nothing else.
fn trim_ows(bytes: &[u8]) -> &[u8] {
    let is_ows = |b: &u8| *b == b' ' || *b == b'\t';
    let start = bytes.iter().position(|b| !is_ows(b)).unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|b| !is_ows(b))
        .map_or(start, |i| i + 1);
    &bytes[start..end]
}

/// Find the cookie named exactly `name` across every `Cookie` header value.
///
/// `name` must be the exact, case-sensitive name the platform sets. See the
/// module docs for what "exactly" excludes and why.
#[must_use]
pub fn find<'h>(headers: impl IntoIterator<Item = &'h [u8]>, name: &str) -> Found<'h> {
    // Every occurrence counts toward a duplicate, whatever its value holds.
    let mut first: Option<&'h [u8]> = None;
    for header in headers {
        for (candidate, value) in pairs(header) {
            if candidate != name.as_bytes() {
                continue;
            }
            if first.is_some() {
                return Found::Duplicate;
            }
            first = Some(value);
        }
    }
    match first.map(std::str::from_utf8) {
        Some(Ok(value)) if !value.is_empty() => Found::One(value),
        _ => Found::Absent,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NAME: &str = "__Host-clwd_session";

    fn find_in(header: &[u8]) -> Found<'_> {
        find([header], NAME)
    }

    #[test]
    fn the_exact_name_is_found() {
        assert_eq!(find_in(b"__Host-clwd_session=real"), Found::One("real"));
        assert_eq!(
            find_in(b"a=1; __Host-clwd_session=real;b=2"),
            Found::One("real")
        );
    }

    /// Every probe row from #62's Phase 0, plus the leading-whitespace rows
    /// that probe missed. None of these is our cookie.
    #[test]
    fn nothing_but_the_exact_name_matches() {
        for header in [
            "=__Host-clwd_session=nameless".as_bytes(),
            b"__HOST-clwd_session=case-variant",
            b"__host-clwd_session=case-variant",
            "__Host-clwd_session\u{2000}=unicode-after".as_bytes(),
            "\u{2000}__Host-clwd_session=unicode-before".as_bytes(),
            "a=1;\u{3000}__Host-clwd_session=ideographic-space".as_bytes(),
            "\u{feff}__Host-clwd_session=bom".as_bytes(),
            b"__Host-clwd_session\x0b=vertical-tab",
            b"x__Host-clwd_session=suffix",
            b"__Host-clwd_sessionx=prefix",
            b"__Host-clwd_session",
        ] {
            assert_eq!(
                find_in(header),
                Found::Absent,
                "{:?}",
                String::from_utf8_lossy(header)
            );
        }
    }

    /// SP and HTAB around a pair are the header's own separator whitespace
    /// and are trimmed. ASCII padding between a name and its `=` is not: no
    /// browser stores a name that way, so it is someone else's cookie.
    #[test]
    fn only_separator_whitespace_is_trimmed() {
        assert_eq!(find_in(b"a=1;   __Host-clwd_session=v  "), Found::One("v"));
        assert_eq!(find_in(b"a=1;\t__Host-clwd_session=v"), Found::One("v"));
        assert_eq!(find_in(b" __Host-clwd_session =padded"), Found::Absent);
        assert_eq!(find_in(b"__Host-clwd_session\t=padded"), Found::Absent);
    }

    /// The ban is what keeps this the only parser. Deleting an entry is the
    /// quiet way to defeat it; deleting the file fails this at compile time.
    #[test]
    fn clippy_still_bans_the_cookie_crate_parsers() {
        let config = include_str!("../../../clippy.toml");
        for function in [
            "parse",
            "parse_encoded",
            "split_parse",
            "split_parse_encoded",
        ] {
            let path = format!("\"cookie::Cookie::{function}\"");
            assert!(
                config.contains(&path),
                "clippy.toml no longer disallows {path}, so platform cookies could be read \
                 with a parser that repairs names and keeps duplicates"
            );
        }
    }

    #[test]
    fn an_empty_value_is_no_cookie() {
        assert_eq!(find_in(b"__Host-clwd_session="), Found::Absent);
    }

    #[test]
    fn duplicates_are_refused_within_and_across_headers() {
        assert_eq!(
            find_in(b"__Host-clwd_session=real; __Host-clwd_session=planted"),
            Found::Duplicate
        );
        assert_eq!(
            find(
                [
                    b"__Host-clwd_session=real".as_slice(),
                    b"__Host-clwd_session=planted".as_slice()
                ],
                NAME
            ),
            Found::Duplicate
        );
    }

    /// A non-UTF-8 neighbour does not hide the real cookie, and a second
    /// copy with a non-UTF-8 value is still a duplicate.
    #[test]
    fn non_utf8_bytes_do_not_poison_the_header() {
        assert_eq!(
            find_in(b"junk=\xff\xfe; __Host-clwd_session=real"),
            Found::One("real")
        );
        assert_eq!(
            find_in(b"__Host-clwd_session=\xff; __Host-clwd_session=real"),
            Found::Duplicate
        );
        assert_eq!(find_in(b"__Host-clwd_session=\xff"), Found::Absent);
    }
}
