//! Byte ⇄ hex conversion, in one place.
//!
//! The crate previously carried fifteen private copies of these helpers — `fn hex`, `fn hex32`,
//! `fn hex20`, and two `mod hex` blocks — spread over thirteen files, plus eighteen inline
//! `format!("{b:02x}")` sites. Worse, the name `hex` meant *encode* in some modules and *decode* in
//! others. One module now owns both directions, so a printed secret and a test vector are formatted
//! by the same code.

/// Lower-case hex for `bytes`: two characters per byte, no `0x` prefix.
pub fn encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

/// Decode an even-length hex string. `None` on an odd length or a non-hex character.
///
/// Decoding is done a nibble at a time rather than by handing each two-character window to
/// [`u8::from_str_radix`], because `from_str_radix` is a *number* parser, not a hex-digit parser:
/// it accepts a leading sign. `decode("+f")` therefore used to return `Some([0x0f])`, silently
/// treating a two-character window that contains only one hex digit as a byte. (`-f` was already
/// rejected, but only because the target type is unsigned — a coincidence of `u8`, not a rule
/// about hex.) Every caller here wants "exactly two hex digits" — a private key, a version prefix,
/// a test vector — and none of them wants a sign, so the sign was pure surface with no legitimate
/// input behind it.
///
/// Working over bytes rather than `str` slices also removes the char-boundary question: a
/// multi-byte UTF-8 sequence has every byte ≥ 0x80, none of which is a hex digit, so it is rejected
/// for the same reason `zz` is instead of needing a separate guard.
pub fn decode(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    bytes
        .chunks_exact(2)
        .map(|pair| Some(nibble(pair[0])? << 4 | nibble(pair[1])?))
        .collect()
}

/// The numeric value of one hex digit, either case. `None` for anything else — including `+`, `-`,
/// whitespace and any non-ASCII byte.
fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Decode exactly `N` bytes (`2 * N` hex characters). `None` on any other length or on non-hex
/// input.
pub fn decode_n<const N: usize>(s: &str) -> Option<[u8; N]> {
    decode(s)?.try_into().ok()
}

/// Decode a hex private key / test vector of exactly 32 bytes, panicking on malformed input.
///
/// Intended for known-answer tests, whose literals are fixed at compile time, so a panic is the
/// correct response to a typo in the vector. Use [`decode_n`] for input that may be malformed.
///
/// Not `#[cfg(test)]`: the known-answer tests that call it now live in the `forager-wallet` crate,
/// and a `cfg(test)` item is compiled out when this crate is built as a dependency.
pub fn hex32(s: &str) -> [u8; 32] {
    decode_n(s).expect("malformed 32-byte hex test vector")
}

#[cfg(test)]
mod tests {
    use super::{decode, decode_n, encode};

    #[test]
    fn encode_is_lowercase_two_chars_per_byte() {
        assert_eq!(encode(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
        assert_eq!(encode(&[]), "");
    }

    #[test]
    fn decode_round_trips_encode() {
        let bytes: Vec<u8> = (0u8..=255).collect();
        assert_eq!(decode(&encode(&bytes)).unwrap(), bytes);
    }

    #[test]
    fn decode_rejects_odd_length_and_non_hex() {
        assert_eq!(decode("abc"), None);
        assert_eq!(decode("zz"), None);
        // Multi-byte UTF-8: byte length is even, and every byte is ≥ 0x80, so no nibble matches.
        assert_eq!(decode("é"), None);
    }

    /// A sign is not a hex digit. The `+` cases decoded before: the previous implementation handed
    /// each two-character window to `u8::from_str_radix`, which parses a *number* and so accepts a
    /// leading `+`, turning a window holding one hex digit into a byte. No caller wants a signed
    /// nibble — each is decoding a key, a version prefix or a test vector — so quietly reading
    /// `+f` as `0f` is a wrong answer rather than a lenient one.
    ///
    /// The `-` cases were already rejected, but only because the target type is unsigned. That is a
    /// property of `u8`, not a rule about hex, and it would not have survived a change of type;
    /// they are pinned here so both signs are now refused for the same stated reason.
    #[test]
    fn decode_rejects_a_signed_nibble() {
        assert_eq!(decode("+f"), None);
        assert_eq!(decode("-f"), None);
        assert_eq!(decode("f+"), None);
        // Not just at the start: a sign anywhere in a longer string is still not a byte.
        assert_eq!(decode("00+f00"), None);
        // Whitespace, the other thing an integer parser is happy to skip.
        assert_eq!(decode(" f"), None);
        assert_eq!(decode("0 "), None);
    }

    #[test]
    fn decode_n_enforces_exact_width() {
        assert!(decode_n::<2>("00ff").is_some());
        assert!(decode_n::<2>("00").is_none());
        assert!(decode_n::<2>("00ff00").is_none());
    }

    /// Uppercase input decodes (hex is case-insensitive) even though `encode` only emits lowercase.
    #[test]
    fn decode_accepts_uppercase() {
        assert_eq!(decode("DEADBEEF").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
    }
}
