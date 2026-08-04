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
pub fn decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    // `str::get` returns `None` on a non-char boundary, so multi-byte UTF-8 input is rejected
    // rather than sliced mid-character.
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok())
        .collect()
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
        // Multi-byte UTF-8: byte length is even, but the slice is not a char boundary.
        assert_eq!(decode("é"), None);
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
