//! Kaspa/Karlsen-family address encoding.
//!
//! This is *not* BIP173 bech32 — it shares the same 5-bit packing and 32-char charset, but uses
//! a different (CashAddr/BCH-style) checksum polynomial, an 8-character checksum (vs bech32's 6),
//! a `:` prefix separator (vs bech32's `1`), and no witness-version byte — the address version is
//! just the first payload byte.
//!
//! Verified bit-exact against the upstream Rust reference implementations (same algorithm; only
//! the prefix strings differ between forks):
//! - `kaspanet/rusty-kaspa` `crypto/addresses/src/bech32.rs`
//! - `karlsen-network/rusty-karlsen` `crypto/addresses/src/bech32.rs`

// The charset is bech32's, verbatim — imported rather than re-declared so the two codecs cannot
// drift apart. Only the checksum polynomial, the checksum width, and the separator differ.
use super::bech32::{convertbits_5_to_8, convertbits_8_to_5, CHARSET};

/// Characters the checksum occupies at the end of the data part: 40 bits at 5 bits each.
const CHECKSUM_CHARS: usize = 8;

/// BCH-style polymod checksum (<https://bch.info/en/specifications>), 64-bit accumulator.
fn polymod(values: impl Iterator<Item = u8>) -> u64 {
    const GEN: [u64; 5] = [
        0x0098_f2bc_8e61,
        0x0079_b76d_99e2,
        0x00f3_3e5f_b3c4,
        0x00ae_2eab_e2a8,
        0x001e_4f43_e470,
    ];
    let mut c: u64 = 1;
    for d in values {
        let c0 = c >> 35;
        c = ((c & 0x07_ffff_ffff) << 5) ^ u64::from(d);
        for (i, gen) in GEN.iter().enumerate() {
            if (c0 >> i) & 1 != 0 {
                c ^= gen;
            }
        }
    }
    c ^ 1
}

/// `checksum(prefix ‖ 0 ‖ payload_5bit ‖ 0×8)`, prefix expanded by masking each byte to 5 bits
/// (unlike bech32's `hrp_expand`, which splits each byte into high-3/low-5 halves).
fn checksum(payload_5bit: &[u8], prefix: &str) -> u64 {
    let prefix_5bit = prefix.bytes().map(|c| c & 0x1f);
    polymod(
        prefix_5bit
            .chain([0u8])
            .chain(payload_5bit.iter().copied())
            .chain([0u8; 8]),
    )
}

/// Encode a Kaspa-family address: `<prefix>:<payload><8-char checksum>`.
///
/// `version` is the address-version byte (0 = PubKey/Schnorr x-only 32B, 1 = PubKeyECDSA 33B,
/// 8 = ScriptHash 32B) and is prepended to `payload` before 5-bit conversion, matching the
/// upstream `Address::encode_payload`.
pub fn encode(prefix: &str, version: u8, payload: &[u8]) -> String {
    let mut full = Vec::with_capacity(1 + payload.len());
    full.push(version);
    full.extend_from_slice(payload);
    let payload_5bit = convertbits_8_to_5(&full);

    let chk = checksum(&payload_5bit, prefix);
    // Checksum is 40 bits (8 five-bit groups): the low 5 bytes of the 8-byte big-endian repr.
    let chk_5bit = convertbits_8_to_5(&chk.to_be_bytes()[3..]);
    debug_assert_eq!(chk_5bit.len(), CHECKSUM_CHARS);

    let mut s = String::with_capacity(prefix.len() + 1 + payload_5bit.len() + chk_5bit.len());
    s.push_str(prefix);
    s.push(':');
    for &d in payload_5bit.iter().chain(chk_5bit.iter()) {
        s.push(CHARSET[d as usize] as char);
    }
    s
}

/// What a Kaspa-family address says once its checksum has been verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    /// The network prefix, exactly as it appeared before the `:` (`kaspa`, `karlsentest`, …).
    pub prefix: String,
    /// The address-version byte — 0 = PubKey (Schnorr x-only), 1 = PubKeyECDSA, 8 = ScriptHash.
    pub version: u8,
    /// The version byte's payload: the 32- or 33-byte key or script hash.
    pub payload: Vec<u8>,
}

/// The value [`polymod`] takes over a well-formed address — the scheme's checksum residual.
///
/// Derived from [`encode`] rather than copied out of a spec. `polymod`'s accumulator is 40 bits
/// wide, and the eight groups appended last are shifted in five bits at a time, so the first of
/// them has only reached bits 30-34 when the last is fed in — none of them ever reaches the bit-35
/// feedback tap. Over those eight steps the function is therefore a plain XOR of their 40-bit
/// concatenation into the result:
///
/// ```text
/// raw(v ‖ d) == raw(v ‖ 0×8) ^ d      where raw is polymod before its trailing `^ 1`
/// ```
///
/// [`encode`] appends `d = polymod(v ‖ 0×8) = raw(v ‖ 0×8) ^ 1`, which makes `raw(v ‖ d) == 1`,
/// which `polymod`'s own `^ 1` turns into 0. Same residual BCH's CashAddr specification states
/// (<https://bch.info/en/specifications>) and the same one `kaspanet/rusty-kaspa`
/// `crypto/addresses/src/bech32.rs` checks in `decode_payload`. The argument above is not what
/// makes it true here, though: `tests::decode_round_trips_every_encoder_vector` is, since the
/// round trip closes for every upstream vector only if this constant matches the encoder.
const VALID_CHECKSUM_RESIDUAL: u64 = 0;

/// Decode and **checksum-verify** a Kaspa-family address — the inverse of [`encode`].
///
/// `Some` means the BCH checksum over `prefix ‖ 0 ‖ payload ‖ checksum` came out at
/// [`VALID_CHECKSUM_RESIDUAL`], so a single mistyped character cannot get here; `None` means the
/// string is not a Kaspa-family address, for any reason. This is what lets
/// [`crate::validate::detect_family`] answer *confidently* about this family, the way it already
/// could for bech32 and base58check.
///
/// Case is significant, deliberately. The `& 0x1f` prefix masking makes the checksum itself
/// case-insensitive, but upstream's charset table (`CHARSET_REV` in
/// `kaspanet/rusty-kaspa` `crypto/addresses/src/bech32.rs`) holds lower case only, so an uppercase
/// address is one upstream rejects — folding case here would accept strings the network does not.
pub fn decode(s: &str) -> Option<Decoded> {
    let (prefix, data) = s.split_once(':')?;

    // The prefix has to be constrained, not merely non-empty. Masking a byte to five bits maps 8
    // different bytes onto each value, so without this a prefix such as `KASPA` or `+aspa` would
    // checksum identically to `kaspa` — a collision the caller would then have to catch.
    if prefix.is_empty()
        || !prefix
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return None;
    }
    // Strictly greater: the data part is a checksum plus at least one payload character.
    if data.len() <= CHECKSUM_CHARS {
        return None;
    }

    let mut data_5bit = Vec::with_capacity(data.len());
    for c in data.bytes() {
        data_5bit.push(CHARSET.iter().position(|&x| x == c)? as u8);
    }

    // Same expansion the encoder checksums over, with the address's own checksum characters in
    // place of the eight zeros.
    let expanded = prefix
        .bytes()
        .map(|c| c & 0x1f)
        .chain([0u8])
        .chain(data_5bit.iter().copied());
    if polymod(expanded) != VALID_CHECKSUM_RESIDUAL {
        return None;
    }

    let full = convertbits_5_to_8(&data_5bit[..data_5bit.len() - CHECKSUM_CHARS])?;
    let (&version, payload) = full.split_first()?;
    Some(Decoded {
        prefix: prefix.to_string(),
        version,
        payload: payload.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::{decode, encode};
    use crate::hexbytes::decode as hex;

    // KATs transcribed verbatim from `karlsen-network/rusty-karlsen`
    // `crypto/addresses/src/bech32.rs` `tests::cases()` (2026-07-01).

    #[test]
    fn karlsen_mainnet_pubkey_all_zero() {
        assert_eq!(
            encode("karlsen", 0, &[0u8; 32]),
            "karlsen:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqu3v2qv4j"
        );
    }

    #[test]
    fn karlsen_mainnet_pubkey_nonzero() {
        let payload =
            hex("5fff3c4da18f45adcdd499e44611e9fff148ba69db3c4ea2ddd955fc46a59522").unwrap();
        assert_eq!(
            encode("karlsen", 0, &payload),
            "karlsen:qp0l70zd5x85ttwd6jv7g3s3a8llzj96d8dncn4zmhv4tlzx5k2jy2qhcgkfe"
        );
    }

    #[test]
    fn karlsentest_pubkey_all_zero() {
        assert_eq!(
            encode("karlsentest", 0, &[0u8; 32]),
            "karlsentest:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0tvfsppx"
        );
    }

    #[test]
    fn karlsentest_pubkey_ecdsa_all_zero() {
        assert_eq!(
            encode("karlsentest", 1, &[0u8; 33]),
            "karlsentest:qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqzg70v3fs"
        );
    }

    // Same algorithm, upstream `kaspanet/rusty-kaspa` prefix — confirms the checksum/charset
    // aren't accidentally Karlsen-specific.
    #[test]
    fn kaspa_mainnet_pubkey_all_zero() {
        assert_eq!(
            encode("kaspa", 0, &[0u8; 32]),
            "kaspa:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkx9awp4e"
        );
    }

    // ---- decoder ----
    //
    // The decoder is tested through the encoder rather than against a second copy of the address
    // literals above: the literal assertions are what pin `encode` to upstream, so driving the
    // decoder from the same `(prefix, version, payload)` inputs means a decoder can only pass by
    // inverting the *upstream-gated* encoder. Re-listing the literals here would let the two drift
    // together on a shared mistake.

    /// The `(prefix, version, payload)` behind every literal vector above.
    fn upstream_inputs() -> Vec<(&'static str, u8, Vec<u8>)> {
        vec![
            ("karlsen", 0, vec![0u8; 32]),
            (
                "karlsen",
                0,
                hex("5fff3c4da18f45adcdd499e44611e9fff148ba69db3c4ea2ddd955fc46a59522").unwrap(),
            ),
            ("karlsentest", 0, vec![0u8; 32]),
            ("karlsentest", 1, vec![0u8; 33]),
            ("kaspa", 0, vec![0u8; 32]),
        ]
    }

    /// Replace one character with a different one from the same charset — the single-key typo a
    /// user actually makes, as opposed to a structural mangling.
    fn flip(s: &str, i: usize) -> String {
        let mut b = s.as_bytes().to_vec();
        b[i] = if b[i] == b'q' { b'p' } else { b'q' };
        String::from_utf8(b).expect("charset is ASCII")
    }

    /// Every encoder vector must decode back to exactly the input that produced it.
    ///
    /// This is also what *proves* the checksum residual `decode` tests for. Nothing in the decoder
    /// re-derives the constant at runtime, so the only evidence that 0 is the right value is that
    /// the round trip closes for every upstream vector while the corruption cases below all fail.
    #[test]
    fn decode_round_trips_every_encoder_vector() {
        for (prefix, version, payload) in upstream_inputs() {
            let encoded = encode(prefix, version, &payload);
            let d = decode(&encoded).unwrap_or_else(|| panic!("{encoded} failed to decode"));
            assert_eq!(d.prefix, prefix);
            assert_eq!(d.version, version);
            assert_eq!(d.payload, payload);
        }
    }

    /// The gap the audit flagged: before this, a Kaspa-family address was accepted on shape alone,
    /// so every case below classified as a confident, valid Kaspa address. Each is a defect a user
    /// hits in practice — a mistyped character, a truncated paste, a stray non-charset letter.
    #[test]
    fn corrupted_addresses_do_not_decode() {
        for (prefix, version, payload) in upstream_inputs() {
            let good = encode(prefix, version, &payload);
            let data_start = prefix.len() + 1;
            assert!(decode(&good).is_some(), "{good} should decode");

            // One flipped character in the payload.
            let bad = flip(&good, data_start);
            assert_eq!(decode(&bad), None, "flipped payload char: {bad}");

            // One flipped character inside the 8-character checksum itself.
            let bad = flip(&good, good.len() - 1);
            assert_eq!(decode(&bad), None, "flipped checksum char: {bad}");

            // A truncated paste — one character short.
            let bad = &good[..good.len() - 1];
            assert_eq!(decode(bad), None, "truncated: {bad}");

            // A character outside the bech32 charset ('b' is one of the four it omits).
            let mut bytes = good.clone().into_bytes();
            bytes[data_start] = b'b';
            let bad = String::from_utf8(bytes).unwrap();
            assert_eq!(decode(&bad), None, "non-charset char: {bad}");

            // Empty payload: a bare prefix, and a prefix plus a checksum-sized run with no data
            // behind it.
            assert_eq!(decode(&format!("{prefix}:")), None);
            assert_eq!(decode(&format!("{prefix}:qqqqqqqq")), None);
        }
    }

    /// The prefix is folded into the checksum, and for these forks it is the *only* thing that
    /// differs — Kaspa, Karlsen and Spectre share the address format byte for byte. If the decoder
    /// skipped the prefix, a Karlsen address would verify as a Kaspa one and detection would
    /// confidently report the wrong chain to pay.
    #[test]
    fn a_valid_payload_under_the_wrong_prefix_does_not_decode() {
        let good = encode("karlsen", 0, &[0u8; 32]);
        let data = good.split_once(':').expect("encoder emits a separator").1;
        for wrong in ["kaspa", "karlsentest", "spectre", "karlse", "karlsenn"] {
            let bad = format!("{wrong}:{data}");
            assert_eq!(decode(&bad), None, "wrong prefix accepted: {bad}");
        }
    }

    /// Structural rejections, so none of them reaches the checksum as a surprise.
    #[test]
    fn malformed_shapes_do_not_decode() {
        for bad in [
            "",
            ":",
            "kaspa",            // no separator at all
            ":qqqqqqqqq",       // empty prefix
            "kaspa:qqqq",       // shorter than the checksum
            "ka spa:qqqqqqqqq", // prefix outside the accepted character set
            "KASPA:QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQKX9AWP4E",
        ] {
            assert_eq!(decode(bad), None, "accepted malformed input: {bad}");
        }
    }
}
