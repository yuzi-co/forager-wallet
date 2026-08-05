/// The 32-character 5-bit charset. Shared with [`crate::codec::cashaddr`] — the Kaspa-family
/// scheme reuses bech32's charset verbatim and diverges only on the checksum and the separator.
pub const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_CONST: u32 = 1;
const BECH32M_CONST: u32 = 0x2bc8_30a3;

fn polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut chk: u32 = 1;
    for &v in values {
        let b = chk >> 25;
        chk = ((chk & 0x1ff_ffff) << 5) ^ u32::from(v);
        for (i, gen) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= gen;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut v: Vec<u8> = hrp.bytes().map(|c| c >> 5).collect();
    v.push(0);
    v.extend(hrp.bytes().map(|c| c & 31));
    v
}

/// Convert 8-bit bytes to 5-bit groups (with padding), per bech32.
///
/// Shared with [`crate::codec::cashaddr`] — the Kaspa/Karlsen address scheme packs bits the same
/// way bech32 does, it just diverges on the checksum polynomial and prefix handling.
pub fn convertbits_8_to_5(data: &[u8]) -> Vec<u8> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();
    for &b in data {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(((acc >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        out.push(((acc << (5 - bits)) & 31) as u8);
    }
    out
}

/// Convert 5-bit groups back to 8-bit bytes — the inverse of [`convertbits_8_to_5`].
///
/// `None` unless the trailing padding is exactly what the forward direction produces: fewer than
/// five leftover bits (five or more would mean a whole group carrying no data at all) and every one
/// of them zero. Sloppy padding is not harmless here — accepting it would give the same bytes two
/// or more spellings, i.e. a second "valid" way to write one address, so this rejects rather than
/// truncating. Same rule as BIP173's reference `convertbits` with `pad = false`.
///
/// Shared with [`crate::codec::cashaddr`], which needs it to recover the payload behind a verified
/// Kaspa-family checksum.
pub fn convertbits_5_to_8(data: &[u8]) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(data.len() * 5 / 8);
    for &v in data {
        if v > 31 {
            return None;
        }
        acc = (acc << 5) | u32::from(v);
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    // What is left in `acc` is the padding: at most four bits, every one of them zero.
    if bits >= 5 || acc & ((1u32 << bits) - 1) != 0 {
        return None;
    }
    Some(out)
}

/// Which bech32 checksum constant a string satisfied — selects SegWit v0 vs v1+ (Taproot).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    Bech32,
    Bech32m,
}

/// Verify a bech32 / bech32m string and return its lower-cased HRP + which checksum matched.
/// `None` if the case is mixed, the separator/charset is malformed, or the checksum fails — so
/// `Some` proves a structurally valid bech32(m) address. Only the HRP + variant are needed for
/// family detection, so the 5-bit payload is not converted back to bytes.
///
/// This is the *string* layer of BIP173/BIP350 and nothing above it. A `Some` says the argument is
/// a well-formed bech32(m) string, not that it is a usable SegWit address: the witness version, the
/// witness program length and the padding rules of BIP173 "Decoding" all live behind the 5-to-8
/// conversion this function never performs, and matching the HRP against a chain is the caller's
/// job ([`crate::validate::detect_family`]). The BIPs' invalid-*address* vectors that fail only on
/// one of those rules are therefore valid strings here; the tests below pin exactly which ones.
///
/// The [`Variant`] is detected, not requested: a string satisfies at most one of the two checksum
/// constants, so `Bech32m` coming back from a witness-v0 address means the address is wrong, not
/// that this function was lenient. Binding version to variant is again the caller's rule.
pub fn verify(s: &str) -> Option<(String, Variant)> {
    // Mixed case is invalid per BIP173 "Uppercase/lowercase": "Decoders MUST NOT accept strings
    // where some characters are uppercase and some are lowercase".
    let has_upper = s.bytes().any(|b| b.is_ascii_uppercase());
    let has_lower = s.bytes().any(|b| b.is_ascii_lowercase());
    if has_upper && has_lower {
        return None;
    }
    let lower = s.to_ascii_lowercase();
    // BIP173 "Bech32": "A Bech32 string is at most 90 characters long". The BCH code's error
    // detection was only ever analysed up to that length, so a longer string is not a bech32 string
    // even when its checksum comes out right — which is exactly the case for the BIPs'
    // `an84characters…` vectors. BIP350 inherits the limit unchanged. Counting bytes rather than
    // characters is sound because every byte that survives the checks below is ASCII.
    if lower.len() > 90 {
        return None;
    }
    let sep = lower.rfind('1')?;
    // Non-empty HRP and a 6-char checksum minimum after the separator.
    if sep == 0 || sep + 7 > lower.len() {
        return None;
    }
    let hrp = &lower[..sep];
    // BIP173 "Bech32": the human-readable part "MUST contain 1 to 83 US-ASCII characters, with each
    // character having a value in the range [33-126]". The 1-to-83 half falls out of the checks
    // above — a non-empty HRP followed by a separator and a six-character checksum inside 90
    // characters is at most 83 — but the character range does not, and `hrp_expand` will cheerfully
    // checksum bytes no encoder can emit: without this the BIPs' 0x20 and 0x7F vectors verify,
    // because their checksums were computed over exactly those out-of-range bytes.
    if hrp.bytes().any(|b| !(33..=126).contains(&b)) {
        return None;
    }
    let mut data = Vec::with_capacity(lower.len() - sep - 1);
    for c in lower[sep + 1..].bytes() {
        data.push(CHARSET.iter().position(|&x| x == c)? as u8);
    }
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(&data);
    match polymod(&values) {
        BECH32_CONST => Some((hrp.to_string(), Variant::Bech32)),
        BECH32M_CONST => Some((hrp.to_string(), Variant::Bech32m)),
        _ => None,
    }
}

/// Encode a SegWit program as a bech32 (v0) or bech32m (v1+) address.
///
/// Selects the checksum XOR constant by witness version: `BECH32_CONST` for v0,
/// `BECH32M_CONST` for v1 and above (BIP173 / BIP350).
pub fn encode(hrp: &str, witver: u8, program: &[u8]) -> String {
    let xor_const = if witver == 0 {
        BECH32_CONST
    } else {
        BECH32M_CONST
    };
    let mut data = vec![witver];
    data.extend(convertbits_8_to_5(program));

    let mut values = hrp_expand(hrp);
    values.extend_from_slice(&data);
    values.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    let chksum = polymod(&values) ^ xor_const;
    let checksum: Vec<u8> = (0..6)
        .map(|i| ((chksum >> (5 * (5 - i))) & 31) as u8)
        .collect();

    let mut s = String::with_capacity(hrp.len() + 1 + data.len() + 6);
    s.push_str(hrp);
    s.push('1');
    for &d in data.iter().chain(checksum.iter()) {
        s.push(CHARSET[d as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::Variant;
    use crate::hexbytes::{decode, hex32};

    /// The two conversions must be exact inverses for every byte length the address schemes use —
    /// 20 (HASH160), 32 (x-only key / script hash), 33 (compressed key), and the off-by-one
    /// neighbours that exercise each possible pad width (0-4 bits).
    #[test]
    fn convertbits_round_trips_every_relevant_length() {
        for n in [0usize, 1, 2, 3, 4, 5, 19, 20, 21, 31, 32, 33, 34] {
            // A pattern, not zeros: all-zero input round-trips even through a broken shift.
            let bytes: Vec<u8> = (0..n)
                .map(|i| (i as u8).wrapping_mul(37).wrapping_add(11))
                .collect();
            let five = super::convertbits_8_to_5(&bytes);
            assert_eq!(
                super::convertbits_5_to_8(&five),
                Some(bytes),
                "round trip failed for {n} bytes"
            );
        }
    }

    /// Padding is the part a decoder is tempted to wave through. Both failure modes have to be
    /// rejected, because either one gives some byte string a second spelling.
    #[test]
    fn convertbits_5_to_8_rejects_bad_padding() {
        // Non-zero pad bits: 2 groups = 10 bits = 1 byte + 2 pad bits, and here they are not zero.
        assert_eq!(super::convertbits_5_to_8(&[0, 1]), None);
        // A pad five bits wide: 3 groups = 15 bits = 1 byte + 7 left over, so the last group
        // carries no data at all and should never have been emitted.
        assert_eq!(super::convertbits_5_to_8(&[0, 0, 0]), None);
        // A group outside the 5-bit range cannot have come from the charset.
        assert_eq!(super::convertbits_5_to_8(&[32]), None);
    }

    #[test]
    fn bip173_segwit_v0_vector() {
        // HASH160(compressed G) — the privkey=1 witness program.
        let prog = decode("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        assert_eq!(
            super::encode("bc", 0, &prog),
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        );
    }

    #[test]
    fn bip86_taproot_still_v1_bech32m() {
        // Regression: witver 1 keeps bech32m (Pearl/BIP86 path).
        let out = hex32("a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c");
        assert_eq!(
            super::encode("bc", 1, &out),
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
        );
    }

    /// BIP173 "Test vectors", the strings listed as valid Bech32. The expected HRP is the text in
    /// front of the *last* `1`, which is why the two-`1` vector's HRP is a bare `1`.
    ///
    /// Asserting the [`Variant`] is half of BIP350's cross-check: `polymod` returns one number, so
    /// a string satisfying `BECH32_CONST` cannot also satisfy `BECH32M_CONST`. Pinning the variant
    /// is therefore the same statement as "none of these is valid Bech32m", which is what BIP350
    /// requires of them.
    #[test]
    fn every_valid_bip173_string_verifies_as_bech32_and_so_is_not_valid_bech32m() {
        const VALID: &[(&str, &str)] = &[
            ("A12UEL5L", "a"),
            ("a12uel5l", "a"),
            (
                "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
                "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio",
            ),
            ("abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw", "abcdef"),
            (
                "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
                "1",
            ),
            (
                "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
                "split",
            ),
            // The BIP warns this is what a lossy US-ASCII encoder turns `\x80` into; it is a
            // legitimate bech32 string all the same, and `?` (0x3F) is inside the HRP's [33-126].
            ("?1ezyfcl", "?"),
        ];
        for &(s, hrp) in VALID {
            assert_eq!(
                super::verify(s),
                Some((hrp.to_string(), Variant::Bech32)),
                "BIP-173 valid Bech32 vector {s:?} did not verify as Bech32"
            );
        }
    }

    /// BIP350 "Test vectors for Bech32m", the strings listed as valid Bech32m. BIP350: "No string
    /// can be simultaneously valid Bech32 and Bech32m, so the above examples also serve as invalid
    /// test vectors for Bech32" — asserting [`Variant::Bech32m`] is that statement, since `verify`
    /// reports the one constant a string actually satisfies.
    ///
    /// These are the same seven strings as the BIP173 list above with different checksums, which is
    /// what makes the pair worth having: an implementation that hard-codes either constant passes
    /// one of these two tests and fails the other.
    #[test]
    fn every_valid_bip350_string_verifies_as_bech32m_and_so_is_not_valid_bech32() {
        const VALID: &[(&str, &str)] = &[
            ("A1LQFN3A", "a"),
            ("a1lqfn3a", "a"),
            (
                "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
                "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber1",
            ),
            ("abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx", "abcdef"),
            (
                "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
                "1",
            ),
            (
                "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
                "split",
            ),
            ("?1v759aa", "?"),
        ];
        for &(s, hrp) in VALID {
            assert_eq!(
                super::verify(s),
                Some((hrp.to_string(), Variant::Bech32m)),
                "BIP-350 valid Bech32m vector {s:?} did not verify as Bech32m"
            );
        }
    }

    /// BIP173 "Test vectors": "The following string are not valid Bech32 (with reason for
    /// invalidity)". Each reason below is the BIP's own.
    ///
    /// Two published vectors are absent because no `&str` can hold them: `0x80 + 1eym55h` and
    /// `de1lg7wt + 0xFF` each contain a byte that is not valid UTF-8, and `verify` takes a `&str`.
    /// Nothing in this crate can reach `verify` with those bytes either — the fuzz target drops
    /// non-UTF-8 input for the same reason — so they are unreachable rather than untested.
    #[test]
    fn every_invalid_bip173_string_is_refused() {
        const INVALID: &[(&str, &str)] = &[
            ("\u{20}1nwldj5", "HRP character out of range (0x20, below 33)"),
            (
                "\u{7f}1axkwrx",
                "HRP character out of range (0x7F, above 126)",
            ),
            (
                "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
                "overall max length exceeded (91 characters)",
            ),
            ("pzry9x0s0muk", "No separator character"),
            ("1pzry9x0s0muk", "Empty HRP"),
            ("x1b4n0q5v", "Invalid data character"),
            ("li1dgmt3", "Too short checksum"),
            ("A1G7SGD8", "checksum calculated with uppercase form of HRP"),
            ("10a06t8", "empty HRP"),
            ("1qzzfhee", "empty HRP"),
        ];
        for &(s, reason) in INVALID {
            assert!(
                super::verify(s).is_none(),
                "accepted BIP-173 invalid vector {s:?} — {reason}"
            );
        }
    }

    /// BIP350 "Test vectors for Bech32m": "The following string are not valid Bech32m (with reason
    /// for invalidity)". `0x80 + 1vctc34` is absent for the same reason as its BIP173 twin — a lone
    /// 0x80 byte is not valid UTF-8, so no `&str` API can be handed it.
    #[test]
    fn every_invalid_bip350_string_is_refused() {
        const INVALID: &[(&str, &str)] = &[
            ("\u{20}1xj0phk", "HRP character out of range (0x20, below 33)"),
            (
                "\u{7f}1g6xzxy",
                "HRP character out of range (0x7F, above 126)",
            ),
            (
                "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4",
                "overall max length exceeded (91 characters)",
            ),
            ("qyrz8wqd2c9m", "No separator character"),
            ("1qyrz8wqd2c9m", "Empty HRP"),
            ("y1b0jsk6g", "Invalid data character"),
            ("lt1igcx5c0", "Invalid data character"),
            ("in1muywd", "Too short checksum"),
            ("mm1crxm3i", "Invalid character in checksum"),
            ("au1s5cgom", "Invalid character in checksum"),
            ("M1VUXWEZ", "checksum calculated with uppercase form of HRP"),
            ("16plkw9", "empty HRP"),
            ("1p2gdwpf", "empty HRP"),
        ];
        for &(s, reason) in INVALID {
            assert!(
                super::verify(s).is_none(),
                "accepted BIP-350 invalid vector {s:?} — {reason}"
            );
        }
    }

    /// The invalid-*address* vectors of BIP173 and BIP350 that a checksum verifier can reject on
    /// its own: a broken checksum, and mixed case. Everything else in those two lists fails on a
    /// SegWit rule that lives above this function — see the tests below.
    ///
    /// The mixed-case pair is what makes `verify`'s opening guard load-bearing: delete it and both
    /// of those strings verify, because lower-casing them restores a valid checksum. The comment on
    /// that guard is a claim, and this is the test that keeps it true.
    #[test]
    fn an_address_vector_with_a_broken_checksum_or_mixed_case_is_refused() {
        const INVALID: &[(&str, &str)] = &[
            (
                // BIP-173: its own valid `…kv8f3t4` vector with the last character bumped.
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
                "BIP-173 invalid address: Invalid checksum",
            ),
            (
                "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
                "BIP-173 invalid address: Mixed case",
            ),
            (
                "bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4",
                "BIP-350 invalid address: Invalid character in checksum",
            ),
            (
                "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq",
                "BIP-350 invalid address: Mixed case",
            ),
        ];
        for &(s, reason) in INVALID {
            assert!(super::verify(s).is_none(), "accepted {s:?} — {reason}");
        }
    }

    /// The invalid-address vectors that are nevertheless well-formed bech32(m) *strings*. Their
    /// checksums are correct; what is wrong with them is a SegWit rule — an unmodelled HRP, a
    /// witness version above 16, a witness program of an illegal length, or padding, none of which
    /// `verify` looks at because it never converts the 5-bit payload back to bytes.
    ///
    /// Pinning them as `Some` is not an endorsement, it is the module boundary written down: if one
    /// of these ever starts returning `None`, `verify` has grown a SegWit opinion and the caller's
    /// checks are no longer the only ones. `bc1gmk9yu` is the clearest case — "Empty data section"
    /// makes it an invalid *address*, while as a *string* it is a textbook valid bech32: an empty
    /// data part followed by a six-character checksum.
    #[test]
    fn an_address_vector_that_breaks_only_a_segwit_rule_is_still_a_valid_bech32_string() {
        const STILL_VALID: &[(&str, &str, Variant, &str)] = &[
            // BIP-173's "invalid segwit addresses".
            (
                "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty",
                "tc",
                Variant::Bech32,
                "Invalid human-readable part",
            ),
            (
                "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2",
                "bc",
                Variant::Bech32,
                "Invalid witness version",
            ),
            (
                "bc1rw5uspcuh",
                "bc",
                Variant::Bech32,
                "Invalid program length",
            ),
            (
                "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
                "bc",
                Variant::Bech32,
                "Invalid program length",
            ),
            (
                "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
                "bc",
                Variant::Bech32,
                "Invalid program length for witness version 0 (per BIP141)",
            ),
            (
                "bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du",
                "bc",
                Variant::Bech32,
                "zero padding of more than 4 bits",
            ),
            (
                "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
                "tb",
                Variant::Bech32,
                "Non-zero padding in 8-to-5 conversion",
            ),
            ("bc1gmk9yu", "bc", Variant::Bech32, "Empty data section"),
            // BIP-350's "invalid segwit addresses". Its list repeats two of BIP-173's strings
            // verbatim (`BC1QR508…` and `bc1gmk9yu`), which are covered above rather than twice.
            (
                "tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut",
                "tc",
                Variant::Bech32m,
                "Invalid human-readable part",
            ),
            (
                "BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R",
                "bc",
                Variant::Bech32m,
                "Invalid witness version",
            ),
            (
                "bc1pw5dgrnzv",
                "bc",
                Variant::Bech32m,
                "Invalid program length (1 byte)",
            ),
            (
                "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav",
                "bc",
                Variant::Bech32m,
                "Invalid program length (41 bytes)",
            ),
            (
                "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf",
                "bc",
                Variant::Bech32m,
                "zero padding of more than 4 bits",
            ),
            (
                "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j",
                "tb",
                Variant::Bech32m,
                "Non-zero padding in 8-to-5 conversion",
            ),
        ];
        for &(s, hrp, variant, reason) in STILL_VALID {
            assert_eq!(
                super::verify(s),
                Some((hrp.to_string(), variant)),
                "{s:?} is invalid as an address ({reason}) but is a valid bech32(m) string"
            );
        }
    }

    /// The four padding vectors are the one class above `verify` this module can still answer for:
    /// [`convertbits_5_to_8`] is exactly the "Re-arrange those bits into groups of 8 bits" step of
    /// BIP173 "Decoding", and both of the BIPs' padding reasons are its two rejection cases. So the
    /// vectors are not out of scope for the crate, only for `verify` — a caller that converts the
    /// payload gets the BIP's verdict, and this pins that it does.
    #[test]
    fn every_padding_vector_is_refused_by_the_five_to_eight_conversion() {
        /// The witness program of an address, as 5-bit groups: everything after the separator, less
        /// the six checksum characters and the leading witness-version character.
        fn program_groups(addr: &str) -> Vec<u8> {
            let lower = addr.to_ascii_lowercase();
            let sep = lower.rfind('1').unwrap();
            lower[sep + 1..lower.len() - 6]
                .bytes()
                .skip(1)
                .map(|c| super::CHARSET.iter().position(|&x| x == c).unwrap() as u8)
                .collect()
        }

        const BAD_PADDING: &[(&str, &str)] = &[
            (
                "bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du",
                "BIP-173: zero padding of more than 4 bits",
            ),
            (
                "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
                "BIP-173: Non-zero padding in 8-to-5 conversion",
            ),
            (
                "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf",
                "BIP-350: zero padding of more than 4 bits",
            ),
            (
                "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j",
                "BIP-350: Non-zero padding in 8-to-5 conversion",
            ),
        ];
        for &(s, reason) in BAD_PADDING {
            assert!(super::verify(s).is_some(), "{s:?} should still checksum");
            assert_eq!(
                super::convertbits_5_to_8(&program_groups(s)),
                None,
                "converted the payload of {s:?} — {reason}"
            );
        }

        // The control: the same treatment of a valid address yields its 20-byte program, so the
        // rejections above are about the padding and not about how `program_groups` slices.
        assert_eq!(
            super::convertbits_5_to_8(&program_groups(
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
            )),
            Some(decode("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap())
        );
    }

    /// BIP350's cross-variant address vectors: a SegWit address whose checksum was computed with
    /// the *other* constant. That is the failure mode BIP350 exists to make detectable, so it is
    /// worth being explicit about where it gets detected.
    ///
    /// `verify` detects the variant instead of being told one, so it accepts each of these and
    /// reports the constant the string actually carries — a v1+ address that says `Bech32`, or a v0
    /// address that says `Bech32m`. Nothing is lost by that: the reported variant is exactly the
    /// evidence a caller needs, and [`crate::validate::detect_family`] maps it straight onto
    /// SegwitV0 vs Taproot. What this pins is that the mismatch is *reported* and never silently
    /// smoothed over by retrying the other constant.
    #[test]
    fn an_address_checksummed_with_the_other_constant_reports_the_constant_it_carries() {
        const CROSSED: &[(&str, &str, Variant, &str)] = &[
            (
                "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
                "bc",
                Variant::Bech32,
                "witness version 1, Bech32 instead of Bech32m",
            ),
            (
                "tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf",
                "tb",
                Variant::Bech32,
                "witness version 2, Bech32 instead of Bech32m",
            ),
            (
                "BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL",
                "bc",
                Variant::Bech32,
                "witness version 16, Bech32 instead of Bech32m",
            ),
            (
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",
                "bc",
                Variant::Bech32m,
                "witness version 0, Bech32m instead of Bech32",
            ),
            (
                "tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47",
                "tb",
                Variant::Bech32m,
                "witness version 0, Bech32m instead of Bech32",
            ),
        ];
        for &(s, hrp, variant, reason) in CROSSED {
            assert_eq!(
                super::verify(s),
                Some((hrp.to_string(), variant)),
                "{s:?} ({reason}) was not reported as {variant:?}"
            );
        }
    }

    /// The cross-check reduced to a single pair of strings. BIP350 publishes `BC1QW508…KV8F3T4` as
    /// a valid address and `bc1qw508…kemeawh` as "Invalid checksum (Bech32m instead of Bech32)",
    /// and the two differ in nothing but their six checksum characters — same HRP, same witness
    /// version, same program, other constant. That difference is the whole of what BIP350 changed.
    #[test]
    fn the_bech32m_twin_of_a_valid_v0_address_differs_only_in_its_checksum() {
        let prog = decode("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        let v0 = super::encode("bc", 0, &prog);
        assert_eq!(v0, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        assert_eq!(
            super::verify(&v0),
            Some(("bc".to_string(), Variant::Bech32))
        );

        let crossed = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh";
        assert_eq!(&v0[..v0.len() - 6], &crossed[..crossed.len() - 6]);
        assert_eq!(
            super::verify(crossed),
            Some(("bc".to_string(), Variant::Bech32m))
        );
    }

    /// Regression for the two rules `verify` was missing until these vectors were asserted. Neither
    /// can be caught by the checksum: the strings below carry checksums computed over exactly the
    /// bytes the BIP forbids, so `polymod` agrees with them and only an explicit rule can say no.
    #[test]
    fn a_string_the_checksum_agrees_with_is_still_refused_when_it_breaks_a_structural_rule() {
        // BIP173 "Bech32": the HRP's characters must be in [33-126]. 0x20 is one below the floor
        // and 0x7F one above the ceiling, so this pair pins both ends of the range.
        assert!(super::verify("\u{20}1nwldj5").is_none());
        assert!(super::verify("\u{7f}1axkwrx").is_none());
        assert!(super::verify("\u{20}1xj0phk").is_none());
        assert!(super::verify("\u{7f}1g6xzxy").is_none());
        // …and the neighbouring in-range values still verify, so the bound is the BIP's rather than
        // an accident: `!` is 33 and `~` is 126.
        assert_eq!(
            super::verify(&super::encode("!", 0, &[0u8; 20])),
            Some(("!".to_string(), Variant::Bech32))
        );
        assert_eq!(
            super::verify(&super::encode("~", 0, &[0u8; 20])),
            Some(("~".to_string(), Variant::Bech32))
        );

        // BIP173 "Bech32": "A Bech32 string is at most 90 characters long". Both BIPs publish a
        // 91-character vector whose checksum is correct; its length is the only thing wrong with it.
        let long_bech32 = "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx";
        let long_bech32m = "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4";
        assert_eq!(long_bech32.len(), 91);
        assert_eq!(long_bech32m.len(), 91);
        assert!(super::verify(long_bech32).is_none());
        assert!(super::verify(long_bech32m).is_none());
        // 90 still verifies, so the limit is off by none: these are the BIPs' longest valid
        // vectors, one per constant.
        assert!(super::verify(
            "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs"
        )
        .is_some());
        assert!(super::verify(
            "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6"
        )
        .is_some());
    }
}
