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
pub fn verify(s: &str) -> Option<(String, Variant)> {
    // Mixed case is invalid per BIP173.
    let has_upper = s.bytes().any(|b| b.is_ascii_uppercase());
    let has_lower = s.bytes().any(|b| b.is_ascii_lowercase());
    if has_upper && has_lower {
        return None;
    }
    let lower = s.to_ascii_lowercase();
    let sep = lower.rfind('1')?;
    // Non-empty HRP and a 6-char checksum minimum after the separator.
    if sep == 0 || sep + 7 > lower.len() {
        return None;
    }
    let hrp = &lower[..sep];
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
}
