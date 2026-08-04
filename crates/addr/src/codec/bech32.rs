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
