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
use super::bech32::{convertbits_8_to_5, CHARSET};

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
    let fivebit_prefix = prefix.bytes().map(|c| c & 0x1f);
    polymod(
        fivebit_prefix
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
    let fivebit_payload = convertbits_8_to_5(&full);

    let chk = checksum(&fivebit_payload, prefix);
    // Checksum is 40 bits (8 five-bit groups): the low 5 bytes of the 8-byte big-endian repr.
    let chk_5bit = convertbits_8_to_5(&chk.to_be_bytes()[3..]);

    let mut s = String::with_capacity(prefix.len() + 1 + fivebit_payload.len() + chk_5bit.len());
    s.push_str(prefix);
    s.push(':');
    for &d in fivebit_payload.iter().chain(chk_5bit.iter()) {
        s.push(CHARSET[d as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::encode;
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
}
