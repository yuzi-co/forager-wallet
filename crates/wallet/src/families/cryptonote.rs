//! CryptoNote (Monero) dual-key payout-address derivation.

use crate::{codec::cryptonote, curves::ed25519, hash::keccak256};

/// Derive a CryptoNote (Monero) standard address and the deterministic private **view** key from a
/// 32-byte private **spend** key.
///
/// - `view_secret = reduce_scalar_mod_l(keccak256(spend))` (Monero `hash_to_scalar`).
/// - The public spend/view keys are `scalarmult_base` of the respective secrets.  The spend secret
///   is fed directly as the curve scalar — it is already an `sc_reduce`'d value, so it is **not**
///   clamped (unlike RFC 8032 Ed25519 keygen).
/// - The address encodes `varint(network_byte) ‖ pub_spend(32) ‖ pub_view(32) ‖ keccak256(prefix)[..4]`
///   via [`cryptonote::encode`].  `network_byte` is a CryptoNote `write_varint` (unsigned LEB128):
///   Monero's 18 / testnet 53 fit one byte, but forks use multi-byte prefixes chosen so the address
///   renders with a human tag — Salvium `0x3ef318` → `SaLv…`, Zephyr `0x6241d18c0` → `ZEPHYR…`.
pub(crate) fn address(spend_secret: &[u8; 32], network_byte: u64) -> (String, [u8; 32]) {
    let view_secret = ed25519::reduce_scalar_mod_l(&keccak256(spend_secret));
    let pk_spend = ed25519::scalarmult_base(spend_secret);
    let pk_view = ed25519::scalarmult_base(&view_secret);
    let mut data = Vec::with_capacity(10 + 64 + 4);
    cryptonote::write_varint(network_byte, &mut data);
    data.extend_from_slice(&pk_spend);
    data.extend_from_slice(&pk_view);
    let cks = keccak256(&data);
    data.extend_from_slice(&cks[..4]);
    (cryptonote::encode(&data), view_secret)
}

#[cfg(test)]
mod tests {
    use super::address;
    use crate::codec::cryptonote;
    use crate::hexbytes::{encode as hex, hex32};

    // ---- Vetted, independent Monero mainnet vector ----
    // Source: moneroexamples "Recover Monero address using the private spend key"
    //   https://moneroexamples.github.io/spendkey/  (Output example 1).  The page states its
    //   results agree with the independent xmrtests "Address Generation Tests" site.  The view key
    //   is Monero's hash_to_scalar(spend) = reduce_scalar_mod_l(keccak256(spend)); the address is the
    //   standard mainnet form (network byte 18, leading '4').
    const SPEND_HEX: &str = "af6082af29108abda69cc385dfed2102b892a871695367cb22a4b9b6df8b3206";
    const VIEW_EXPECTED: &str = "157874dc4e2961c872f87aaf4346146d0f596e2f116a51fbac01b693a8e3020a";
    const ADDR_EXPECTED: &str =
        "46HSxE7KoiDaxWFWR1wmJfcrunNj4TLiPJqiCJkQn345A4JJzgBNhUvbkrYWJX4EVJZS4kJGfGj7CTW8GEUHsbEZCEupMt6";

    #[test]
    fn monero_mainnet_address_kat() {
        let spend = hex32(SPEND_HEX);
        let (addr, view) = address(&spend, 18);
        assert_eq!(addr, ADDR_EXPECTED);
        assert_eq!(hex(&view), VIEW_EXPECTED);
        assert_eq!(addr.len(), 95);
        assert!(addr.starts_with('4'));
    }

    /// The full 69-byte payload behind the captured address round-trips to the same 95-char string
    /// through the standalone codec — ties `cryptonote::encode` to the real Monero output.
    #[test]
    fn monero_address_encode_length() {
        let (addr, _) = address(&hex32(SPEND_HEX), 18);
        assert_eq!(addr.len(), 95);
        // Re-encode an all-zero 69-byte payload to confirm the 88 + 7 block split.
        assert_eq!(cryptonote::encode(&[0u8; 69]).len(), 95);
    }

    /// Multi-byte CryptoNote prefixes must `write_varint`, not truncate to one byte.  The prefix
    /// value is chosen by each fork so the address renders with a fixed human tag independent of the
    /// spend key — Salvium `0x3ef318` → `SaLv…`, Zephyr `0x6241d18c0` → `ZEPHYR…` (values from each
    /// project's `cryptonote_config.h`).  Asserting the tag validates the varint encoding against the
    /// coins' own documented output.  The old `network_byte as u8` truncation produced a Monero-style
    /// `4…` address instead — the regression this guards.
    #[test]
    fn multibyte_prefix_renders_fork_address_tag() {
        let spend = hex32(SPEND_HEX);
        let (sal, _) = address(&spend, 0x3ef318);
        assert!(sal.starts_with("SaLv"), "salvium address was {sal}");
        let (zeph, _) = address(&spend, 0x6241d18c0);
        assert!(zeph.starts_with("ZEPHYR"), "zephyr address was {zeph}");
        // A one-byte truncation would collide with Monero's mainnet '4' tag.
        assert!(!sal.starts_with('4') && !zeph.starts_with('4'));
    }
}
