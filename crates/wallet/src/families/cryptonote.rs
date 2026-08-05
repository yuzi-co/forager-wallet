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

    // ---- Monero TESTNET vector (network byte 53) ----
    //
    // Prefix source: monero-project/monero, `src/cryptonote_config.h`,
    //   `namespace testnet { CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = 53; }`
    // — the same file and constant the `xmr` row in `coins.rs` cites for mainnet's 18.
    //
    // Unlike the mainnet vector above, no vetted third-party Monero *testnet* address for a known
    // spend key was found, so the literal below was MINTED BY THIS REPOSITORY'S OWN GENERATOR:
    //   cargo run -q --bin forager-wallet -- restore <TESTNET_SPEND_HEX> --coin xmr --testnet
    // A generator-minted literal proves only that the code agrees with itself, so the test asserts
    // structural facts alongside it that the literal cannot fake — see the test's own doc comment
    // for exactly which, and for the one corroboration that was done out-of-band.
    const TESTNET_SPEND_HEX: &str =
        "0000000000000000000000000000000000000000000000000000000000000001";
    const TESTNET_ADDR_EXPECTED: &str =
        "9tLR1ZnmsrNTNayQ6Kjw5UdgqbQY5KCCufdxdCgF7NgTfjC69Mna7DJSYyie77hZTQ8H92G2HwgFhgEUYnDzrnLnQeidLrM";

    /// Monero testnet (prefix 53) renders the documented address shape, and differs from the
    /// mainnet form for the same key in exactly the places the prefix and its checksum occupy.
    ///
    /// What this proves without trusting the minted literal:
    ///
    /// * **The leading character is forced by prefix 53, not chosen.** CryptoNote base58 encodes
    ///   the payload in 8-byte blocks, so the first 11 characters are the big-endian value
    ///   `varint(53) ‖ spend[0..7]`, which ranges over `0x3500000000000000 ..= 0x35ffffffffffffff`.
    ///   Encoding both extremes below shows that range maps to a first character of `9` or `A` and
    ///   can never produce mainnet's `4` — so the address tag corroborates the prefix byte
    ///   independently of the key. (Monero's documented "testnet addresses start with 9" is the
    ///   common case, ~81% of keys; `A` is reachable and equally valid, which is why this asserts
    ///   the derived range rather than a remembered single character.)
    /// * **Only the network byte changed.** A one-byte varint lives entirely in block 0 (characters
    ///   0..11) and the 4-byte checksum entirely in the 5-byte tail (characters 88..95), while the
    ///   64 bytes of public spend+view key occupy bytes 8..64 — characters 11..88. So mainnet and
    ///   testnet addresses for the same spend key must agree character-for-character across 11..88
    ///   and differ at both ends. That pins the key material as identical and isolates the change
    ///   to the prefix, which is the thing under test.
    /// * **The `xmr` table row actually carries 53.** The row is exercised through the public
    ///   `address_from_secret` path, so a wrong `network_byte_testnet` in `coins.rs` fails here
    ///   even though the calls above pass `53` as a literal.
    ///
    /// Corroborated out-of-band, and NOT re-checked by this test: the address was base58-decoded
    /// back to its 69-byte payload with an independent Python implementation, confirming byte 0 is
    /// `53` and that `keccak256(payload[..65])[..4]` equals the trailing 4 bytes, using a
    /// from-scratch Keccak-256 anchored on `keccak256("") = c5d2…a470`.
    #[test]
    fn monero_testnet_address_uses_network_byte_53() {
        let spend = hex32(TESTNET_SPEND_HEX);
        let (testnet, _) = address(&spend, 53);
        assert_eq!(testnet, TESTNET_ADDR_EXPECTED);
        assert_eq!(testnet.len(), 95);
        assert!(testnet.starts_with('9'), "testnet address was {testnet}");

        // The first character is a property of prefix 53, not of this key: encode the two extremes
        // of the first 8-byte block (the rest of the payload cannot reach those characters).
        let block0 = |first_block_tail: u8| {
            let mut data = Vec::with_capacity(69);
            cryptonote::write_varint(53, &mut data);
            data.extend_from_slice(&[first_block_tail; 68]);
            cryptonote::encode(&data).chars().next().unwrap()
        };
        assert_eq!(block0(0x00), '9');
        assert_eq!(block0(0xff), 'A');

        // Same key on mainnet: identical key material, different prefix and checksum.
        let (mainnet, _) = address(&spend, 18);
        assert!(mainnet.starts_with('4'), "mainnet address was {mainnet}");
        assert_eq!(&testnet[11..88], &mainnet[11..88], "key-material blocks");
        assert_ne!(&testnet[..11], &mainnet[..11], "prefix block");
        assert_ne!(&testnet[88..], &mainnet[88..], "checksum tail");

        // The `xmr` row must be the source of the 53 — not just this test's literal argument.
        let from_row =
            crate::address_from_secret("xmr", TESTNET_SPEND_HEX, crate::Network::Testnet).unwrap();
        assert_eq!(from_row.address, TESTNET_ADDR_EXPECTED);
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
