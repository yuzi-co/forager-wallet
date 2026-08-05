use crate::{codec::base58, curves::secp256k1, hash};

/// Derive a Bitcoin-style P2PKH address: `BASE58CHECK(version ‖ HASH160(pubkey))`.
///
/// `version` is a byte **slice**, not a byte: Bitcoin-family coins use a one-byte prefix, and
/// Zcash-family transparent addresses use two (`0x1C,0xB8` → `t1…`). [`crate::hd`] calls the same
/// encoder, so the single-key and BIP44 paths cannot drift apart.
///
/// Both hashes are Bitcoin's and neither is a parameter: HASH160 here, SHA256d inside
/// [`base58::encode_check`]. `coins::FamilyParams::P2pkh` carries version bytes only, so a caller
/// choosing this encoder is also choosing that pair — right for every coin in the table and for
/// every Bitcoin-derived fork, wrong for Groestlcoin and Decred, which are cited and warned about
/// in `coins::FamilyParams::P2pkh` and in the `p2pkh:` coin token's caveat.
pub(crate) fn address(d: &secp256k1::Secret, version: &[u8], compressed: bool) -> String {
    let pk = if compressed {
        secp256k1::pubkey_compressed(d).to_vec()
    } else {
        secp256k1::pubkey_uncompressed(d).to_vec()
    };
    address_from_pubkey(&pk, version)
}

/// `BASE58CHECK(version ‖ HASH160(pubkey))` for an already-serialised pubkey — the shared tail of
/// [`address`] and of the BIP44 derivation in [`crate::hd`].
pub(crate) fn address_from_pubkey(pubkey: &[u8], version: &[u8]) -> String {
    let mut payload = Vec::with_capacity(version.len() + 20);
    payload.extend_from_slice(version);
    payload.extend_from_slice(&hash::hash160(pubkey));
    base58::encode_check(&payload)
}

#[cfg(test)]
mod tests {
    use super::address;
    use crate::curves::secp256k1::secret_from_hex;

    /// The two hash primitives this family hard-wires, pinned end to end: the decoded payload is
    /// exactly `version ‖ HASH160(pubkey)`, and it decodes at all only because the checksum is
    /// SHA256d — `base58::decode_check` verifies that before returning `Some`.
    ///
    /// No coin row selects either hash, so this is the only place the pair is asserted. A chain
    /// that changes one (Groestlcoin's Groestl-512 checksum, Decred's BLAKE-256) cannot be minted
    /// here, and the `p2pkh:` coin token's caveat tells the user so; whoever changes a primitive
    /// must fail this test first and update that text with it.
    #[test]
    fn a_p2pkh_address_is_hash160_under_a_double_sha256_base58check() {
        use crate::codec::base58;
        use crate::curves::secp256k1::pubkey_compressed;

        let d = secret_from_hex("01");
        let pubkey = pubkey_compressed(&d).to_vec();
        let decoded = base58::decode_check(&super::address_from_pubkey(&pubkey, &[0x00]))
            .expect("the checksum is SHA256d, so decode_check accepts it");

        let mut expected = vec![0x00u8];
        expected.extend_from_slice(&crate::hash::hash160(&pubkey));
        assert_eq!(decoded, expected);
    }

    #[test]
    fn btc_p2pkh_privkey_one() {
        let d = secret_from_hex("01");
        assert_eq!(
            address(&d, &[0x00], true),
            "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
        );
    }

    /// A two-byte Zcash-family prefix renders a `t1…` transparent address from the same key — the
    /// width the previous single-byte signature could not express.
    #[test]
    fn two_byte_prefix_renders_zcash_t_address() {
        let d = secret_from_hex("01");
        let addr = address(&d, &[0x1c, 0xb8], true);
        assert!(addr.starts_with("t1"), "zcash t-address was {addr}");
    }
}
