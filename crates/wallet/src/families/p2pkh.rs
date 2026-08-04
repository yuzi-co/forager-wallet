use crate::{codec::base58, curves::secp256k1, hash};

/// Derive a Bitcoin-style P2PKH address: `BASE58CHECK(version ‖ HASH160(pubkey))`.
///
/// `version` is a byte **slice**, not a byte: Bitcoin-family coins use a one-byte prefix, and
/// Zcash-family transparent addresses use two (`0x1C,0xB8` → `t1…`). [`crate::hd`] calls the same
/// encoder, so the single-key and BIP44 paths cannot drift apart.
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
