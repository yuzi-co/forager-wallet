use crate::{codec::bech32, curves::secp256k1, hash};

/// Derive a SegWit v0 P2WPKH address: `HASH160(compressed_pubkey)` encoded as bech32.
pub(crate) fn address(d: &secp256k1::Secret, hrp: &str) -> String {
    let program = hash::hash160(&secp256k1::pubkey_compressed(d));
    bech32::encode(hrp, 0, &program)
}

#[cfg(test)]
mod tests {
    use crate::curves::secp256k1::secret_from_hex;

    use super::address;

    #[test]
    fn segwit_v0_privkey_one() {
        assert_eq!(
            address(&secret_from_hex("01"), "bc"),
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        );
    }
}
