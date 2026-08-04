use crate::{codec::base58, curves::secp256k1, hash};

/// XDAG modern "account" address: `BASE58CHECK(HASH160(compressed_pubkey))` — Bitcoin's hash160
/// and Base58Check, but with **no version byte** prepended (the one deviation from P2PKH).
///
/// Pinned to `XDagger/xdagj` (MIT): `crypto/keys/AddressUtils.toBytesAddress` (compressed pubkey
/// → `HashUtils.sha256hash160` = `RIPEMD160(SHA256(pk))`) then `crypto/encoding/Base58.encodeCheck`
/// (append `SHA256(SHA256(payload))[0..4]`, Base58-encode). This block-independent format is the
/// one the current node's wallet/CLI/RPC and the live pool-reward path all use; a freshly
/// generated key yields a usable address with no on-chain block required. See `docs/algos/xdag.md`.
pub(crate) fn address(d: &secp256k1::Secret) -> String {
    let pk = secp256k1::pubkey_compressed(d).to_vec();
    // No version byte: the payload is the bare 20-byte hash160; `encode_check` appends the
    // 4-byte double-SHA256 checksum. (Contrast `p2pkh::address`, which prepends a version byte.)
    base58::encode_check(&hash::hash160(&pk))
}

#[cfg(test)]
mod tests {
    use super::address;
    use crate::hexbytes::encode as hex;
    use crate::{curves::secp256k1, hash};

    /// KAT from xdagj's hardcoded `SampleKeys.java` keypair (MIT). `PRIVATE_KEY_STRING` derives
    /// the compressed pubkey `02506bc1…6aaba` (`PUBLIC_KEY_COMPRESS_STRING`), whose XDAG address
    /// is `Base58Check(hash160(pubkey))` with no version byte. Cross-checked against xdagj's own
    /// derivation; the checksum/alphabet are further gated by xdagj's `PubkeyAddressUtilsTest`
    /// valid/invalid literals. NB: `SampleKeys.ADDRESS` is the *Ethereum* address for this key,
    /// not the XDAG one — do not confuse them.
    #[test]
    fn xdag_address_from_xdagj_sample_key() {
        let priv_hex = "a392604efc2fad9c0b3da43b5f698a2e3f270f170d859912be0d54742275c5f6";
        let d = secp256k1::secret_from_hex(priv_hex);
        // Intermediate cross-checks isolate a failure to pubkey vs hash160 vs encoding.
        let pk = secp256k1::pubkey_compressed(&d).to_vec();
        assert_eq!(
            hex(&pk),
            "02506bc1dc099358e5137292f4efdd57e400f29ba5132aa5d12b18dac1c1f6aaba"
        );
        assert_eq!(
            hex(&hash::hash160(&pk)),
            "e6cfaab9a59ba187f0a45db0b169c21bb48f09b3"
        );
        assert_eq!(address(&d), "N3RC53vbaDNrziTdWmctBEeQ4fo38moXu");
    }
}
