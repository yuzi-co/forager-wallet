use crate::{codec::base58, curves::secp256k1};

const ADDR_TYPE_P2PKH: u8 = 0x00;

/// Derive an Alephium P2PKH address: `Base58(0x00 ‖ Blake2b256(compressed_pubkey))`.
///
/// No checksum and no network byte — unlike Bitcoin/Ergo, Alephium addresses carry no built-in
/// checksum, and they are network-agnostic (mainnet vs testnet is chosen out-of-band by which
/// node/API a wallet talks to, not encoded in the address itself).
///
/// Source: `alephium/alephium-web3` `packages/web3/src/address/address.ts`
/// (`addressFromPublicKey`, default `keyType`) + `AddressType.P2PKH = 0x00`.
pub(crate) fn address(d: &secp256k1::Secret) -> String {
    let pk = secp256k1::pubkey_compressed(d);
    let hash = blake2b_simd::Params::new().hash_length(32).hash(&pk);

    let mut body = vec![ADDR_TYPE_P2PKH];
    body.extend_from_slice(hash.as_bytes());
    base58::encode(&body)
}

#[cfg(test)]
mod tests {
    use super::address;
    use crate::curves::secp256k1::secret_from_hex;

    // Official end-to-end KAT from `alephium/alephium-web3`
    // `packages/web3/src/address/address.test.ts` ("should compute address from public key"),
    // cross-referenced with `publicKeyFromPrivateKey` in the same test file (same privkey derives
    // the pubkey the address test starts from) — a genuine privkey -> address oracle vector, not
    // a self-composed one.
    #[test]
    fn alph_official_privkey_kat() {
        let d = secret_from_hex("91411e484289ec7e8b3058697f53f9b26fa7305158b4ef1a81adfbabcf090e45");
        assert_eq!(address(&d), "1ACCkgFfmTif46T3qK12znuWjb5Bk9jXpqaeWt2DXx8oc");
    }
}
