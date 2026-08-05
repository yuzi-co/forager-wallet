use sha2::{Digest, Sha256};

// Keccak-256, for Ethereum's address derivation and EIP-55 case checksum and for the CryptoNote
// address checksum. The implementation used to live here, in `src/keccak.rs`; it moved down into
// `forager-addr` when detection grew a use for it — the classification half verifies both of those
// checksums, and the same hash computing and checking a consensus-critical value has to be one
// implementation, not two that can drift. `forager-addr` carries no curve, entropy source or
// wordlist, so nothing about the split changed by moving a hash across it.
pub(crate) use forager_addr::hash::keccak256;

/// BIP340 tagged hash: `SHA256(SHA256(tag) ‖ SHA256(tag) ‖ msg)`.
pub(crate) fn tagged_hash(tag: &str, msg: &[u8]) -> [u8; 32] {
    let t = Sha256::digest(tag.as_bytes());
    let mut h = Sha256::new();
    h.update(t);
    h.update(t);
    h.update(msg);
    h.finalize().into()
}

pub(crate) fn hash160(data: &[u8]) -> [u8; 20] {
    crate::ripemd160::ripemd160(&Sha256::digest(data))
}

#[cfg(test)]
mod tests {
    use super::hash160;
    use crate::hexbytes;

    #[test]
    fn hash160_of_secp_g_compressed() {
        // HASH160 of the compressed pubkey for privkey=1 (point G).
        let g =
            hexbytes::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap();
        assert_eq!(
            hexbytes::encode(&hash160(&g)),
            "751e76e8199196d454941c45d1b3a323f1433bd6"
        );
    }
}
