use crate::{codec::base58, curves::secp256k1};

const NETWORK_MAINNET: u8 = 0x00;
const NETWORK_TESTNET: u8 = 0x10;
const ADDR_TYPE_P2PK: u8 = 0x01;

/// Derive an Ergo P2PK address: `Base58(prefix_byte ‖ compressed_pubkey ‖ checksum)`, where
/// `prefix_byte = network_prefix + address_type` and `checksum = Blake2b256(prefix_byte ‖
/// compressed_pubkey)[..4]`.
///
/// Source: `ergoplatform/sigma-rust` `ergotree-ir/src/chain/address.rs` (`AddressEncoder`) +
/// `ergo-chain-types/src/ec_point.rs` (confirms the P2PK content bytes are the plain SEC1
/// compressed point — same 33-byte encoding as [`secp256k1::pubkey_compressed`], no extra
/// wrapping). Network bytes: Mainnet = 0x00, Testnet = 0x10; address type P2PK = 0x01.
pub(crate) fn address(d: &secp256k1::Secret, testnet: bool) -> String {
    let network = if testnet {
        NETWORK_TESTNET
    } else {
        NETWORK_MAINNET
    };
    let mut body = vec![network + ADDR_TYPE_P2PK];
    body.extend_from_slice(&secp256k1::pubkey_compressed(d));

    let checksum = blake2b_simd::Params::new().hash_length(32).hash(&body);
    body.extend_from_slice(&checksum.as_bytes()[..4]);
    base58::encode(&body)
}

#[cfg(test)]
mod tests {
    use super::address;
    use crate::curves::secp256k1::secret_from_hex;

    // Independent oracle: Python stdlib `hashlib.blake2b(body, digest_size=32)` (confirmed a
    // proper BLAKE2b-256 parameterization, not a BLAKE2b-512 truncation, against the well-known
    // `blake2b-256("") = 0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8` vector)
    // + a hand-rolled base58 encoder, computed from the same G-compressed pubkey already
    // KAT-verified elsewhere in this crate (`hash::tests::hash160_of_secp_g_compressed`).
    // Addresses start with the digit sigma-rust's own docs say to expect ("9" mainnet / "3"
    // testnet P2PK), corroborating the byte layout independently of the oracle script.
    #[test]
    fn erg_mainnet_privkey_one() {
        assert_eq!(
            address(&secret_from_hex("01"), false),
            "9fSgJ7BmUxBQJ454prQDQ7fQMBkXPLaAmDnimgTtjym6FYPHjAV"
        );
    }

    #[test]
    fn erg_testnet_privkey_one() {
        assert_eq!(
            address(&secret_from_hex("01"), true),
            "3WwXpssaZwcNzaGMv3AgxBdTPJQBt5gCmqBsg3DykQ39bYdhJBsN"
        );
    }
}
