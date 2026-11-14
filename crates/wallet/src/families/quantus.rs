//! Quantus Network account address.
//!
//! `address = SS58(prefix 189, Poseidon2(ML-DSA-87 public key))`, where the key pair comes from
//! the 32-byte seed `xi` of FIPS 204 `ML-DSA.KeyGen_internal`.
//!
//! Sources: `Quantus-Network/chain` `primitives/dilithium-crypto` (`IdentifyAccount`:
//! `AccountId32::new(qp_poseidon_core::hash_bytes(public_key))`); `Quantus-Network/qp-poseidon`
//! (MIT-0) `hash_bytes`; `Quantus-Network/quantus-cli` `src/cli/address_format.rs` (SS58 prefix
//! 189). Quantus's own ML-DSA crate is GPL-3.0, so key generation uses RustCrypto's `ml-dsa`
//! instead. Its `from_seed` is FIPS 204 `KeyGen_internal`, and Quantus's keygen is validated
//! byte-exact against the FIPS 204 ACVP vectors from the same seed, so the two agree. The KAT
//! below checks that end to end against an address Quantus publishes.

use ml_dsa::{Keypair, MlDsa87};
use zeroize::Zeroize;

use crate::coins::QUANTUS_SS58_PREFIX;

/// ML-DSA-87 public key (FIPS 204 `pkEncode`) for the 32-byte seed `xi`.
fn public_key(seed: &[u8; 32]) -> Vec<u8> {
    let sk = ml_dsa::SigningKey::<MlDsa87>::from_seed(&(*seed).into());
    sk.verifying_key().encode().to_vec()
}

/// The 32-byte AccountId32 for a seed: Poseidon2 `hash_bytes` of the public key.
pub(crate) fn account_id(seed: &[u8; 32]) -> [u8; 32] {
    qp_poseidon_core::hash_bytes(&public_key(seed))
}

/// Two-byte SS58 spelling of a network prefix in 64..=16383 (SS58 specification).
fn ss58_prefix_bytes(id: u16) -> [u8; 2] {
    [
        (((id & 0xfc) >> 2) as u8) | 0x40,
        ((id >> 8) as u8) | (((id & 0x03) << 6) as u8),
    ]
}

/// SS58 string of a 32-byte account id: `base58(prefix ‖ id ‖ blake2b512("SS58PRE" ‖ prefix ‖ id)[..2])`.
pub(crate) fn ss58(id: &[u8; 32]) -> String {
    let mut body = ss58_prefix_bytes(QUANTUS_SS58_PREFIX).to_vec();
    body.extend_from_slice(id);
    let mut state = blake2b_simd::Params::new().hash_length(64).to_state();
    state.update(b"SS58PRE");
    state.update(&body);
    body.extend_from_slice(&state.finalize().as_bytes()[..2]);
    crate::codec::base58::encode(&body)
}

/// Quantus address of a 32-byte seed.
pub(crate) fn address(seed: &[u8; 32]) -> String {
    ss58(&account_id(seed))
}

/// Parse a seed as 64 hex characters, whitespace ignored (the same shape as the Parano1d master
/// secret). Any 32 bytes are a valid ML-DSA seed.
pub(crate) fn parse_seed(input: &str) -> Option<[u8; 32]> {
    let mut compact: String = input.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let out = crate::hexbytes::decode_n::<32>(&compact);
    compact.zeroize();
    out
}

#[cfg(test)]
mod tests {
    use super::{account_id, address, parse_seed, public_key, ss58};
    use crate::hexbytes::encode as hex;

    /// quantus-cli `src/wallet/mod.rs`, `test_known_values`: this mnemonic imported with
    /// ML-DSA-87 and no derivation gives `NO_DERIVE`. quantus-cli takes the BIP-39 seed
    /// (`mnemonic_to_seed`, empty passphrase, 64 bytes) and passes its first 32 bytes to
    /// `Dilithium87Pair::from_seed`.
    const MNEMONIC: &str = "orchard answer curve patient visual flower maze noise retreat penalty cage small earth domain scan pitch bottom crunch theme club client swap slice raven";
    const NO_DERIVE: &str = "qzmTAz3UUw1WGUuVh8nbFmPwcftomduwy6twq6NDR6y9qqtEs";

    fn mnemonic_seed() -> [u8; 32] {
        let s = crate::bip39::seed(MNEMONIC, "").unwrap();
        let mut x = [0u8; 32];
        x.copy_from_slice(&s.as_bytes()[..32]);
        x
    }

    #[test]
    fn quantus_cli_no_derivation_vector_end_to_end() {
        let seed = mnemonic_seed();
        assert_eq!(public_key(&seed).len(), 2592);
        assert_eq!(
            hex(&account_id(&seed)),
            "586c2cc8b99325a0455f20485fce964f040670a810ee4639e5f6ce9b85215c66"
        );
        assert_eq!(address(&seed), NO_DERIVE);
    }

    /// Both published addresses decode to a 36-byte SS58 body with prefix bytes `6f 40`, and
    /// re-encoding the account id reproduces the string.
    #[test]
    fn published_addresses_decode_and_re_encode() {
        for a in [
            NO_DERIVE,
            "qzm5QCox8Dp5A3oSXZZYHD8YoYgPz7enykZb6RPUropdCyN5h",
        ] {
            let raw = crate::codec::base58::decode(a).unwrap();
            assert_eq!(raw.len(), 36);
            assert_eq!(raw[..2], [0x6f, 0x40]);
            let mut id = [0u8; 32];
            id.copy_from_slice(&raw[2..34]);
            assert_eq!(ss58(&id), a);
        }
    }

    #[test]
    fn seed_parsing() {
        let h = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        assert!(parse_seed(h).is_some());
        assert!(parse_seed(&h[..62]).is_none());
        assert!(parse_seed(&h.replace('0', "g")).is_none());
    }
}
