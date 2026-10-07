//! Conflux Core Space addresses (CIP-37).
//!
//! The key and the hash are Ethereum's: secp256k1, then keccak256 over the uncompressed public
//! key without its `0x04` tag, last 20 bytes. One step differs, and it is the step that makes a
//! Conflux address a Conflux address rather than an Ethereum one:
//!
//! ```text
//! buffer[0] = (buffer[0] & 0x0f) | 0x10
//! ```
//!
//! Conflux encodes the *address type* in the leading four bits of the address itself — `0x1…` is a
//! user address, `0x8…` a contract, `0x0…` a builtin — so a key-derived address has those bits
//! forced to `0001`. The 20 bytes are then rendered by CIP-37's base32 scheme
//! ([`forager_addr::codec::conflux`]).
//!
//! Pinned to `Conflux-Chain/js-conflux-sdk` (LGPL-3.0) `src/util/sign.js`
//! `publicKeyToAddress` for the derivation, read for its two lines of arithmetic rather than
//! copied, and to `Conflux-Chain/CIPs` `CIPs/cip-37.md` for the encoding. The KAT is the keypair
//! that project's own test suite publishes as its canonical vector
//! (`test/util/sign.test.js`: `KEY`, `PUBLIC`, `ADDRESS`).
//!
//! WARNING: this is **Core Space**, not eSpace. The same key also has a valid `0x…` eSpace
//! address, and the two are different payout targets. A Conflux mining pool wants the Core Space
//! form and rejects the other, so the two must never be treated as one family.

use crate::{curves::secp256k1, hash::keccak256};
use forager_addr::codec::conflux;

/// The 20-byte Core Space address for a secret: keccak160 of the public key, typed as a user
/// address.
pub(crate) fn addr20(d: &secp256k1::Secret) -> [u8; 20] {
    let pk = secp256k1::pubkey_uncompressed(d); // 0x04 ‖ x ‖ y
    let hash = keccak256(&pk[1..]); // keccak of x‖y
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash[12..]);
    // Force `type.user`. Conflux reads the type from these four bits, so leaving the keccak
    // nibble in place would mint an address the network reads as a contract or a builtin for
    // 15 keys out of 16.
    out[0] = (out[0] & 0x0f) | 0x10;
    out
}

/// The CIP-37 address for a secret under the given network prefix.
pub(crate) fn address(d: &secp256k1::Secret, hrp: &str) -> String {
    conflux::encode(hrp, &addr20(d))
}

#[cfg(test)]
mod tests {
    use super::{addr20, address};
    use crate::curves::secp256k1::secret_from_hex;

    /// `Conflux-Chain/js-conflux-sdk` `test/util/sign.test.js` publishes this triple as the
    /// canonical keypair vector: `KEY`, the 64-byte `PUBLIC` it derives, and `ADDRESS` as the
    /// testnet CIP-37 string. `privateKeyToAddress(KEY)` and `publicKeyToAddress(PUBLIC)` are both
    /// asserted equal to it there, so it exercises the whole path this module implements.
    const KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const ADDRESS_TESTNET: &str = "cfxtest:aasm4c231py7j34fghntcfkdt2nm9xv1tu6jd3r1s7";

    #[test]
    fn cfx_matches_the_sdk_canonical_vector() {
        assert_eq!(address(&secret_from_hex(KEY), "cfxtest"), ADDRESS_TESTNET);
    }

    /// The same 20 bytes under the mainnet prefix. Derived by decoding the vector above rather
    /// than by trusting this encoder: the prefix is folded into the checksum, so the mainnet
    /// string is not the testnet one with a different prefix glued on.
    #[test]
    fn cfx_mainnet_is_the_same_twenty_bytes() {
        let want = {
            let d = forager_addr::codec::conflux::decode(ADDRESS_TESTNET).expect("vector decodes");
            forager_addr::codec::conflux::encode("cfx", &d.addr)
        };
        assert_eq!(address(&secret_from_hex(KEY), "cfx"), want);
        assert_eq!(want, "cfx:aasm4c231py7j34fghntcfkdt2nm9xv1tu0dukn7m1");
    }

    /// Every derived address is a user address, whatever the keccak nibble was.
    #[test]
    fn every_derived_address_is_type_user() {
        for i in 1u8..=64 {
            let a = addr20(&secret_from_hex(&format!("{i:064x}")));
            assert_eq!(a[0] & 0xf0, 0x10, "secret {i} typed as {:#x}", a[0] & 0xf0);
        }
    }

    /// The forcing is a replacement of the top nibble, not an OR over it. An OR would leave
    /// `0x8…` as `0x9…`, which is neither a user nor a contract address, so pin the low nibble
    /// through: it must survive untouched.
    #[test]
    fn forcing_the_type_keeps_the_low_nibble() {
        use crate::hash::keccak256;
        let d = secret_from_hex(KEY);
        let pk = crate::curves::secp256k1::pubkey_uncompressed(&d);
        let raw = keccak256(&pk[1..])[12];
        let got = addr20(&d)[0];
        assert_eq!(got & 0x0f, raw & 0x0f);
        assert_eq!(got & 0xf0, 0x10);
    }
}
