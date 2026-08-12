use sha2::{Digest, Sha256};

use crate::curves::secp256k1;

/// Warthog (WART) address: `HEX(HASH160(compressed_pubkey) ‖ SHA256(HASH160(..))[0..4])`.
///
/// Bitcoin's hash160 payload, but rendered as raw lowercase hex with a **single**-SHA-256
/// checksum — no Base58, no version byte, no human-readable prefix. The result is always 48
/// characters.
///
/// Pinned to `warthog-network/core@54403b8` (MIT): `src/shared/src/crypto/crypto.cpp`
/// (`PubKey::address` — `ripemd160(sha256(compressed_pubkey))`) and
/// `src/shared/src/crypto/address.cpp` (`AddressView::serialize` appends
/// `sha256(address20)[0..4]`; `to_string` hex-encodes the 24 bytes).
///
/// NB: the checksum is a **single** SHA-256 of the 20-byte payload, not the double-SHA-256 that
/// Base58Check uses — see [`crate::families::xdag`], whose payload is identical and whose
/// checksum is not.
pub(crate) fn address(d: &secp256k1::Secret) -> String {
    let pk = secp256k1::pubkey_compressed(d).to_vec();
    let payload = crate::hash::hash160(&pk);
    let mut out = payload.to_vec();
    out.extend_from_slice(&Sha256::digest(payload)[..4]);
    crate::hexbytes::encode(&out)
}

#[cfg(test)]
mod tests {
    use super::address;
    use crate::curves::secp256k1;
    use crate::hexbytes::encode as hex;

    /// KAT from the Warthog project's own client libraries, which publish this keypair as their
    /// canonical vector: `warthog-network/warthog_py` (`tests/test_account.py`) and
    /// `warthog-network/warthog-ts` (`src/tests/account.test.ts`) assert the same private key,
    /// compressed pubkey and address. Two independent implementations, and the derivation was
    /// additionally re-computed from the raw primitives before this test was written.
    ///
    /// Consensus source for the format: `warthog-network/core@54403b8`,
    /// `src/shared/src/crypto/crypto.cpp` (`PubKey::address` = `ripemd160(sha256(pubkey33))`) and
    /// `src/shared/src/crypto/address.cpp` (`AddressView::serialize` appends
    /// `sha256(address20)[0..4]`, `to_string` hex-encodes the 24 bytes).
    #[test]
    fn warthog_address_from_the_project_client_library_vector() {
        let priv_hex = "966a71a98bb5d13e9116c0dffa3f1a7877e45c6f563897b96cfd5c59bf0803e0";
        let d = secp256k1::secret_from_hex(priv_hex);
        // Intermediate cross-checks isolate a failure to pubkey vs hash160 vs encoding.
        let pk = secp256k1::pubkey_compressed(&d).to_vec();
        assert_eq!(
            hex(&pk),
            "02916a397088159baf27b3ce1271a859e3e6ea27db913a94086423e5867994e705"
        );
        assert_eq!(
            hex(&crate::hash::hash160(&pk)),
            "3661579d61abde5837a8686dc4d65348a2fc61b1"
        );
        assert_eq!(
            address(&d),
            "3661579d61abde5837a8686dc4d65348a2fc61b1fe5f4093"
        );
    }
}
