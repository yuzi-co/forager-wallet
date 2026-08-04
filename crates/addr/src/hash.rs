//! The one hash the address codecs need. Everything else — `hash160`, the BIP340 tagged hash,
//! Keccak — is generation-side and stays in the `forager-wallet` crate.

use sha2::{Digest, Sha256};

pub(crate) fn double_sha256(data: &[u8]) -> [u8; 32] {
    let h1 = Sha256::digest(data);
    Sha256::digest(h1).into()
}
