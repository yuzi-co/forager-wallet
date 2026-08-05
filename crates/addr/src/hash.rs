//! The hashes the address codecs need — one per checksum scheme detection can verify. Everything
//! else — `hash160`, the BIP340 tagged hash, Keccak — is generation-side and stays in the
//! `forager-wallet` crate.

use sha2::{Digest, Sha256};

pub(crate) fn double_sha256(data: &[u8]) -> [u8; 32] {
    let h1 = Sha256::digest(data);
    Sha256::digest(h1).into()
}

/// BLAKE2b with a 32-byte digest, for the Ergo P2PK address checksum.
///
/// This is a proper BLAKE2b-256 parameterization — the output length goes into the parameter block
/// and changes the initial state — **not** a truncation of BLAKE2b-512. Ergo uses the former, so
/// truncating the latter would produce four wrong checksum bytes for every address. The test below
/// pins that distinction against a published vector rather than leaving it to the reader.
pub(crate) fn blake2b256(data: &[u8]) -> [u8; 32] {
    let hash = blake2b_simd::Params::new().hash_length(32).hash(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::{blake2b256, double_sha256};
    use crate::hexbytes;

    /// The well-known `BLAKE2b-256("")` vector. Its value differs from the first 32 bytes of
    /// `BLAKE2b-512("")`, so this fails if the digest length is ever applied as a truncation
    /// instead of as a parameter — the one way to get Ergo's checksum silently wrong.
    #[test]
    fn blake2b256_of_the_empty_string() {
        assert_eq!(
            hexbytes::encode(&blake2b256(b"")),
            "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
        );
        // BLAKE2b-512("") begins `786a02f742015903…`; a truncation would yield that, not the above.
        assert_ne!(
            hexbytes::encode(&blake2b256(b""))[..16],
            *"786a02f742015903"
        );
    }

    /// `SHA256(SHA256(""))`, the base58check construction, from the same published-vector angle.
    #[test]
    fn double_sha256_of_the_empty_string() {
        assert_eq!(
            hexbytes::encode(&double_sha256(b"")),
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
        );
    }
}
