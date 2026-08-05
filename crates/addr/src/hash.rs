//! The hashes the address codecs need — one per checksum scheme detection can verify. Everything
//! else — `hash160`, the BIP340 tagged hash — is generation-side and stays in the `forager-wallet`
//! crate.
//!
//! Two of the three come from a dependency (`sha2`, `blake2b_simd`). The third, Keccak-256, is
//! written out here: it is the only hash this crate needs that no allowed dependency provides, and
//! `tests/hygiene.rs` pins the dependency list to four crates none of which carries a curve, an
//! entropy source or a wordlist. Adding a Keccak crate to reach two checksums would trade that
//! guarantee for ~130 lines of permutation, so the permutation is written out instead.

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

// ---------------------------------------------------------------------------
// Keccak-256 (original Keccak, pad byte `0x01` — NOT FIPS-202 SHA3-256).
//
// Ethereum and the CryptoNote/Monero family use the original Keccak-256 hash: identical
// Keccak-f[1600] permutation to NIST SHA3-256 but with domain byte `0x01` in the multi-rate
// padding 10*1 scheme, not `0x06`. Two families' checksums rest on that one byte, so the tests at
// the bottom of this file assert the distinction against both published digests rather than
// trusting a comment to survive a cleanup.
//
// Reference: <https://keccak.team/keccak_specs_summary.html>
//
// This implementation was written for `forager-wallet` and moved down here when detection grew a
// use for it: Ethereum's EIP-55 case checksum and CryptoNote's four-byte address checksum are both
// Keccak, and both live on the classification side. `forager-wallet` now calls this one, so there
// is a single implementation of a consensus-critical hash in the workspace rather than two that
// can silently diverge.
// ---------------------------------------------------------------------------

/// 24 round constants for Keccak-f[1600], from the Keccak team reference.
#[rustfmt::skip]
const RC: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

/// Lane rotation offsets `r(x, y)`, indexed as `ROT[x + 5*y]`.
///
/// Derived from the Keccak reference spec table 2.
#[rustfmt::skip]
const ROT: [u32; 25] = [
     0,  1, 62, 28, 27,   // y = 0, x = 0..4
    36, 44,  6, 55, 20,   // y = 1, x = 0..4
     3, 10, 43, 25, 39,   // y = 2, x = 0..4
    41, 45, 15, 21,  8,   // y = 3, x = 0..4
    18,  2, 61, 56, 14,   // y = 4, x = 0..4
];

/// Apply 24 rounds of Keccak-f[1600] to the state in-place.
fn keccak_f(state: &mut [u64; 25]) {
    for &rc in &RC {
        // θ: column-parity mix.
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        for i in 0..25 {
            state[i] ^= d[i % 5];
        }

        // ρ + π: rotation and lane permutation (combined into one pass).
        let mut b = [0u64; 25];
        for x in 0..5_usize {
            for y in 0..5_usize {
                let dst_x = y;
                let dst_y = (2 * x + 3 * y) % 5;
                b[dst_x + 5 * dst_y] = state[x + 5 * y].rotate_left(ROT[x + 5 * y]);
            }
        }

        // χ: non-linear bit-mix across each row.
        for x in 0..5_usize {
            for y in 0..5_usize {
                state[x + 5 * y] =
                    b[x + 5 * y] ^ ((!b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
            }
        }

        // ι: round constant injection into lane (0, 0).
        state[0] ^= rc;
    }
}

/// Rate for Keccak-256: r = 1088 bits = 136 bytes = 17 u64 lanes.
const RATE: usize = 136;

/// XOR a 136-byte (rate-sized) block into the first 17 state lanes (little-endian).
fn xor_rate_block(state: &mut [u64; 25], block: &[u8; RATE]) {
    for (i, chunk) in block.chunks_exact(8).enumerate() {
        // `chunks_exact(8)` on a 136-byte array yields exactly 8-byte slices.
        state[i] ^= u64::from_le_bytes(chunk.try_into().unwrap());
    }
}

/// Compute original Keccak-256 of `data`.
///
/// Uses domain pad byte `0x01` and multi-rate padding 10*1.  This is the hash used by Ethereum
/// (`keccak256`) and by the CryptoNote address checksum, and is distinct from FIPS-202 SHA3-256
/// (`0x06` pad).
///
/// Public because the sibling `forager-wallet` crate derives Ethereum and CryptoNote addresses with
/// the same hash this crate verifies them with, and one implementation of a consensus-critical hash
/// is better than two. It is the only item this module exports outside the crate.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut state = [0u64; 25];

    // Absorb all complete rate-sized blocks.
    let mut pos = 0;
    while pos + RATE <= data.len() {
        let block: &[u8; RATE] = data[pos..pos + RATE].try_into().unwrap();
        xor_rate_block(&mut state, block);
        keccak_f(&mut state);
        pos += RATE;
    }

    // Build the final (padded) block: tail || 0x01 || 0x00…0x00 || 0x80.
    //
    // Keccak pad10*1: always at least two bits (one byte each for the domain bit
    // and the terminating `1`-bit). When the tail exactly fills the rate we still
    // need a fresh full padding block.
    let mut block = [0u8; RATE];
    let tail = &data[pos..];
    block[..tail.len()].copy_from_slice(tail);
    block[tail.len()] ^= 0x01; // original Keccak domain byte (first padding bit)
    block[RATE - 1] ^= 0x80; // terminating `1`-bit of pad10*1
    xor_rate_block(&mut state, &block);
    keccak_f(&mut state);

    // Squeeze the first 32 bytes (4 u64 lanes, little-endian) as the Keccak-256 digest.
    let mut out = [0u8; 32];
    for (i, lane) in state[..4].iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&lane.to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{blake2b256, double_sha256, keccak256};
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

    /// The two published Keccak-256 vectors Ethereum's own tooling is anchored to: the empty string
    /// and `"abc"`.
    #[test]
    fn keccak256_matches_the_published_vectors() {
        assert_eq!(
            hexbytes::encode(&keccak256(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        assert_eq!(
            hexbytes::encode(&keccak256(b"abc")),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        );
    }

    /// Keccak-256 is **not** SHA3-256, and the difference is one byte of padding: original Keccak
    /// appends the domain byte `0x01`, FIPS-202 appends `0x06`. The permutation, the rate and the
    /// digest length are identical, so a `sha3` crate substituted here — or that one byte
    /// "corrected" to the FIPS value — would compile, pass every structural test, and silently
    /// produce a wrong checksum for every Ethereum and CryptoNote address.
    ///
    /// Asserting the inequality against the published SHA3-256 digest of the empty string is what
    /// makes that swap fail loudly rather than quietly.
    #[test]
    fn keccak256_is_the_original_keccak_and_not_fips202_sha3() {
        const SHA3_256_OF_EMPTY: &str =
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
        assert_ne!(hexbytes::encode(&keccak256(b"")), SHA3_256_OF_EMPTY);
        // And the value it *is*, so this test cannot pass by the function being broken outright.
        assert_eq!(
            hexbytes::encode(&keccak256(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    /// Messages long enough to need more than one permutation.
    ///
    /// Keccak-256's rate is 136 bytes: a message of 135 bytes or fewer is absorbed in a single
    /// block, so the whole loop that XORs a second block into the state and permutes again never
    /// runs. Every Keccak-256 vector this crate could otherwise cite is short — the empty string,
    /// `"abc"` — and so is every input the crate actually hashes in production (an EIP-55 body is
    /// 40 bytes, a CryptoNote checksum preimage 65 or 66). The multi-block path was therefore
    /// carried by no test at all, which is precisely the code a reader would want pinned, since a
    /// bug there cannot be caught by any address this repository mints.
    ///
    /// **Provenance, stated plainly, because it is weaker than the vectors above.** The Keccak team
    /// published `ShortMsgKAT` files for original Keccak, but they are no longer present in XKCP,
    /// and the digests below are not quotations from a specification. They were produced by a
    /// Keccak-256 written independently of this one, for this purpose, and corroborated in two
    /// directions before being written down:
    ///
    /// 1. Its permutation and sponge reproduce **all 256 byte-aligned vectors** of the official
    ///    XKCP `ShortMsgKAT_SHA3-256.txt`, **120 of which are 136 bytes or longer** — so the
    ///    multi-block absorb being pinned here is itself validated against an official source, up
    ///    to the 255-byte ceiling of that file.
    /// 2. Changing only the padding byte from FIPS-202's `0x06` to original Keccak's `0x01` — the
    ///    sole difference between the two functions — makes it reproduce both published Keccak-256
    ///    digests asserted above.
    ///
    /// So these are corroborated by an independent implementation, not published by the Keccak
    /// team for Keccak-256. That is a real difference in strength and the reason it is written
    /// here. If a published multi-block Keccak-256 KAT becomes available, prefer it to these.
    ///
    /// If this test ever fails, the vectors are not the thing to adjust.
    #[test]
    fn keccak256_absorbs_messages_longer_than_one_block() {
        /// `0x00, 0x01, … 0xff, 0x00, …` — an input whose every byte differs from its neighbours,
        /// so a block boundary handled off by one changes the digest.
        fn counting_bytes(n: usize) -> Vec<u8> {
            (0..n).map(|i| (i % 256) as u8).collect()
        }

        // 135 bytes: one byte under the rate, so still a single permutation. The control — it
        // proves the two-block cases below differ because of the extra block and not because the
        // function is broken for long input generally.
        assert_eq!(
            hexbytes::encode(&keccak256(&counting_bytes(135))),
            "cbdfd9dee5faad3818d6b06f95a219fd290b0e1706f6a82e5a595b9ce9faca62"
        );
        // 136 bytes: the message fills the first block exactly, so the padding has nowhere to go
        // and forces a whole second block of its own. The case an implementation gets wrong by
        // padding in place.
        assert_eq!(
            hexbytes::encode(&keccak256(&counting_bytes(136))),
            "7ce759f1ab7f9ce437719970c26b0a66ff11fe3e38e17df89cf5d29c7d7f807e"
        );
        // 137 bytes: one byte into the second block.
        assert_eq!(
            hexbytes::encode(&keccak256(&counting_bytes(137))),
            "ac73d4fae68b8453f764007c1a20ce95994187861f0c3227a3a8e99a73a3b1db"
        );
        // 272 bytes: two full blocks, so a third permutation for the padding. This one reaches
        // past the 255-byte ceiling of the SHA3-256 KAT that anchors the oracle, so it rests on
        // the same absorb loop being iterated once more rather than on an official vector.
        assert_eq!(
            hexbytes::encode(&keccak256(&counting_bytes(272))),
            "fdf2ec49e749960d3c8521a0219af8d03e30e2b3bf19bd16150ee0eaf133d66e"
        );
    }
}
