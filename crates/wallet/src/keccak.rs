//! Clean-room Keccak-256 (original Keccak, pad byte `0x01` — NOT FIPS-202 SHA3-256).
//!
//! Ethereum and the CryptoNote/Monero family use the original Keccak-256 hash: identical
//! Keccak-f[1600] permutation to NIST SHA3-256 but with domain byte `0x01` in the
//! multi-rate padding 10*1 scheme, not `0x06`.
//!
//! Reference: <https://keccak.team/keccak_specs_summary.html>
//! KAT vectors are Ethereum `keccak256("")` and `keccak256("abc")`.

// ---------------------------------------------------------------------------
// Keccak-f[1600] permutation constants.
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

// ---------------------------------------------------------------------------
// Keccak-f[1600] permutation.
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Sponge construction.
// ---------------------------------------------------------------------------

/// Rate for Keccak-256: r = 1088 bits = 136 bytes = 17 u64 lanes.
const RATE: usize = 136;

/// XOR a 136-byte (rate-sized) block into the first 17 state lanes (little-endian).
fn xor_rate_block(state: &mut [u64; 25], block: &[u8; RATE]) {
    for (i, chunk) in block.chunks_exact(8).enumerate() {
        // Safety: chunks_exact(8) on a 136-byte array yields exactly 8-byte slices.
        state[i] ^= u64::from_le_bytes(chunk.try_into().unwrap());
    }
}

/// Compute original Keccak-256 of `data`.
///
/// Uses domain pad byte `0x01` and multi-rate padding 10*1.  This is the hash
/// used by Ethereum (`keccak256`) and is distinct from FIPS-202 SHA3-256 (`0x06` pad).
pub(crate) fn keccak256(data: &[u8]) -> [u8; 32] {
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

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::keccak256;
    use crate::hexbytes::encode as hex;

    #[test]
    fn keccak256_kat() {
        // Original Keccak-256 (0x01 pad), NOT FIPS-202 SHA3-256.
        assert_eq!(
            hex(&keccak256(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        assert_eq!(
            hex(&keccak256(b"abc")),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        );
    }
}
