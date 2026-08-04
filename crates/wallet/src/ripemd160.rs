//! Clean-room RIPEMD-160 (ISO/IEC 10118-3), used for `hash160` = RIPEMD-160 ∘ SHA-256.
//!
//! **This is a copy of `crates/algos/ripemd160` in the closed Forager monorepo, not a fork of
//! it.** This crate is published and cannot depend on a path crate that stays closed, and
//! publishing a separate `forager-ripemd160` crate was rejected: the `ripemd160` name on
//! crates.io is taken by a deprecated crate, and a product-named reimplementation of a frozen
//! 1996 standard would have no users.
//!
//! Duplication is safe here for a reason that did not hold elsewhere in the split. RIPEMD-160 was
//! finalized in 1996 and cannot change, and both copies are gated against the standard vectors, so
//! a divergence fails a test immediately on both sides rather than drifting silently. See
//! `the repository README`.
//!
//! Re-derived from the published specification (Dobbertin/Bosselaers/Preneel). The design is two
//! parallel 80-step lines (left/right) with independent message-word permutations, rotate amounts,
//! and per-round constants, combined at the end via a single rotation of the five state registers.
//! Little-endian word framing. No `unsafe`, no external crates.

// ---------------------------------------------------------------------------
// Tables
// ---------------------------------------------------------------------------

/// Left message-word selection.
#[rustfmt::skip]
const RL: [usize; 80] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
];

/// Right message-word selection.
#[rustfmt::skip]
const RR: [usize; 80] = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
];

/// Left rotate amounts.
#[rustfmt::skip]
const SL: [u32; 80] = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
];

/// Right rotate amounts.
#[rustfmt::skip]
const SR: [u32; 80] = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
];

/// Left-line per-round additive constants (one per 16-step round).
const KL: [u32; 5] = [
    0x0000_0000,
    0x5a82_7999,
    0x6ed9_eba1,
    0x8f1b_bcdc,
    0xa953_fd4e,
];

/// Right-line per-round additive constants.
const KR: [u32; 5] = [
    0x50a2_8be6,
    0x5c4d_d124,
    0x6d70_3ef3,
    0x7a6d_76e9,
    0x0000_0000,
];

// ---------------------------------------------------------------------------
// Round function (both lines share the same five non-linear functions,
// but applied in reverse order on the right line).
// ---------------------------------------------------------------------------

#[inline(always)]
fn f(j: usize, x: u32, y: u32, z: u32) -> u32 {
    match j {
        0..=15 => x ^ y ^ z,
        16..=31 => (x & y) | (!x & z),
        32..=47 => (x | !y) ^ z,
        48..=63 => (x & z) | (y & !z),
        _ => x ^ (y | !z),
    }
}

// ---------------------------------------------------------------------------
// Compression
// ---------------------------------------------------------------------------

/// Process one 512-bit block into the five-word state.
fn compress(h: &mut [u32; 5], block: &[u8; 64]) {
    // Decode block as 16 little-endian 32-bit words.
    let mut x = [0u32; 16];
    for (i, w) in x.iter_mut().enumerate() {
        *w = u32::from_le_bytes(block[4 * i..4 * i + 4].try_into().unwrap());
    }

    // Initialise both parallel lines from the current hash state.
    let (mut al, mut bl, mut cl, mut dl, mut el) = (h[0], h[1], h[2], h[3], h[4]);
    let (mut ar, mut br, mut cr, mut dr, mut er) = (h[0], h[1], h[2], h[3], h[4]);

    for j in 0..80usize {
        let round = j / 16;

        // Left line.
        let t = al
            .wrapping_add(f(j, bl, cl, dl))
            .wrapping_add(x[RL[j]])
            .wrapping_add(KL[round])
            .rotate_left(SL[j])
            .wrapping_add(el);
        al = el;
        el = dl;
        dl = cl.rotate_left(10);
        cl = bl;
        bl = t;

        // Right line (functions applied in reverse order: use index 79-j).
        let t = ar
            .wrapping_add(f(79 - j, br, cr, dr))
            .wrapping_add(x[RR[j]])
            .wrapping_add(KR[round])
            .rotate_left(SR[j])
            .wrapping_add(er);
        ar = er;
        er = dr;
        dr = cr.rotate_left(10);
        cr = br;
        br = t;
    }

    // Combine: rotate all five state words by one position.
    let t = h[1].wrapping_add(cl).wrapping_add(dr);
    h[1] = h[2].wrapping_add(dl).wrapping_add(er);
    h[2] = h[3].wrapping_add(el).wrapping_add(ar);
    h[3] = h[4].wrapping_add(al).wrapping_add(br);
    h[4] = h[0].wrapping_add(bl).wrapping_add(cr);
    h[0] = t;
}

// ---------------------------------------------------------------------------
// Public entry-point
// ---------------------------------------------------------------------------

/// Compute RIPEMD-160 of `data`. Returns a 20-byte digest (little-endian words).
pub fn ripemd160(data: &[u8]) -> [u8; 20] {
    // Initial hash state (little-endian byte order of magic constants).
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];

    // Merkle-Damgård padding: 0x80, zero-bytes, 64-bit LE bit-length.
    // Padded length is smallest multiple of 64 bytes ≥ (data.len() + 9).
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let used = (data.len() + 1) % 64; // bytes consumed by data + 0x80 byte
    let pad_zeros = if used <= 56 { 56 - used } else { 120 - used };

    let total = data.len() + 1 + pad_zeros + 8;
    let mut msg = Vec::with_capacity(total);
    msg.extend_from_slice(data);
    msg.push(0x80);
    msg.extend(std::iter::repeat_n(0u8, pad_zeros));
    msg.extend_from_slice(&bit_len.to_le_bytes());

    // Process each 64-byte block.
    for chunk in msg.chunks_exact(64) {
        let block: &[u8; 64] = chunk.try_into().unwrap();
        compress(&mut h, block);
    }

    // Serialise state as 20 bytes, little-endian.
    let mut out = [0u8; 20];
    for (i, w) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&w.to_le_bytes());
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::ripemd160;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn standard_vectors() {
        // Published RIPEMD-160 known-answer tests (Bosselaers, "test suite").
        assert_eq!(
            hex(&ripemd160(b"")),
            "9c1185a5c5e9fc54612808977ee8f548b2258d31"
        );
        assert_eq!(
            hex(&ripemd160(b"abc")),
            "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
        );
        assert_eq!(
            hex(&ripemd160(b"message digest")),
            "5d0689ef49d2fae572b881b123a85ffa21595f36"
        );
        // Two-block message (exercises the multi-block path and padding overflow).
        assert_eq!(
            hex(&ripemd160(
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
            )),
            "b0e20b6e3116640286ed3a87a5713079b21f5189"
        );
    }
}
