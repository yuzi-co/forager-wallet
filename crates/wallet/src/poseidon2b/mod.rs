//! Poseidon2b over GF(2^128): the hash Parano1d (NOID) derives its spend secrets and addresses with.
//!
//! The permutation is `t = 4` lanes, `x^7` S-box, 8 full and 58 partial rounds. Its round constants
//! and MDS entries are copied from `ignotusnemo/parano1d@52938433`
//! `noid_poseidon2b/src/native/permutation.rs` (Apache-2.0, Copyright 2026 Paranoid Zero; see
//! `NOTICE` and `THIRD-PARTY.md` at the repository root) as tower-basis integers. The sponge
//! follows the same reference's `noid_poseidon2b/src/native/compression.rs` and
//! `native/domain.rs`.
//!
//! The reference stores field elements in the Binius *tower* basis and multiplies in the *flat*
//! (GCM, `x^128 + x^7 + x^2 + x + 1`) basis. This port keeps the sponge state in the flat basis
//! throughout and converts only where a value crosses the interface: absorbed lanes and the IV go
//! in through [`tower_to_flat`], squeezed lanes come out through [`flat_to_tower`]. The change of
//! basis is GF(2)-linear, so XOR-absorbing in either basis is the same operation, and the result is
//! bit-identical to the reference. The vectors in `tests` below were captured from the reference
//! crates themselves.
//!
//! Everything here is portable integer code: no `unsafe`, no carry-less-multiply intrinsics. A
//! wallet hashes a handful of blocks per address, so speed is not a concern.

mod basis_tables;

use zeroize::Zeroize;

use basis_tables::{FLAT_TO_TOWER, TOWER_TO_FLAT};

/// Lanes in the permutation state.
const T: usize = 4;
const FULL_ROUNDS: usize = 8;
const PARTIAL_ROUNDS: usize = 58;
const ROUNDS: usize = FULL_ROUNDS + PARTIAL_ROUNDS;
/// Rounds `PARTIAL_START..PARTIAL_END` are partial; the rest are full.
const PARTIAL_START: usize = FULL_ROUNDS / 2;
const PARTIAL_END: usize = PARTIAL_START + PARTIAL_ROUNDS;

/// Round constants in the tower basis, `[lane][round]`, as the reference writes them.
#[rustfmt::skip]
const RC_TOWER: [[u8; ROUNDS]; T] = [
    [0, 1, 0, 3, 7, 7, 6, 6, 2, 1, 7, 2, 2, 3, 3, 2, 6, 5, 7, 5, 0, 2, 2, 3, 1, 5, 2, 6, 1, 4, 1, 0, 3, 7, 2, 0, 1, 2, 4, 1, 0, 0, 2, 5, 7, 2, 0, 4, 1, 5, 5, 1, 2, 7, 3, 1, 0, 1, 3, 7, 1, 6, 1, 6, 6, 2],
    [3, 3, 0, 6, 7, 1, 1, 2, 7, 3, 7, 5, 7, 1, 7, 3, 6, 1, 7, 5, 5, 5, 7, 1, 6, 5, 1, 2, 6, 3, 5, 4, 4, 6, 3, 2, 3, 0, 4, 1, 0, 6, 1, 7, 6, 7, 1, 6, 4, 1, 4, 0, 4, 3, 4, 0, 3, 0, 0, 7, 3, 2, 3, 5, 0, 2],
    [6, 0, 5, 3, 2, 5, 6, 5, 6, 7, 2, 7, 6, 4, 1, 0, 6, 3, 2, 6, 2, 1, 5, 3, 1, 7, 7, 6, 7, 1, 1, 4, 4, 4, 6, 2, 5, 4, 0, 3, 1, 4, 1, 6, 1, 6, 7, 7, 6, 2, 7, 3, 3, 3, 0, 2, 6, 4, 0, 0, 0, 3, 1, 4, 1, 5],
    [7, 1, 1, 5, 1, 2, 2, 7, 5, 0, 5, 5, 1, 4, 6, 5, 2, 4, 0, 1, 0, 4, 6, 4, 3, 7, 3, 2, 4, 0, 1, 6, 3, 3, 2, 6, 3, 4, 6, 3, 2, 3, 5, 1, 1, 2, 4, 5, 5, 6, 0, 5, 5, 6, 4, 1, 2, 1, 5, 7, 1, 3, 1, 2, 2, 2],
];

/// The full-round MDS matrix in the tower basis.
const MDS_FULL_TOWER: [[u128; T]; T] = [[5, 7, 1, 3], [4, 6, 1, 1], [1, 3, 5, 7], [1, 1, 4, 6]];
/// The partial-round MDS diagonal in the tower basis; the matrix is all ones off the diagonal.
const MDS_PARTIAL_DIAG_TOWER: [u128; T] = [0x20, 0x2000, 0x200, 0x800];

/// Apply a GF(2) 128x128 matrix given as row images: XOR row `i` for every set bit `i` of `v`.
const fn apply_matrix(m: &[u128; 128], v: u128) -> u128 {
    let mut r = 0u128;
    let mut i = 0;
    while i < 128 {
        if (v >> i) & 1 == 1 {
            r ^= m[i];
        }
        i += 1;
    }
    r
}

/// Tower basis to flat basis.
const fn tower_to_flat(v: u128) -> u128 {
    apply_matrix(&TOWER_TO_FLAT, v)
}

/// Flat basis to tower basis.
const fn flat_to_tower(v: u128) -> u128 {
    apply_matrix(&FLAT_TO_TOWER, v)
}

/// Round constants in the flat basis, `[round][lane]`.
const RC: [[u128; T]; ROUNDS] = {
    let mut rc = [[0u128; T]; ROUNDS];
    let mut r = 0;
    while r < ROUNDS {
        let mut i = 0;
        while i < T {
            rc[r][i] = tower_to_flat(RC_TOWER[i][r] as u128);
            i += 1;
        }
        r += 1;
    }
    rc
};

/// The full-round MDS matrix in the flat basis.
const MDS_FULL: [[u128; T]; T] = {
    let mut m = [[0u128; T]; T];
    let mut i = 0;
    while i < T {
        let mut j = 0;
        while j < T {
            m[i][j] = tower_to_flat(MDS_FULL_TOWER[i][j]);
            j += 1;
        }
        i += 1;
    }
    m
};

/// The partial-round diagonal minus one, in the flat basis. Off the diagonal the matrix is all
/// ones, so `out[i] = sum(x) + (d[i] - 1) * x[i]`, and subtraction is XOR.
const MDS_PARTIAL_DIAG_M1: [u128; T] = {
    let mut d = [0u128; T];
    let mut i = 0;
    while i < T {
        d[i] = tower_to_flat(MDS_PARTIAL_DIAG_TOWER[i] ^ 1);
        i += 1;
    }
    d
};

/// Reduce the 256-bit carry-less product `hi * x^128 + lo` modulo the GCM polynomial.
const fn reduce(hi: u128, lo: u128) -> u128 {
    // hi * x^128 = hi * (x^7 + x^2 + x + 1). The bits shifted past degree 127 form `over`, which
    // has degree at most 6, and fold once more.
    let fold = hi ^ (hi << 1) ^ (hi << 2) ^ (hi << 7);
    let over = (hi >> 127) ^ (hi >> 126) ^ (hi >> 121);
    lo ^ fold ^ over ^ (over << 1) ^ (over << 2) ^ (over << 7)
}

/// 32x32 carry-less multiply with integer multiplies. Each operand is split into four interleaved
/// bit classes, so every partial product has at most 8 terms per bit position and its carries
/// never reach the next bit of the same class.
const fn clmul32(x: u32, y: u32) -> u64 {
    const M: [u64; 4] = [0x1111_1111, 0x2222_2222, 0x4444_4444, 0x8888_8888];
    let (x, y) = (x as u64, y as u64);
    let (x0, x1, x2, x3) = (x & M[0], x & M[1], x & M[2], x & M[3]);
    let (y0, y1, y2, y3) = (y & M[0], y & M[1], y & M[2], y & M[3]);
    let z0 = (x0 * y0) ^ (x1 * y3) ^ (x2 * y2) ^ (x3 * y1);
    let z1 = (x0 * y1) ^ (x1 * y0) ^ (x2 * y3) ^ (x3 * y2);
    let z2 = (x0 * y2) ^ (x1 * y1) ^ (x2 * y0) ^ (x3 * y3);
    let z3 = (x0 * y3) ^ (x1 * y2) ^ (x2 * y1) ^ (x3 * y0);
    (z0 & 0x1111_1111_1111_1111)
        | (z1 & 0x2222_2222_2222_2222)
        | (z2 & 0x4444_4444_4444_4444)
        | (z3 & 0x8888_8888_8888_8888)
}

/// 64x64 carry-less multiply, one Karatsuba level over [`clmul32`].
const fn clmul64(a: u64, b: u64) -> u128 {
    let (a0, a1) = (a as u32, (a >> 32) as u32);
    let (b0, b1) = (b as u32, (b >> 32) as u32);
    let lo = clmul32(a0, b0);
    let hi = clmul32(a1, b1);
    let mid = clmul32(a0 ^ a1, b0 ^ b1) ^ lo ^ hi;
    (lo as u128) ^ ((mid as u128) << 32) ^ ((hi as u128) << 64)
}

/// `a * b` in GF(2^128), flat basis.
const fn mul(a: u128, b: u128) -> u128 {
    let (a0, a1) = (a as u64, (a >> 64) as u64);
    let (b0, b1) = (b as u64, (b >> 64) as u64);
    let lo = clmul64(a0, b0);
    let hi = clmul64(a1, b1);
    let mid = clmul64(a0 ^ a1, b0 ^ b1) ^ lo ^ hi;
    reduce(hi ^ (mid >> 64), lo ^ (mid << 64))
}

/// `x^7`, as `x * x^2 * x^4`.
fn sbox(x: u128) -> u128 {
    let x2 = mul(x, x);
    let x4 = mul(x2, x2);
    mul(mul(x, x2), x4)
}

fn mds_full(s: &mut [u128; T]) {
    let x = *s;
    for (out, row) in s.iter_mut().zip(MDS_FULL.iter()) {
        let mut o = 0u128;
        for (&xj, &m) in x.iter().zip(row.iter()) {
            o ^= mul(xj, m);
        }
        *out = o;
    }
}

/// The Poseidon2b permutation on a flat-basis state.
fn permute(s: &mut [u128; T]) {
    mds_full(s);
    for (r, rc) in RC.iter().enumerate() {
        if (PARTIAL_START..PARTIAL_END).contains(&r) {
            s[0] = sbox(s[0] ^ rc[0]);
            let sum = s[0] ^ s[1] ^ s[2] ^ s[3];
            for (lane, d) in s.iter_mut().zip(MDS_PARTIAL_DIAG_M1) {
                *lane = sum ^ mul(*lane, d);
            }
        } else {
            for (lane, c) in s.iter_mut().zip(rc) {
                *lane = sbox(*lane ^ c);
            }
            mds_full(s);
        }
    }
}

/// The capacity IV for an 8-byte domain tag, in the tower basis: `label = u64::from_be_bytes(tag)`
/// and the IV is `[label << 64, label]`. Reference: `native/domain.rs` `capacity_iv`.
pub(crate) fn capacity_iv(tag: &[u8; 8]) -> [u128; 2] {
    let label = u128::from(u64::from_be_bytes(*tag));
    [label << 64, label]
}

/// A Poseidon2b sponge, rate 2 and capacity 2, absorbing whole rate blocks only.
///
/// The reference's sponge buffers bytes; every construction this crate needs absorbs whole
/// 32-byte blocks, and for those the reference's buffering reduces to exactly this: XOR the two
/// little-endian 128-bit lanes into the rate, then permute. Zeroed on drop, because the state
/// carries a master or spend secret.
pub(crate) struct Sponge {
    /// Flat-basis state: `[rate0, rate1, cap0, cap1]`.
    state: [u128; T],
}

impl Drop for Sponge {
    fn drop(&mut self) {
        self.state.zeroize();
    }
}

impl Sponge {
    /// A sponge with the rate zeroed and the capacity set to `iv` (tower basis).
    /// Reference: `Poseidon2bSponge::with_iv`.
    pub(crate) fn with_iv(iv: [u128; 2]) -> Self {
        Self {
            state: [0, 0, tower_to_flat(iv[0]), tower_to_flat(iv[1])],
        }
    }

    /// Absorb one rate block of two tower-basis lanes and permute.
    pub(crate) fn absorb_block(&mut self, a: u128, b: u128) {
        self.state[0] ^= tower_to_flat(a);
        self.state[1] ^= tower_to_flat(b);
        permute(&mut self.state);
    }

    /// Squeeze the rate as 32 bytes, each lane in the tower basis, little-endian, without padding.
    /// Reference: `Poseidon2bSponge::finalize_no_pad`, sound only after whole-block absorbs, which
    /// is all this type can do.
    pub(crate) fn finalize_no_pad(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(&flat_to_tower(self.state[0]).to_le_bytes());
        out[16..].copy_from_slice(&flat_to_tower(self.state[1]).to_le_bytes());
        out
    }

    /// Absorb the padding block and squeeze. Reference: `Poseidon2bSponge::finalize` with no bytes
    /// buffered, where `fill_padding` makes a full 32-byte block `0x80, 0…, 0x01`. Read as two
    /// little-endian lanes, that block is `0x80` and `0x01 << 120`.
    pub(crate) fn finalize(mut self) -> [u8; 32] {
        self.absorb_block(0x80, 1u128 << 120);
        self.finalize_no_pad()
    }
}

/// Split 32 bytes into the two little-endian 128-bit lanes the reference absorbs them as
/// (`Block128::from(u128::from_le_bytes(..))`).
pub(crate) fn lanes(bytes: &[u8; 32]) -> (u128, u128) {
    let mut lo = [0u8; 16];
    let mut hi = [0u8; 16];
    lo.copy_from_slice(&bytes[..16]);
    hi.copy_from_slice(&bytes[16..]);
    let out = (u128::from_le_bytes(lo), u128::from_le_bytes(hi));
    lo.zeroize();
    hi.zeroize();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bit-serial shift-and-add multiply, the textbook definition, to check [`mul`] against.
    fn mul_bitwise(a: u128, b: u128) -> u128 {
        let (mut r, mut a) = (0u128, a);
        for i in 0..128 {
            if (b >> i) & 1 == 1 {
                r ^= a;
            }
            let carry = a >> 127;
            a <<= 1;
            if carry == 1 {
                a ^= 0x87;
            }
        }
        r
    }

    #[test]
    fn multiply_matches_the_definition() {
        let mut v = vec![0u128, 1, 2, 0x87, u128::MAX, 1 << 127, (1 << 64) | 1];
        let mut x = 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210u128;
        for _ in 0..24 {
            x = x.wrapping_mul(0x9e37_79b9_7f4a_7c15_f39c_c060_5ced_c834) ^ (x >> 61);
            v.push(x);
        }
        for &a in &v {
            for &b in &v {
                assert_eq!(mul(a, b), mul_bitwise(a, b), "{a:x} * {b:x}");
            }
        }
    }

    /// Change-of-basis vectors captured from the reference (`noid_core::hardware::
    /// tower_to_flat_u128` / `flat_to_tower_u128`).
    #[test]
    fn basis_change_matches_reference() {
        for (tower, flat) in [
            (1u128, 1u128),
            (2, 0x3d5bd35c94646a247573da4a5f7710ed),
            (0x87, 0xceed02caea3b7a540e77e2026ab2d377),
            (
                0x0123456789abcdeffedcba9876543210,
                0xfbdef4953abe30e869895f34f5ee64e2,
            ),
        ] {
            assert_eq!(tower_to_flat(tower), flat);
            assert_eq!(flat_to_tower(flat), tower);
        }
        assert_eq!(flat_to_tower(2), 0xe9453afbbb5efa683426e20fcdbc3b96);
    }

    fn permute_tower(st: [u128; T]) -> [u128; T] {
        let mut s = st.map(tower_to_flat);
        permute(&mut s);
        s.map(flat_to_tower)
    }

    /// Permutation vectors captured from the reference (`Poseidon2bPermutation::permute_mut`,
    /// tower basis in and out).
    #[test]
    fn permutation_matches_reference() {
        assert_eq!(
            permute_tower([0; 4]),
            [0xf45a, 0xf2b6, 0xd578, 0x0bf8],
            "all-zero state"
        );
        assert_eq!(
            permute_tower([1, 0, 1, 0]),
            [0x33e3, 0xa8e1, 0x3948, 0x7c50],
            "[1, 0, 1, 0]"
        );
        assert_eq!(
            permute_tower([
                0x0123456789abcdeffedcba9876543210,
                0xffff0000ffff0000aaaa5555aaaa5555,
                0x11112222333344445555666677778888,
                0xdeadbeefcafebabe0123456789abcdef,
            ]),
            [
                0x151994a655cbaaa4195071b72415cc0e,
                0xbf0c28977c0ab1e25a16456ae9eff77c,
                0xe24ed06034983e4fe07d754484fddc73,
                0xf95d4b6bd9521e68d07a268f2c573a3c,
            ],
            "mixed state"
        );
    }

    /// The MDS entry `1` is the field's one in both bases, which is what lets a reader check the
    /// flat-basis matrix against the reference's tower-basis one by eye.
    #[test]
    fn tower_one_is_flat_one() {
        assert_eq!(tower_to_flat(1), 1);
        assert_eq!(MDS_FULL[0][2], 1);
    }
}
