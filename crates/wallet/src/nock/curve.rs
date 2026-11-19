//! The Cheetah curve `y^2 = x^3 + x + b` over `Fp6` (Toposware, ePrint 2022/277), in affine
//! coordinates, with the generator and group order Nockchain fixes.
//!
//! Ported from `zorp-corp/nockchain@ed1edfcc` (MIT OR Apache-2.0), `crypto/cheetah.rs` for the
//! constants and the affine group law, cross-checked against `hoon/common/ztd/three.hoon`. Only
//! public-key derivation is here: no signing, no verification, no point decoding.

use super::field::{f6_add, f6_inv, f6_mul, f6_neg, f6_scale, f6_sub, Fp6, ONE, ZERO};

/// Group order `n = 0x7af2599b3b3f22d0563fbf0f990a37b5327aa72330157722d443623eaed4accf`, as
/// little-endian 64-bit limbs.
pub(super) const GROUP_ORDER: [u64; 4] = [
    0xd443_623e_aed4_accf,
    0x327a_a723_3015_7722,
    0x563f_bf0f_990a_37b5,
    0x7af2_599b_3b3f_22d0,
];

/// An affine point, or the identity (`inf`), as the reference's `a-pt` `[x y inf]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Point {
    pub(super) x: Fp6,
    pub(super) y: Fp6,
    pub(super) inf: bool,
}

/// The identity, `[0 1 %.y]`.
pub(super) const IDENTITY: Point = Point {
    x: ZERO,
    y: ONE,
    inf: true,
};

/// The generator `A_GEN`.
pub(super) const GENERATOR: Point = Point {
    x: [
        2_754_611_494_552_410_273,
        8_599_518_745_794_843_693,
        10_526_511_002_404_673_680,
        4_830_863_958_577_994_148,
        375_185_138_577_093_320,
        12_938_930_721_685_970_739,
    ],
    y: [
        15_384_029_202_802_550_068,
        2_774_812_795_997_841_935,
        14_375_303_400_746_062_753,
        10_708_493_419_890_101_954,
        13_187_678_623_570_541_764,
        9_990_732_138_772_505_951,
    ],
    inf: false,
};

fn neg(p: &Point) -> Point {
    Point {
        x: p.x,
        y: f6_neg(&p.y),
        inf: p.inf,
    }
}

fn square(f: &Fp6) -> Fp6 {
    f6_mul(f, f)
}

/// `slope^2 - x1 - x2`, `slope (x1 - x3) - y1`: the shared tail of the chord and tangent rules.
fn finish(slope: &Fp6, p: &Point, x_sum: &Fp6) -> Point {
    let x = f6_sub(&square(slope), x_sum);
    let y = f6_sub(&f6_mul(slope, &f6_sub(&p.x, &x)), &p.y);
    Point { x, y, inf: false }
}

fn double(p: &Point) -> Point {
    if p.inf || p.y == ZERO {
        return IDENTITY;
    }
    // slope = (3 x^2 + 1) / (2 y); the curve's `a` coefficient is 1.
    let num = f6_add(&f6_scale(3, &square(&p.x)), &ONE);
    let den = f6_scale(2, &p.y);
    let slope = f6_mul(&num, &f6_inv(&den).expect("2y is non-zero"));
    finish(&slope, p, &f6_scale(2, &p.x))
}

pub(super) fn add(p: &Point, q: &Point) -> Point {
    if p.inf {
        return *q;
    }
    if q.inf {
        return *p;
    }
    if *p == neg(q) {
        return IDENTITY;
    }
    if p == q {
        return double(p);
    }
    let num = f6_sub(&p.y, &q.y);
    let den = f6_sub(&p.x, &q.x);
    let slope = f6_mul(&num, &f6_inv(&den).expect("distinct x"));
    finish(&slope, p, &f6_add(&p.x, &q.x))
}

/// `scalar * p`, double-and-add from the low bit. `scalar` is little-endian 64-bit limbs of any
/// length: the reference vectors multiply by unreduced 384-bit integers.
pub(super) fn scalar_mul(scalar: &[u64], p: &Point) -> Point {
    let mut acc = IDENTITY;
    let mut base = *p;
    for limb in scalar {
        for bit in 0..64 {
            if (limb >> bit) & 1 == 1 {
                acc = add(&acc, &base);
            }
            base = double(&base);
        }
    }
    acc
}

/// Whether `a < GROUP_ORDER`.
pub(super) fn below_group_order(a: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] != GROUP_ORDER[i] {
            return a[i] < GROUP_ORDER[i];
        }
    }
    false
}
