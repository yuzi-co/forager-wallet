//! The Goldilocks field `Fp` (`p = 2^64 - 2^32 + 1`) and its degree-6 extension
//! `Fp6 = Fp[u] / (u^6 - 7)` that the Cheetah curve lives over.
//!
//! Elements are canonical (`< p`) and in plain, not Montgomery, form, which is what the reference
//! keeps in a public key. Plain schoolbook arithmetic over `u128`: an address needs a few hundred
//! thousand multiplications, so clarity wins over the reference's Karatsuba.

/// `p = 2^64 - 2^32 + 1`.
pub(super) const P: u64 = 0xffff_ffff_0000_0001;

pub(super) fn add(a: u64, b: u64) -> u64 {
    ((u128::from(a) + u128::from(b)) % u128::from(P)) as u64
}

pub(super) fn sub(a: u64, b: u64) -> u64 {
    add(a, neg(b))
}

pub(super) fn neg(a: u64) -> u64 {
    if a == 0 {
        0
    } else {
        P - a
    }
}

pub(super) fn mul(a: u64, b: u64) -> u64 {
    ((u128::from(a) * u128::from(b)) % u128::from(P)) as u64
}

fn pow(mut base: u64, mut exp: u64) -> u64 {
    let mut acc = 1;
    while exp > 0 {
        if exp & 1 == 1 {
            acc = mul(acc, base);
        }
        base = mul(base, base);
        exp >>= 1;
    }
    acc
}

/// `a^-1` by Fermat. `a` must be non-zero.
pub(super) fn inv(a: u64) -> u64 {
    debug_assert!(a != 0);
    pow(a, P - 2)
}

/// An element of `Fp6`: coefficients `[a0, .., a5]` of `a0 + a1 u + .. + a5 u^5`, with `u^6 = 7`.
pub(super) type Fp6 = [u64; 6];

pub(super) const ZERO: Fp6 = [0; 6];
pub(super) const ONE: Fp6 = [1, 0, 0, 0, 0, 0];

pub(super) fn f6_add(f: &Fp6, g: &Fp6) -> Fp6 {
    std::array::from_fn(|i| add(f[i], g[i]))
}

pub(super) fn f6_sub(f: &Fp6, g: &Fp6) -> Fp6 {
    std::array::from_fn(|i| sub(f[i], g[i]))
}

pub(super) fn f6_neg(f: &Fp6) -> Fp6 {
    std::array::from_fn(|i| neg(f[i]))
}

/// Multiply by a base-field scalar.
pub(super) fn f6_scale(s: u64, f: &Fp6) -> Fp6 {
    std::array::from_fn(|i| mul(s, f[i]))
}

pub(super) fn f6_mul(f: &Fp6, g: &Fp6) -> Fp6 {
    // Full product has degree 10; fold `u^(k+6) = 7 u^k`.
    let mut wide = [0u64; 11];
    for i in 0..6 {
        for j in 0..6 {
            wide[i + j] = add(wide[i + j], mul(f[i], g[j]));
        }
    }
    std::array::from_fn(|k| {
        if k < 5 {
            add(wide[k], mul(7, wide[k + 6]))
        } else {
            wide[k]
        }
    })
}

/// Multiply by `u`.
fn f6_mul_u(f: &Fp6) -> Fp6 {
    [mul(7, f[5]), f[0], f[1], f[2], f[3], f[4]]
}

/// `f^-1`, or `None` for zero. Solves `f * x = 1` as a 6x6 linear system over `Fp`: column `j`
/// of the matrix is `f * u^j`. Gaussian elimination needs only base-field inverses.
pub(super) fn f6_inv(f: &Fp6) -> Option<Fp6> {
    let mut cols = [ZERO; 6];
    let mut cur = *f;
    for col in &mut cols {
        *col = cur;
        cur = f6_mul_u(&cur);
    }
    // Augmented rows: m[i] = [cols[0][i], .., cols[5][i] | e0[i]].
    let mut m = [[0u64; 7]; 6];
    for (i, row) in m.iter_mut().enumerate() {
        for (j, col) in cols.iter().enumerate() {
            row[j] = col[i];
        }
        row[6] = u64::from(i == 0);
    }
    for c in 0..6 {
        let pivot = (c..6).find(|&r| m[r][c] != 0)?;
        m.swap(c, pivot);
        let scale = inv(m[c][c]);
        for v in &mut m[c] {
            *v = mul(*v, scale);
        }
        for r in 0..6 {
            if r != c && m[r][c] != 0 {
                let factor = m[r][c];
                for k in 0..7 {
                    m[r][k] = sub(m[r][k], mul(factor, m[c][k]));
                }
            }
        }
    }
    Some(std::array::from_fn(|i| m[i][6]))
}
