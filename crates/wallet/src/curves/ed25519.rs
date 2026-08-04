//! Clean-room **Edwards25519** (RFC 8032) scalar-base-multiply + point compression.
//!
//! Secures Monero payout keys (wired in Task 11). Pure `num-bigint`, no external curve crate.
//! The twisted-Edwards curve is `-x² + y² = 1 + d·x²·y²` over the field `p = 2²⁵⁵ − 19`, with
//! `d = -121665 · inv(121666) mod p`, base point `B = (x, 4/5)` (x recovered with low bit 0 per
//! RFC 8032 §5.1), and group order `l = 2²⁵² + 27742317777372353535851937790883648493`.
//!
//! `a = -1` is a square and `d` is a non-square in `GF(p)`, so the twisted-Edwards addition
//! formula below is **complete** — it is exception-free for all inputs, including doubling and
//! the identity `(0, 1)`. Timing is irrelevant: this runs at keygen only, never signs a secret.

use num_bigint::BigUint;
use num_traits::{One, Zero};

/// Field prime `p = 2²⁵⁵ − 19`.
fn p() -> BigUint {
    (BigUint::one() << 255u32) - 19u32
}

/// Group order `l = 2²⁵² + 27742317777372353535851937790883648493`.
fn l() -> BigUint {
    (BigUint::one() << 252u32)
        + BigUint::parse_bytes(b"27742317777372353535851937790883648493", 10).unwrap()
}

/// Modular inverse via Fermat (`m` prime): `a^(m-2) mod m`.
fn inv(a: &BigUint, m: &BigUint) -> BigUint {
    a.modpow(&(m - 2u32), m)
}

/// Curve constant `d = -121665 · inv(121666) mod p`.
fn d_param(m: &BigUint) -> BigUint {
    let num = m - 121665u32; // -121665 mod p
    let den = inv(&BigUint::from(121666u32), m);
    (num * den) % m
}

/// `sqrt(-1) = 2^((p-1)/4) mod p`, used to fix up the square-root branch in `recover_x`.
fn sqrt_m1(m: &BigUint) -> BigUint {
    let exp = (m - 1u32) / 4u32;
    BigUint::from(2u32).modpow(&exp, m)
}

/// Recover the `x` coordinate from `y` and the desired low bit `sign` (RFC 8032 §5.1.3).
fn recover_x(y: &BigUint, sign: u32, m: &BigUint, d: &BigUint) -> BigUint {
    let y2 = (y * y) % m;
    let u = (&y2 + m - 1u32) % m; // y² − 1
    let v = (d * &y2 + 1u32) % m; // d·y² + 1
                                  // Candidate root: x = u·v³ · (u·v⁷)^((p−5)/8).
    let v3 = v.modpow(&BigUint::from(3u32), m);
    let v7 = v.modpow(&BigUint::from(7u32), m);
    let exp = (m - 5u32) / 8u32;
    let mut x = (&u * &v3 % m) * (&u * &v7 % m).modpow(&exp, m) % m;
    // Verify v·x² == ±u, fixing the off-by-sqrt(-1) branch as needed.
    let vx2 = (&v * &x % m) * &x % m;
    if vx2 != u {
        let neg_u = (m - &u) % m;
        debug_assert_eq!(vx2, neg_u, "y has no x on the curve");
        x = (x * sqrt_m1(m)) % m;
    }
    // Select the root whose low bit matches `sign`.
    if (&x % 2u32) != BigUint::from(sign) {
        x = m - &x;
    }
    x
}

/// Base point `B = (x, 4/5)`, x taken with low bit 0 (RFC 8032 §5.1).
fn base(m: &BigUint, d: &BigUint) -> (BigUint, BigUint) {
    let y = (BigUint::from(4u32) * inv(&BigUint::from(5u32), m)) % m;
    let x = recover_x(&y, 0, m, d);
    (x, y)
}

/// Complete twisted-Edwards point addition (`a = -1`); also handles doubling and identity.
fn add(
    p1: &(BigUint, BigUint),
    p2: &(BigUint, BigUint),
    m: &BigUint,
    d: &BigUint,
) -> (BigUint, BigUint) {
    let (x1, y1) = p1;
    let (x2, y2) = p2;
    let x1x2 = (x1 * x2) % m;
    let y1y2 = (y1 * y2) % m;
    let dxy = (d * &x1x2 % m) * &y1y2 % m; // d·x₁x₂·y₁y₂
                                           // x₃ = (x₁y₂ + y₁x₂) / (1 + d·x₁x₂y₁y₂)
    let x_num = ((x1 * y2) % m + (y1 * x2) % m) % m;
    let x_den = (BigUint::one() + &dxy) % m;
    let x3 = (x_num * inv(&x_den, m)) % m;
    // y₃ = (y₁y₂ + x₁x₂) / (1 − d·x₁x₂y₁y₂)   (a = −1 ⇒ −a·x₁x₂ = +x₁x₂)
    let y_num = (&y1y2 + &x1x2) % m;
    let y_den = (m + 1u32 - &dxy) % m;
    let y3 = (y_num * inv(&y_den, m)) % m;
    (x3, y3)
}

/// `scalar · point` via double-and-add over the little-endian scalar.
fn scalarmult(
    scalar_le: &[u8; 32],
    point: &(BigUint, BigUint),
    m: &BigUint,
    d: &BigUint,
) -> (BigUint, BigUint) {
    let k = BigUint::from_bytes_le(scalar_le);
    let mut acc = (BigUint::zero(), BigUint::one()); // identity
    let mut addend = point.clone();
    for i in 0..k.bits() {
        if k.bit(i) {
            acc = add(&acc, &addend, m, d);
        }
        addend = add(&addend, &addend, m, d);
    }
    acc
}

/// Encode `v` as 32-byte little-endian, zero-padded.
fn to_le32(v: &BigUint) -> [u8; 32] {
    let raw = v.to_bytes_le();
    let mut out = [0u8; 32];
    out[..raw.len()].copy_from_slice(&raw);
    out
}

/// Compress a point to 32 bytes (RFC 8032 §5.1.2): little-endian `y`, MSB ← low bit of `x`.
fn compress(x: &BigUint, y: &BigUint) -> [u8; 32] {
    let mut out = to_le32(y);
    if (x % 2u32) == BigUint::one() {
        out[31] |= 0x80;
    }
    out
}

/// Multiply the base point `B` by `scalar` (little-endian) and return the compressed point.
///
/// `scalar` is a raw little-endian integer — Monero feeds an `sc_reduce`'d scalar, not a clamped
/// one; the RFC-8032 SHA-512+clamp keygen lives only in the tests.
pub(crate) fn scalarmult_base(scalar: &[u8; 32]) -> [u8; 32] {
    let m = p();
    let d = d_param(&m);
    let b = base(&m, &d);
    let (x, y) = scalarmult(scalar, &b, &m, &d);
    compress(&x, &y)
}

/// Reduce a 32-byte little-endian integer modulo the group order `l`, returning 32-byte LE.
pub(crate) fn reduce_scalar_mod_l(b: &[u8; 32]) -> [u8; 32] {
    to_le32(&(BigUint::from_bytes_le(b) % l()))
}

#[cfg(test)]
mod tests {
    use super::{reduce_scalar_mod_l, scalarmult_base};
    use crate::hexbytes::{encode as hex, hex32};
    use sha2::{Digest, Sha512};

    /// Full RFC 8032 §7.1 key derivation: `a = clamp(SHA-512(sk)[0..32])`, pubkey = `compress(a·B)`.
    fn pubkey_from_secret(sk_hex: &str) -> String {
        let h = Sha512::digest(hex32(sk_hex));
        let mut a = [0u8; 32];
        a.copy_from_slice(&h[..32]);
        a[0] &= 0xF8;
        a[31] &= 0x7F;
        a[31] |= 0x40;
        hex(&scalarmult_base(&a))
    }

    /// RFC 8032 §7.1 TEST 1 (source: rfc-editor.org/rfc/rfc8032.txt, §7.1).
    #[test]
    fn rfc8032_test1_pubkey() {
        assert_eq!(
            pubkey_from_secret("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
    }

    /// RFC 8032 §7.1 TEST 2 — independent second anchor (source: rfc-editor.org §7.1).
    #[test]
    fn rfc8032_test2_pubkey() {
        assert_eq!(
            pubkey_from_secret("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"),
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
        );
    }

    /// `reduce_scalar_mod_l` is identity on a small in-range scalar and idempotent on any input.
    #[test]
    fn reduce_scalar_mod_l_in_range_and_idempotent() {
        let small = hex32("0700000000000000000000000000000000000000000000000000000000000000");
        assert_eq!(reduce_scalar_mod_l(&small), small);

        let big = [0xffu8; 32];
        let once = reduce_scalar_mod_l(&big);
        assert_eq!(reduce_scalar_mod_l(&once), once);
    }
}
