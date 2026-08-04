//! secp256k1 point arithmetic for payout-address derivation, backed by [`k256`].
//!
//! The curve layer used to be hand-rolled on `num-bigint` (naive variable-time double-and-add over
//! freshly generated private keys).  It now delegates to `k256` — pure Rust, audited, constant-time
//! scalar arithmetic — which was already in the dependency graph via `bip32` (HD mode) and
//! `algo-nexapow`.  Output is byte-identical for every supported coin; the module's shape is
//! unchanged apart from the scalar type ([`Secret`] instead of a `BigUint`).
//!
//! BIP340/341 conventions still live here, because they are *encoding* rules rather than curve
//! arithmetic:
//! - [`internal_xonly`] is the **untweaked** x-only key (`bytes(d·G).x`) — what the Kaspa-family
//!   `Version::PubKey` addresses carry.
//! - [`taptweak_output`] applies the BIP341 output-key tweak on top of it (Taproot / Pearl).

use k256::elliptic_curve::ops::{MulByGenerator, Reduce};
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint, Scalar, SecretKey, U256};

use crate::hash::tagged_hash;
use crate::WalletError;

/// A validated secp256k1 private scalar in `1..n-1`.
///
/// `k256::SecretKey` enforces the range invariant on construction and zeroizes on drop, so the
/// crate never carries an unchecked scalar around.
pub(crate) type Secret = SecretKey;

/// Copy a 32-byte field element out of `k256`'s `FieldBytes` (big-endian, already fixed width —
/// no left-padding needed, unlike the old `BigUint::to_bytes_be`).
fn fb_to_32(fb: &FieldBytes) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(fb);
    out
}

/// Validate `priv32` is a curve scalar in `1..n-1`, returning it as a [`Secret`].
pub(crate) fn scalar_in_range(priv32: &[u8; 32]) -> Result<Secret, WalletError> {
    SecretKey::from_slice(priv32).map_err(|_| WalletError::PrivKeyOutOfRange)
}

/// Lift an x-only coordinate to the curve point with **even** Y (BIP340 `lift_x`).
///
/// Expressed as a SEC1 decompression with the `0x02` (even-Y) prefix — exactly BIP340's
/// definition.  `None` when `x` is not a valid x-coordinate (`x ≥ p`, or `x³ + 7` is not a
/// quadratic residue); the hand-rolled predecessor silently returned an off-curve point instead.
fn lift_x(x: &[u8; 32]) -> Option<AffinePoint> {
    let mut sec1 = [0u8; 33];
    sec1[0] = 0x02;
    sec1[1..].copy_from_slice(x);
    let encoded = EncodedPoint::from_bytes(sec1).ok()?;
    Option::from(AffinePoint::from_encoded_point(&encoded))
}

/// Derive the Taproot **internal** x-only key (`bytes(d·G).x`) for private key `d`.
pub(crate) fn internal_xonly(d: &Secret) -> [u8; 32] {
    fb_to_32(&d.public_key().as_affine().x())
}

/// The 32-byte Taproot **output** key for a key-path-only spend: `Q = lift_x(P) + t·G`,
/// `t = int(hash_TapTweak(P_xonly))`, returned x-only. (`internal_xonly` is the BIP341
/// internal key.)
///
/// Panics only if `internal_xonly` is not a valid x-only public key.  Every crate call site feeds
/// it the output of [`internal_xonly`], which is by construction the x-coordinate of a real curve
/// point, so the branch is unreachable — and a panic is strictly preferable to emitting an
/// unspendable payout address.
pub(crate) fn taptweak_output(internal_xonly: &[u8; 32]) -> [u8; 32] {
    let internal = lift_x(internal_xonly)
        .expect("BIP341 internal key must be a valid x-only secp256k1 public key");
    // BIP341 takes `t = int(hash_TapTweak(P))` and requires `t < n`; reducing mod n matches the
    // previous implementation bit-for-bit and differs only on a ~2^-128 input.
    let tweak_hash = FieldBytes::from(tagged_hash("TapTweak", internal_xonly));
    let t = <Scalar as Reduce<U256>>::reduce_bytes(&tweak_hash);
    let q = ProjectivePoint::from(internal) + ProjectivePoint::mul_by_generator(&t);
    fb_to_32(&q.to_affine().x())
}

/// 33-byte compressed SEC1 pubkey for secret `d`: 0x02/0x03 ‖ x (prefix by y parity).
pub(crate) fn pubkey_compressed(d: &Secret) -> [u8; 33] {
    let mut out = [0u8; 33];
    out.copy_from_slice(d.public_key().to_encoded_point(true).as_bytes());
    out
}

/// 65-byte uncompressed SEC1 pubkey: 0x04 ‖ x ‖ y.
pub(crate) fn pubkey_uncompressed(d: &Secret) -> [u8; 65] {
    let mut out = [0u8; 65];
    out.copy_from_slice(d.public_key().to_encoded_point(false).as_bytes());
    out
}

/// Test-only: build a [`Secret`] from a big-endian hex private key (left-padded to 32 bytes), so
/// the family KATs can keep writing their vectors as the literals their upstream sources use.
#[cfg(test)]
pub(crate) fn secret_from_hex(hex: &str) -> Secret {
    let bytes = crate::hexbytes::decode(hex).expect("bad test key hex");
    assert!(bytes.len() <= 32, "bad test key: {hex}");
    // Left-pad to 32 bytes so a short literal like "01" means the big-endian scalar 1.
    let mut priv32 = [0u8; 32];
    priv32[32 - bytes.len()..].copy_from_slice(&bytes);
    scalar_in_range(&priv32).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hexbytes::{encode as hex, hex32};

    /// Differential vectors captured from the **previous** hand-rolled `num-bigint` implementation
    /// (commit `3b1b9d51`, before the `k256` port) by printing its raw output for each key.  They
    /// are the regression oracle for the port: every byte here was produced by the code this module
    /// replaced, so any divergence — parity convention, `lift_x` normalization, tweak reduction,
    /// left-padding — fails loudly instead of silently minting a foreign address.
    ///
    /// Columns: `privkey`, `internal_xonly`, `taptweak_output(internal_xonly)`,
    /// `pubkey_compressed`, `pubkey_uncompressed`.
    ///
    /// Coverage: `d = 1` (generator), small scalars, both `n-1` and `n-2` (odd-Y pubkeys, the
    /// near-group-order edge), the Pearl/xdagj/Alephium KAT keys, a fixed pseudo-random key, and
    /// the XMR non-canonical key.  The xdagj row's tweak output starts with `00`, which pins the
    /// 32-byte left-padding the old `BigUint::to_bytes_be` path needed.
    #[allow(clippy::type_complexity)]
    const DIFF_VECTORS: &[(&str, &str, &str, &str, &str)] = &[
        (
            "0000000000000000000000000000000000000000000000000000000000000001",
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "da4710964f7852695de2da025290e24af6d8c281de5a0b902b7135fd9fd74d21",
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000002",
            "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            "cafd90c7026f0b6ab98df89490d02732881f2f4b5900856358dddff4679c2ffb",
            "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            "04c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee51ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000003",
            "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
            "418c46636d9e1a683f58e35b42336e776fdcc3b2d4e39e7a0bf1ab0716e3c5fa",
            "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
            "04f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000004",
            "e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13",
            "9317856ed22b3699e792f38ad803f9f3fafabf70a2c8983af715592242c29ca8",
            "02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13",
            "04e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd1351ed993ea0d455b75642e2098ea51448d967ae33bfbdfe40cfe97bdc47739922",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000005",
            "2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4",
            "ee713c671c569fbb39901ea3f75195854ba615099ab33a6aecaa5ed539522f93",
            "022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4",
            "042f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4d8ac222636e5e3d6d4dba9dda6c9c426f788271bab0d6840dca87d3aa6ac62d6",
        ),
        // n-1: the largest in-range scalar. Its pubkey is -G, so Y is odd (0x03 prefix) while the
        // x-only key equals G's — the exact place a parity mix-up would hide.
        (
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "da4710964f7852695de2da025290e24af6d8c281de5a0b902b7135fd9fd74d21",
            "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798b7c52588d95c3b9aa25b0403f1eef75702e84bb7597aabe663b82f6f04ef2777",
        ),
        // n-2: second odd-Y near-order case.
        (
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413f",
            "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            "cafd90c7026f0b6ab98df89490d02732881f2f4b5900856358dddff4679c2ffb",
            "03c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            "04c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5e51e970159c23cc65c3a7be6b99315110809cd9acd992f1edc9bce55af301705",
        ),
        // Pearl KAT private key (`lib.rs` `KAT_PRIV`) — odd Y.
        (
            "511d49d0d994f96fc1d8f5fd7e6f1c4060fc5867b45ca222b3a15301d0cc03d2",
            "ce833cce3880ee49ec77183891b2c8c5948563127e0a97aa3957ad678d342c2c",
            "7c649c8b6caa12268d44be78e3bd10cb9790c18442491bd18349f0b447054f78",
            "03ce833cce3880ee49ec77183891b2c8c5948563127e0a97aa3957ad678d342c2c",
            "04ce833cce3880ee49ec77183891b2c8c5948563127e0a97aa3957ad678d342c2ce4dc0d2619637163817fe1abcbd434ba69f1e294c65d9a1d8f18dd5c7dbc356d",
        ),
        // xdagj SampleKeys private key — the tweak output has a leading zero byte.
        (
            "a392604efc2fad9c0b3da43b5f698a2e3f270f170d859912be0d54742275c5f6",
            "506bc1dc099358e5137292f4efdd57e400f29ba5132aa5d12b18dac1c1f6aaba",
            "007b9ab7542d65289399ff2dca2ffcf0f5303b6aa9b075ded4444ba81734ecd8",
            "02506bc1dc099358e5137292f4efdd57e400f29ba5132aa5d12b18dac1c1f6aaba",
            "04506bc1dc099358e5137292f4efdd57e400f29ba5132aa5d12b18dac1c1f6aaba645c0b7b58158babbfa6c6cd5a48aa7340a8749176b120e8516216787a13dc76",
        ),
        // Alephium official KAT private key — odd Y.
        (
            "91411e484289ec7e8b3058697f53f9b26fa7305158b4ef1a81adfbabcf090e45",
            "0f9f042a9410969f1886f85fa20f6e43176ae23fc5e64db15b3767c84c5db2dc",
            "673b259816e94ef1944b9bfa68c09fdf7b3c578cda33ac48236ea6f092e4cd14",
            "030f9f042a9410969f1886f85fa20f6e43176ae23fc5e64db15b3767c84c5db2dc",
            "040f9f042a9410969f1886f85fa20f6e43176ae23fc5e64db15b3767c84c5db2dc856bd03c22c8faec3c43d30d4967ae3a9f689d733ff703d7fe2940be5048ea6d",
        ),
        // Fixed pseudo-random key.
        (
            "7f3e2a1b0c9d8e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f",
            "a49e52aa2502e4d64298c371411428d08e7aba01c1d5fea65e96e0876bb6b24f",
            "9d66dcf8cb4781340622a7390d3cb795ab9b59888ee869ad8bc2a3be17d31ec2",
            "02a49e52aa2502e4d64298c371411428d08e7aba01c1d5fea65e96e0876bb6b24f",
            "04a49e52aa2502e4d64298c371411428d08e7aba01c1d5fea65e96e0876bb6b24f2ccdb029f68b674e64c54f7133bc10b3a12aaa8d664745edff5bec708ff345b8",
        ),
        // The XMR-canonicity key from `lib.rs` (secp256k1-valid, ed25519-non-canonical).
        (
            "0100000000000000000000000000000000000000000000000000000000000020",
            "2a67761fb1d82ff5586c801638958ae8e70d92b33a3227d0dbea82d66a283c3a",
            "e76edffb70a0e0c004daeeba3dd7e7b7cb975d9421a8bfb2653bc64f9a459418",
            "032a67761fb1d82ff5586c801638958ae8e70d92b33a3227d0dbea82d66a283c3a",
            "042a67761fb1d82ff5586c801638958ae8e70d92b33a3227d0dbea82d66a283c3af1a030a164249fab60e97cf2569b7d5ed0f69dc1fe163cb131505774834dc08f",
        ),
    ];

    #[test]
    fn matches_prior_hand_rolled_implementation() {
        for (key, want_internal, want_tweak, want_compressed, want_uncompressed) in DIFF_VECTORS {
            let d = secret_from_hex(key);
            let internal = internal_xonly(&d);
            assert_eq!(hex(&internal), *want_internal, "internal_xonly for {key}");
            assert_eq!(
                hex(&taptweak_output(&internal)),
                *want_tweak,
                "taptweak_output for {key}"
            );
            assert_eq!(
                hex(&pubkey_compressed(&d)),
                *want_compressed,
                "pubkey_compressed for {key}"
            );
            assert_eq!(
                hex(&pubkey_uncompressed(&d)),
                *want_uncompressed,
                "pubkey_uncompressed for {key}"
            );
        }
    }

    /// `internal_xonly` is the *untweaked* key: it must equal the compressed pubkey's x bytes and
    /// must NOT equal the BIP341 output key.  Kaspa/Karlsen/Spectre addresses depend on this.
    #[test]
    fn internal_key_is_untweaked() {
        for (key, ..) in DIFF_VECTORS {
            let d = secret_from_hex(key);
            let internal = internal_xonly(&d);
            assert_eq!(internal, pubkey_compressed(&d)[1..]);
            assert_ne!(internal, taptweak_output(&internal));
        }
    }

    /// Zero and `≥ n` are rejected; `1` and `n-1` are accepted.
    #[test]
    fn scalar_range_bounds() {
        const N: &str = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
        assert_eq!(
            scalar_in_range(&[0u8; 32]).err(),
            Some(WalletError::PrivKeyOutOfRange)
        );
        assert_eq!(
            scalar_in_range(&hex32(N)).err(),
            Some(WalletError::PrivKeyOutOfRange)
        );
        assert_eq!(
            scalar_in_range(&[0xffu8; 32]).err(),
            Some(WalletError::PrivKeyOutOfRange)
        );
        assert!(scalar_in_range(&hex32(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ))
        .is_ok());
        assert!(scalar_in_range(&hex32(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"
        ))
        .is_ok());
    }

    /// `lift_x` follows BIP340: it always returns the even-Y point, so lifting the x of an odd-Y
    /// pubkey yields that pubkey's negation, not the pubkey itself.
    #[test]
    fn lift_x_normalizes_to_even_y() {
        // n-1 → pubkey -G (odd Y); lifting its x must give G (even Y).
        let d = secret_from_hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140");
        let odd = pubkey_compressed(&d);
        assert_eq!(odd[0], 0x03);
        let lifted = lift_x(&internal_xonly(&d)).unwrap();
        let mut even = [0u8; 33];
        even.copy_from_slice(lifted.to_encoded_point(true).as_bytes());
        assert_eq!(even[0], 0x02);
        assert_eq!(even[1..], odd[1..]);
    }

    /// An x that is not on the curve is rejected rather than silently lifted to garbage.
    #[test]
    fn lift_x_rejects_off_curve_and_overflow() {
        // x = 5: 5³ + 7 = 132 is not a quadratic residue mod p, so no curve point has this x.
        let mut x = [0u8; 32];
        x[31] = 5;
        assert!(lift_x(&x).is_none());
        // x = p (and anything above) is out of the field.
        assert!(lift_x(&[0xffu8; 32]).is_none());
    }
}
