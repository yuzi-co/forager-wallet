//! Nockchain (NOCK) address encoding: the Tip5 digest of a public key (the "payee hash", a v1 pkh)
//! as one base58 integer.
//!
//! A digest is five Goldilocks limbs `[a, b, c, d, e]`, each below `p = 2^64 - 2^32 + 1`. The
//! address is `base58(a + b p + c p^2 + d p^3 + e p^4)` over the Bitcoin alphabet. Source:
//! `zorp-corp/nockchain@ed1edfcc` (MIT OR Apache-2.0), Hoon `digest-to-atom` in
//! `hoon/common/ztd/three.hoon` and `zkvm-jetpack/src/jets/base58_jets.rs`.
//!
//! Three properties set this encoding apart from the base58check coins in this crate, and the
//! first two are why a NOCK address is checked so loosely:
//!
//! - **There is no checksum.** A mistyped address that still decodes below `p^5` is a different,
//!   valid address, and funds sent to it are gone. Only the charset, the length and the range can
//!   be verified.
//! - **There is no version byte and no prefix.** The string looks like a transaction id or a block
//!   id, which are the same encoding of the same kind of digest.
//! - **Leading zeros are not special.** The string is the integer's digits, so a `1` (digit zero)
//!   cannot lead a non-zero value, and [`base58::encode`](super::base58::encode)'s one-`1`-per-zero-byte
//!   rule does not apply.

use num_bigint::BigUint;
use num_traits::Zero;

use super::base58::ALPHABET;

/// The Goldilocks prime, `2^64 - 2^32 + 1`.
pub const P: u64 = 0xffff_ffff_0000_0001;

/// Shortest address a pool accepts. LuckyPool's `addressPattern` is `^[1-9A-HJ-NP-Za-km-z]{40,55}$`.
pub const MIN_LEN: usize = 40;

/// Longest address: `p^5 < 2^320` needs at most 55 base58 digits.
pub const MAX_LEN: usize = 55;

/// Length below which a digest is vanishingly unlikely: a random one is at least `58^53` with
/// probability about `1 - 2^-9.6`, so 54 and 55 characters are what real addresses look like.
/// Detection (as opposed to validation) keys on this, because every shorter length is shared with
/// a corrupted address of another family.
pub const TYPICAL_MIN_LEN: usize = 54;

fn p_pow(k: u32) -> BigUint {
    BigUint::from(P).pow(k)
}

/// The address string for a digest.
pub fn encode_digest(digest: &[u64; 5]) -> String {
    let p = BigUint::from(P);
    let mut n = BigUint::zero();
    for limb in digest.iter().rev() {
        n = n * &p + BigUint::from(*limb);
    }
    if n.is_zero() {
        return char::from(ALPHABET[0]).to_string();
    }
    let digits = n.to_radix_be(58);
    digits
        .into_iter()
        .map(|d| char::from(ALPHABET[usize::from(d)]))
        .collect()
}

/// The digest an address encodes, or `None` unless the string is 40 to 55 Bitcoin-alphabet
/// characters whose integer value is below `p^5` (equivalently: five limbs, each below `p`).
pub fn decode_digest(s: &str) -> Option<[u64; 5]> {
    if !(MIN_LEN..=MAX_LEN).contains(&s.len()) {
        return None;
    }
    let mut n = BigUint::zero();
    for c in s.bytes() {
        let d = ALPHABET.iter().position(|&a| a == c)?;
        n = n * 58u32 + BigUint::from(d as u32);
    }
    if n >= p_pow(5) {
        return None;
    }
    let p = BigUint::from(P);
    let mut out = [0u64; 5];
    for limb in &mut out {
        let rem = &n % &p;
        *limb = rem.iter_u64_digits().next().unwrap_or(0);
        n /= &p;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// v1 pkh addresses the reference wallet's own tests use as recipients
    /// (`crates/apps/nockchain-wallet/src/tests.rs`, `recipient.rs`): real digests in the real
    /// encoding.
    const REFERENCE_ADDRESSES: [&str; 3] = [
        "9yPePjfWAdUnzaQKyxcRXKRa5PpUzKKEwtpECBZsUYt9Jd7egSDEWoV",
        "9phXGACnW4238oqgvn2gpwaUjG3RAqcxq2Ash2vaKp8KjzSd3MQ56Jt",
        "DKrgXqE8bXR1uBZ3t4vU13m2KquGCDbnn1PeoPL7dxSHTucGPFDPt53",
    ];

    #[test]
    fn reference_addresses_decode_and_re_encode_exactly() {
        for a in REFERENCE_ADDRESSES {
            let d = decode_digest(a).unwrap_or_else(|| panic!("{a} must decode"));
            assert!(d.iter().all(|l| *l < P), "{a}");
            assert_eq!(encode_digest(&d), a);
        }
    }

    #[test]
    fn digest_limb_order_is_least_significant_first() {
        // Digest [1, 0, 0, 0, 0] is the integer 1, which is the single digit "2".
        assert_eq!(encode_digest(&[1, 0, 0, 0, 0]), "2");
        // [0, 1, 0, 0, 0] is p.
        let p = BigUint::from(P);
        let expected: String = p
            .to_radix_be(58)
            .into_iter()
            .map(|d| char::from(ALPHABET[usize::from(d)]))
            .collect();
        assert_eq!(encode_digest(&[0, 1, 0, 0, 0]), expected);
    }

    #[test]
    fn leading_zero_limbs_shorten_the_string_and_are_never_padded() {
        let short = encode_digest(&[5, 0, 0, 0, 0]);
        assert_eq!(short, "6");
        assert!(
            decode_digest(&short).is_none(),
            "below the 40-character floor"
        );
        let d = [1, 2, 3, 4, P - 5];
        assert!((54..=55).contains(&encode_digest(&d).len()));
    }

    #[test]
    fn the_range_check_is_exactly_p_to_the_fifth() {
        let max = [P - 1; 5];
        let s = encode_digest(&max);
        assert_eq!(decode_digest(&s), Some(max));
        // p^5 itself decodes to a value one past the largest digest.
        let over = (p_pow(5)).to_radix_be(58);
        let s: String = over
            .into_iter()
            .map(|d| char::from(ALPHABET[usize::from(d)]))
            .collect();
        assert_eq!(decode_digest(&s), None);
    }

    #[test]
    fn length_and_charset_bounds() {
        assert!(decode_digest(&"2".repeat(39)).is_none());
        assert!(decode_digest(&"2".repeat(56)).is_none());
        assert!(decode_digest(&"2".repeat(40)).is_some());
        assert!(decode_digest(&"2".repeat(55)).is_some());
        for bad in ["0", "O", "I", "l"] {
            let s = format!("{}{bad}", "2".repeat(44));
            assert!(decode_digest(&s).is_none(), "{bad}");
        }
    }
}
