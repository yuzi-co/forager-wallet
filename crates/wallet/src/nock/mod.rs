//! Nockchain key derivation: BIP39 seed to master secret key to Cheetah public key to the v1
//! payee-hash address.
//!
//! Ported from `zorp-corp/nockchain@ed1edfcc` (MIT OR Apache-2.0): `hoon/common/slip10.hoon`
//! (`from-seed`), `hoon/common/ztd/three.hoon` (`ser-a-pt`, `hash-noun-varlen`, `digest-to-atom`),
//! `hoon/common/tx-engine-0.hoon` (`schnorr-pubkey` `hash`) and the Rust mirrors under
//! `crates/lib/nockchain-math`. See the repository `NOTICE`.
//!
//! The pieces, in order:
//!
//! 1. `I = HMAC-SHA512(key = "Nockchain seed", data = seed)` with the 64-byte BIP39 seed (empty
//!    passphrase). The secret key is `I[..32]` as a big-endian integer and the chain code is
//!    `I[32..]`. If the key is not below the group order, `I` is hashed again under the same key
//!    until it is, the SLIP-10 retry rule.
//! 2. The public key is `sk * G` on the Cheetah curve, an `Fp6` point `(x, y)`.
//! 3. The v1 address is the Tip5 `hash-noun-varlen` of the noun `[x y inf]` (the two `Fp6`
//!    coordinates as six-tuples, `inf` the loobean `%.n` = 1), five limbs, base58 of
//!    `a + b p + c p^2 + d p^3 + e p^4`. The base58 half lives in `forager_addr::codec::nock`.
//!
//! Only the master key is derived. Nockchain's wallet pays the master public key's hash, so no
//! child derivation is needed for a payout address.

mod curve;
mod field;
mod tip5;

use sha2::{Digest, Sha512};
use zeroize::{Zeroize, Zeroizing};

use curve::{below_group_order, scalar_mul, Point, GENERATOR};
use tip5::Noun;

/// HMAC key of the master derivation: the cord `'dees niahckcoN'` in the Hoon, whose big-endian
/// byte reading, the one Hoon's `hmac-sha512l` uses, is this string.
const DOMAIN_SEPARATOR: &[u8] = b"Nockchain seed";

/// HMAC-SHA512 (RFC 2104), written out over `sha2`: this crate has no `hmac` dependency of its
/// own, and a 128-byte-block HMAC is shorter than the dependency's manifest entry.
fn hmac_sha512(key: &[u8], data: &[u8]) -> Zeroizing<[u8; 64]> {
    const BLOCK: usize = 128;
    let mut k = Zeroizing::new([0u8; BLOCK]);
    if key.len() > BLOCK {
        k[..64].copy_from_slice(&Sha512::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = Zeroizing::new([0x36u8; BLOCK]);
    let mut opad = Zeroizing::new([0x5cu8; BLOCK]);
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha512::new();
    inner.update(&ipad[..]);
    inner.update(data);
    let mut inner_digest = inner.finalize();
    let mut outer = Sha512::new();
    outer.update(&opad[..]);
    outer.update(inner_digest);
    inner_digest.zeroize();
    let mut out = Zeroizing::new([0u8; 64]);
    out.copy_from_slice(&outer.finalize());
    out
}

/// Big-endian 32 bytes to four little-endian 64-bit limbs.
fn limbs_le(be: &[u8; 32]) -> [u64; 4] {
    std::array::from_fn(|i| {
        let start = (3 - i) * 8;
        u64::from_be_bytes(be[start..start + 8].try_into().expect("8 bytes"))
    })
}

/// The master secret key of a BIP39 seed, and its chain code. The chain code only feeds child
/// derivation, which a payout address does not need, so only the tests keep it.
pub(crate) struct Master {
    pub(crate) secret_key: Zeroizing<[u8; 32]>,
    #[cfg(test)]
    pub(crate) chain_code: Zeroizing<[u8; 32]>,
}

/// SLIP-10 master key of `seed` (`slip10.hoon` `from-seed`). A zero key is rejected along with one
/// at or above the group order: the reference only tests `< n`, but a zero key is the identity,
/// has no public key, and has probability 2^-255.
pub(crate) fn master_from_seed(seed: &[u8]) -> Master {
    let mut der = hmac_sha512(DOMAIN_SEPARATOR, seed);
    loop {
        let mut left = Zeroizing::new([0u8; 32]);
        left.copy_from_slice(&der[..32]);
        let limbs = limbs_le(&left);
        if limbs != [0; 4] && below_group_order(&limbs) {
            return Master {
                secret_key: left,
                #[cfg(test)]
                chain_code: Zeroizing::new(der[32..].try_into().expect("32 bytes")),
            };
        }
        der = hmac_sha512(DOMAIN_SEPARATOR, &der[..]);
    }
}

/// `sk * G`, or `None` unless `0 < sk < n`.
fn public_key(secret_key: &[u8; 32]) -> Option<Point> {
    let mut limbs = limbs_le(secret_key);
    let ok = limbs != [0; 4] && below_group_order(&limbs);
    let point = ok.then(|| scalar_mul(&limbs, &GENERATOR));
    limbs.zeroize();
    point
}

/// `ser-a-pt`: `0x01 ‖ y5..y0 ‖ x5..x0`, each limb a big-endian `u64`. The legacy v0 address is
/// the base58 of these 97 bytes.
#[cfg(test)]
fn serialize_public_key(p: &Point) -> [u8; 97] {
    let mut out = [0u8; 97];
    out[0] = 1;
    let limbs = p.y.iter().rev().chain(p.x.iter().rev());
    for (chunk, limb) in out[1..].as_chunks_mut::<8>().0.iter_mut().zip(limbs) {
        chunk.copy_from_slice(&limb.to_be_bytes());
    }
    out
}

/// The noun the pubkey hash covers: `[x y inf]` with `x` and `y` six-tuples of limbs
/// (`a0` first) and `inf` the loobean, `%.n` = 1 for a finite point.
fn public_key_noun(p: &Point) -> Noun {
    let tuple = |f: &[u64; 6]| Noun::tuple(&f.map(Noun::Atom));
    Noun::tuple(&[tuple(&p.x), tuple(&p.y), Noun::Atom(u64::from(!p.inf))])
}

/// Tip5 digest of a public key: Hoon `hash:schnorr-pubkey`, `(hash-hashable leaf+form)`.
fn public_key_hash(p: &Point) -> [u64; 5] {
    tip5::hash_noun_varlen(&public_key_noun(p))
}

/// The v1 address of a secret key, or `None` for a key outside `1..n-1`.
pub(crate) fn address_of_secret_key(secret_key: &[u8; 32]) -> Option<String> {
    let p = public_key(secret_key)?;
    Some(forager_addr::codec::nock::encode_digest(&public_key_hash(
        &p,
    )))
}

#[cfg(test)]
mod tests;
