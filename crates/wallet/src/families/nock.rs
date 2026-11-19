//! Nockchain (NOCK) payout address: the v1 payee hash of the master public key of a BIP39 seed.
//!
//! The key scheme is Nockchain's own SLIP-10 variant on the Cheetah curve, implemented in
//! [`crate::nock`]; this module joins it to the mnemonic and the wallet API. The wallet's own
//! `keygen` conditions 32 random bytes and a salt through Argon2 before it forms the phrase. That
//! step only conditions entropy, and the wallet imports any valid BIP39 phrase, so this crate mints
//! a phrase straight from OS entropy and the result imports into the official wallet
//! (`import-keys --seedphrase --version 1`) all the same.
//!
//! Only the master key is used: the official wallet pays the master public key's hash, so no child
//! derivation is involved. The BIP39 passphrase is always empty, as the official import has none.

use zeroize::Zeroizing;

use crate::bip39::{self, Bip39Error};
use crate::nock;

/// The v1 address of a master secret key, or `None` unless it is in `1..n-1`.
pub(crate) fn address(secret_key: &[u8; 32]) -> Option<String> {
    nock::address_of_secret_key(secret_key)
}

/// A master secret key as the 64 hexadecimal characters this crate prints, whitespace ignored. A
/// key outside `1..n-1` is refused: it has no public key.
pub(crate) fn parse_secret_key(input: &str) -> Option<Zeroizing<[u8; 32]>> {
    let mut compact: String = input.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let key = crate::hexbytes::decode_n::<32>(&compact);
    zeroize::Zeroize::zeroize(&mut compact);
    let key = Zeroizing::new(key?);
    nock::address_of_secret_key(&key).map(|_| key)
}

/// The master secret key of a BIP39 phrase (12 to 24 words, empty passphrase).
pub(crate) fn secret_key_from_phrase(phrase: &str) -> Result<Zeroizing<[u8; 32]>, Bip39Error> {
    let seed = bip39::seed(phrase, "")?;
    Ok(nock::master_from_seed(seed.as_bytes()).secret_key)
}
