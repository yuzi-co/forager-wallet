//! **BIP39 / BIP44 hierarchical-deterministic (HD) transparent-address keygen.**
//!
//! Opt-in companion to the single-key generator in [`crate`].  Where [`crate::generate`] mints one
//! standalone random key, this module derives keys from a 24-word BIP39 mnemonic at the *standard*
//! BIP44 path
//!
//! ```text
//! m / 44' / <slip44> ' / <account> ' / 0 / <index>
//! ```
//!
//! and prints the address **at that path** — i.e. exactly what any standard BIP44 wallet (Trezor,
//! Ledger, Electrum, Ian Coleman's tool, …) reproduces from the same phrase.  That is what makes
//! the mnemonic a faithful backup of the printed address, addressing the honesty concern the
//! single-key design raised (a phrase whose standard derivation would *not* match a printed key).
//!
//! ## Scope
//! Transparent **base58check P2PKH on secp256k1** only — the Bitcoin/Zcash-family coins Forager
//! mines that have both a base58 P2PKH scheme and a registered SLIP-44 coin type.  No shielded
//! (sapling/orchard) addresses; no bech32/Taproot/Ethereum/CryptoNote (those families keep the
//! single-key path).  Zcash-family transparent addresses use a two-byte version prefix; all others
//! use one byte — [`crate::coins::FamilyParams`] carries either.
//!
//! ## Coin table
//! There is no separate HD coin table.  A row in [`crate::coins::COINS`] is HD-derivable when it
//! carries a `hd_slip44` **and** its family has a base58 P2PKH form — [`supported`] applies exactly
//! that filter.  The version and WIF bytes therefore have one definition per coin, shared with the
//! single-key generator.
//!
//! ## Provenance
//! Mnemonic↔seed (BIP39) and BIP32/BIP44 child derivation are delegated to the audited `bip32`
//! crate (pure-Rust `k256` backend).  Address/WIF *encoding* reuses this crate's own clean-room
//! primitives — the very same [`crate::families::p2pkh`] encoder the single-key path uses, plus
//! [`crate::secret::wif`].  Every coin row is locked by a known-answer test in `tests/hd_kat.rs`
//! against an independent oracle anchored to the canonical BIP39/BIP32 published vectors.

use bip32::{DerivationPath, Mnemonic, PrivateKey, XPrv};
use zeroize::{Zeroize, Zeroizing};

use crate::coins::{CoinSpec, COINS};
use crate::curves::secp256k1;
use crate::{families, secret};

/// All coins the HD generator supports: every [`COINS`] row that carries a SLIP-44 coin type and
/// has a base58 P2PKH address form.
pub fn supported() -> Vec<&'static CoinSpec> {
    COINS.iter().filter(|c| c.hd_parts().is_some()).collect()
}

/// Look up an HD-capable coin by ticker (case-insensitive). `None` when the ticker is unknown **or**
/// the coin is single-key only (e.g. Ethereum, Monero, Kaspa — no base58 P2PKH form).
pub fn lookup(symbol: &str) -> Option<&'static CoinSpec> {
    let spec = crate::coins::lookup(symbol)?;
    spec.hd_parts().map(|_| spec)
}

/// The result of one HD derivation.
///
/// `wif` encodes the **private key** — treat it as secret: print it only to the explicit command
/// output the user asked for, never to logs.  The [`core::fmt::Debug`] impl redacts it.
#[derive(Clone)]
pub struct HdAccount {
    /// Ticker of the coin.
    pub symbol: &'static str,
    /// Human-readable coin name.
    pub name: &'static str,
    /// The full BIP44 derivation path used (`m/44'/…/0/index`).
    pub path: String,
    /// Payout address in the coin's canonical base58check P2PKH form.
    pub address: String,
    /// Compressed Wallet Import Format private key (secret).
    pub wif: String,
}

impl core::fmt::Debug for HdAccount {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HdAccount")
            .field("symbol", &self.symbol)
            .field("name", &self.name)
            .field("path", &self.path)
            .field("address", &self.address)
            .field("wif", &"<redacted>")
            .finish()
    }
}

/// Errors from HD keygen.
#[derive(Debug, PartialEq, Eq)]
pub enum HdError {
    /// The requested ticker is not an HD-capable coin (run [`supported`]).
    UnknownCoin(String),
    /// The supplied mnemonic failed BIP39 validation (bad word / length / checksum).
    InvalidMnemonic,
    /// The OS entropy source failed.
    Entropy,
    /// BIP32 derivation failed (astronomically unlikely — an invalid child scalar).
    Derivation,
}

impl core::fmt::Display for HdError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HdError::UnknownCoin(t) => write!(f, "coin '{t}' does not support HD (BIP44) keygen"),
            HdError::InvalidMnemonic => {
                f.write_str("invalid BIP39 mnemonic (check the words, length, and checksum)")
            }
            HdError::Entropy => f.write_str("failed to read OS entropy"),
            HdError::Derivation => f.write_str("BIP32 key derivation failed"),
        }
    }
}

impl std::error::Error for HdError {}

/// Generate a fresh **24-word (256-bit)** BIP39 English mnemonic from the OS CSPRNG.
///
/// The returned phrase zeroizes on drop; the caller must display it exactly once and never persist
/// it — anyone with it controls every address derived from it.
pub fn generate_mnemonic() -> Result<Zeroizing<String>, HdError> {
    let mut entropy = [0u8; 32];
    getrandom::getrandom(&mut entropy).map_err(|_| HdError::Entropy)?;
    // 256 bits of entropy -> 24 words. `Default::default()` selects English (the only BIP39
    // language `bip32` ships and the only one standardized).
    let mnemonic = Mnemonic::from_entropy(entropy, Default::default());
    entropy.zeroize();
    Ok(Zeroizing::new(mnemonic.phrase().to_string()))
}

/// Validate a BIP39 mnemonic phrase (word list + checksum). `Ok(())` if importable.
pub fn validate_mnemonic(phrase: &str) -> Result<(), HdError> {
    Mnemonic::new(phrase.trim(), Default::default())
        .map(|_| ())
        .map_err(|_| HdError::InvalidMnemonic)
}

/// Derive the payout address + WIF for `coin` at the standard BIP44 path
/// `m/44'/<slip44>'/<account>'/0/<index>` from `phrase` (+ optional BIP39 `passphrase`).
///
/// The private key is materialised only transiently and its byte buffer is zeroized before return;
/// the returned [`HdAccount::wif`] is the sole secret the caller receives.
pub fn derive(
    phrase: &str,
    passphrase: &str,
    coin: &CoinSpec,
    account: u32,
    index: u32,
) -> Result<HdAccount, HdError> {
    // A row without a SLIP-44 type or without a base58 P2PKH form is not HD-derivable. `lookup`
    // already filters those out, but `derive` is public and takes any `CoinSpec`.
    let (slip44, version, wif_byte) = coin
        .hd_parts()
        .ok_or_else(|| HdError::UnknownCoin(coin.ticker.to_string()))?;

    let mnemonic =
        Mnemonic::new(phrase.trim(), Default::default()).map_err(|_| HdError::InvalidMnemonic)?;
    // `Seed` zeroizes its 64 bytes on drop.
    let seed = mnemonic.to_seed(passphrase);
    let path_str = format!("m/44'/{slip44}'/{account}'/0/{index}");
    let path: DerivationPath = path_str.parse().map_err(|_| HdError::Derivation)?;
    let xprv = XPrv::derive_from_path(&seed, &path).map_err(|_| HdError::Derivation)?;

    // 32-byte child private scalar. Fully-qualified to pick the bip32 trait method (`[u8; 32]`),
    // not k256's inherent `to_bytes` (a GenericArray).
    let mut priv32: [u8; 32] = PrivateKey::to_bytes(xprv.private_key());

    let d = secp256k1::scalar_in_range(&priv32).map_err(|_| HdError::Derivation)?;
    let pubkey = secp256k1::pubkey_compressed(&d);
    // Same encoder as the single-key path — see `families::p2pkh`.
    let address = families::p2pkh::address_from_pubkey(&pubkey, version);
    let wif = secret::wif(&priv32, wif_byte, true);

    priv32.zeroize();
    Ok(HdAccount {
        symbol: coin.ticker,
        name: coin.name,
        path: path_str,
        address,
        wif,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_is_case_insensitive() {
        assert_eq!(lookup("BTC").unwrap().ticker, "btc");
        assert_eq!(lookup("Zec").unwrap().hd_slip44, Some(133));
        assert!(lookup("eth").is_none()); // Ethereum is single-key only
    }

    /// `supported()` is exactly the HD-capable subset of the one coin table: every coin that has a
    /// SLIP-44 type and a base58 P2PKH form, and nothing whose family lacks one.
    ///
    /// Pinned deliberately. A coin becomes HD-capable as a side effect of gaining `hd_slip44`, so
    /// this list changing is the signal to add HD KAT coverage for the new coin — not something to
    /// update reflexively.
    #[test]
    fn supported_is_the_hd_capable_subset_of_coins() {
        let tickers: Vec<&str> = supported().iter().map(|c| c.ticker).collect();
        assert_eq!(
            tickers,
            [
                "btc", "ltc", "vtc", "doge", "rvn", "firo", "mewc", "zec", "btg", "kmd", "btcz",
                "zer"
            ]
        );
        for c in supported() {
            assert!(c.hd_slip44.is_some(), "{}", c.ticker);
            assert!(c.params.p2pkh_parts().is_some(), "{}", c.ticker);
        }
        // Single-key-only families must never appear.
        for t in [
            "pearl", "eth", "etc", "ubq", "xmr", "kas", "kls", "spr", "erg", "alph", "xdag",
        ] {
            assert!(lookup(t).is_none(), "{t} must not be HD-capable");
        }
    }

    /// `derive` rejects a `CoinSpec` that is not HD-capable rather than inventing a path.
    #[test]
    fn derive_rejects_non_hd_coin() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let eth = crate::coins::lookup("eth").unwrap();
        assert!(matches!(
            derive(phrase, "", eth, 0, 0),
            Err(HdError::UnknownCoin(_))
        ));
    }

    #[test]
    fn generate_mnemonic_is_24_words_and_valid() {
        let m = generate_mnemonic().unwrap();
        assert_eq!(m.split_whitespace().count(), 24);
        validate_mnemonic(&m).unwrap();
    }

    #[test]
    fn two_fresh_mnemonics_differ() {
        // Sanity that entropy actually varies (not a fixed/seeded RNG).
        assert_ne!(*generate_mnemonic().unwrap(), *generate_mnemonic().unwrap());
    }

    #[test]
    fn derive_is_deterministic_for_same_inputs() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let a = derive(phrase, "", lookup("btc").unwrap(), 0, 0).unwrap();
        let b = derive(phrase, "", lookup("btc").unwrap(), 0, 0).unwrap();
        assert_eq!(a.address, b.address);
        assert_eq!(a.wif, b.wif);
        assert_eq!(a.path, "m/44'/0'/0'/0/0");
    }

    #[test]
    fn invalid_mnemonic_rejected() {
        assert_eq!(
            validate_mnemonic("not a real mnemonic phrase"),
            Err(HdError::InvalidMnemonic)
        );
    }

    #[test]
    fn debug_redacts_wif() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let a = derive(phrase, "", lookup("btc").unwrap(), 0, 0).unwrap();
        let dbg = format!("{a:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains(&a.wif));
    }
}
