//! **BIP39 hierarchical-deterministic (HD) address keygen (BIP44 / BIP84 / BIP86).**
//!
//! Opt-in companion to the single-key generator in [`crate`].  Where [`crate::generate`] mints one
//! standalone random key, this module derives keys from a 24-word BIP39 mnemonic at a *standard*
//! path
//!
//! ```text
//! m / <purpose> ' / <slip44> ' / <account> ' / 0 / <index>
//! ```
//!
//! and prints the address **at that path** — i.e. exactly what any standard BIP44 wallet (Trezor,
//! Ledger, Electrum, Ian Coleman's tool, …) reproduces from the same phrase.  That is what makes
//! the mnemonic a faithful backup of the printed address, addressing the honesty concern the
//! single-key design raised (a phrase whose standard derivation would *not* match a printed key).
//!
//! ## Scope
//! Four address types on secp256k1, selected by [`Purpose`]:
//!
//! | Purpose | Path | Address |
//! |---|---|---|
//! | [`Purpose::Bip44`] | `m/44'` | base58check P2PKH, or the Ethereum-family EIP-55 address |
//! | [`Purpose::Bip84`] | `m/84'` | native SegWit v0 P2WPKH (bech32) |
//! | [`Purpose::Bip86`] | `m/86'` | Taproot P2TR key-path (bech32m) |
//!
//! Each coin's **native** purpose is the one whose address type matches what the single-key
//! generator produces for it — see [`native_purpose`]. That alignment is deliberate: if `--hd`
//! returned a legacy address for a coin whose single-key path returns SegWit, the mnemonic would
//! be a backup of a worse address than the tool otherwise hands out.
//!
//! No shielded (sapling/orchard) addresses, and no CryptoNote: that family has no BIP32 path at
//! all, so Monero and its forks stay single-key only.
//!
//! ## Coin table
//! There is no separate HD coin table.  A row in [`crate::coins::COINS`] is HD-derivable when it
//! carries a `hd_slip44` **and** its family has at least one derivable purpose — [`supported`]
//! applies exactly that filter.  A coin with no registered SLIP-44 type is deliberately excluded
//! even when its family would work: inventing a coin type would produce a path no other wallet
//! reproduces, which defeats the point of deriving from a standard mnemonic.
//!
//! ## Provenance
//! Mnemonic↔seed (BIP39) and BIP32/BIP44 child derivation are delegated to the audited `bip32`
//! crate (pure-Rust `k256` backend).  Address/WIF *encoding* reuses this crate's own clean-room
//! primitives — the very same [`crate::families::p2pkh`] encoder the single-key path uses, plus
//! [`crate::secret::wif`].  Every coin row is locked by a known-answer test in `tests/hd_kat.rs`
//! against an independent oracle anchored to the canonical BIP39/BIP32 published vectors.

use bip32::{DerivationPath, Mnemonic, PrivateKey, XPrv};
use zeroize::{Zeroize, Zeroizing};

use crate::coins::{CoinSpec, FamilyParams, COINS};
use crate::curves::secp256k1;
use crate::{families, secret, SecretStd};

/// Which BIP-43 purpose — that is, which address type — an HD derivation targets.
///
/// The purpose is the first path element, and wallets key their address type off it. Deriving the
/// same seed under a different purpose yields a different, equally valid set of addresses, so the
/// purpose must be reported alongside the address or the user cannot restore it elsewhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// BIP44 — `m/44'`. Legacy base58check P2PKH, or the Ethereum-family EIP-55 address.
    Bip44,
    /// BIP84 — `m/84'`. Native SegWit v0 P2WPKH (bech32).
    Bip84,
    /// BIP86 — `m/86'`. Taproot P2TR key-path spend (bech32m).
    Bip86,
}

impl Purpose {
    /// The purpose number that appears in the derivation path.
    pub fn number(self) -> u32 {
        match self {
            Purpose::Bip44 => 44,
            Purpose::Bip84 => 84,
            Purpose::Bip86 => 86,
        }
    }

    /// Parse a CLI token. Accepts `bip44`/`44`/`legacy`, `bip84`/`84`/`segwit`, `bip86`/`86`/
    /// `taproot`, case-insensitively.
    pub fn parse(token: &str) -> Option<Purpose> {
        match token.trim().to_ascii_lowercase().as_str() {
            "bip44" | "44" | "legacy" | "p2pkh" => Some(Purpose::Bip44),
            "bip84" | "84" | "segwit" | "p2wpkh" => Some(Purpose::Bip84),
            "bip86" | "86" | "taproot" | "p2tr" => Some(Purpose::Bip86),
            _ => None,
        }
    }
}

impl core::fmt::Display for Purpose {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "bip{}", self.number())
    }
}

/// The purpose whose address type matches what this coin's **single-key** generator produces.
///
/// Keeping these aligned is the point: `new --coin btc` and `new --hd --coin btc` should hand the
/// user the same kind of address, or one of the two is quietly worse than the other.
pub fn native_purpose(coin: &CoinSpec) -> Option<Purpose> {
    match coin.params {
        FamilyParams::SegwitV0 { .. } => Some(Purpose::Bip84),
        FamilyParams::Taproot { .. } => Some(Purpose::Bip86),
        FamilyParams::P2pkh { .. } | FamilyParams::Ethereum => Some(Purpose::Bip44),
        _ => None,
    }
}

/// Whether `coin` can be derived under `purpose`.
///
/// A coin may support several. Bitcoin's row is `SegwitV0` and its Taproot addresses reuse the same
/// bech32 HRP, so a `SegwitV0` row serves BIP44, BIP84 and BIP86 alike.
pub fn supports(coin: &CoinSpec, purpose: Purpose) -> bool {
    if coin.hd_slip44.is_none() {
        return false;
    }
    match purpose {
        Purpose::Bip44 => {
            matches!(coin.params, FamilyParams::Ethereum) || coin.params.p2pkh_parts().is_some()
        }
        Purpose::Bip84 => matches!(coin.params, FamilyParams::SegwitV0 { .. }),
        Purpose::Bip86 => matches!(
            coin.params,
            FamilyParams::SegwitV0 { .. } | FamilyParams::Taproot { .. }
        ),
    }
}

/// Every purpose `coin` supports, native one first.
pub fn purposes(coin: &CoinSpec) -> Vec<Purpose> {
    let native = native_purpose(coin);
    [Purpose::Bip44, Purpose::Bip84, Purpose::Bip86]
        .into_iter()
        .filter(|p| supports(coin, *p))
        .fold(Vec::new(), |mut acc, p| {
            if Some(p) == native {
                acc.insert(0, p);
            } else {
                acc.push(p);
            }
            acc
        })
}

/// All coins the HD generator supports: every [`COINS`] row that carries a SLIP-44 coin type and
/// an address family HD can derive.
pub fn supported() -> Vec<&'static CoinSpec> {
    COINS
        .iter()
        .filter(|c| c.hd_slip44.is_some() && native_purpose(c).is_some())
        .collect()
}

/// Look up an HD-capable coin by ticker (case-insensitive). `None` when the ticker is unknown **or**
/// the coin has no registered SLIP-44 type or no HD-derivable address family (Monero, Kaspa, …).
pub fn lookup(symbol: &str) -> Option<&'static CoinSpec> {
    let spec = crate::coins::lookup(symbol)?;
    (spec.hd_slip44.is_some() && native_purpose(spec).is_some()).then_some(spec)
}

/// The result of one HD derivation.
///
/// `secret` encodes the **private key** — treat it as secret: print it only to the explicit command
/// output the user asked for, never to logs.  The [`core::fmt::Debug`] impl redacts it.
#[derive(Clone)]
pub struct HdAccount {
    /// Ticker of the coin.
    pub symbol: &'static str,
    /// Human-readable coin name.
    pub name: &'static str,
    /// The purpose this account was derived under.
    pub purpose: Purpose,
    /// The full derivation path used (`m/<purpose>'/<slip44>'/<account>'/0/<index>`).
    pub path: String,
    /// Payout address, in the form the purpose selects.
    pub address: String,
    /// The private key in this family's standard importable encoding (secret).
    pub secret: SecretStd,
}

impl HdAccount {
    /// The secret as one printable line, whatever encoding the family uses.
    pub fn secret_str(&self) -> &str {
        match &self.secret {
            SecretStd::Wif(s) | SecretStd::EthHex(s) | SecretStd::RawHex(s) => s,
            // HD derivation never produces a CryptoNote seed: that family has no BIP32 path.
            SecretStd::MoneroMnemonic { view_key_hex, .. } => view_key_hex,
        }
    }
}

impl core::fmt::Debug for HdAccount {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HdAccount")
            .field("symbol", &self.symbol)
            .field("name", &self.name)
            .field("purpose", &self.purpose)
            .field("path", &self.path)
            .field("address", &self.address)
            .field("secret", &"<redacted>")
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
    /// The coin has no address form for the requested purpose (e.g. BIP84 on a P2PKH-only coin).
    UnsupportedPurpose {
        /// The coin that was asked for.
        coin: String,
        /// The purpose that does not apply to it.
        purpose: Purpose,
    },
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
            HdError::UnsupportedPurpose { coin, purpose } => {
                write!(f, "coin '{coin}' has no {purpose} address form")
            }
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
    purpose: Purpose,
    account: u32,
    index: u32,
) -> Result<HdAccount, HdError> {
    // `lookup` already filters non-derivable rows out, but `derive` is public and takes any
    // `CoinSpec`, so re-check here rather than trusting the caller.
    let slip44 = coin
        .hd_slip44
        .ok_or_else(|| HdError::UnknownCoin(coin.ticker.to_string()))?;
    if !supports(coin, purpose) {
        return Err(HdError::UnsupportedPurpose {
            coin: coin.ticker.to_string(),
            purpose,
        });
    }

    let mnemonic =
        Mnemonic::new(phrase.trim(), Default::default()).map_err(|_| HdError::InvalidMnemonic)?;
    // `Seed` zeroizes its 64 bytes on drop.
    let seed = mnemonic.to_seed(passphrase);
    let path_str = format!("m/{}'/{slip44}'/{account}'/0/{index}", purpose.number());
    let path: DerivationPath = path_str.parse().map_err(|_| HdError::Derivation)?;
    let xprv = XPrv::derive_from_path(&seed, &path).map_err(|_| HdError::Derivation)?;

    // 32-byte child private scalar. Fully-qualified to pick the bip32 trait method (`[u8; 32]`),
    // not k256's inherent `to_bytes` (a GenericArray).
    let mut priv32: [u8; 32] = PrivateKey::to_bytes(xprv.private_key());

    let d = secp256k1::scalar_in_range(&priv32).map_err(|_| HdError::Derivation)?;

    // Every arm below reuses the SAME encoder the single-key path uses, so an HD address and a
    // single-key address of the same type cannot diverge.
    let (address, secret) = match (purpose, coin.params) {
        (Purpose::Bip44, FamilyParams::Ethereum) => (
            families::ethereum::address(&d),
            SecretStd::EthHex(secret::eth_hex(&priv32)),
        ),
        (Purpose::Bip44, params) => {
            // `supports` already proved this is `Some`.
            let (version, wif_byte) = params.p2pkh_parts().expect("checked by supports");
            let pubkey = secp256k1::pubkey_compressed(&d);
            (
                families::p2pkh::address_from_pubkey(&pubkey, version),
                SecretStd::Wif(secret::wif(&priv32, wif_byte, true)),
            )
        }
        (Purpose::Bip84, FamilyParams::SegwitV0 { hrp, wif, .. }) => (
            families::segwitv0::address(&d, hrp),
            SecretStd::Wif(secret::wif(&priv32, wif, true)),
        ),
        (Purpose::Bip86, params) => {
            // BIP86 key-path spend: tweak the internal x-only key exactly as the single-key
            // Taproot path does, then encode as bech32m (witness version 1).
            let internal = secp256k1::internal_xonly(&d);
            let output = secp256k1::taptweak_output(&internal);
            let (hrp, wif_byte) = match params {
                FamilyParams::SegwitV0 { hrp, wif, .. } => (hrp, Some(wif)),
                FamilyParams::Taproot { hrp, .. } => (hrp, None),
                _ => unreachable!("checked by supports"),
            };
            let addr = crate::codec::bech32::encode(hrp, 1, &output);
            // A row that carries a WIF byte exports one, because a WIF is importable and raw hex
            // often is not. A Taproot-only row has no WIF byte, so it exports raw hex — the same
            // choice the single-key Taproot path makes.
            let sec = match wif_byte {
                Some(b) => SecretStd::Wif(secret::wif(&priv32, b, true)),
                None => SecretStd::RawHex(crate::hexbytes::encode(&priv32)),
            };
            (addr, sec)
        }
        _ => unreachable!("supports() admits only the combinations handled above"),
    };

    priv32.zeroize();
    Ok(HdAccount {
        symbol: coin.ticker,
        name: coin.name,
        purpose,
        path: path_str,
        address,
        secret,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_is_case_insensitive() {
        assert_eq!(lookup("BTC").unwrap().ticker, "btc");
        assert_eq!(lookup("Zec").unwrap().hd_slip44, Some(133));
        // Ethereum-family rows ARE HD-capable (BIP44 m/44'/60'). Monero is not: CryptoNote has
        // no BIP32 path at all.
        assert_eq!(lookup("eth").unwrap().hd_slip44, Some(60));
        assert!(lookup("xmr").is_none());
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
                "btc", "ltc", "vtc", "doge", "rvn", "firo", "mewc", "etc", "eth", "ubq", "zec",
                "btg", "kmd", "btcz", "zer"
            ]
        );
        for c in supported() {
            assert!(c.hd_slip44.is_some(), "{}", c.ticker);
            // Every supported row must have at least one derivable purpose, and its native purpose
            // must be one of them.
            let ps = purposes(c);
            assert!(!ps.is_empty(), "{}", c.ticker);
            assert_eq!(Some(ps[0]), native_purpose(c), "{}", c.ticker);
        }
        // Families with no BIP32 path, or with no registered SLIP-44 type, must never appear.
        // `pearl`, `ethw` and `octa` are absent for the second reason: SLIP-44 registers no coin
        // type for them, and inventing one would produce a path no other wallet reproduces.
        for t in [
            "pearl", "ethw", "octa", "xmr", "kas", "kls", "spr", "erg", "alph", "xdag", "scash",
            "alpha",
        ] {
            assert!(lookup(t).is_none(), "{t} must not be HD-capable");
        }
    }

    /// `derive` rejects a `CoinSpec` that is not HD-capable rather than inventing a path.
    #[test]
    fn derive_rejects_non_hd_coin() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        // Monero: no BIP32 derivation exists for CryptoNote, so no purpose applies.
        let xmr = crate::coins::lookup("xmr").unwrap();
        assert!(matches!(
            derive(phrase, "", xmr, Purpose::Bip44, 0, 0),
            Err(HdError::UnknownCoin(_))
        ));
        // A coin that IS HD-capable still rejects a purpose its family cannot encode.
        let doge = crate::coins::lookup("doge").unwrap();
        assert!(matches!(
            derive(phrase, "", doge, Purpose::Bip84, 0, 0),
            Err(HdError::UnsupportedPurpose { .. })
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
        let a = derive(phrase, "", lookup("btc").unwrap(), Purpose::Bip44, 0, 0).unwrap();
        let b = derive(phrase, "", lookup("btc").unwrap(), Purpose::Bip44, 0, 0).unwrap();
        assert_eq!(a.address, b.address);
        assert_eq!(a.secret_str(), b.secret_str());
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
        let a = derive(phrase, "", lookup("btc").unwrap(), Purpose::Bip44, 0, 0).unwrap();
        let dbg = format!("{a:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains(a.secret_str()));
    }
}
