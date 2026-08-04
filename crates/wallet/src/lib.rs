//! **Multi-coin secp256k1 payout-address keygen.**
//!
//! Supports Taproot (Pearl, Bitcoin P2TR), SegWit v0 P2WPKH (Bitcoin, Litecoin, …), P2PKH
//! (Dogecoin, Ravencoin, …), and Ethereum-family (ETC, ETH, …) payout addresses derived from a
//! random secp256k1 private key.  The coin table lives in [`coins`]; use [`supported()`] to
//! enumerate available coins, [`generate()`] to mint a fresh wallet, or
//! [`address_from_secret()`] / [`address_from_secret_kind()`] to derive an address from an
//! existing private key.
//!
//! Every address codec (bech32/bech32m, base58check, cashaddr, CryptoNote, EIP-55) is implemented
//! here against public BIP/EIP specs and gated against canonical known-answer tests.  secp256k1
//! point arithmetic is delegated to [`k256`](https://docs.rs/k256) (RustCrypto: pure Rust, audited,
//! constant-time scalar math) rather than hand-rolled; the BIP340/341 x-only and Taproot-tweak
//! *conventions* on top of it still live in [`curves::secp256k1`].  Ed25519 (CryptoNote) remains a
//! local clean-room implementation.
//!
//! ## HD (BIP39/BIP44) mode
//! The opt-in [`hd`] module adds standard hierarchical-deterministic keygen (24-word BIP39
//! mnemonic → BIP44 `m/44'/coin'/account'/0/index` → transparent P2PKH address + WIF) for the
//! Bitcoin/Zcash-family base58 coins, so the printed address is exactly what a standard BIP44
//! wallet reproduces from the same phrase.  It is *additive* — the single-key API above is
//! unchanged.  HD derivation is delegated to the well-audited `bip32` crate (BIP39 + BIP32 on the
//! pure-Rust `k256` backend); this crate's own curve stays the single-key authority.
//!
//! ## Back-compat Pearl API
//! The original Pearl-only helpers ([`address_from_privkey`], [`address_from_hex`],
//! [`generate_pearl`]) remain public for callers that predate the generic API.

#![forbid(unsafe_code)]

pub mod cli;
mod curves;
mod families;
mod hash;
pub mod hd;
mod keccak;
mod mnemonic;
mod ripemd160;
mod secret;
mod wordlist_en;

// Address classification and the coin table live in the `wallet-addr` crate, which deliberately
// depends on no curve, entropy or mnemonic code. They are re-exported here so that every existing
// `forager_wallet::…` path — and every intra-crate `crate::codec::` / `crate::coins::` / `crate::hexbytes::`
// reference — keeps resolving unchanged. See the repository README.
pub use forager_addr::{check, coins, detect_family, family_name, validate, Family, Verdict};
pub(crate) use forager_addr::{codec, hexbytes};

/// Which network an address targets (selects version bytes / HRP / prefix).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// Mainnet.
    Mainnet,
    /// Testnet.
    Testnet,
}

impl Network {
    /// Pearl bech32m HRP for this network (back-compat; Pearl-specific).
    pub fn hrp(self) -> &'static str {
        match self {
            Network::Mainnet => "prl",
            Network::Testnet => "tprl",
        }
    }
}

/// Standard secret-key encoding for a coin family.
// `MoneroMnemonic` carries a 25-element `[String; 25]`, so it is intentionally much larger than the
// other (single-`String`) variants.  Boxing it would buy nothing: a `Wallet` is minted only at
// keygen, never in a hot path or large collection.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretStd {
    /// Wallet Import Format (base58check) for P2PKH / SegWit v0 coins.
    Wif(String),
    /// `0x`-prefixed 64-char lowercase hex (Ethereum-family coins).
    EthHex(String),
    /// Monero full-wallet restore secret (CryptoNote coins): the 25-word English seed phrase
    /// (which encodes the private spend seed) plus the deterministic private view key as hex.
    MoneroMnemonic {
        /// The 25 English mnemonic words (24 data words + 1 checksum word).
        words: [String; 25],
        /// The deterministic private **view** key as 64-char lowercase hex.
        view_key_hex: String,
    },
    /// Raw 64-char lowercase hex without prefix (Taproot coins).
    RawHex(String),
}

/// A generated or derived payout wallet.
#[derive(Debug, Clone)]
pub struct Wallet {
    /// Ticker of the coin this wallet was generated for (e.g. `"pearl"`, `"btc"`).
    pub coin: &'static str,
    /// Payout address in the coin's canonical encoding.
    pub address: String,
    /// Raw 32-byte secp256k1 private key (back this up — it controls the funds).
    pub privkey: [u8; 32],
    /// Private key as 64-char lowercase hex (no prefix).
    pub secret_hex: String,
    /// Private key in the coin's standard secret encoding (WIF, EthHex, or RawHex).
    pub secret_std: SecretStd,
}

/// Errors from key parsing / generation.
#[derive(Debug, PartialEq, Eq)]
pub enum WalletError {
    /// A private-key hex string was not exactly 64 hex chars / 32 bytes, or non-hex.
    BadPrivKeyHex,
    /// The private key was zero or ≥ the curve order (not a valid scalar).
    PrivKeyOutOfRange,
    /// The OS entropy source failed.
    Entropy,
    /// The requested ticker is not in the coin table.
    UnknownCoin(String),
    /// The coin does not support testnet (its testnet params are `None`).
    UnsupportedTestnet,
    /// A runtime `family:params` coin token was malformed (carries the parser message).
    BadCoinToken(String),
}

impl std::fmt::Display for WalletError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WalletError::BadPrivKeyHex => {
                f.write_str("private key must be 64 hex characters (32 bytes)")
            }
            WalletError::PrivKeyOutOfRange => {
                f.write_str("private key out of range (must be 1..n-1)")
            }
            WalletError::Entropy => f.write_str("failed to read OS entropy"),
            WalletError::UnknownCoin(t) => write!(f, "unknown coin ticker: {t}"),
            WalletError::UnsupportedTestnet => {
                f.write_str("this coin does not support testnet addresses")
            }
            WalletError::BadCoinToken(m) => write!(f, "bad coin token: {m}"),
        }
    }
}

impl std::error::Error for WalletError {}

// ---------------------------------------------------------------------------
// Generic public API.
// ---------------------------------------------------------------------------

/// Return all coins supported by the wallet crate.
pub fn supported() -> &'static [coins::CoinSpec] {
    coins::COINS
}

/// Resolve a `--coin` argument to a [`coins::CoinSpec`].
///
/// A plain ticker (`btc`, `xdag`) hits the KAT-gated [`COINS`] table.  A `family:params` token
/// (contains `:`) is parsed on the fly via [`coins::parse_token`] — an UNVERIFIED ad-hoc spec the
/// caller must flag (see [`is_custom_token`]).  Anything else is [`WalletError::UnknownCoin`].
pub(crate) fn resolve_spec(coin: &str) -> Result<coins::CoinSpec, WalletError> {
    if let Some(s) = coins::lookup(coin) {
        return Ok(*s);
    }
    if coin.contains(':') {
        return coins::parse_token(coin).map_err(WalletError::BadCoinToken);
    }
    Err(WalletError::UnknownCoin(coin.into()))
}

/// Whether a `--coin` argument is a runtime `family:params` token rather than a table ticker.
/// Runtime tokens are UNVERIFIED (no KAT) — callers print a warning before trusting the address.
pub fn is_custom_token(coin: &str) -> bool {
    coins::lookup(coin).is_none() && coin.contains(':')
}

/// Derive the payout address and secret encoding for `coin` from a 64-hex-char private key.
///
/// For SegWit v0 coins the default (non-legacy) path produces a bech32 P2WPKH address.
/// Use [`address_from_secret_kind`] with `legacy = true` to get the P2PKH form instead.
pub fn address_from_secret(
    coin: &str,
    secret_hex: &str,
    net: Network,
) -> Result<Wallet, WalletError> {
    address_from_secret_kind(coin, secret_hex, net, false)
}

/// Like [`address_from_secret`] but `legacy = true` selects the P2PKH address form for
/// dual-address SegWit v0 coins (ignored for other families).
pub fn address_from_secret_kind(
    coin: &str,
    secret_hex: &str,
    net: Network,
    legacy: bool,
) -> Result<Wallet, WalletError> {
    let spec = resolve_spec(coin)?;
    let priv32 = parse_privkey_hex(secret_hex)?;
    let d = curves::secp256k1::scalar_in_range(&priv32)?;
    build_wallet(&spec, &d, &priv32, net, legacy)
}

/// Generate a fresh payout [`Wallet`] for `coin` on `net` from OS entropy.
pub fn generate(coin: &str, net: Network) -> Result<Wallet, WalletError> {
    let spec = resolve_spec(coin)?;
    loop {
        let mut buf = [0u8; 32];
        getrandom::getrandom(&mut buf).map_err(|_| WalletError::Entropy)?;
        // Rejection sampling: `scalar_in_range` is the single range authority (0 < d < n).
        let Ok(d) = curves::secp256k1::scalar_in_range(&buf) else {
            continue;
        };
        return build_wallet(&spec, &d, &buf, net, false);
    }
}

/// Run [`dispatch`] and assemble the [`Wallet`] — the shared tail of [`address_from_secret_kind`]
/// and [`generate`], so the two paths cannot report a key differently.
fn build_wallet(
    spec: &coins::CoinSpec,
    d: &curves::secp256k1::Secret,
    priv32: &[u8; 32],
    net: Network,
    legacy: bool,
) -> Result<Wallet, WalletError> {
    let (address, secret_std, canon_priv) = dispatch(spec, d, priv32, net, legacy)?;
    Ok(Wallet {
        coin: spec.ticker,
        address,
        privkey: *priv32,
        // `dispatch` returns the canonical private key it actually used: identical to the input for
        // secp256k1 families, but the sc_reduce'd spend scalar for CryptoNote.  Print that so
        // `secret_hex` and `secret_std` always agree on the same canonical scalar.
        secret_hex: hexbytes::encode(&canon_priv),
        secret_std,
    })
}

/// Select the mainnet or testnet form of a per-network parameter.
///
/// Every family whose address encoding differs per network threads its parameter through here, so
/// the "testnet is unsupported for this coin" error is raised in exactly one place.
fn pick<T>(net: Network, mainnet: T, testnet: Option<T>) -> Result<T, WalletError> {
    match net {
        Network::Mainnet => Ok(mainnet),
        Network::Testnet => testnet.ok_or(WalletError::UnsupportedTestnet),
    }
}

/// Dispatch address + secret derivation for one [`coins::CoinSpec`].
///
/// Returns `(address, secret_std, canonical_private_key)`.  The canonical private key equals the
/// input for secp256k1 families, but is the `sc_reduce`'d spend scalar for CryptoNote — callers
/// print it as `secret_hex` so it always agrees with `secret_std`.
pub(crate) fn dispatch(
    spec: &coins::CoinSpec,
    d: &curves::secp256k1::Secret,
    priv32: &[u8; 32],
    net: Network,
    legacy: bool,
) -> Result<(String, SecretStd, [u8; 32]), WalletError> {
    // The five raw-hex-secret families (Taproot, Kaspa, Ergo, Alephium, XDAG) differ only in how
    // they render the address, so they fall through to the shared `RawHex` tail below.  The three
    // families with their own secret encoding (SegWit/P2PKH → WIF, Ethereum → 0x-hex, CryptoNote →
    // 25-word phrase) return early.
    let address = match spec.params {
        coins::FamilyParams::Taproot { hrp, hrp_testnet } => {
            let hrp = pick(net, hrp, hrp_testnet)?;
            let internal = curves::secp256k1::internal_xonly(d);
            let output = curves::secp256k1::taptweak_output(&internal);
            codec::bech32::encode(hrp, 1, &output)
        }
        coins::FamilyParams::KaspaAddr {
            prefix,
            prefix_testnet,
        } => {
            let prefix = pick(net, prefix, prefix_testnet)?;
            // Kaspa/Karlsen `Version::PubKey` addresses carry the *untweaked* BIP340 x-only
            // pubkey — unlike Taproot, there is no `TapTweak` step.
            let xonly = curves::secp256k1::internal_xonly(d);
            codec::cashaddr::encode(prefix, 0, &xonly)
        }
        // Ergo's network prefix is a protocol constant for both networks, so it has no
        // `UnsupportedTestnet` case.  Alephium and XDAG addresses are network-agnostic outright:
        // `net` is accepted and changes nothing.
        coins::FamilyParams::Ergo => families::ergo::address(d, net == Network::Testnet),
        coins::FamilyParams::Alephium => families::alephium::address(d),
        coins::FamilyParams::Xdag => families::xdag::address(d),

        coins::FamilyParams::SegwitV0 {
            hrp,
            hrp_testnet,
            wif,
            p2pkh_version,
            p2pkh_version_testnet,
        } => {
            let addr = if legacy {
                let ver = pick(net, p2pkh_version, p2pkh_version_testnet)?;
                families::p2pkh::address(d, ver, true)
            } else {
                families::segwitv0::address(d, pick(net, hrp, hrp_testnet)?)
            };
            return Ok((
                addr,
                SecretStd::Wif(secret::wif(priv32, wif, true)),
                *priv32,
            ));
        }
        coins::FamilyParams::P2pkh {
            version,
            version_testnet,
            wif,
            compressed,
        } => {
            let ver = pick(net, version, version_testnet)?;
            let addr = families::p2pkh::address(d, ver, compressed);
            return Ok((
                addr,
                SecretStd::Wif(secret::wif(priv32, wif, compressed)),
                *priv32,
            ));
        }
        coins::FamilyParams::Ethereum => {
            // Ethereum addresses are network-agnostic at the derivation level.
            let addr = families::ethereum::address(d);
            return Ok((addr, SecretStd::EthHex(secret::eth_hex(priv32)), *priv32));
        }
        coins::FamilyParams::CryptoNote {
            network_byte,
            network_byte_testnet,
        } => {
            let nb = pick(net, network_byte, network_byte_testnet)?;
            // The input is a 32-byte Monero spend secret; `d` (a secp256k1 scalar) is unused here.
            // reduce_scalar_mod_l ensures the spend scalar is canonical (< l), so the printed key is
            // importable by standard Monero wallet tooling.  Idempotent: already-canonical keys
            // round-trip unchanged, so existing KATs on canonical inputs still pass.
            let spend_reduced = curves::ed25519::reduce_scalar_mod_l(priv32);
            let (addr, view_secret) = families::cryptonote::address(&spend_reduced, nb);
            // The 25-word seed encodes the canonical spend scalar (same value used for the
            // address, so phrase and address agree); the view key is the deterministic Monero
            // hash_to_scalar(spend).  Together they are the full-wallet restore secret.
            let s = SecretStd::MoneroMnemonic {
                words: mnemonic::monero_25(&spend_reduced),
                view_key_hex: hexbytes::encode(&view_secret),
            };
            return Ok((addr, s, spend_reduced));
        }
    };

    Ok((
        address,
        SecretStd::RawHex(hexbytes::encode(priv32)),
        *priv32,
    ))
}

// ---------------------------------------------------------------------------
// Back-compat Pearl-specific API (predates generic API; used by wallet_cmd.rs until Task 13).
// ---------------------------------------------------------------------------

/// Derive the Pearl bech32m P2TR payout address from a raw 32-byte private key.
pub fn address_from_privkey(priv32: &[u8; 32], net: Network) -> Result<String, WalletError> {
    let d = curves::secp256k1::scalar_in_range(priv32)?;
    let internal = curves::secp256k1::internal_xonly(&d);
    let output = curves::secp256k1::taptweak_output(&internal);
    Ok(codec::bech32::encode(net.hrp(), 1, &output))
}

/// Parse a 64-char hex Pearl private key and derive its address on `net`.
pub fn address_from_hex(priv_hex: &str, net: Network) -> Result<String, WalletError> {
    let priv32 = parse_privkey_hex(priv_hex)?;
    address_from_privkey(&priv32, net)
}

/// Parse a 64-hex-char (32-byte) private key into raw bytes.
pub fn parse_privkey_hex(priv_hex: &str) -> Result<[u8; 32], WalletError> {
    hexbytes::decode_n(priv_hex.trim()).ok_or(WalletError::BadPrivKeyHex)
}

/// Generate a fresh Pearl payout wallet (back-compat wrapper; prefer `generate("pearl", net)`).
pub fn generate_pearl(net: Network) -> Result<Wallet, WalletError> {
    generate("pearl", net)
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::bech32::encode as bech32m_encode;
    use crate::curves::secp256k1::taptweak_output;
    use crate::hexbytes::hex32;

    // ---- Canonical BIP86 Taproot test vector (the standard anchor). ----
    // m/86'/0'/0'/0/0 from the BIP86 mnemonic.
    const BIP86_INTERNAL: &str = "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115";
    const BIP86_OUTPUT: &str = "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c";
    const BIP86_ADDRESS: &str = "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr";

    #[test]
    fn taptweak_matches_bip86_output_key() {
        let out = taptweak_output(&hex32(BIP86_INTERNAL));
        assert_eq!(hexbytes::encode(&out), BIP86_OUTPUT);
    }

    #[test]
    fn bech32m_matches_bip86_mainnet_address() {
        let out = taptweak_output(&hex32(BIP86_INTERNAL));
        assert_eq!(bech32m_encode("bc", 1, &out), BIP86_ADDRESS);
    }

    // ---- Pearl determinism (fixed key → fixed address). ----
    // Cross-checked against the validated Python reference.
    const KAT_PRIV: &str = "511d49d0d994f96fc1d8f5fd7e6f1c4060fc5867b45ca222b3a15301d0cc03d2";
    const KAT_PRL: &str = "prl1p03jfezmv4gfzdr2yheuw80gsewtepsvygfy3h5vrf8ctg3c9fauqlepk9f";
    const KAT_TPRL: &str = "tprl1p03jfezmv4gfzdr2yheuw80gsewtepsvygfy3h5vrf8ctg3c9fauq5k9g6u";

    #[test]
    fn prl_address_is_deterministic() {
        assert_eq!(
            address_from_hex(KAT_PRIV, Network::Mainnet).unwrap(),
            KAT_PRL
        );
        assert_eq!(
            address_from_hex(KAT_PRIV, Network::Testnet).unwrap(),
            KAT_TPRL
        );
    }

    #[test]
    fn generate_roundtrips_and_is_well_formed() {
        let w = generate("pearl", Network::Mainnet).unwrap();
        assert!(w.address.starts_with("prl1p"), "{}", w.address);
        // 3-char HRP + '1' + witver(1) + 52 (32-byte program in 5-bit groups) + 6 checksum.
        assert_eq!(w.address.len(), 63);
        assert_eq!(
            address_from_privkey(&w.privkey, Network::Mainnet).unwrap(),
            w.address
        );
        assert_eq!(w.coin, "pearl");
        assert_eq!(w.secret_hex.len(), 64);
    }

    #[test]
    fn rejects_bad_and_out_of_range_keys() {
        assert_eq!(parse_privkey_hex("xyz"), Err(WalletError::BadPrivKeyHex));
        assert_eq!(
            address_from_privkey(&[0u8; 32], Network::Mainnet),
            Err(WalletError::PrivKeyOutOfRange)
        );
    }

    // ---- Generic API tests (Task 9) ----

    // Privkey = 1 (0x000...001) is a well-established secp256k1 test vector.
    const PRIV1: &str = "0000000000000000000000000000000000000000000000000000000000000001";

    /// BTC SegWit v0 P2WPKH for privkey=1.
    /// KAT source: BIP173 / bitcoin/src/test/key_tests.cpp; segwit_addr reference impl.
    /// Verified independently: same hash160 as produces 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH (BTC
    /// P2PKH), encoded bech32 with HRP "bc".
    #[test]
    fn btc_segwit_v0_privkey_one() {
        let w = address_from_secret("btc", PRIV1, Network::Mainnet).unwrap();
        assert_eq!(w.address, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        assert_eq!(w.coin, "btc");
        match &w.secret_std {
            SecretStd::Wif(s) => {
                assert_eq!(s, "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn");
            }
            _ => panic!("expected SecretStd::Wif"),
        }
    }

    /// BTC P2PKH legacy address for privkey=1 (via `legacy=true`).
    /// KAT source: Bitcoin Core key_tests; address is 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH.
    #[test]
    fn btc_legacy_path() {
        let w = address_from_secret_kind("btc", PRIV1, Network::Mainnet, true).unwrap();
        assert_eq!(w.address, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
    }

    /// XDAG modern account address through the public seam. KAT input is xdagj's hardcoded
    /// `SampleKeys.PRIVATE_KEY_STRING` (MIT); expected address cross-derived from xdagj's
    /// derivation and gated bit-for-bit in `families::xdag`. Confirms the `xdag` ticker resolves,
    /// dispatches to the no-version Base58Check family, and exports a raw-hex secret.
    #[test]
    fn xdag_address_from_xdagj_sample_key() {
        const XDAG_PRIV: &str = "a392604efc2fad9c0b3da43b5f698a2e3f270f170d859912be0d54742275c5f6";
        let w = address_from_secret("xdag", XDAG_PRIV, Network::Mainnet).unwrap();
        assert_eq!(w.address, "N3RC53vbaDNrziTdWmctBEeQ4fo38moXu");
        assert_eq!(w.coin, "xdag");
        match &w.secret_std {
            SecretStd::RawHex(s) => assert_eq!(s, XDAG_PRIV),
            _ => panic!("expected SecretStd::RawHex"),
        }
    }

    /// ETC and ETH share Ethereum address derivation (EIP-55, keccak160 of uncompressed pubkey).
    /// KAT source: eth_privkey_one test in families/ethereum.rs (priv=1 → well-known checksum addr).
    #[test]
    fn etc_eth_address_privkey_one() {
        let w = address_from_secret("etc", PRIV1, Network::Mainnet).unwrap();
        assert_eq!(w.address, "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf");
        assert_eq!(w.coin, "etc");
        match &w.secret_std {
            SecretStd::EthHex(s) => assert!(s.starts_with("0x")),
            _ => panic!("expected SecretStd::EthHex"),
        }
    }

    /// ETH ticker should produce the same address as ETC.
    #[test]
    fn eth_address_privkey_one() {
        let w = address_from_secret("eth", PRIV1, Network::Mainnet).unwrap();
        assert_eq!(w.address, "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf");
    }

    /// Pearl back-compat: the generic API produces the same address as the old Pearl-specific path.
    /// KAT source: KAT_PRL constant above (cross-checked against Python reference).
    #[test]
    fn pearl_back_compat() {
        let w = address_from_secret("pearl", KAT_PRIV, Network::Mainnet).unwrap();
        assert_eq!(w.address, KAT_PRL);
        assert_eq!(w.coin, "pearl");
        match &w.secret_std {
            SecretStd::RawHex(s) => assert_eq!(s.len(), 64),
            _ => panic!("expected SecretStd::RawHex"),
        }
    }

    /// Unknown coin ticker → WalletError::UnknownCoin.
    #[test]
    fn unknown_coin_errors() {
        assert!(matches!(
            address_from_secret("nope", PRIV1, Network::Mainnet),
            Err(WalletError::UnknownCoin(_))
        ));
    }

    /// SCASH — address bytes are byte-identical to Bitcoin (unchanged base58/bech32 params), so
    /// privkey=1 yields the exact BIP173 Bitcoin vector.  KAT anchored by `btc_segwit_v0_privkey_one`.
    /// Source: scashnetwork/scash (MIT) src/kernel/chainparams.cpp — Bitcoin prefixes unchanged.
    #[test]
    fn scash_matches_bitcoin_bytes() {
        let w = address_from_secret("scash", PRIV1, Network::Mainnet).unwrap();
        assert_eq!(w.address, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        // Legacy P2PKH (version 0x00) is likewise identical to Bitcoin's.
        let l = address_from_secret_kind("scash", PRIV1, Network::Mainnet, true).unwrap();
        assert_eq!(l.address, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
    }

    /// ALPHA (Unicity) — Bitcoin params except bech32 HRP "alpha".  The witness program (5-bit
    /// data) is HRP-independent and equals Bitcoin's for privkey=1; only the "alpha1" HRP and the
    /// trailing 6-char checksum differ.  The legacy P2PKH form (version 0x00) is Bitcoin-identical,
    /// pinning the non-HRP bytes.  Source: unicitynetwork/alpha (MIT) src/kernel/chainparams.cpp.
    #[test]
    fn alpha_hrp_over_bitcoin_hash160() {
        let w = address_from_secret("alpha", PRIV1, Network::Mainnet).unwrap();
        // HRP + HRP-independent data prefix (same witness program as BTC's bc1qw508d6…).
        assert!(
            w.address
                .starts_with("alpha1qw508d6qejxtdg4y5r3zarvary0c5xw7k"),
            "unexpected alpha address: {}",
            w.address
        );
        let l = address_from_secret_kind("alpha", PRIV1, Network::Mainnet, true).unwrap();
        assert_eq!(l.address, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
    }

    // ---- runtime `family:params` coin tokens (UNVERIFIED escape hatch) ----

    /// A `p2pkh:` token with Bitcoin's bytes reproduces Bitcoin's legacy address for privkey=1.
    #[test]
    fn token_p2pkh_reproduces_bitcoin_legacy() {
        assert!(is_custom_token("p2pkh:ver=0x00,wif=0x80"));
        let w = address_from_secret("p2pkh:ver=0x00,wif=0x80", PRIV1, Network::Mainnet).unwrap();
        assert_eq!(w.address, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
        assert_eq!(w.coin, "p2pkh:ver=0x00,wif=0x80");
    }

    /// A `segwit:` token with HRP "bc" reproduces Bitcoin's bech32 address for privkey=1.
    #[test]
    fn token_segwit_reproduces_bitcoin_bech32() {
        let w = address_from_secret("segwit:hrp=bc,wif=0x80", PRIV1, Network::Mainnet).unwrap();
        assert_eq!(w.address, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    }

    /// A `cryptonote:net=18` token reproduces Monero's mainnet address for a fixed spend key —
    /// same encoder as the `xmr` table row (network byte 18), so the address matches byte-for-byte.
    #[test]
    fn token_cryptonote_matches_xmr_row() {
        let key = "0000000000000000000000000000000000000000000000000000000000000001";
        let from_row = address_from_secret("xmr", key, Network::Mainnet).unwrap();
        let from_token = address_from_secret("cryptonote:net=18", key, Network::Mainnet).unwrap();
        assert_eq!(from_row.address, from_token.address);
    }

    /// Decimal and 0x-hex integer forms are equivalent (18 == 0x12).
    #[test]
    fn token_int_decimal_and_hex_equivalent() {
        let key = "0000000000000000000000000000000000000000000000000000000000000001";
        let dec = address_from_secret("cryptonote:net=18", key, Network::Mainnet).unwrap();
        let hex = address_from_secret("cryptonote:net=0x12", key, Network::Mainnet).unwrap();
        assert_eq!(dec.address, hex.address);
    }

    /// A `taproot:hrp=prl` token reproduces the Pearl row's address — same encoder, same HRP.
    #[test]
    fn token_taproot_matches_pearl_row() {
        let row = address_from_secret("pearl", KAT_PRIV, Network::Mainnet).unwrap();
        let token = address_from_secret("taproot:hrp=prl", KAT_PRIV, Network::Mainnet).unwrap();
        assert_eq!(token.address, row.address);
        assert_eq!(token.address, KAT_PRL);
    }

    /// A `kaspa:prefix=kaspa` token reproduces the `kas` row's address.
    #[test]
    fn token_kaspa_matches_kas_row() {
        let row = address_from_secret("kas", PRIV1, Network::Mainnet).unwrap();
        let token = address_from_secret("kaspa:prefix=kaspa", PRIV1, Network::Mainnet).unwrap();
        assert_eq!(token.address, row.address);
    }

    /// The four zero-parameter family tokens reproduce their table rows exactly — nothing is read out
    /// of the token, so the token and the row must agree byte-for-byte.
    #[test]
    fn token_zero_parameter_families_match_their_rows() {
        for (token, ticker) in [
            ("ethereum:", "eth"),
            ("ergo:", "erg"),
            ("alephium:", "alph"),
            ("xdag:", "xdag"),
        ] {
            let t = address_from_secret(token, PRIV1, Network::Mainnet).unwrap();
            let r = address_from_secret(ticker, PRIV1, Network::Mainnet).unwrap();
            assert_eq!(t.address, r.address, "{token}");
            assert!(is_custom_token(token), "{token} must be flagged UNVERIFIED");
        }
    }

    /// Malformed tokens surface `BadCoinToken`, not a silent wrong address.
    #[test]
    fn token_errors_are_typed() {
        assert!(matches!(
            address_from_secret("segwit:wif=0x80", PRIV1, Network::Mainnet), // missing hrp
            Err(WalletError::BadCoinToken(_))
        ));
        assert!(matches!(
            // Unrecognised parameter — ignoring it would mint a wrong-parameter address.
            address_from_secret("cryptonote:net=18,net_tets=53", PRIV1, Network::Mainnet),
            Err(WalletError::BadCoinToken(_))
        ));
        assert!(matches!(
            address_from_secret("bogus:x=1", PRIV1, Network::Mainnet), // unknown family
            Err(WalletError::BadCoinToken(_))
        ));
        assert!(matches!(
            address_from_secret("p2pkh:ver=999,wif=0x80", PRIV1, Network::Mainnet), // byte oob
            Err(WalletError::BadCoinToken(_))
        ));
    }

    /// LTC SegWit v0 P2WPKH for privkey=1.
    /// KAT source: same hash160 as BTC privkey=1 (algorithm-identical), encoded bech32 HRP "ltc".
    /// Chain params confirmed: litecoin-project/litecoin/src/chainparams.cpp
    ///   PUBKEY_ADDRESS=48(0x30), SECRET_KEY=176(0xb0), bech32_hrp="ltc".
    /// Address computed via independent JS bech32 implementation and cross-verified.
    #[test]
    fn ltc_segwit_v0_privkey_one() {
        let w = address_from_secret("ltc", PRIV1, Network::Mainnet).unwrap();
        assert_eq!(w.address, "ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9");
        assert_eq!(w.coin, "ltc");
        match &w.secret_std {
            SecretStd::Wif(s) => {
                // LTC WIF for privkey=1, compressed, wif_byte=0xb0.
                assert_eq!(s, "T33ydQRKp4FCW5LCLLUB7deioUMoveiwekdwUwyfRDeGZm76aUjV");
            }
            _ => panic!("expected SecretStd::Wif"),
        }
    }

    /// VTC SegWit v0 for privkey=1, plus the `--legacy` `V…` form.
    /// Chain params confirmed: vertcoin-project/vertcoin-core/src/chainparams.cpp
    ///   PUBKEY_ADDRESS=71(0x47), SECRET_KEY=128(0x80), bech32_hrp="vtc".
    /// Addresses computed via an independent JS bech32 + base58check oracle, itself validated
    /// against two published constants (BIP173's `bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4`
    /// and BTC legacy `1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH`) before deriving these.
    #[test]
    fn vtc_segwit_v0_and_legacy_privkey_one() {
        let w = address_from_secret("vtc", PRIV1, Network::Mainnet).unwrap();
        assert_eq!(w.address, "vtc1qw508d6qejxtdg4y5r3zarvary0c5xw7kuk9r06");
        assert_eq!(w.coin, "vtc");
        match &w.secret_std {
            // VTC shares Bitcoin's WIF byte (0x80), so the WIF is Bitcoin's for the same key.
            SecretStd::Wif(s) => {
                assert_eq!(s, "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn");
            }
            _ => panic!("expected SecretStd::Wif"),
        }

        let legacy = address_from_secret_kind("vtc", PRIV1, Network::Mainnet, true).unwrap();
        assert_eq!(legacy.address, "Vkg6Ts44mskyD668xZkxFkjqovjXX9yUzZ");

        let testnet = address_from_secret("vtc", PRIV1, Network::Testnet).unwrap();
        assert_eq!(
            testnet.address,
            "tvtc1qw508d6qejxtdg4y5r3zarvary0c5xw7ktyx2us"
        );
    }

    /// FIRO P2PKH for privkey=1.
    /// Chain params confirmed: firoorg/firo/src/chainparams.cpp
    ///   PUBKEY_ADDRESS=82(0x52), SECRET_KEY=210(0xd2); testnet PUBKEY_ADDRESS=65(0x41).
    /// Address computed via the same independent JS base58check oracle described above.
    #[test]
    fn firo_p2pkh_privkey_one() {
        let w = address_from_secret("firo", PRIV1, Network::Mainnet).unwrap();
        assert_eq!(w.address, "aBPjJ4LEarrcCrd6EBRTb8jVjUZuHQFVnD");
        assert_eq!(w.coin, "firo");
        match &w.secret_std {
            SecretStd::Wif(s) => {
                assert_eq!(s, "Y4mR4tfumHPsdfnK8utYBYsHGFBzJswfBmpNWPkt7VGU91p8Yd1d");
            }
            _ => panic!("expected SecretStd::Wif"),
        }

        let testnet = address_from_secret("firo", PRIV1, Network::Testnet).unwrap();
        assert_eq!(testnet.address, "TLeUZDGLWnyiJVFcp3m3M1782uBsGWa8uf");
    }

    /// MEWC P2PKH for privkey=1.
    /// Chain params confirmed: Meowcoin-Foundation/Meowcoin/src/kernel/chainparams.cpp
    ///   PUBKEY_ADDRESS=50(0x32), SECRET_KEY=112(0x70); testnet PUBKEY_ADDRESS=109(0x6d).
    /// Address computed via the same independent JS base58check oracle described above.
    #[test]
    fn mewc_p2pkh_privkey_one() {
        let w = address_from_secret("mewc", PRIV1, Network::Mainnet).unwrap();
        assert_eq!(w.address, "MJaRnao1s62a2zAKSkmG582KbLKianqb7v");
        assert_eq!(w.coin, "mewc");
        match &w.secret_std {
            SecretStd::Wif(s) => {
                assert_eq!(s, "HZwd35MkcDcQ8xV2wVD2AVbYsfW4VsNREUmbfsobzbQiYaKZBbVi");
            }
            _ => panic!("expected SecretStd::Wif"),
        }

        let testnet = address_from_secret("mewc", PRIV1, Network::Testnet).unwrap();
        assert_eq!(testnet.address, "m3X1szP1kjNGHZPRtWR4gX5jj6XNYKHWwN");
    }

    /// DOGE P2PKH for privkey=1.
    /// Chain params confirmed: dogecoin/dogecoin/src/chainparams.cpp
    ///   PUBKEY_ADDRESS=30(0x1e), SECRET_KEY=158(0x9e).
    /// Address computed via independent JS base58check implementation from privkey=1 hash160.
    #[test]
    fn doge_p2pkh_privkey_one() {
        let w = address_from_secret("doge", PRIV1, Network::Mainnet).unwrap();
        assert_eq!(w.address, "DFpN6QqFfUm3gKNaxN6tNcab1FArL9cZLE");
        assert_eq!(w.coin, "doge");
        match &w.secret_std {
            SecretStd::Wif(s) => {
                assert_eq!(s, "QNcdLVw8fHkixm6NNyN6nVwxKek4u7qrioRbQmjxac5TVoTtZuot");
            }
            _ => panic!("expected SecretStd::Wif"),
        }
    }

    /// RVN P2PKH for privkey=1.
    /// Chain params confirmed: RavenProject/Ravencoin/src/chainparams.cpp
    ///   PUBKEY_ADDRESS=60(0x3c), SECRET_KEY=128(0x80).
    /// Address computed via independent JS base58check implementation from privkey=1 hash160.
    #[test]
    fn rvn_p2pkh_privkey_one() {
        let w = address_from_secret("rvn", PRIV1, Network::Mainnet).unwrap();
        assert_eq!(w.address, "RKxTdfmtxtfLDKZBgx6SvNkBtNu9jRYnLh");
        assert_eq!(w.coin, "rvn");
        match &w.secret_std {
            SecretStd::Wif(s) => {
                // RVN uses wif_byte=0x80 (same as BTC), so WIF is identical.
                assert_eq!(s, "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn");
            }
            _ => panic!("expected SecretStd::Wif"),
        }
    }

    /// KLS (Karlsen) address for privkey=1.
    ///
    /// This is a wiring test, not an independent oracle: the two primitives `dispatch` composes
    /// are each independently KAT-verified elsewhere — `internal_xonly` against the BIP86
    /// Taproot vector above, `codec::cashaddr::encode` against the upstream
    /// `karlsen-network/rusty-karlsen` / `kaspanet/rusty-kaspa` bech32 test vectors (see
    /// `codec/cashaddr.rs`). This only proves `dispatch` wires them together correctly: right
    /// prefix, right version byte (0 = PubKey), and no accidental Taproot tweak (Kaspa/Karlsen
    /// addresses carry the *untweaked* x-only key, unlike BIP341).
    #[test]
    fn kls_address_matches_manual_xonly_plus_cashaddr() {
        let priv32 = hex32(PRIV1);
        let d = curves::secp256k1::scalar_in_range(&priv32).unwrap();
        let xonly = curves::secp256k1::internal_xonly(&d);
        let expected = crate::codec::cashaddr::encode("karlsen", 0, &xonly);

        let w = address_from_secret("kls", PRIV1, Network::Mainnet).unwrap();
        assert_eq!(w.address, expected);
        assert!(w.address.starts_with("karlsen:"), "{}", w.address);
        match &w.secret_std {
            SecretStd::RawHex(s) => assert_eq!(s.len(), 64),
            _ => panic!("expected SecretStd::RawHex"),
        }
    }

    #[test]
    fn kls_testnet_prefix() {
        let w = address_from_secret("kls", PRIV1, Network::Testnet).unwrap();
        assert!(w.address.starts_with("karlsentest:"), "{}", w.address);
    }

    #[test]
    fn kls_generate_roundtrips() {
        let w = generate("kls", Network::Mainnet).unwrap();
        assert!(w.address.starts_with("karlsen:"), "{}", w.address);
        assert_eq!(w.coin, "kls");
        assert_eq!(w.secret_hex.len(), 64);
    }

    /// KAS (Kaspa) address for privkey=1 — same wiring test rationale as `kls` above, just the
    /// upstream `kaspa`/`kaspatest` prefix instead of the Karlsen fork's.
    #[test]
    fn kas_address_matches_manual_xonly_plus_cashaddr() {
        let priv32 = hex32(PRIV1);
        let d = curves::secp256k1::scalar_in_range(&priv32).unwrap();
        let xonly = curves::secp256k1::internal_xonly(&d);
        let expected = crate::codec::cashaddr::encode("kaspa", 0, &xonly);

        let w = address_from_secret("kas", PRIV1, Network::Mainnet).unwrap();
        assert_eq!(w.address, expected);
        assert!(w.address.starts_with("kaspa:"), "{}", w.address);
    }

    #[test]
    fn kas_testnet_prefix() {
        let w = address_from_secret("kas", PRIV1, Network::Testnet).unwrap();
        assert!(w.address.starts_with("kaspatest:"), "{}", w.address);
    }

    /// SPR (Spectre) address for privkey=1 — same wiring-test rationale as `kls`/`kas` above, with
    /// the `spectre`/`spectretest` prefixes from `spectre-project/rusty-spectre`
    /// `crypto/addresses/src/lib.rs` (`Prefix::as_str`). Spectre is a rusty-kaspa fork that left the
    /// address crate untouched, so version 0 (`PubKey`) over the *untweaked* x-only key still holds.
    #[test]
    fn spr_address_matches_manual_xonly_plus_cashaddr() {
        let priv32 = hex32(PRIV1);
        let d = curves::secp256k1::scalar_in_range(&priv32).unwrap();
        let xonly = curves::secp256k1::internal_xonly(&d);
        let expected = crate::codec::cashaddr::encode("spectre", 0, &xonly);

        let w = address_from_secret("spr", PRIV1, Network::Mainnet).unwrap();
        assert_eq!(w.address, expected);
        assert!(w.address.starts_with("spectre:"), "{}", w.address);
    }

    #[test]
    fn spr_testnet_prefix() {
        let w = address_from_secret("spr", PRIV1, Network::Testnet).unwrap();
        assert!(w.address.starts_with("spectretest:"), "{}", w.address);
    }

    #[test]
    fn spr_generate_roundtrips() {
        let w = generate("spr", Network::Mainnet).unwrap();
        assert!(w.address.starts_with("spectre:"), "{}", w.address);
        assert_eq!(w.coin, "spr");
        assert_eq!(w.secret_hex.len(), 64);
    }

    /// UBQ (Ubiq) shares Ethereum's address derivation (it's an Ethereum fork) — should match
    /// ETC/ETH's already-KAT-verified address for the same privkey.
    #[test]
    fn ubq_address_matches_eth() {
        let w = address_from_secret("ubq", PRIV1, Network::Mainnet).unwrap();
        assert_eq!(w.address, "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf");
        assert_eq!(w.coin, "ubq");
    }

    /// ERG (Ergo) address for privkey=1, against the independent Python-oracle vectors computed
    /// in `families::ergo::tests` (see that module for how they were derived).
    #[test]
    fn erg_mainnet_address_privkey_one() {
        let w = address_from_secret("erg", PRIV1, Network::Mainnet).unwrap();
        assert_eq!(
            w.address,
            "9fSgJ7BmUxBQJ454prQDQ7fQMBkXPLaAmDnimgTtjym6FYPHjAV"
        );
        assert_eq!(w.coin, "erg");
        match &w.secret_std {
            SecretStd::RawHex(s) => assert_eq!(s.len(), 64),
            _ => panic!("expected SecretStd::RawHex"),
        }
    }

    #[test]
    fn erg_testnet_address_privkey_one() {
        let w = address_from_secret("erg", PRIV1, Network::Testnet).unwrap();
        assert_eq!(
            w.address,
            "3WwXpssaZwcNzaGMv3AgxBdTPJQBt5gCmqBsg3DykQ39bYdhJBsN"
        );
    }

    /// ALPH (Alephium) address, against the official `alephium/alephium-web3` KAT (see
    /// `families::alephium::tests` for the source). Also confirms mainnet/testnet produce the
    /// identical address (network-agnostic scheme).
    #[test]
    fn alph_address_matches_official_kat() {
        let priv_hex = "91411e484289ec7e8b3058697f53f9b26fa7305158b4ef1a81adfbabcf090e45";
        let w = address_from_secret("alph", priv_hex, Network::Mainnet).unwrap();
        assert_eq!(w.address, "1ACCkgFfmTif46T3qK12znuWjb5Bk9jXpqaeWt2DXx8oc");
        assert_eq!(w.coin, "alph");

        let w_testnet = address_from_secret("alph", priv_hex, Network::Testnet).unwrap();
        assert_eq!(w_testnet.address, w.address);
    }

    // ---- Zcash-family transparent P2PKH rows (single-key path) ----

    /// The five Zcash-family rows through the public seam.
    ///
    /// These are **wiring tests**, in the same sense as the `kas`/`kls`/`spr` tests above: the two
    /// pieces they compose are each independently verified elsewhere. The version and WIF bytes are
    /// locked by `tests/hd_kat.rs`, whose expected addresses come from a from-scratch Python oracle
    /// anchored to the published BIP39 and BIP32 vectors — and both paths now read the *same*
    /// `COINS` row, so those KATs pin these bytes too. The base58check encoder is pinned by
    /// `codec::base58` and by every Bitcoin-family KAT above.
    ///
    /// What is left to prove is that the ticker resolves to those bytes and renders the address
    /// prefix each chain documents (`t1…` for the Zcash-derived chains, `G…` for Bitcoin Gold,
    /// `R…` for Komodo) — the independent check, since a wrong version byte moves the prefix.
    #[test]
    fn zcash_family_rows_render_documented_prefixes() {
        for (ticker, prefix) in [
            ("zec", "t1"),
            ("btcz", "t1"),
            ("zer", "t1"),
            ("btg", "G"),
            ("kmd", "R"),
        ] {
            let w = address_from_secret(ticker, PRIV1, Network::Mainnet).unwrap();
            assert!(
                w.address.starts_with(prefix),
                "{ticker} address {} should start with {prefix}",
                w.address
            );
            assert_eq!(w.coin, ticker);
            // Composed from the row's own bytes: proves `dispatch` applied the version prefix and
            // hash160 in the documented order, with no extra byte.
            let (version, _) = coins::lookup(ticker).unwrap().params.p2pkh_parts().unwrap();
            let d = curves::secp256k1::scalar_in_range(&hex32(PRIV1)).unwrap();
            let expected = families::p2pkh::address_from_pubkey(
                &curves::secp256k1::pubkey_compressed(&d),
                version,
            );
            assert_eq!(w.address, expected, "{ticker}");
            assert!(matches!(w.secret_std, SecretStd::Wif(_)), "{ticker}");
        }
    }

    /// The Zcash-family rows carry no source-verified testnet prefix, so `--testnet` must error
    /// rather than emit a wrong-network address.
    #[test]
    fn zcash_family_rows_reject_testnet() {
        for ticker in ["zec", "btcz", "zer", "btg", "kmd"] {
            assert_eq!(
                address_from_secret(ticker, PRIV1, Network::Testnet).err(),
                Some(WalletError::UnsupportedTestnet),
                "{ticker}"
            );
        }
    }

    /// Detection recognises a two-byte-prefix t-address as the P2PKH family — the case the previous
    /// first-byte-only match could not model.
    #[test]
    fn detects_zcash_t_address_family() {
        let w = address_from_secret("zec", PRIV1, Network::Mainnet).unwrap();
        assert_eq!(detect_family(&w.address), Some(Family::P2pkh));
    }

    /// ETHW (EthereumPoW) and OCTA (OctaSpace) are EVM chains that inherit Ethereum's address
    /// derivation unchanged, and the family takes no per-coin parameters — so the KAT is that both
    /// reproduce the address `etc_eth_address_privkey_one` already pins for privkey=1.
    #[test]
    fn ethw_and_octa_match_ethereum_bytes() {
        for ticker in ["ethw", "octa"] {
            let w = address_from_secret(ticker, PRIV1, Network::Mainnet).unwrap();
            assert_eq!(
                w.address, "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf",
                "{ticker}"
            );
            assert_eq!(w.coin, ticker);
            assert!(matches!(w.secret_std, SecretStd::EthHex(_)), "{ticker}");
        }
    }

    /// ZEPH (Zephyr) and SAL (Salvium) are CryptoNote forks differing from Monero only in the network
    /// prefix, which each project chose so its addresses render with a fixed human tag.
    ///
    /// KAT source: the tag itself. `families::cryptonote`'s
    /// `multibyte_prefix_renders_fork_address_tag` gates the same two prefixes against those
    /// documented tags, and the ZEPH prefix is live-verified — an address minted from this row was
    /// accepted as the login address by `zephyr.herominers.com` on 2026-07-27 (docs/coins.md).
    ///
    /// Each row is also compared against the `cryptonote:net=` token for the same prefix, so a row
    /// cannot carry a prefix other than the one asserted here.
    #[test]
    fn zeph_and_sal_render_documented_prefixes() {
        let xmr = address_from_secret("xmr", PRIV1, Network::Mainnet).unwrap();
        for (ticker, tag, net) in [
            ("zeph", "ZEPHYR", 0x6241d18c0u64),
            ("sal", "SaLv", 0x3ef318),
        ] {
            let w = address_from_secret(ticker, PRIV1, Network::Mainnet).unwrap();
            assert!(w.address.starts_with(tag), "{ticker}: {}", w.address);
            assert_eq!(w.coin, ticker);
            let token =
                address_from_secret(&format!("cryptonote:net={net}"), PRIV1, Network::Mainnet)
                    .unwrap();
            assert_eq!(w.address, token.address, "{ticker}");
            // Truncating the multi-byte prefix to one byte would collide with Monero's own `4…` tag.
            assert_ne!(w.address, xmr.address, "{ticker}");
            assert!(
                matches!(w.secret_std, SecretStd::MoneroMnemonic { .. }),
                "{ticker}"
            );
        }
    }

    /// Neither fork's testnet prefix is source-verified, so `--testnet` must error rather than emit a
    /// wrong-network address — the same policy as the Zcash-family rows.
    #[test]
    fn zeph_and_sal_reject_testnet() {
        for ticker in ["zeph", "sal"] {
            assert_eq!(
                address_from_secret(ticker, PRIV1, Network::Testnet).err(),
                Some(WalletError::UnsupportedTestnet),
                "{ticker}"
            );
        }
    }

    /// supported() returns the COINS slice.
    #[test]
    fn supported_is_non_empty() {
        assert!(!supported().is_empty());
        assert!(supported().iter().any(|c| c.ticker == "pearl"));
        assert!(supported().iter().any(|c| c.ticker == "btc"));
    }

    /// Test that attempting to derive a testnet address for a coin without testnet support
    /// returns WalletError::UnsupportedTestnet.
    #[test]
    fn unsupported_testnet_error_taproot() {
        // Construct a synthetic Taproot coin with no testnet HRP.
        let test_spec = coins::CoinSpec {
            ticker: "test_no_testnet",
            name: "Test Coin (No Testnet)",
            params: coins::FamilyParams::Taproot {
                hrp: "test",
                hrp_testnet: None, // <-- testnet unsupported
            },
            hd_slip44: None,
        };

        // Use privkey=1 (a well-known secp256k1 test vector).
        let d = curves::secp256k1::scalar_in_range(&hex32(PRIV1)).unwrap();
        let priv32 = hex32(PRIV1);

        // Attempt to dispatch with Network::Testnet should error with UnsupportedTestnet.
        let result = dispatch(&test_spec, &d, &priv32, Network::Testnet, false);
        assert_eq!(result, Err(WalletError::UnsupportedTestnet));
    }

    /// Test that attempting to derive a testnet address for a SegWit v0 coin without testnet support
    /// returns WalletError::UnsupportedTestnet.
    #[test]
    fn unsupported_testnet_error_segwit_v0() {
        // Construct a synthetic SegWit v0 coin with no testnet HRP.
        let test_spec = coins::CoinSpec {
            ticker: "test_no_testnet_segwit",
            name: "Test Coin SegWit (No Testnet)",
            params: coins::FamilyParams::SegwitV0 {
                hrp: "test",
                hrp_testnet: None, // <-- testnet unsupported
                wif: 0x80,
                p2pkh_version: &[0x00],
                p2pkh_version_testnet: None, // <-- testnet unsupported for legacy path too
            },
            hd_slip44: None,
        };

        let d = curves::secp256k1::scalar_in_range(&hex32(PRIV1)).unwrap();
        let priv32 = hex32(PRIV1);

        // Attempt to dispatch with Network::Testnet should error with UnsupportedTestnet.
        let result = dispatch(&test_spec, &d, &priv32, Network::Testnet, false);
        assert_eq!(result, Err(WalletError::UnsupportedTestnet));
    }

    /// Test that attempting to derive a testnet address for a P2PKH coin without testnet support
    /// returns WalletError::UnsupportedTestnet.
    #[test]
    fn unsupported_testnet_error_p2pkh() {
        // Construct a synthetic P2PKH coin with no testnet version byte.
        let test_spec = coins::CoinSpec {
            ticker: "test_no_testnet_p2pkh",
            name: "Test Coin P2PKH (No Testnet)",
            params: coins::FamilyParams::P2pkh {
                version: &[0x00],
                version_testnet: None, // <-- testnet unsupported
                wif: 0x80,
                compressed: true,
            },
            hd_slip44: None,
        };

        let d = curves::secp256k1::scalar_in_range(&hex32(PRIV1)).unwrap();
        let priv32 = hex32(PRIV1);

        // Attempt to dispatch with Network::Testnet should error with UnsupportedTestnet.
        let result = dispatch(&test_spec, &d, &priv32, Network::Testnet, false);
        assert_eq!(result, Err(WalletError::UnsupportedTestnet));
    }

    /// XMR canonicity: a spend key that is non-canonical for ed25519 (> l) must be
    /// sc_reduce'd before the address and secret_hex are emitted.
    ///
    /// Key chosen: big-endian 0x0100…0020.
    /// - As big-endian: 2^248 + 32 — well below secp256k1 n, so `scalar_in_range` passes.
    /// - As little-endian ed25519 scalar: 0x20 * 2^248 + 1 = 2^253 + 1 > l (≈ 2^252), so
    ///   the key IS non-canonical and requires reduction.
    ///
    /// Assertions:
    /// (a) printed `secret_hex` is a reduce_scalar_mod_l fixpoint (canonical, importable by Monero).
    /// (b) re-deriving from the printed canonical key gives the same address — proves the
    ///     printed key and the emitted address are self-consistent (stable round-trip).
    #[test]
    fn xmr_generated_spend_key_is_canonical() {
        // 0x0100…0020: secp256k1-valid (big-endian < n), ed25519-non-canonical (LE > l).
        const NON_CANONICAL_HEX: &str =
            "0100000000000000000000000000000000000000000000000000000000000020";
        let w =
            address_from_secret_kind("xmr", NON_CANONICAL_HEX, Network::Mainnet, false).unwrap();

        // Parse the printed (reduced) secret back to bytes.
        let printed = hex32(&w.secret_hex);

        // (a) Printed secret must be a reduce_scalar_mod_l fixpoint — i.e. already canonical.
        let reduced_again = curves::ed25519::reduce_scalar_mod_l(&printed);
        assert_eq!(
            printed, reduced_again,
            "printed spend key must be canonical (reduce_scalar_mod_l fixpoint)"
        );

        // (b) Re-derive from the printed canonical key — must produce the same address.
        //     This proves self-consistency: the printed key, when imported into Monero wallet
        //     tooling (which uses the key verbatim), gives back the same address.
        let w2 = address_from_secret_kind("xmr", &w.secret_hex, Network::Mainnet, false).unwrap();
        assert_eq!(
            w.address, w2.address,
            "re-deriving from the printed canonical key must give the same address"
        );
    }
}
