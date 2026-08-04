//! Static coin registry: the address-family parameters for every coin Forager can generate a
//! payout address for.
//!
//! A row carries only [`FamilyParams`]; the high-level [`Family`] is *derived* from it by
//! [`FamilyParams::family`]. Storing both would let a copy-pasted row claim one family while
//! encoding another — a mislabel that reaches the pool-payout warning in
//! `forager::wallet_preflight` — so the discriminant has exactly one source.

/// High-level address family — one variant per address construction algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// Bitcoin-style P2PKH: `BASE58CHECK(version ‖ HASH160(compressed_or_uncompressed_pubkey))`.
    P2pkh,
    /// Bitcoin-style SegWit v0 P2WPKH (bech32) with an optional P2PKH legacy path.
    SegwitV0,
    /// Bitcoin-style Taproot P2TR (bech32m key-path only, BIP340/341/350).
    Taproot,
    /// Ethereum-family: EIP-55 checksummed `0x`-prefixed 20-byte address derived from the
    /// uncompressed pubkey via keccak256.
    Ethereum,
    /// CryptoNote (Monero / XMR): curve25519 + dual spend/view keys.
    CryptoNote,
    /// Kaspa-family (Kaspa, Karlsen, …): raw BIP340 x-only pubkey (no Taproot tweak) encoded with
    /// the CashAddr-style scheme from `kaspa-addresses` (`<prefix>:<payload><8-char checksum>`).
    KaspaAddr,
    /// Ergo P2PK: `Base58(prefix_byte ‖ compressed_pubkey ‖ Blake2b256(..)[..4])`.
    Ergo,
    /// Alephium P2PKH: `Base58(0x00 ‖ Blake2b256(compressed_pubkey))` — no checksum, network-agnostic.
    Alephium,
    /// XDAG modern account address: `Base58Check(HASH160(compressed_pubkey))` — Bitcoin's hash160
    /// + Base58Check but with NO version byte, network-agnostic.
    Xdag,
}

/// Per-coin parameters that parameterise the address-derivation algorithm.
///
/// The base58 version prefix is a **byte slice**, not a single byte: Bitcoin-family coins use one
/// byte, and Zcash-family transparent addresses use two (e.g. `0x1C,0xB8` → `t1…`).
#[derive(Debug, Clone, Copy)]
pub enum FamilyParams {
    /// P2PKH parameters.
    P2pkh {
        /// Version prefix for mainnet addresses (e.g. `[0x00]` for BTC, `[0x1E]` for DOGE,
        /// `[0x1C, 0xB8]` for a Zcash-family t-address).
        version: &'static [u8],
        /// Version prefix for testnet addresses, or `None` if testnet is not supported.
        version_testnet: Option<&'static [u8]>,
        /// WIF prefix byte for mainnet private-key export.
        wif: u8,
        /// Whether to use compressed pubkeys (almost always `true` for modern coins).
        compressed: bool,
    },
    /// SegWit v0 P2WPKH parameters.  The P2PKH version bytes enable the optional legacy path.
    SegwitV0 {
        /// bech32 HRP for mainnet (e.g. `"bc"` for Bitcoin).
        hrp: &'static str,
        /// bech32 HRP for testnet, or `None` if testnet is not supported.
        hrp_testnet: Option<&'static str>,
        /// WIF prefix byte for mainnet private-key export.
        wif: u8,
        /// P2PKH version prefix for mainnet (used by `address_from_secret_kind(..., legacy=true)`).
        p2pkh_version: &'static [u8],
        /// P2PKH version prefix for testnet (used by the legacy path on testnet).
        p2pkh_version_testnet: Option<&'static [u8]>,
    },
    /// Taproot P2TR parameters (key-path spend only, BIP340/341/350).
    Taproot {
        /// bech32m HRP for mainnet (e.g. `"prl"` for Pearl, `"bc"` for Bitcoin).
        hrp: &'static str,
        /// bech32m HRP for testnet, or `None` if testnet is not supported.
        hrp_testnet: Option<&'static str>,
    },
    /// Ethereum-family: no per-network parameters at the key level (address is network-agnostic).
    Ethereum,
    /// CryptoNote network prefix, written as an unsigned-LEB128 varint (so multi-byte fork
    /// prefixes such as Zephyr's `0x6241d18c0` encode correctly).
    CryptoNote {
        /// Network prefix (varint) for mainnet addresses.
        network_byte: u64,
        /// Network prefix for testnet addresses, or `None` if testnet is not supported.
        network_byte_testnet: Option<u64>,
    },
    /// Kaspa-family address prefix parameters.
    KaspaAddr {
        /// CashAddr-style prefix for mainnet (e.g. `"karlsen"`, `"kaspa"`).
        prefix: &'static str,
        /// Prefix for testnet, or `None` if testnet is not supported.
        prefix_testnet: Option<&'static str>,
    },
    /// Ergo has no per-coin parameters — the network/address-type bytes are protocol constants.
    Ergo,
    /// Alephium has no per-coin parameters — the address is network-agnostic.
    Alephium,
    /// XDAG has no per-coin parameters — the address is network-agnostic (no version byte).
    Xdag,
}

impl FamilyParams {
    /// The [`Family`] these parameters encode.  One variant maps to exactly one family, so this is
    /// total — there is no "unknown family" case for a caller to handle.
    pub fn family(&self) -> Family {
        match self {
            FamilyParams::P2pkh { .. } => Family::P2pkh,
            FamilyParams::SegwitV0 { .. } => Family::SegwitV0,
            FamilyParams::Taproot { .. } => Family::Taproot,
            FamilyParams::Ethereum => Family::Ethereum,
            FamilyParams::CryptoNote { .. } => Family::CryptoNote,
            FamilyParams::KaspaAddr { .. } => Family::KaspaAddr,
            FamilyParams::Ergo => Family::Ergo,
            FamilyParams::Alephium => Family::Alephium,
            FamilyParams::Xdag => Family::Xdag,
        }
    }

    /// The `(mainnet base58 P2PKH version prefix, WIF byte)` pair, for the families that have one.
    ///
    /// `Some` for [`FamilyParams::P2pkh`] and for [`FamilyParams::SegwitV0`] (whose legacy path is
    /// P2PKH); `None` for every other family.
    pub fn p2pkh_parts(&self) -> Option<(&'static [u8], u8)> {
        match *self {
            FamilyParams::P2pkh { version, wif, .. } => Some((version, wif)),
            FamilyParams::SegwitV0 {
                p2pkh_version, wif, ..
            } => Some((p2pkh_version, wif)),
            _ => None,
        }
    }

    /// Every base58 P2PKH version prefix this row models (mainnet, then testnet if present).
    /// Used by address *detection* to match a decoded payload's leading bytes.
    pub fn p2pkh_version_prefixes(&self) -> impl Iterator<Item = &'static [u8]> {
        let (main, test) = match *self {
            FamilyParams::P2pkh {
                version,
                version_testnet,
                ..
            } => (Some(version), version_testnet),
            FamilyParams::SegwitV0 {
                p2pkh_version,
                p2pkh_version_testnet,
                ..
            } => (Some(p2pkh_version), p2pkh_version_testnet),
            _ => (None, None),
        };
        [main, test].into_iter().flatten()
    }
}

/// One row in the [`COINS`] table.
///
/// This is the **single** coin table: it feeds both the single-key generator and the BIP44 HD
/// generator in [`crate::hd`]. The two used to be separate statics that each hard-coded the version
/// and WIF bytes for BTC/LTC/DOGE/RVN, so the same four coins were written twice and could drift.
#[derive(Debug, Clone, Copy)]
pub struct CoinSpec {
    /// Lower-case ticker symbol used to look up the coin (e.g. `"btc"`, `"pearl"`).
    pub ticker: &'static str,
    /// Human-readable coin name.
    pub name: &'static str,
    /// Family-specific parameters.  The [`Family`] is derived via [`FamilyParams::family`].
    pub params: FamilyParams,
    /// `Some(coin_type)` enables BIP44 HD derivation for this row at
    /// `m/44'/<coin_type>'/<account>'/0/<index>`; the number is the SLIP-44 registered coin type
    /// from `satoshilabs/slips/slip-0044.md`.
    ///
    /// `None` means Forager does not offer `--hd` for the coin — either it has no registered coin
    /// type, or its family is not base58 P2PKH (Taproot, Ethereum, CryptoNote, Kaspa, Ergo,
    /// Alephium, XDAG). A row is HD-derivable only when this is `Some` **and**
    /// [`FamilyParams::p2pkh_parts`] is `Some`; [`crate::hd::supported`] enforces both.
    pub hd_slip44: Option<u32>,
}

impl CoinSpec {
    /// The coin's address [`Family`], derived from [`CoinSpec::params`].
    pub fn family(&self) -> Family {
        self.params.family()
    }

    /// The `(slip44, p2pkh version prefix, WIF byte)` triple when this coin supports BIP44 HD
    /// derivation, else `None`.
    pub fn hd_parts(&self) -> Option<(u32, &'static [u8], u8)> {
        let slip44 = self.hd_slip44?;
        let (version, wif) = self.params.p2pkh_parts()?;
        Some((slip44, version, wif))
    }
}

/// All coins for which Forager can derive a payout address.
///
/// Chain-param sources and KAT vectors are cited per-coin in `lib.rs` tests.
/// **Do not add a row here without a passing `#[test]` KAT in `lib.rs`.**
pub static COINS: &[CoinSpec] = &[
    // ---- Taproot family ----
    CoinSpec {
        ticker: "pearl",
        name: "Pearl",
        hd_slip44: None,
        params: FamilyParams::Taproot {
            hrp: "prl",
            hrp_testnet: Some("tprl"),
        },
    },
    // ---- SegWit v0 family ----
    // BTC: chainparams PUBKEY_ADDRESS=0, SECRET_KEY=128(0x80), bech32_hrp="bc"
    //      testnet: PUBKEY_ADDRESS=111(0x6f), bech32_hrp="tb"
    //      Source: bitcoin/src/chainparams.cpp (mainnet + testnet3)
    CoinSpec {
        ticker: "btc",
        name: "Bitcoin",
        hd_slip44: Some(0),
        params: FamilyParams::SegwitV0 {
            hrp: "bc",
            hrp_testnet: Some("tb"),
            wif: 0x80,
            p2pkh_version: &[0x00],
            p2pkh_version_testnet: Some(&[0x6f]),
        },
    },
    // LTC: chainparams PUBKEY_ADDRESS=48(0x30), SECRET_KEY=176(0xb0), bech32_hrp="ltc"
    //      testnet: PUBKEY_ADDRESS=111(0x6f), bech32_hrp="tltc"
    //      Source: litecoin-project/litecoin/src/chainparams.cpp
    CoinSpec {
        ticker: "ltc",
        name: "Litecoin",
        hd_slip44: Some(2),
        params: FamilyParams::SegwitV0 {
            hrp: "ltc",
            hrp_testnet: Some("tltc"),
            wif: 0xb0,
            p2pkh_version: &[0x30],
            p2pkh_version_testnet: Some(&[0x6f]),
        },
    },
    // VTC: chainparams PUBKEY_ADDRESS=71(0x47), SECRET_KEY=128(0x80), bech32_hrp="vtc"
    //      testnet: PUBKEY_ADDRESS=74(0x4a), bech32_hrp="tvtc"
    //      Source: vertcoin-project/vertcoin-core/src/chainparams.cpp
    //      SegWit has been active on Vertcoin for years, so `vtc1q…` is the default and
    //      `--legacy` renders the `V…` form, matching how BTC and LTC are handled above.
    CoinSpec {
        ticker: "vtc",
        name: "Vertcoin",
        hd_slip44: Some(28),
        params: FamilyParams::SegwitV0 {
            hrp: "vtc",
            hrp_testnet: Some("tvtc"),
            wif: 0x80,
            p2pkh_version: &[0x47],
            p2pkh_version_testnet: Some(&[0x4a]),
        },
    },
    // ---- P2PKH family ----
    // DOGE: chainparams PUBKEY_ADDRESS=30(0x1e), SECRET_KEY=158(0x9e)
    //       testnet: PUBKEY_ADDRESS=113(0x71)
    //       Source: dogecoin/dogecoin/src/chainparams.cpp
    CoinSpec {
        ticker: "doge",
        name: "Dogecoin",
        hd_slip44: Some(3),
        params: FamilyParams::P2pkh {
            version: &[0x1e],
            version_testnet: Some(&[0x71]),
            wif: 0x9e,
            compressed: true,
        },
    },
    // RVN: chainparams PUBKEY_ADDRESS=60(0x3c), SECRET_KEY=128(0x80)
    //      testnet: PUBKEY_ADDRESS=111(0x6f)
    //      Source: RavenProject/Ravencoin/src/chainparams.cpp
    CoinSpec {
        ticker: "rvn",
        name: "Ravencoin",
        hd_slip44: Some(175),
        params: FamilyParams::P2pkh {
            version: &[0x3c],
            version_testnet: Some(&[0x6f]),
            wif: 0x80,
            compressed: true,
        },
    },
    // FIRO: chainparams PUBKEY_ADDRESS=82(0x52), SECRET_KEY=210(0xd2), no bech32_hrp
    //       testnet: PUBKEY_ADDRESS=65(0x41)
    //       Source: firoorg/firo/src/chainparams.cpp
    //       SLIP-44 registers Firo under its former name, ZCoin/XZC, as coin type 136.
    CoinSpec {
        ticker: "firo",
        name: "Firo",
        hd_slip44: Some(136),
        params: FamilyParams::P2pkh {
            version: &[0x52],
            version_testnet: Some(&[0x41]),
            wif: 0xd2,
            compressed: true,
        },
    },
    // MEWC: chainparams PUBKEY_ADDRESS=50(0x32), SECRET_KEY=112(0x70)
    //       testnet: PUBKEY_ADDRESS=109(0x6d)
    //       Source: Meowcoin-Foundation/Meowcoin/src/kernel/chainparams.cpp
    //       The params also set bech32_hrp="mewc", but Meowcoin is a Ravencoin fork (it keeps
    //       Ravencoin's SCRIPT_ADDRESS=122) and pools pay out to the `M…` form. Registering it
    //       as P2PKH keeps payouts on the address type the network actually uses.
    CoinSpec {
        ticker: "mewc",
        name: "Meowcoin",
        hd_slip44: Some(1669),
        params: FamilyParams::P2pkh {
            version: &[0x32],
            version_testnet: Some(&[0x6d]),
            wif: 0x70,
            compressed: true,
        },
    },
    // ---- Ethereum family ----
    // ETC shares ETH's address-derivation (EIP-55 checksummed keccak160); no chain params differ.
    CoinSpec {
        ticker: "etc",
        name: "Ethereum Classic",
        hd_slip44: None,
        params: FamilyParams::Ethereum,
    },
    CoinSpec {
        ticker: "eth",
        name: "Ethereum",
        hd_slip44: None,
        params: FamilyParams::Ethereum,
    },
    // ---- CryptoNote family ----
    // XMR: mainnet network byte 18 (addresses start with '4'), testnet 53.
    //      Source: monero-project/monero src/cryptonote_config.h
    //        CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = 18, TESTNET = 53.
    CoinSpec {
        ticker: "xmr",
        name: "Monero",
        hd_slip44: None,
        params: FamilyParams::CryptoNote {
            network_byte: 18,
            network_byte_testnet: Some(53),
        },
    },
    // Zephyr (ZEPH) and Salvium (SAL): CryptoNote forks that mine stock RandomX `rx/0`.  Both differ
    // from Monero only in the network prefix, which each project chose so its addresses render with
    // a fixed human tag — ZEPH `0x6241d18c0` → `ZEPHYR…`, SAL `0x3ef318` → `SaLv…`.  The prefix is
    // written as a varint, so a multi-byte value is not truncated; `families::cryptonote` gates both
    // prefixes against those documented tags.  The ZEPH prefix is additionally live-verified: a
    // `ZEPHYR…` address minted from this row was accepted as the login address by
    // `zephyr.herominers.com` on 2026-07-27 (docs/coins.md).
    // `network_byte_testnet: None` for both — neither testnet prefix is source-verified, so
    // `--testnet` errors rather than emitting a wrong-network address.
    CoinSpec {
        ticker: "zeph",
        name: "Zephyr",
        hd_slip44: None,
        params: FamilyParams::CryptoNote {
            network_byte: 0x6241d18c0,
            network_byte_testnet: None,
        },
    },
    CoinSpec {
        ticker: "sal",
        name: "Salvium",
        hd_slip44: None,
        params: FamilyParams::CryptoNote {
            network_byte: 0x3ef318,
            network_byte_testnet: None,
        },
    },
    // ---- Kaspa family ----
    // Kaspa (KAS): kaspanet/rusty-kaspa crypto/addresses/src/lib.rs (Prefix enum).
    CoinSpec {
        ticker: "kas",
        name: "Kaspa",
        hd_slip44: None,
        params: FamilyParams::KaspaAddr {
            prefix: "kaspa",
            prefix_testnet: Some("kaspatest"),
        },
    },
    // Karlsen (KLS): a Kaspa (BlockDAG) fork; address scheme is byte-identical to Kaspa's
    // `kaspa-addresses` crate with the prefix swapped ("karlsen"/"karlsentest" vs "kaspa"/
    // "kaspatest"). Source: karlsen-network/rusty-karlsen crypto/addresses/src/lib.rs (Prefix enum).
    CoinSpec {
        ticker: "kls",
        name: "Karlsen",
        hd_slip44: None,
        params: FamilyParams::KaspaAddr {
            prefix: "karlsen",
            prefix_testnet: Some("karlsentest"),
        },
    },
    // Spectre (SPR): a Kaspa (BlockDAG) fork mining SpectreX/AstroBWTv3; the address scheme is the
    // unmodified `kaspa-addresses` crate with the prefix swapped. Source:
    // spectre-project/rusty-spectre crypto/addresses/src/lib.rs — `Prefix::{Mainnet => "spectre",
    // Testnet => "spectretest", Simnet => "spectresim", Devnet => "spectredev"}`, same
    // `Version::{PubKey, PubKeyECDSA, ScriptHash}` set as upstream Kaspa.
    CoinSpec {
        ticker: "spr",
        name: "Spectre",
        hd_slip44: None,
        params: FamilyParams::KaspaAddr {
            prefix: "spectre",
            prefix_testnet: Some("spectretest"),
        },
    },
    // ---- Ergo family ----
    // ERG: Autolykos2's coin. Source: ergoplatform/sigma-rust
    // ergotree-ir/src/chain/address.rs (AddressEncoder) + ergo-chain-types/src/ec_point.rs.
    CoinSpec {
        ticker: "erg",
        name: "Ergo",
        hd_slip44: None,
        params: FamilyParams::Ergo,
    },
    // ---- Alephium family ----
    // ALPH: Blake3's coin. Source: alephium/alephium-web3 packages/web3/src/address/address.ts
    // (addressFromPublicKey, default keyType) + AddressType.P2PKH = 0x00.
    CoinSpec {
        ticker: "alph",
        name: "Alephium",
        hd_slip44: None,
        params: FamilyParams::Alephium,
    },
    // ---- Ethereum family (continued) ----
    // Ubiq (UBQ): an Ethereum fork; address derivation is identical (EIP-55 checksummed
    // keccak160), no chain params differ — same as ETC/ETH above.
    CoinSpec {
        ticker: "ubq",
        name: "Ubiq",
        hd_slip44: None,
        params: FamilyParams::Ethereum,
    },
    // EthereumPoW (ETHW) and OctaSpace (OCTA) are EVM chains that inherit Ethereum's address
    // derivation unchanged (EIP-55 checksummed keccak160 of the uncompressed pubkey).  The family
    // takes no per-coin parameters, so these rows add no new bytes to get wrong: the KAT is that
    // both reproduce the address `etc_eth_address_privkey_one` already pins for privkey=1.
    CoinSpec {
        ticker: "ethw",
        name: "EthereumPoW",
        hd_slip44: None,
        params: FamilyParams::Ethereum,
    },
    CoinSpec {
        ticker: "octa",
        name: "OctaSpace",
        hd_slip44: None,
        params: FamilyParams::Ethereum,
    },
    // ---- XDAG family ----
    // XDAG: modern account address = Base58Check(HASH160(compressed_pubkey)), no version byte.
    // Source: XDagger/xdagj (MIT) crypto/keys/AddressUtils.toBytesAddress +
    // crypto/encoding/Base58.encodeCheck; docs/algos/xdag.md.
    CoinSpec {
        ticker: "xdag",
        name: "XDAG",
        hd_slip44: None,
        params: FamilyParams::Xdag,
    },
    // SCASH ("Satoshi Cash", RandomX): address bytes left BYTE-IDENTICAL to Bitcoin — P2PKH
    // 0x00, WIF 0x80, bech32 HRP "bc"; testnet 0x6f/"tb". So a SCASH address is indistinguishable
    // from a BTC one (same encoder, same bytes).  Source: scashnetwork/scash (MIT),
    // src/kernel/chainparams.cpp (base58Prefixes + bech32_hrp unchanged from Bitcoin).
    CoinSpec {
        ticker: "scash",
        name: "Scash",
        hd_slip44: None,
        params: FamilyParams::SegwitV0 {
            hrp: "bc",
            hrp_testnet: Some("tb"),
            wif: 0x80,
            p2pkh_version: &[0x00],
            p2pkh_version_testnet: Some(&[0x6f]),
        },
    },
    // ALPHA (Unicity Alpha, RandomX): Bitcoin params EXCEPT the bech32 HRP — P2PKH 0x00,
    // WIF 0x80 (both Bitcoin-identical), bech32 HRP "alpha" (testnet "talpha").  The witness
    // program is the same HASH160 as Bitcoin for a given key; only the HRP + checksum differ.
    // Source: unicitynetwork/alpha (MIT), src/kernel/chainparams.cpp.
    CoinSpec {
        ticker: "alpha",
        name: "Unicity Alpha",
        hd_slip44: None,
        params: FamilyParams::SegwitV0 {
            hrp: "alpha",
            hrp_testnet: Some("talpha"),
            wif: 0x80,
            p2pkh_version: &[0x00],
            p2pkh_version_testnet: Some(&[0x6f]),
        },
    },
    // ---- Zcash-family transparent P2PKH ----
    // Two-byte PUBKEY_ADDRESS prefixes, so these rows were previously expressible only in the
    // separate HD table (whose version field was already a byte slice).  Version + WIF bytes and
    // SLIP-44 coin types are the ones `tests/hd_kat.rs` already locks against its published-vector
    // oracle; each row's citation is that file's table.
    //   zec  Zcash          slip44 133  PUBKEY_ADDRESS 0x1C,0xB8  SECRET_KEY 0x80  zcash/zcash
    //   btg  Bitcoin Gold   slip44 156  PUBKEY_ADDRESS 0x26       SECRET_KEY 0x80  BTCGPU/BTCGPU
    //   kmd  Komodo         slip44 141  PUBKEY_ADDRESS 0x3C       SECRET_KEY 0xBC  KomodoPlatform/komodo
    //   btcz BitcoinZ       slip44 177  PUBKEY_ADDRESS 0x1C,0xB8  SECRET_KEY 0x80  btcz/bitcoinz
    //   zer  Zero           slip44 323  PUBKEY_ADDRESS 0x1C,0xB8  SECRET_KEY 0x80  zerocurrency/zero
    // `version_testnet: None` throughout — the testnet prefixes are not source-verified, so
    // `--testnet` errors rather than emitting a wrong-network address.
    CoinSpec {
        ticker: "zec",
        name: "Zcash (transparent)",
        params: FamilyParams::P2pkh {
            version: &[0x1c, 0xb8],
            version_testnet: None,
            wif: 0x80,
            compressed: true,
        },
        hd_slip44: Some(133),
    },
    CoinSpec {
        ticker: "btg",
        name: "Bitcoin Gold",
        params: FamilyParams::P2pkh {
            version: &[0x26],
            version_testnet: None,
            wif: 0x80,
            compressed: true,
        },
        hd_slip44: Some(156),
    },
    CoinSpec {
        ticker: "kmd",
        name: "Komodo",
        params: FamilyParams::P2pkh {
            version: &[0x3c],
            version_testnet: None,
            wif: 0xbc,
            compressed: true,
        },
        hd_slip44: Some(141),
    },
    CoinSpec {
        ticker: "btcz",
        name: "BitcoinZ",
        params: FamilyParams::P2pkh {
            version: &[0x1c, 0xb8],
            version_testnet: None,
            wif: 0x80,
            compressed: true,
        },
        hd_slip44: Some(177),
    },
    CoinSpec {
        ticker: "zer",
        name: "Zero",
        params: FamilyParams::P2pkh {
            version: &[0x1c, 0xb8],
            version_testnet: None,
            wif: 0x80,
            compressed: true,
        },
        hd_slip44: Some(323),
    },
    // vtc, dgb: deferred until their KATs land.
];

/// Look up a coin by ticker (case-insensitive).  Returns `None` for unknown tickers.
pub fn lookup(ticker: &str) -> Option<&'static CoinSpec> {
    COINS.iter().find(|c| c.ticker.eq_ignore_ascii_case(ticker))
}

/// One runtime coin-token family: the family name, every parameter [`parse_token`] accepts for it,
/// and a human syntax line plus a worked example for CLI help.
///
/// This is the **single** source for three things that must agree: the parser's parameter
/// allow-list, its unknown-family error message, and the `forager wallet list` help text.  The help
/// text used to be a hand-maintained copy of the grammar and could drift from what the parser
/// actually accepted.
#[derive(Debug, Clone, Copy)]
pub struct TokenSyntax {
    /// Family name — the part before the `:` in a coin token.
    pub family: &'static str,
    /// Every `key=` this family accepts, required and optional alike.
    pub keys: &'static [&'static str],
    /// Every bare flag (a parameter with no `=`) this family accepts.
    pub flags: &'static [&'static str],
    /// Human-readable grammar for help output.
    pub syntax: &'static str,
    /// A worked example token.  Every entry's example must parse — see the
    /// `every_grammar_family_parses_its_example` test.
    pub example: &'static str,
}

/// The runtime coin-token grammar: one row per address family a token can drive.
///
/// The four zero-parameter families (`ethereum`, `ergo`, `alephium`, `xdag`) encode no per-coin
/// bytes, so their token is the bare family name plus the `:` the grammar requires.  Those four add
/// no capability over the `eth`/`erg`/`alph`/`xdag` table rows; they are here so every implemented
/// family is reachable through one grammar rather than a list of exceptions.
pub static TOKEN_GRAMMAR: &[TokenSyntax] = &[
    TokenSyntax {
        family: "p2pkh",
        keys: &["ver", "wif"],
        flags: &["uncompressed"],
        syntax: "p2pkh:ver=<byte>,wif=<byte>[,uncompressed]",
        example: "p2pkh:ver=0x00,wif=0x80",
    },
    TokenSyntax {
        family: "segwit",
        keys: &["hrp", "wif", "ver"],
        flags: &[],
        syntax: "segwit:hrp=<str>,wif=<byte>[,ver=<byte>]",
        example: "segwit:hrp=bc,wif=0x80",
    },
    TokenSyntax {
        family: "taproot",
        keys: &["hrp"],
        flags: &[],
        syntax: "taproot:hrp=<str>",
        example: "taproot:hrp=prl",
    },
    TokenSyntax {
        family: "cryptonote",
        keys: &["net", "net_test"],
        flags: &[],
        syntax: "cryptonote:net=<int>[,net_test=<int>]",
        example: "cryptonote:net=18",
    },
    TokenSyntax {
        family: "kaspa",
        keys: &["prefix"],
        flags: &[],
        syntax: "kaspa:prefix=<str>",
        example: "kaspa:prefix=kaspa",
    },
    TokenSyntax {
        family: "ethereum",
        keys: &[],
        flags: &[],
        syntax: "ethereum:",
        example: "ethereum:",
    },
    TokenSyntax {
        family: "ergo",
        keys: &[],
        flags: &[],
        syntax: "ergo:",
        example: "ergo:",
    },
    TokenSyntax {
        family: "alephium",
        keys: &[],
        flags: &[],
        syntax: "alephium:",
        example: "alephium:",
    },
    TokenSyntax {
        family: "xdag",
        keys: &[],
        flags: &[],
        syntax: "xdag:",
        example: "xdag:",
    },
];

/// Parse a runtime `family:params` coin token into an ad-hoc [`CoinSpec`].
///
/// This is the escape hatch for coins not in the [`COINS`] table: it lets a user drive one of the
/// already-implemented (and KAT-gated) family *encoders* with hand-supplied parameters, so a new
/// Bitcoin/Monero/Kaspa fork can be minted without a code change.  The params are comma-separated
/// `key=value` pairs; integers are decimal unless `0x`-prefixed.  [`TOKEN_GRAMMAR`] lists the
/// families and their parameters.
///
/// **UNVERIFIED — the caller MUST warn.** Every [`COINS`] row is gated by a known-answer test; a
/// token's bytes are user-supplied and unchecked, so a wrong version byte yields a
/// valid-*looking* address that silently misdirects the payout.  The encoder is trusted; the
/// parameters are not.  The leaked `ticker`/`name` strings live for the process lifetime — keygen
/// is a one-shot CLI action, never a hot path.
pub fn parse_token(token: &str) -> Result<CoinSpec, String> {
    let (family, rest) = token
        .split_once(':')
        .ok_or_else(|| format!("coin token '{token}' is not of the form 'family:params'"))?;

    let Some(grammar) = TOKEN_GRAMMAR.iter().find(|g| g.family == family) else {
        let names: Vec<&str> = TOKEN_GRAMMAR.iter().map(|g| g.family).collect();
        return Err(format!(
            "unknown coin family '{family}' (expected {})",
            names.join(" | ")
        ));
    };

    // Split the params into `key=value` pairs and bare flags (e.g. `uncompressed`).
    let mut kv: Vec<(&str, &str)> = Vec::new();
    let mut flags: Vec<&str> = Vec::new();
    for part in rest.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        match part.split_once('=') {
            Some((k, v)) => kv.push((k.trim(), v.trim())),
            None => flags.push(part),
        }
    }
    // Reject an unrecognised parameter instead of ignoring it.  A mistyped optional parameter —
    // `net_tets=`, `uncompresed` — would otherwise be dropped in silence and mint a valid-looking
    // address built from the wrong parameters, which is the one failure this escape hatch must not
    // hide.  A mistyped *required* parameter is already caught by `req` below.
    if let Some((key, _)) = kv.iter().copied().find(|(k, _)| !grammar.keys.contains(k)) {
        return Err(format!(
            "token '{token}': family '{family}' has no '{key}=' parameter (expected {})",
            grammar.syntax
        ));
    }
    if let Some(flag) = flags.iter().copied().find(|f| !grammar.flags.contains(f)) {
        return Err(format!(
            "token '{token}': family '{family}' has no '{flag}' flag (expected {})",
            grammar.syntax
        ));
    }

    let get = |key: &str| kv.iter().find(|(k, _)| *k == key).map(|(_, v)| *v);
    let req = |key: &str| get(key).ok_or_else(|| format!("token '{token}': missing '{key}='"));

    let params = match family {
        "p2pkh" => FamilyParams::P2pkh {
            version: leak_bytes(vec![parse_byte(req("ver")?)?]),
            version_testnet: None,
            wif: parse_byte(req("wif")?)?,
            compressed: !flags.contains(&"uncompressed"),
        },
        "segwit" => FamilyParams::SegwitV0 {
            hrp: leak(req("hrp")?.to_string()),
            hrp_testnet: None,
            wif: parse_byte(req("wif")?)?,
            p2pkh_version: leak_bytes(vec![match get("ver") {
                Some(v) => parse_byte(v)?,
                None => 0x00,
            }]),
            p2pkh_version_testnet: None,
        },
        "taproot" => FamilyParams::Taproot {
            hrp: leak(req("hrp")?.to_string()),
            hrp_testnet: None,
        },
        "cryptonote" => FamilyParams::CryptoNote {
            network_byte: parse_uint(req("net")?)?,
            network_byte_testnet: match get("net_test") {
                Some(v) => Some(parse_uint(v)?),
                None => None,
            },
        },
        "kaspa" => FamilyParams::KaspaAddr {
            prefix: leak(req("prefix")?.to_string()),
            prefix_testnet: None,
        },
        // The zero-parameter families: nothing to read out of the token.
        "ethereum" => FamilyParams::Ethereum,
        "ergo" => FamilyParams::Ergo,
        "alephium" => FamilyParams::Alephium,
        "xdag" => FamilyParams::Xdag,
        // Unreachable while `TOKEN_GRAMMAR` and this match list the same families — the lookup above
        // already rejected any name the grammar does not carry.  Report it instead of panicking, so a
        // grammar row added without an arm here degrades to a clear message; the
        // `every_grammar_family_parses_its_example` test proves the two agree.
        other => {
            return Err(format!(
                "coin family '{other}' is declared in the grammar but not implemented"
            ))
        }
    };

    Ok(CoinSpec {
        ticker: leak(token.to_string()),
        name: leak(format!("custom {family}")),
        params,
        // A runtime token names no chain, so no SLIP-44 coin type is knowable: HD is never offered
        // for one. `--hd` takes a table ticker.
        hd_slip44: None,
    })
}

/// Leak an owned string to `'static`.  Bounded: only runtime coin tokens reach this, in the
/// one-shot `wallet` CLI path — never a loop or hot path.
fn leak(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

/// Leak an owned byte vector to `'static`, for a runtime token's version prefix.  Same bound as
/// [`leak`]: at most one allocation per `wallet` invocation.
fn leak_bytes(v: Vec<u8>) -> &'static [u8] {
    Box::leak(v.into_boxed_slice())
}

/// Parse a `u64` in decimal, or hex when `0x`/`0X`-prefixed.
fn parse_uint(s: &str) -> Result<u64, String> {
    let parsed = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => s.parse::<u64>(),
    };
    parsed.map_err(|_| format!("invalid integer '{s}' (use decimal, or 0x-prefixed hex)"))
}

/// Parse a single byte (0..=255) in decimal or `0x` hex.
fn parse_byte(s: &str) -> Result<u8, String> {
    let v = parse_uint(s)?;
    u8::try_from(v).map_err(|_| format!("byte value '{s}' out of range (0..=255)"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_is_case_insensitive() {
        assert!(lookup("BTC").is_some());
        assert!(lookup("btc").is_some());
        assert!(lookup("Btc").is_some());
    }

    #[test]
    fn lookup_unknown_returns_none() {
        assert!(lookup("unknown_coin_xyz").is_none());
    }

    #[test]
    fn all_tickers_are_lowercase() {
        for spec in COINS {
            assert_eq!(
                spec.ticker,
                spec.ticker.to_ascii_lowercase(),
                "ticker must be lowercase: {}",
                spec.ticker
            );
        }
    }

    #[test]
    fn no_duplicate_tickers() {
        let mut seen = std::collections::HashSet::new();
        for spec in COINS {
            assert!(
                seen.insert(spec.ticker),
                "duplicate ticker: {}",
                spec.ticker
            );
        }
    }

    /// Every modelled version prefix is one or two bytes wide — the only widths any modelled chain
    /// uses. An empty prefix would make `detect_family` match every base58check address.
    #[test]
    fn version_prefixes_are_one_or_two_bytes() {
        for spec in COINS {
            for v in spec.params.p2pkh_version_prefixes() {
                assert!(
                    (1..=2).contains(&v.len()),
                    "{}: version prefix must be 1..=2 bytes, got {v:?}",
                    spec.ticker
                );
            }
        }
    }

    /// Every [`TOKEN_GRAMMAR`] row's worked example parses, and the row is self-consistent: the
    /// `syntax` and `example` both begin with the family name plus `:`.  This is what proves the
    /// grammar table and the `parse_token` match arms list the same families — a row added to one
    /// and not the other fails here instead of at a user's prompt.
    #[test]
    fn every_grammar_family_parses_its_example() {
        for g in TOKEN_GRAMMAR {
            let prefix = format!("{}:", g.family);
            assert!(g.syntax.starts_with(&prefix), "syntax: {}", g.syntax);
            assert!(g.example.starts_with(&prefix), "example: {}", g.example);
            let spec = parse_token(g.example)
                .unwrap_or_else(|e| panic!("example for '{}' must parse: {e}", g.family));
            assert_eq!(spec.ticker, g.example);
            // A runtime token names no chain, so HD is never offered for one.
            assert!(spec.hd_slip44.is_none(), "{}", g.family);
        }
    }

    #[test]
    fn grammar_family_names_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for g in TOKEN_GRAMMAR {
            assert!(
                seen.insert(g.family),
                "duplicate token family: {}",
                g.family
            );
        }
    }

    /// Every implemented [`Family`] is reachable through some coin token, so the escape hatch has no
    /// blind spot: a fork of any supported family can be minted without a code change.
    #[test]
    fn grammar_covers_every_family() {
        let reachable: Vec<Family> = TOKEN_GRAMMAR
            .iter()
            .map(|g| parse_token(g.example).unwrap().family())
            .collect();
        for f in [
            Family::P2pkh,
            Family::SegwitV0,
            Family::Taproot,
            Family::Ethereum,
            Family::CryptoNote,
            Family::KaspaAddr,
            Family::Ergo,
            Family::Alephium,
            Family::Xdag,
        ] {
            assert!(reachable.contains(&f), "no coin token produces {f:?}");
        }
    }

    /// An unrecognised parameter is an error, not something to ignore.  A silently dropped
    /// `net_tets=` or `uncompresed` would mint an address from the wrong parameters.
    #[test]
    fn unknown_parameter_is_rejected() {
        for token in [
            "p2pkh:ver=0x00,wif=0x80,uncompresed", // mistyped flag
            "p2pkh:ver=0x00,wif=0x80,compressed",  // flag this family does not define
            "cryptonote:net=18,net_tets=53",       // mistyped optional key
            "ethereum:hrp=bc",                     // key on a zero-parameter family
            "taproot:hrp=prl,wif=0x80",            // key from another family
        ] {
            assert!(parse_token(token).is_err(), "{token} must be rejected");
        }
        // The spellings the grammar does define still parse.
        assert!(parse_token("p2pkh:ver=0x00,wif=0x80,uncompressed").is_ok());
        assert!(parse_token("cryptonote:net=18,net_test=53").is_ok());
    }

    /// The unknown-family message names every family the grammar carries, so it stays correct as the
    /// grammar grows.
    #[test]
    fn unknown_family_error_lists_the_grammar() {
        let err = parse_token("bogus:x=1").unwrap_err();
        for g in TOKEN_GRAMMAR {
            assert!(err.contains(g.family), "{err} omits {}", g.family);
        }
    }

    /// `family()` agrees with the params variant for every row — the invariant the removed
    /// `CoinSpec::family` field could previously violate.
    #[test]
    fn derived_family_matches_params_variant() {
        for spec in COINS {
            let expected = match spec.params {
                FamilyParams::P2pkh { .. } => Family::P2pkh,
                FamilyParams::SegwitV0 { .. } => Family::SegwitV0,
                FamilyParams::Taproot { .. } => Family::Taproot,
                FamilyParams::Ethereum => Family::Ethereum,
                FamilyParams::CryptoNote { .. } => Family::CryptoNote,
                FamilyParams::KaspaAddr { .. } => Family::KaspaAddr,
                FamilyParams::Ergo => Family::Ergo,
                FamilyParams::Alephium => Family::Alephium,
                FamilyParams::Xdag => Family::Xdag,
            };
            assert_eq!(spec.family(), expected, "{}", spec.ticker);
        }
    }
}
