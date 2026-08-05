//! Static coin registry: the address-family parameters for every coin Forager can generate a
//! payout address for.
//!
//! A row carries only [`FamilyParams`]; the high-level [`Family`] is *derived* from it by
//! [`FamilyParams::family`]. Storing both would let a copy-pasted row claim one family while
//! encoding another — a mislabel that reaches the pool-payout warning in
//! `forager::wallet_preflight` — so the discriminant has exactly one source.

use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

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
    ///
    /// A row carries the *bytes* only.  The two hash primitives are fixed by the encoder and are
    /// not expressible here: `families::p2pkh` hashes the pubkey with HASH160 (SHA-256 then
    /// RIPEMD-160), and [`crate::codec::base58::encode_check`] checksums with the first four bytes
    /// of double-SHA-256.  Every coin in [`COINS`] is a Bitcoin derivative that keeps both, so no
    /// row here is wrong — but the pair is an *assumption*, and it is the one thing a
    /// [`parse_token`] `p2pkh:` token cannot restate.  Two shipping chains break it:
    ///   - **Groestlcoin** keeps HASH160 unchanged (`src/hash.h`, `CHash160` = SHA-256 +
    ///     RIPEMD-160) but replaces the base58check checksum: `src/base58.cpp`'s
    ///     `EncodeBase58Check` calls `XCoin::HashForAddress`, which `src/groestlcoin.h` aliases to
    ///     `HashGroestl` — Groestl-512 applied twice, the first 32 bytes of the second digest
    ///     (`src/groestlcoin-hash.cpp`).  The patch is in base58 itself, so every base58check
    ///     string differs, address and WIF alike.  Its `PUBKEY_ADDRESS` is 36 and `SECRET_KEY` 128
    ///     (`src/kernel/chainparams.cpp`), which is exactly why `p2pkh:ver=0x24,wif=0x80` looks
    ///     plausible.  Source: `Groestlcoin/groestlcoin`.
    ///   - **Decred** changes both: `Hash160` is `ripemd160(blake256(·))` (`decred/dcrd`
    ///     `dcrutil/hash160.go` over `chaincfg/chainhash/hashfuncs.go`'s `HashB`), and the
    ///     checksum is double-BLAKE-256 over a *two*-byte version (`decred/base58`
    ///     `base58check.go`, `CheckEncode(input []byte, version [2]byte)`; mainnet
    ///     `PubKeyHashAddrID` is `0x07,0x3f` → `Ds…`).  Decred is out of reach twice over: this
    ///     `version` field is a slice and could hold two bytes, but [`parse_token`]'s `ver=` reads
    ///     a single byte, so no token can even name it.
    ///
    /// Neither is in [`COINS`], and neither can be added by a table row: each needs a hash
    /// primitive this workspace does not implement, and the table's own rule is that no row lands
    /// without a passing KAT.  The defence for the runtime escape hatch is therefore the
    /// [`TokenSyntax::caveat`] on the `p2pkh` grammar row, which the CLI prints.
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
        hd_slip44: Some(61), // SLIP-44: satoshilabs/slips
        params: FamilyParams::Ethereum,
    },
    CoinSpec {
        ticker: "eth",
        name: "Ethereum",
        hd_slip44: Some(60), // SLIP-44: satoshilabs/slips
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
        hd_slip44: Some(108), // SLIP-44: satoshilabs/slips
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
    // dgb: deferred until its KATs land.  (vtc landed: it is a SegWit v0 row above, with
    // single-key, --legacy and testnet KATs in the wallet crate and BIP44/84/86 vectors in
    // tests/hd_kat.rs.)
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
    /// What this family assumes but does not let the token state, or `None` when the token's
    /// parameters are the whole story.
    ///
    /// A token can only carry what [`parse_token`] has a slot for.  Where the encoder additionally
    /// hard-wires something a real chain varies — the P2PKH hash primitives, see
    /// [`FamilyParams::P2pkh`] — the token cannot express it and the parser cannot check it, so the
    /// only remaining defence is telling the user.  Printed verbatim by `forager-wallet list` and
    /// again beside the minted address; one line per `\n`, kept short enough for a terminal.
    pub caveat: Option<&'static str>,
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
        caveat: Some(
            "This token sets bytes, not hashes: it always uses Bitcoin's HASH160 pubkey hash\n\
             and Bitcoin's SHA256d base58check checksum. That is right for Bitcoin-derived\n\
             chains and WRONG for Groestlcoin (double-Groestl-512 checksum) and Decred\n\
             (BLAKE-256, two-byte version) — for those, both the address and the WIF are\n\
             wrong, and no `ver=` can fix it.",
        ),
    },
    TokenSyntax {
        family: "segwit",
        keys: &["hrp", "wif", "ver"],
        flags: &[],
        syntax: "segwit:hrp=<str>,wif=<byte>[,ver=<byte>]",
        example: "segwit:hrp=bc,wif=0x80",
        // The bech32 address itself carries no hash-based checksum, but `--legacy` and the WIF
        // both go through the same base58check encoder as `p2pkh:`, so they inherit its
        // assumption. Spelled out rather than cross-referenced: the two caveats are printed
        // independently, and a user reading the `segwit:` line may never see the `p2pkh:` one.
        caveat: Some(
            "The `--legacy` address form and the WIF are base58check with Bitcoin's SHA256d\n\
             checksum, so they are wrong for a chain that changed it (e.g. Groestlcoin).",
        ),
    },
    TokenSyntax {
        family: "taproot",
        keys: &["hrp"],
        flags: &[],
        syntax: "taproot:hrp=<str>",
        example: "taproot:hrp=prl",
        caveat: None,
    },
    TokenSyntax {
        family: "cryptonote",
        keys: &["net", "net_test"],
        flags: &[],
        syntax: "cryptonote:net=<int>[,net_test=<int>]",
        example: "cryptonote:net=18",
        caveat: None,
    },
    TokenSyntax {
        family: "kaspa",
        keys: &["prefix"],
        flags: &[],
        syntax: "kaspa:prefix=<str>",
        example: "kaspa:prefix=kaspa",
        caveat: None,
    },
    TokenSyntax {
        family: "ethereum",
        keys: &[],
        flags: &[],
        syntax: "ethereum:",
        example: "ethereum:",
        caveat: None,
    },
    TokenSyntax {
        family: "ergo",
        keys: &[],
        flags: &[],
        syntax: "ergo:",
        example: "ergo:",
        caveat: None,
    },
    TokenSyntax {
        family: "alephium",
        keys: &[],
        flags: &[],
        syntax: "alephium:",
        example: "alephium:",
        caveat: None,
    },
    TokenSyntax {
        family: "xdag",
        keys: &[],
        flags: &[],
        syntax: "xdag:",
        example: "xdag:",
        caveat: None,
    },
];

/// The [`TokenSyntax::caveat`] for a runtime coin token's family, or `None` if it has none.
///
/// Keyed off the token's `family:` prefix, so the warning printed beside a minted address comes
/// from the same grammar row as the `forager-wallet list` help text — a caveat cannot appear in one
/// place and not the other.  `None` for a table ticker (which has no `:`) and for an unknown
/// family, both of which are the caller's own error to report.
pub fn token_caveat(token: &str) -> Option<&'static str> {
    let (family, _) = token.split_once(':')?;
    TOKEN_GRAMMAR
        .iter()
        .find(|g| g.family == family)
        .and_then(|g| g.caveat)
}

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
/// parameters are not.  The `ticker`/`name`/prefix strings are interned (see [`intern`]) and live
/// for the process lifetime, so calling this repeatedly with the same token allocates once.
///
/// A token is also narrower than a family: it can only say what the grammar has a slot for.  The
/// `p2pkh:` token supplies version and WIF bytes but no hash primitives, and the encoder's
/// Bitcoin pair is wrong for some real chains — [`token_caveat`] carries the text the caller must
/// print, and [`FamilyParams::P2pkh`] names the chains and cites them.
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
            version: intern_bytes(vec![parse_byte(req("ver")?)?]),
            version_testnet: None,
            wif: parse_byte(req("wif")?)?,
            compressed: !flags.contains(&"uncompressed"),
        },
        "segwit" => FamilyParams::SegwitV0 {
            hrp: intern(req("hrp")?.to_string()),
            hrp_testnet: None,
            wif: parse_byte(req("wif")?)?,
            p2pkh_version: intern_bytes(vec![match get("ver") {
                Some(v) => parse_byte(v)?,
                None => 0x00,
            }]),
            p2pkh_version_testnet: None,
        },
        "taproot" => FamilyParams::Taproot {
            hrp: intern(req("hrp")?.to_string()),
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
            prefix: intern(req("prefix")?.to_string()),
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
        ticker: intern(token.to_string()),
        name: intern(format!("custom {family}")),
        params,
        // A runtime token names no chain, so no SLIP-44 coin type is knowable: HD is never offered
        // for one. `--hd` takes a table ticker.
        hd_slip44: None,
    })
}

/// Intern an owned string as `'static`, reusing the allocation if this exact value has been
/// interned before.
///
/// [`CoinSpec`] holds `&'static str` because every row in [`COINS`] is a compile-time literal;
/// [`parse_token`] mints a row at runtime and so has to produce `'static` data from an owned
/// `String`. It did that with a bare `Box::leak` per call, justified by a comment reading "only
/// runtime coin tokens reach this, in the one-shot `wallet` CLI path — never a loop or hot path".
/// That was true of the CLI and false of the crate: `forager-addr` is published, and `parse_token`
/// is `pub`. A caller that re-reads its configuration — the miner reloading a pool token — leaked
/// three allocations per parse, forever, growing with uptime rather than with the number of coins
/// it had ever seen. A library cannot rely on a property of one of its callers.
///
/// Interning restores the bound the comment claimed: memory is proportional to the number of
/// *distinct* values interned, not to the number of calls, so re-parsing the same token in a loop
/// allocates once and then never again. Deliberate leaking remains, and remains the right shape —
/// an interned value is genuinely immortal, and there is no free to get wrong.
///
/// This is not a defence against an attacker feeding unbounded distinct tokens; nothing that hands
/// arbitrary strings to a coin-table parser is in a position to be defended from here. It closes
/// the case that arises without an adversary, which is the one that was actually reachable.
fn intern(s: String) -> &'static str {
    static POOL: OnceLock<Mutex<HashSet<&'static str>>> = OnceLock::new();
    let pool = POOL.get_or_init(Mutex::default);
    // A panic inside the critical section cannot leave the set inconsistent — the only operations
    // are a lookup and an insert of an already-leaked reference — so a poisoned lock is recoverable
    // rather than a reason to abort a payout-address parse.
    let mut pool = pool.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(hit) = pool.get(s.as_str()) {
        return hit;
    }
    let leaked: &'static str = Box::leak(s.into_boxed_str());
    pool.insert(leaked);
    leaked
}

/// Intern an owned byte vector as `'static`, for a runtime token's version prefix. Same reasoning
/// and same bound as [`intern`].
fn intern_bytes(v: Vec<u8>) -> &'static [u8] {
    static POOL: OnceLock<Mutex<HashSet<&'static [u8]>>> = OnceLock::new();
    let pool = POOL.get_or_init(Mutex::default);
    let mut pool = pool.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(hit) = pool.get(v.as_slice()) {
        return hit;
    }
    let leaked: &'static [u8] = Box::leak(v.into_boxed_slice());
    pool.insert(leaked);
    leaked
}

/// Parse a `u64` in decimal, or hex when `0x`/`0X`-prefixed.
///
/// Digits only: no sign. Both `str::parse::<u64>` and [`u64::from_str_radix`] accept a leading `+`,
/// so `p2pkh:ver=0x+00` and `cryptonote:net=+18` parsed cleanly before this guard. That matters
/// more here than it would in a general-purpose parser, because this whole path is the
/// **unverified** escape hatch: a token's bytes are never checked against a known-answer test, so
/// the grammar is the only thing standing between a typo and a valid-looking address that
/// misdirects a payout. A parser that accepts input the documented grammar does not describe —
/// `<int>`, not `[+-]<int>` — narrows that gap for no one's benefit; a version byte has no sign.
fn parse_uint(s: &str) -> Result<u64, String> {
    let (digits, radix) = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => (hex, 16),
        None => (s, 10),
    };
    let malformed = || format!("invalid integer '{s}' (use decimal, or 0x-prefixed hex)");
    let digits_only = !digits.is_empty()
        && digits.bytes().all(|b| match radix {
            16 => b.is_ascii_hexdigit(),
            _ => b.is_ascii_digit(),
        });
    if !digits_only {
        return Err(malformed());
    }
    // Overflow is still `from_str_radix`'s to catch: the guard above is about shape, not range.
    u64::from_str_radix(digits, radix).map_err(|_| malformed())
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

    /// The `p2pkh` token names the hashes it assumes and the chains that assumption is wrong for.
    ///
    /// This is the guarantee the grammar cannot make structurally: [`FamilyParams::P2pkh`] carries
    /// version and WIF bytes but no hasher, so `parse_token` has nothing to validate and no way to
    /// refuse a Groestlcoin or Decred token — those tokens are well-formed. The caveat is the only
    /// thing standing between a user and a silently wrong address, so pin its contents rather than
    /// its mere presence.
    #[test]
    fn the_p2pkh_caveat_names_the_hashes_it_assumes_and_the_chains_it_is_wrong_for() {
        let row = TOKEN_GRAMMAR
            .iter()
            .find(|g| g.family == "p2pkh")
            .expect("the grammar has a p2pkh row");
        let caveat = row.caveat.expect("the p2pkh row must carry a caveat");
        for needle in ["HASH160", "SHA256d", "Groestlcoin", "Decred"] {
            assert!(caveat.contains(needle), "p2pkh caveat omits {needle}");
        }
    }

    /// The caveat reaches the user for the token they actually typed, not just for the bare family
    /// name — the CLI looks it up by the `--coin` argument it was handed.
    #[test]
    fn token_caveat_resolves_for_any_spelling_of_a_caveated_family() {
        let p2pkh = TOKEN_GRAMMAR
            .iter()
            .find(|g| g.family == "p2pkh")
            .and_then(|g| g.caveat);
        // Groestlcoin's own PUBKEY_ADDRESS=36 / SECRET_KEY=128 (src/kernel/chainparams.cpp): the
        // exact token that parses cleanly and mints an address Groestlcoin will not recognise.
        assert_eq!(token_caveat("p2pkh:ver=0x24,wif=0x80"), p2pkh);
        assert_eq!(token_caveat("p2pkh:ver=0x00,wif=0x80,uncompressed"), p2pkh);
        assert!(token_caveat("ethereum:").is_none());
        assert!(token_caveat("btc").is_none()); // a table ticker is not a token
        assert!(token_caveat("bogus:x=1").is_none());
    }

    /// Every caveat is printable: non-empty, and no blank line inside it. Both render as a bare
    /// `!!` in the CLI, which reads as a warning that forgot to say anything.
    #[test]
    fn every_caveat_has_only_non_empty_lines() {
        for g in TOKEN_GRAMMAR {
            let Some(caveat) = g.caveat else { continue };
            assert!(!caveat.is_empty(), "{}: empty caveat", g.family);
            for line in caveat.lines() {
                assert!(!line.trim().is_empty(), "{}: blank caveat line", g.family);
            }
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

    /// An integer parameter is digits, with no sign.
    ///
    /// Both `str::parse::<u64>` and `u64::from_str_radix` accept a leading `+`, so the first block
    /// below all parsed before the guard in [`parse_uint`]: `p2pkh:ver=0x+00` yielded version byte
    /// `0x00` and `cryptonote:net=+18` yielded Monero's prefix, from tokens the documented grammar
    /// (`<int>`, `<byte>`) does not describe. This is the *unverified* escape hatch — a token's
    /// bytes never meet a known-answer test — so the grammar is the only check they get, and
    /// accepting input it does not describe widens the one gap that matters.
    ///
    /// The second block was already rejected, by `from_str_radix` erroring on a negative into an
    /// unsigned type and on an empty string. Those are properties of the callee, not decisions this
    /// parser was making, so they are pinned here rather than left to be re-derived.
    #[test]
    fn an_integer_parameter_does_not_take_a_sign() {
        for token in [
            "p2pkh:ver=0x+00,wif=0x80",
            "p2pkh:ver=+0,wif=0x80",
            "p2pkh:ver=0x00,wif=+128",
            "cryptonote:net=+18",
            "cryptonote:net=18,net_test=+53",
        ] {
            assert!(parse_token(token).is_err(), "{token} must be rejected");
        }
        for token in [
            "p2pkh:ver=-1,wif=0x80",
            "p2pkh:ver=0x,wif=0x80",
            "p2pkh:ver=,wif=0x80",
        ] {
            assert!(parse_token(token).is_err(), "{token} must be rejected");
        }

        // The spellings the grammar does describe are untouched, in both radices.
        assert!(parse_token("p2pkh:ver=0x00,wif=0x80").is_ok());
        assert!(parse_token("p2pkh:ver=0,wif=128").is_ok());
        assert!(parse_token("p2pkh:ver=0X1E,wif=0x9E").is_ok());
        assert_eq!(parse_uint("0x1e"), Ok(30));
        assert_eq!(parse_uint("30"), Ok(30));
        // Range is still checked, and separately from shape.
        assert!(parse_byte("256").is_err());
        assert!(parse_uint("0xfffffffffffffffff").is_err());
    }

    /// Re-parsing a token allocates once, not once per call.
    ///
    /// [`parse_token`] has to produce `'static` data from runtime strings, and used to do it with a
    /// bare `Box::leak` on every success — three allocations per call, never reused. The comment
    /// defending that said the path was "never a loop or hot path", which described the `wallet`
    /// CLI rather than the crate: `forager-addr` is published and `parse_token` is `pub`, so a
    /// caller re-reading its configuration grew with its uptime instead of with the number of
    /// distinct coins it had seen.
    ///
    /// Pointer equality is the assertion because it is the property that matters — that the second
    /// parse returned the *same* allocation, not merely an equal string. Comparing the strings
    /// would pass under the old code too.
    #[test]
    fn parsing_the_same_token_twice_reuses_one_allocation() {
        const TOKEN: &str = "p2pkh:ver=0x1e,wif=0x9e";
        let a = parse_token(TOKEN).unwrap();
        let b = parse_token(TOKEN).unwrap();

        assert!(std::ptr::eq(a.ticker, b.ticker), "ticker re-leaked");
        assert!(std::ptr::eq(a.name, b.name), "name re-leaked");
        let (va, _) = a.params.p2pkh_parts().unwrap();
        let (vb, _) = b.params.p2pkh_parts().unwrap();
        assert!(std::ptr::eq(va, vb), "version prefix re-leaked");

        // Equal values interned through different call sites and different owned `String`s still
        // land on one allocation: `name` here is `format!("custom p2pkh")` built afresh each time.
        assert_eq!(a.name, "custom p2pkh");

        // A genuinely different token is a different allocation — interning must not be collapsing
        // distinct values onto one another.
        let c = parse_token("p2pkh:ver=0x00,wif=0x80").unwrap();
        assert!(!std::ptr::eq(a.ticker, c.ticker));
        assert!(
            std::ptr::eq(a.name, c.name),
            "same family, same name string"
        );
        let (vc, _) = c.params.p2pkh_parts().unwrap();
        assert!(!std::ptr::eq(va, vc));
        assert_eq!(vc, &[0x00u8][..]);
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
