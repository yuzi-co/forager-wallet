//! Known-answer tests for the **testnet** address forms of the coin table.
//!
//! Testnet parameters are the easiest thing in [`forager_wallet::coins`] to get silently wrong: a
//! row can declare a testnet version byte or HRP that no test ever mints, and a typo there ships as
//! a valid-looking address on the wrong network.  Mainnet forms are covered coin by coin in
//! `lib.rs`; this file exists so that *declaring* a testnet variant is not enough — every row that
//! declares one must have its testnet output pinned somewhere, and
//! [`every_row_declaring_a_testnet_variant_has_a_testnet_kat`] fails when a new declaration appears
//! without one.
//!
//! **Provenance.** The single external anchor is BIP-173's own published testnet P2WPKH example.
//! Everything else is either derived from it or minted by this repository's generator and pinned
//! together with a structural fact that a wrong version byte or HRP would break; each constant says
//! which, immediately above it.  Nothing here was recalled from memory.

use forager_wallet::{address_from_secret, address_from_secret_kind, coins, Network};

/// Private key `1`.  Its compressed public key is `0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28
/// D959F2815B16F81798` — the key BIP-173's "Examples" section names verbatim — and the witness
/// program those examples encode is its HASH160, `751e76e8199196d454941c45d1b3a323f1433bd6`.  That
/// shared starting point is what makes the addresses below traceable to a spec rather than to us,
/// and it is the same `PRIV1` the mainnet KATs in `lib.rs` use.
const PRIV1: &str = "0000000000000000000000000000000000000000000000000000000000000001";

/// The bech32 payload for that witness program: witness-version character `q` followed by the
/// 32 data characters of HASH160.  Every testnet SegWit v0 row must reproduce it exactly; only the
/// HRP and the 6-character checksum may differ between coins.
const WITNESS_BODY: &str = "qw508d6qejxtdg4y5r3zarvary0c5xw7k";

/// BTC testnet P2WPKH is asserted directly against the address published in BIP-173.
///
/// Source: bitcoin/bips `bip-0173.mediawiki`, "Examples" — `Testnet P2WPKH:
/// tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx`.  This is the anchor the rest of the file leans on:
/// it fixes both the testnet HRP `tb` (bitcoin/src/chainparams.cpp, testnet3 `bech32_hrp`) and the
/// bech32 checksum over it, from a document independent of this repository.
#[test]
fn btc_testnet_p2wpkh_matches_the_published_bip173_vector() {
    let w = address_from_secret("btc", PRIV1, Network::Testnet).unwrap();
    assert_eq!(w.address, "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx");
}

/// The other rows that declare a testnet bech32 HRP encode the *same* witness program, so each
/// address must be `<hrp>1` + [`WITNESS_BODY`] + a 6-character checksum and nothing else.
///
/// The HRPs come from each project's `chainparams.cpp` (cited in each row's comment in
/// `coins.rs`); the addresses were minted by this repository's generator.  The structural split
/// asserted here is what makes the minted literals worth pinning: a row that carried a wrong
/// witness program — a truncated or mainnet-derived HASH160 — would fail the body check even though
/// its own checksum would still be self-consistent.
#[test]
fn testnet_bech32_rows_differ_from_bitcoin_only_in_hrp_and_checksum() {
    for (ticker, hrp, expect) in [
        ("btc", "tb", "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"),
        (
            "ltc",
            "tltc",
            "tltc1qw508d6qejxtdg4y5r3zarvary0c5xw7klfsuq0",
        ),
        // SCASH leaves Bitcoin's address parameters byte-identical, testnet included, so its
        // testnet address is Bitcoin's testnet address — asserted, not assumed.
        ("scash", "tb", "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"),
        (
            "alpha",
            "talpha",
            "talpha1qw508d6qejxtdg4y5r3zarvary0c5xw7k5f2w9x",
        ),
    ] {
        let w = address_from_secret(ticker, PRIV1, Network::Testnet).unwrap();
        assert_eq!(w.address, expect, "{ticker}");
        let body = w
            .address
            .strip_prefix(&format!("{hrp}1"))
            .unwrap_or_else(|| panic!("{ticker}: {} lacks hrp {hrp}", w.address));
        assert_eq!(&body[..body.len() - 6], WITNESS_BODY, "{ticker} program");
    }
}

/// Every row that declares testnet P2PKH version `0x6f` must render the *same* address for the same
/// key, because base58check over `0x6f ‖ HASH160` has no other input.
///
/// `mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r` was minted by this repository's generator and independently
/// recomputed as `base58check(0x6f ‖ 751e76e8…33bd6)` by a from-scratch Python base58check oracle;
/// the HASH160 is BIP-173's published one (see [`PRIV1`]).  Version `0x6f` itself is
/// `base58Prefixes[PUBKEY_ADDRESS]` for testnet3 in bitcoin/src/chainparams.cpp, and each row's
/// comment in `coins.rs` cites its own project's copy of that value.
///
/// Cross-checking the rows against one another is the point: any row whose declared byte drifted
/// from `0x6f` produces a different string and fails, without needing a separate literal per coin.
#[test]
fn rows_declaring_bitcoins_testnet_p2pkh_version_render_one_shared_address() {
    const V6F: &str = "mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r";
    // SegWit v0 rows reach their P2PKH form through `--legacy`; the P2PKH-family rows have no other.
    for ticker in ["btc", "ltc", "scash", "alpha"] {
        let w = address_from_secret_kind(ticker, PRIV1, Network::Testnet, true).unwrap();
        assert_eq!(w.address, V6F, "{ticker} legacy testnet");
    }
    let rvn = address_from_secret("rvn", PRIV1, Network::Testnet).unwrap();
    assert_eq!(rvn.address, V6F, "rvn testnet");

    // …and testnet must not be quietly rendering the mainnet byte: BTC mainnet legacy for the same
    // key is `1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH` (pinned by `vtc_segwit_v0_and_legacy_privkey_one`
    // in `lib.rs`, which cites it as the constant its base58check oracle was validated against).
    let mainnet = address_from_secret_kind("btc", PRIV1, Network::Mainnet, true).unwrap();
    assert_eq!(mainnet.address, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
    assert_ne!(mainnet.address, V6F);
}

/// DOGE is the one P2PKH row whose testnet byte is not `0x6f`: `0x71` (113), from
/// dogecoin/dogecoin/src/chainparams.cpp.  Minted by this repository's generator and independently
/// recomputed as `base58check(0x71 ‖ 751e76e8…33bd6)` by the same from-scratch Python oracle.
///
/// The `n` prefix is derived, not remembered: over the whole HASH160 range, `0x71 ‖ h160` encodes to
/// a first character of `n` and only `n` (whereas `0x6f` straddles `m`/`n`), so the leading
/// character corroborates the version byte independently of this key.  It must also differ from the
/// `0x6f` address above, or the two declarations would be indistinguishable.
#[test]
fn doge_testnet_p2pkh_uses_version_0x71() {
    let w = address_from_secret("doge", PRIV1, Network::Testnet).unwrap();
    assert_eq!(w.address, "nesRpRaAbTDmZHwmzBkLd2AtF7Z9L9z5S2");
    assert!(w.address.starts_with('n'), "{}", w.address);
    assert_ne!(w.address, "mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r");
}

/// Kadikama's testnet byte is `0x2e` (46), one above its mainnet `0x2d` (45), from Kadikama Core's
/// chainparams.  Minted by this repository's generator and independently recomputed as
/// `base58check(0x2e ‖ 751e76e8…33bd6)` by a from-scratch Python base58check oracle, which
/// reproduced both the mainnet and testnet strings exactly.
///
/// **The leading character does not distinguish the two networks, and that is the point of this
/// test.** Bracketing the whole HASH160 space at both ends gives, for `0x2d`, `K7D9JtQxx7rR…` to
/// `KWYkHziFfJKJ…`, and for `0x2e`, `KWYkHziFfJKJ…` to `KutMH71YNUnB…` — all 34 characters, all
/// leading `K`. So `K…` is *guaranteed* for both, and consecutive version bytes land inside one
/// base58 character: testnet's low end is byte-for-byte mainnet's high end, because 46's range
/// begins exactly where 45's ends. A reader cannot tell a Kadikama testnet payout address from a
/// mainnet one by looking at it, and neither can a check that only inspects the first character.
/// Pinning both strings is what separates them here.
#[test]
fn kad_testnet_p2pkh_uses_version_0x2e_and_looks_like_mainnet() {
    let testnet = address_from_secret("kad", PRIV1, Network::Testnet).unwrap();
    assert_eq!(testnet.address, "KhE1r9bs2NB4mFbyM5Rz8cwB5KHwmcP829");

    let mainnet = address_from_secret("kad", PRIV1, Network::Mainnet).unwrap();
    assert_eq!(mainnet.address, "KHtQs3JaKBiBwpTtKf6feVfPSp3131uG3M");

    // Both `K`, both 34 characters — indistinguishable by shape, distinct by value. If a future
    // edit made testnet render the mainnet byte, the first two assertions would still both pass
    // shape checks; only this one would fail.
    assert_ne!(testnet.address, mainnet.address);
    assert!(testnet.address.starts_with('K'), "{}", testnet.address);
    assert!(mainnet.address.starts_with('K'), "{}", mainnet.address);
    assert_eq!(testnet.address.len(), mainnet.address.len());
}

/// Whether a row declares any testnet-specific parameter at all.
///
/// Ergo, Alephium and XDAG are excluded by construction: their families take no `Option` testnet
/// parameter — Ergo switches on a protocol constant present in both networks, and the other two
/// have network-agnostic addresses — so there is no per-row value that could be wrong.
fn declares_testnet(params: &coins::FamilyParams) -> bool {
    match params {
        coins::FamilyParams::Taproot { hrp_testnet, .. } => hrp_testnet.is_some(),
        coins::FamilyParams::KaspaAddr { prefix_testnet, .. } => prefix_testnet.is_some(),
        coins::FamilyParams::SegwitV0 {
            hrp_testnet,
            p2pkh_version_testnet,
            ..
        } => hrp_testnet.is_some() || p2pkh_version_testnet.is_some(),
        coins::FamilyParams::P2pkh {
            version_testnet, ..
        } => version_testnet.is_some(),
        coins::FamilyParams::CryptoNote {
            network_byte_testnet,
            ..
        } => network_byte_testnet.is_some(),
        coins::FamilyParams::Ergo
        | coins::FamilyParams::Alephium
        | coins::FamilyParams::Xdag
        | coins::FamilyParams::Warthog
        | coins::FamilyParams::Ethereum => false,
    }
}

/// Pinned deliberately: a row gains a testnet form the moment someone adds a `*_testnet` value, and
/// nothing else forces that value to be minted even once.  This list changing is the signal to add
/// a testnet KAT for the new row — not something to update reflexively.
///
/// Where each row's testnet output is pinned today:
/// * `btc`, `ltc`, `scash`, `alpha`, `rvn`, `doge`, `kad` — this file.
/// * `xmr` — `families::cryptonote::tests::monero_testnet_address_uses_network_byte_53`.
/// * `pearl`, `vtc`, `firo`, `mewc`, `kas`, `kls`, `spr` — their per-coin tests in `lib.rs`.
#[test]
fn every_row_declaring_a_testnet_variant_has_a_testnet_kat() {
    let declared: Vec<&str> = coins::COINS
        .iter()
        .filter(|c| declares_testnet(&c.params))
        .map(|c| c.ticker)
        .collect();
    assert_eq!(
        declared,
        [
            "pearl", "btc", "ltc", "vtc", "doge", "rvn", "firo", "mewc", "kad", "xmr", "kas",
            "kls", "spr", "scash", "alpha"
        ]
    );
    // Every one of them must actually mint on testnet rather than error — the cheap half of the
    // guarantee, applied uniformly; the per-coin tests above pin the exact strings.
    for ticker in declared {
        assert!(
            address_from_secret(ticker, PRIV1, Network::Testnet).is_ok(),
            "{ticker} declares a testnet variant but cannot mint one"
        );
    }
}
