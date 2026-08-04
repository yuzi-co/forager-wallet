//! Known-answer tests for the BIP39/BIP44 HD generator ([`forager_wallet::hd`]).
//!
//! **Non-circularity.** The expected address/WIF constants below were produced by an *independent*
//! reference oracle (a from-scratch Python implementation of PBKDF2-HMAC-SHA512 seed derivation,
//! BIP32 CKDpriv, secp256k1, and base58check) that was itself validated against two canonical,
//! published vectors before it was trusted: (a) the BIP39 seed for the 24-word all-zero-entropy
//! mnemonic + passphrase `"TREZOR"`, taken verbatim from the official `trezor/python-mnemonic`
//! `vectors.json` and re-asserted here directly via `bip32::Mnemonic::to_seed`; and (b) BIP32
//! test-vector 1 (seed `000102…0f` → master key/chain code).
//!
//! Version bytes come from each coin's `chainparams.cpp` (`base58Prefixes[PUBKEY_ADDRESS]` /
//! `[SECRET_KEY]`, mainnet); SLIP-44 coin types from `slip-0044.md`.  `forager_wallet::hd::derive` (which
//! routes through the `bip32` crate) is a third, independent stack; agreement across all three
//! anchors the values.
//!
//! `bip32::Mnemonic` is 24-word (256-bit) only, so the canonical test mnemonic here is the 24-word
//! all-zero-entropy vector (`abandon` ×23 + `art`), not the shorter 12-word form.

use forager_wallet::hd;

/// Canonical BIP39 24-word all-zero-entropy mnemonic (`abandon` ×23 + `art`).
const ABANDON: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Anchor #1: the mnemonic->seed step reproduces the official Trezor BIP39 vector.
#[test]
fn bip39_canonical_seed_vector() {
    let mnemonic = bip32::Mnemonic::new(ABANDON, Default::default()).unwrap();
    let seed = mnemonic.to_seed("TREZOR");
    assert_eq!(
        hex(seed.as_bytes()),
        "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd309717\
         0af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8"
    );
}

/// Assert a coin derives the expected address AND WIF at the standard path
/// `m/44'/slip44'/0'/0/0` from the canonical mnemonic with no passphrase.
fn check(sym: &str, expect_addr: &str, expect_wif: &str) {
    let coin = hd::lookup(sym).unwrap_or_else(|| panic!("{sym} must be HD-capable"));
    let slip44 = coin.hd_slip44.expect("an HD-capable row carries a slip44");
    let acct = hd::derive(ABANDON, "", coin, hd::Purpose::Bip44, 0, 0).unwrap();
    assert_eq!(acct.path, format!("m/44'/{slip44}'/0'/0/0"), "{sym} path");
    assert_eq!(acct.address, expect_addr, "{sym} address");
    assert_eq!(acct.secret_str(), expect_wif, "{sym} wif");
}

// ---- Per-coin address+WIF KATs at m/44'/slip44'/0'/0/0 (mnemonic = ABANDON, no passphrase) ----

#[test]
fn btc_bip44_vector() {
    check(
        "btc",
        "1KBdbBJRVYffWHWWZ1moECfdVBSEnDpLHi",
        "L42rpqMcjt1LtyvZCSTLkaif5mjFyTXTHSVuckRZEM7GaD2KLCkc",
    );
}

#[test]
fn ltc_bip44_vector() {
    check(
        "ltc",
        "LUmq6tzbxhCQe8NwdkkRuR7emEbQGyYVBA",
        "T7LNeds5xBzWqFge9C7tHqhfnhxtfMChwWchehWnksXjCT6QeS8o",
    );
}

#[test]
fn doge_bip44_vector() {
    check(
        "doge",
        "DL1DoPj4HvpnRT9n3YfCkhHXe5287wMyWD",
        "QSMmFVLHzpT2i4L8rUHZNZUyq2y9gLVbX2CtqTn3wqknJJwAJtRu",
    );
}

#[test]
fn rvn_bip44_vector() {
    check(
        "rvn",
        "RY8N6w2WDisbZLGoFbfzrMmAibgVMXQ6f8",
        "Kzov2mjrBN6iyDs5MfTgWKu4p1CAQyPy4rkUN9UjJQxNuLcWo3UZ",
    );
}

/// VTC at `m/44'/28'/0'/0/0`. SLIP-44 coin type 28 (satoshilabs/slips, slip-0044.md).
/// BIP44 is P2PKH, so this is the `V…` form even though `vtc new` defaults to SegWit v0.
#[test]
fn vtc_bip44_vector() {
    check(
        "vtc",
        "VnnFBkra9iYM1Yn8iWZN5fi32goydgSnX3",
        "KwdRZrJHwau3EwzKqNF5FaGJCpb5R6Cf6AM4ufH7rEkUpcHFqvVr",
    );
}

/// FIRO at `m/44'/136'/0'/0/0`. SLIP-44 registers Firo under its former name ZCoin/XZC as 136.
#[test]
fn firo_bip44_vector() {
    check(
        "firo",
        "a7R2uA9dpQbudJvdSjHKUefjKgHn4XACnV",
        "Y94KzNB4YAdRgVMFDk5LkR2Cy4yCk8rtLRrfGR5i4oota4hgtKWa",
    );
}

/// MEWC at `m/44'/1669'/0'/0/0`. SLIP-44 coin type 1669.
#[test]
fn mewc_bip44_vector() {
    check(
        "mewc",
        "MRbEXiPcBcN9wTg9XHDhN5Q471vtncZDxe",
        "HcCQ9zp4aykLsa6XSqX4yZmouaSdiYTdYRYbhQVhYz6BkV619iWf",
    );
}

#[test]
fn zec_transparent_bip44_vector() {
    check(
        "zec",
        "t1dUDJ62ANtmebE8drFg7g2MWYwXHQ6Xu3F",
        "KyJMEVEzCwzDf9SuefFaMEiPBg44BLCtFpyEsaomWVGGQYtxLopP",
    );
}

#[test]
fn btg_bip44_vector() {
    check(
        "btg",
        "GaWb7TbRjWWTAMSJNBWmLr5QL6uJPRcmr9",
        "L1REG9i1nQ7WuVciJu2VKKzNVd6Kheekizr1xNP3e3aeJrMfzvNc",
    );
}

#[test]
fn kmd_bip44_vector() {
    check(
        "kmd",
        "RXmrbdP1wDZZ2KQexsivDxv4dAT74HpBTi",
        "Ur8znKEToatV3Wmwg92a4W94VZj9p1CDjfdEtQJWYsG8RxMa7965",
    );
}

#[test]
fn btcz_transparent_bip44_vector() {
    check(
        "btcz",
        "t1dUuY8Xukc3q9yS2ywEKoZbGVA7kFmpP6v",
        "L3WNS55UpurfHNqRKnvn6mzchMVSHMK52nfE1ob8eVTzqz8JFY4T",
    );
}

#[test]
fn zer_transparent_bip44_vector() {
    check(
        "zer",
        "t1N23kXeyVyE2SY8KrttMYD3854EALufiZP",
        "L13q8q4uC4eYTHHA2TiyoAYZpo7ApFutf1a1dAAmDnikw6TJdaGy",
    );
}

// ---- BIP84 / BIP86 / Ethereum-family purposes ----

/// Assert a coin derives the expected address AND secret at `m/<purpose>'/slip44'/0'/0/0`.
fn check_at(sym: &str, purpose: hd::Purpose, expect_addr: &str, expect_secret: &str) {
    let coin = hd::lookup(sym).unwrap_or_else(|| panic!("{sym} must be HD-capable"));
    let slip44 = coin.hd_slip44.expect("an HD-capable row carries a slip44");
    let acct = hd::derive(ABANDON, "", coin, purpose, 0, 0).unwrap();
    assert_eq!(
        acct.path,
        format!("m/{}'/{slip44}'/0'/0/0", purpose.number()),
        "{sym} {purpose} path"
    );
    assert_eq!(acct.address, expect_addr, "{sym} {purpose} address");
    assert_eq!(acct.secret_str(), expect_secret, "{sym} {purpose} secret");
}

// BIP84 — native SegWit v0 at m/84'. This is what `new --hd --coin btc` now produces by default,
// matching the address type `new --coin btc` produces.
#[test]
fn btc_bip84_vector() {
    check_at(
        "btc",
        hd::Purpose::Bip84,
        "bc1qzmtrqsfuaf6l6kkcsseumq26ukaphfj9skkug6",
        "Kwej7t6aewN3Zur424Fqb2BN9eRiZ83pnA2LWJABcWDCWrtVPvZa",
    );
}

#[test]
fn ltc_bip84_vector() {
    check_at(
        "ltc",
        hd::Purpose::Bip84,
        "ltc1qj0xmcw3ttxgsfhzzcft9ac9nwp8smzq778lu3c",
        "TBKLVh5eGEFa4j19b1KuLb7BHJBd4ML24J2BsEXJEjVUAKJZiNfx",
    );
}

#[test]
fn vtc_bip84_vector() {
    check_at(
        "vtc",
        hd::Purpose::Bip84,
        "vtc1q758cxdacrl2unt9a727hgty7c2707schku355t",
        "Kyo7w21dfXKjqei3pXRsW37wD3SbRTuEDxc8NX4LJtWcNhFmNuGJ",
    );
}

// BIP86 — Taproot key-path at m/86'. The oracle's Taproot tweak was anchored against this crate's
// own `KAT_PRL` / `KAT_TPRL` pearl vectors before these values were derived.
#[test]
fn btc_bip86_vector() {
    check_at(
        "btc",
        hd::Purpose::Bip86,
        "bc1p68a8a3vuv2cxzs7e2gjc5v3qy3zdnfaxwftyqe9k9nquvm6r4w2ssldtzp",
        "KwkuH29aDSdcMoafd3oSSo9BanhFtWnoTAszM2DbsZtXr4rhFDnX",
    );
}

#[test]
fn ltc_bip86_vector() {
    check_at(
        "ltc",
        hd::Purpose::Bip86,
        "ltc1p3a7h4sp2aj3hywnxyhc4unumqta4jjgjj9l8pmanezflvnu6xkyqf7zxgg",
        "T3F3ojWLCWUSqqK6DvzgxerS5DJy9xhCokYRzHUvHQ9jQdUETsth",
    );
}

#[test]
fn vtc_bip86_vector() {
    check_at(
        "vtc",
        hd::Purpose::Bip86,
        "vtc1p74suvzx204075n6f22cmk3vd4ha86hvc333yr5l67g9j6dq5esdqhnntcq",
        "KxEJ7B9jfEMeHLimuwAfQT5vNzjHDZyniMuXbJqcHVd7NGNPend1",
    );
}

// Ethereum-family at BIP44. The oracle's keccak256 was anchored on keccak256("") and its EIP-55
// checksum on the published privkey=1 address 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf.
#[test]
fn eth_bip44_vector() {
    check_at(
        "eth",
        hd::Purpose::Bip44,
        "0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb",
        "0x1053fae1b3ac64f178bcc21026fd06a3f4544ec2f35338b001f02d1d8efa3d5f",
    );
}

#[test]
fn etc_bip44_vector() {
    check_at(
        "etc",
        hd::Purpose::Bip44,
        "0x6758B8ABB06e1a034cE15Cb3827C829705CcAEE1",
        "0x6591cd7b9f113a9bb5fc5df954d6896d48809d345320fb9e9b2aca35cd6bda6d",
    );
}

#[test]
fn ubq_bip44_vector() {
    check_at(
        "ubq",
        hd::Purpose::Bip44,
        "0xf4FCceD95787B2583b02851f03DcaE3Fe2aC2853",
        "0x2e1991d4c4b841cea58f7b8883b97eddc146c8b0d23191fff197ceb8e6dd1616",
    );
}

/// A purpose a coin's family cannot encode is a clear error, not a silently wrong address.
#[test]
fn unsupported_purpose_is_rejected() {
    let doge = hd::lookup("doge").unwrap();
    assert!(hd::derive(ABANDON, "", doge, hd::Purpose::Bip84, 0, 0).is_err());
    let eth = hd::lookup("eth").unwrap();
    assert!(hd::derive(ABANDON, "", eth, hd::Purpose::Bip86, 0, 0).is_err());
}

/// The default purpose must give HD the same address type the single-key generator gives, or one
/// of the two paths is quietly worse than the other.
#[test]
fn native_purpose_matches_single_key_address_type() {
    for (sym, want) in [
        ("btc", hd::Purpose::Bip84),
        ("ltc", hd::Purpose::Bip84),
        ("vtc", hd::Purpose::Bip84),
        ("doge", hd::Purpose::Bip44),
        ("firo", hd::Purpose::Bip44),
        ("eth", hd::Purpose::Bip44),
    ] {
        let coin = hd::lookup(sym).unwrap();
        assert_eq!(hd::native_purpose(coin), Some(want), "{sym}");
    }
}

// ---- passphrase + non-zero account/index path coverage ----

/// BIP39 passphrase ("25th word") must change the derived key -> anchored to the TREZOR-passphrase
/// seed asserted above.
#[test]
fn passphrase_changes_derivation() {
    let coin = hd::lookup("btc").unwrap();
    let plain = hd::derive(ABANDON, "", coin, hd::Purpose::Bip44, 0, 0).unwrap();
    let with_pp = hd::derive(ABANDON, "TREZOR", coin, hd::Purpose::Bip44, 0, 0).unwrap();
    assert_ne!(plain.address, with_pp.address);
    assert_eq!(with_pp.address, "12Wr5H8qyTZ3XwpwZDJDjdimS1doBoj19u");
    assert_eq!(
        with_pp.secret_str(),
        "L27mgHbgtBRaRtQYpLaorkg5GTyn3TBbxrRiDMLo54dKBkinWZ18"
    );
}

/// account and index levels of the path are honoured (BTC, account 1, index 5).
#[test]
fn account_and_index_vector() {
    let coin = hd::lookup("btc").unwrap();
    let acct = hd::derive(ABANDON, "", coin, hd::Purpose::Bip44, 1, 5).unwrap();
    assert_eq!(acct.path, "m/44'/0'/1'/0/5");
    assert_eq!(acct.address, "1FeubPzDiLuPy6JbPYXZ7D1Mms2hvf36AK");
    assert_eq!(
        acct.secret_str(),
        "KxT5rPzYPLrxcgdtx9pjAWijtV7ZcWXyBM8Au6JM8hTy6p1uj7AH"
    );
}

/// A restored mnemonic reproduces the same address a standard wallet would (import round-trip).
#[test]
fn restore_is_deterministic() {
    let coin = hd::lookup("zec").unwrap();
    let a = hd::derive(ABANDON, "", coin, hd::Purpose::Bip44, 0, 0).unwrap();
    let b = hd::derive(ABANDON, "", coin, hd::Purpose::Bip44, 0, 0).unwrap();
    assert_eq!(a.address, b.address);
    assert_eq!(a.secret_str(), b.secret_str());
}
