//! Known-answer tests for the BIP39/BIP44 HD generator ([`forager_wallet::hd`]).
//!
//! **Non-circularity.** The expected address/WIF constants below were produced by an *independent*
//! reference oracle (a from-scratch Python implementation of PBKDF2-HMAC-SHA512 seed derivation,
//! BIP32 CKDpriv, secp256k1, and base58check) that was itself validated against two canonical,
//! published vectors before it was trusted: (a) the BIP39 seed for the 24-word all-zero-entropy
//! mnemonic + passphrase `"TREZOR"`, taken verbatim from the official `trezor/python-mnemonic`
//! `vectors.json` and re-asserted here directly, through both this crate's `bip39` and
//! `bip32::Mnemonic::to_seed`, which must agree; and (b) BIP32
//! test-vector 1 (seed `000102…0f` → master key/chain code).
//!
//! Version bytes come from each coin's `chainparams.cpp` (`base58Prefixes[PUBKEY_ADDRESS]` /
//! `[SECRET_KEY]`, mainnet); SLIP-44 coin types from `slip-0044.md`.  `forager_wallet::hd::derive` (which
//! routes through the `bip32` crate) is a third, independent stack; agreement across all three
//! anchors the values.
//!
//! Every per-coin vector below uses the 24-word all-zero-entropy mnemonic (`abandon` ×23 + `art`).
//! They were written when the mnemonic→seed step was delegated to `bip32`, which parses 256-bit
//! phrases only, and they are **unchanged** — these are addresses users may already hold, so the
//! clean-room BIP39 swap had to move exactly none of them.
//!
//! What the swap *added* is the second half of this file: the BIP84 and BIP86 test vectors, which
//! the BIP texts publish against the **12-word** mnemonic and which therefore could never be
//! asserted here before. Those come straight from `bitcoin/bips` — `bip-0084.mediawiki` and
//! `bip-0086.mediawiki`, "Test vectors" section — which makes them the strongest anchors in the
//! file: not this crate's output, not the oracle's, but the specification's own.

use forager_wallet::{bip39, hd};

/// Canonical BIP39 24-word all-zero-entropy mnemonic (`abandon` ×23 + `art`).
const ABANDON: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

/// The 12-word all-zero-entropy mnemonic (`abandon` ×11 + `about`) — the phrase BIP84 and BIP86
/// publish their test vectors against, and the length `bip32::Mnemonic` rejects outright.
const ABANDON_12: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Anchor #1: the mnemonic->seed step reproduces the official Trezor BIP39 vector.
///
/// Asserted through `forager_wallet::bip39` — the implementation `hd::derive` actually calls —
/// and then cross-checked against `bip32`'s, which is what the per-coin constants below were
/// originally produced under. Both must equal the published seed; if they ever diverge, every
/// address in this file has silently moved.
#[test]
fn bip39_canonical_seed_vector() {
    const PUBLISHED: &str = "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd309717\
                             0af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8";
    let ours = bip39::seed(ABANDON, "TREZOR").expect("the canonical phrase must parse");
    assert_eq!(hex(ours.as_bytes()), PUBLISHED);

    let theirs = bip32::Mnemonic::new(ABANDON, Default::default())
        .unwrap()
        .to_seed("TREZOR");
    assert_eq!(hex(theirs.as_bytes()), PUBLISHED);
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

// ===========================================================================
// The BIP84 / BIP86 published vectors, from the 12-word mnemonic.
//
// Everything above this line predates the clean-room BIP39 and is byte-for-byte unchanged by it.
// Everything below was impossible before: `bip32::Mnemonic` accepts 256-bit phrases only, and both
// BIPs publish their vectors against the 128-bit `abandon ×11 about` phrase, so the specification's
// own answers had never been asserted against this crate.
//
// Provenance: `bitcoin/bips`, `bip-0084.mediawiki` and `bip-0086.mediawiki`, "Test vectors".
// Transcribed from the BIP texts, not from this crate's output and not from the reference oracle.
// ===========================================================================

/// Derive from the 12-word BIP84/BIP86 mnemonic at `m/<purpose>'/0'/0'/0/<index>` and assert the
/// address the BIP publishes.
///
/// Note the fixed `0` change level: `hd::derive` derives the external (receive) chain only, so the
/// published *change* vectors — `m/84'/0'/0'/1/0` and `m/86'/0'/0'/1/0` — are not reachable through
/// the public API and are deliberately not asserted here rather than half-asserted through some
/// other path. The receive chain is what this tool hands out, and the address_index level is
/// covered below at both 0 and 1.
fn check_spec_vector(purpose: hd::Purpose, index: u32, expect_addr: &str) -> String {
    let btc = hd::lookup("btc").expect("btc is HD-capable");
    let acct = hd::derive(ABANDON_12, "", btc, purpose, 0, index)
        .expect("the 12-word spec mnemonic must derive");
    assert_eq!(
        acct.path,
        format!("m/{}'/0'/0'/0/{index}", purpose.number()),
        "{purpose} index {index} path"
    );
    assert_eq!(acct.address, expect_addr, "{purpose} index {index} address");
    acct.secret_str().to_string()
}

/// BIP84 `m/84'/0'/0'/0/0` — the first receiving address, with the WIF the BIP publishes for it.
#[test]
fn bip84_spec_vector_first_receiving_address() {
    let wif = check_spec_vector(
        hd::Purpose::Bip84,
        0,
        "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
    );
    assert_eq!(wif, "KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d");
}

/// BIP84 `m/84'/0'/0'/0/1` — the second receiving address. The address_index level must actually
/// advance, or a wallet deriving a fresh address per payment would reuse the first one.
#[test]
fn bip84_spec_vector_second_receiving_address() {
    let wif = check_spec_vector(
        hd::Purpose::Bip84,
        1,
        "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g",
    );
    assert_eq!(wif, "Kxpf5b8p3qX56DKEe5NqWbNUP9MnqoRFzZwHRtsFqhzuvUJsYZCy");
}

/// BIP86 `m/86'/0'/0'/0/0` — **and the loop this closes.**
///
/// `src/lib.rs` already pins `BIP86_ADDRESS` as
/// `bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr`, but it gets there from the
/// BIP's published `internal_key` hex, hardcoded: it proves the Taproot tweak and the bech32m
/// encoder, and nothing before them. The mnemonic → seed → BIP32 path → x-only key → tweak →
/// bech32m chain had never been exercised end to end in this repo, because its published starting
/// point is a 12-word phrase the code could not parse.
///
/// This test starts from that phrase and arrives at the same string. Reproducing it means the
/// clean-room BIP39, the `bip32` CKDpriv derivation, the Taproot tweak and the bech32m encoder all
/// agree with the specification *and with each other* — four independently sourced pieces meeting
/// at one 62-character answer that no one of them could have faked.
#[test]
fn bip86_spec_vector_first_receiving_address_closes_the_loop() {
    check_spec_vector(
        hd::Purpose::Bip86,
        0,
        "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
    );
}

/// BIP86 `m/86'/0'/0'/0/1` — the second receiving address.
///
/// The BIP publishes no WIF for its Taproot rows (it gives `xprv`/`internal_key`/`output_key`), so
/// only the address is asserted. Asserting a WIF here would mean inventing one.
#[test]
fn bip86_spec_vector_second_receiving_address() {
    check_spec_vector(
        hd::Purpose::Bip86,
        1,
        "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh",
    );
}

// ---------------------------------------------------------------------------
// Defect 1 — short phrases, at the integration layer.
// ---------------------------------------------------------------------------

/// **The regression.** A 12-word phrase validates and derives through `hd`.
///
/// `bip32 0.5.3`'s `Phrase::new` requires `entropy.len() == KEY_SIZE + 1` with `KEY_SIZE == 32`,
/// so it rejects every 128-bit phrase — the most common length in circulation — and `hd` then
/// reported it to the user as "invalid BIP39 mnemonic (check the words, length, and checksum)".
/// The words, length and checksum were all fine.
#[test]
fn twelve_word_mnemonic_validates_and_derives() {
    assert_eq!(ABANDON_12.split_whitespace().count(), 12);
    hd::validate_mnemonic(ABANDON_12).expect("a valid 12-word phrase must validate");

    let btc = hd::lookup("btc").unwrap();
    let acct = hd::derive(ABANDON_12, "", btc, hd::Purpose::Bip84, 0, 0)
        .expect("a valid 12-word phrase must derive");
    assert_eq!(acct.address, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");

    // Pin the upstream behaviour this works around, so the test keeps explaining itself.
    assert!(
        bip32::Mnemonic::new(ABANDON_12, Default::default()).is_err(),
        "if bip32 ever accepts 12-word phrases, this regression's cause is gone"
    );
}

/// The other newly-legal lengths — 15, 18 and 21 words — validate too.
///
/// The official `trezor/python-mnemonic` file publishes no 15- or 21-word rows, so there is no
/// upstream phrase to quote for those two. Rather than invent one, each phrase is *encoded* from
/// fixed entropy by `bip39::entropy_to_phrase` — the encoder that `tests/bip39_kat.rs` locks
/// against all 24 official rows — and then fed back through the `hd` boundary this file is about.
/// What is under test here is that `hd` accepts the length, which is exactly what was broken.
#[test]
fn fifteen_eighteen_and_twentyone_word_phrases_validate() {
    for (i, &entropy_len) in bip39::ENTROPY_LENGTHS.iter().enumerate() {
        let words = bip39::WORD_COUNTS[i];
        if !matches!(words, 15 | 18 | 21) {
            continue; // 12 and 24 have published vectors of their own, asserted elsewhere.
        }
        let phrase = bip39::entropy_to_phrase(&vec![0x5a; entropy_len]).expect("legal length");
        assert_eq!(phrase.split_whitespace().count(), words);
        hd::validate_mnemonic(&phrase).unwrap_or_else(|e| panic!("{words} words rejected: {e}"));

        // And a length that validates must also derive — accepting a phrase and then failing to
        // use it would be a worse bug than rejecting it.
        let btc = hd::lookup("btc").unwrap();
        hd::derive(&phrase, "", btc, hd::Purpose::Bip84, 0, 0)
            .unwrap_or_else(|e| panic!("{words} words failed to derive: {e}"));
    }
    // The 18-word length also has an official row; assert that one directly, so the coverage does
    // not rest entirely on this crate's own encoder.
    const OFFICIAL_18: &str = "gravity machine north sort system female filter attitude volume \
                               fold club stay feature office ecology stable narrow fog";
    assert_eq!(OFFICIAL_18.split_whitespace().count(), 18);
    hd::validate_mnemonic(OFFICIAL_18).expect("an official 18-word row must validate");
}

// ---------------------------------------------------------------------------
// Defect 2 — NFKD passphrase normalization, at the integration layer.
// ---------------------------------------------------------------------------

/// The published non-ASCII passphrase from `bip32JP/bip32JP.github.io`'s `test_JP_BIP39.json`
/// (`㍍ガバヴァぱばぐゞちぢ十人十色`), in its composed form.
const NFKD_COMPOSED: &str = "\u{334d}\u{30ac}\u{30d0}\u{30f4}\u{30a1}\u{3071}\u{3070}\u{3050}\u{309e}\u{3061}\u{3062}\u{5341}\u{4eba}\u{5341}\u{8272}";

/// The same passphrase in NFKD normal form: U+334D `㍍` expands to the four katakana `メートル`,
/// and each voiced kana splits into base + U+3099/U+309A. 78 UTF-8 bytes against the composed
/// form's 45 — genuinely different byte strings.
const NFKD_DECOMPOSED: &str = "\u{30e1}\u{30fc}\u{30c8}\u{30eb}\u{30ab}\u{3099}\u{30cf}\u{3099}\u{30a6}\u{3099}\u{30a1}\u{306f}\u{309a}\u{306f}\u{3099}\u{304f}\u{3099}\u{309d}\u{3099}\u{3061}\u{3061}\u{3099}\u{5341}\u{4eba}\u{5341}\u{8272}";

/// **A non-ASCII `--passphrase` now derives the spec address, through `hd::derive`.**
///
/// BIP39 §"From mnemonic to seed" requires the PBKDF2 salt to be `"mnemonic" ‖ NFKD(passphrase)`.
/// `bip32 0.5.3`'s `to_seed` builds it as `format!("mnemonic{}", password).as_bytes()` — raw UTF-8,
/// no normalization — so a user who typed a non-ASCII passphrase got an address that no other
/// wallet reproduces, and funds sent there could not be recovered anywhere else.
///
/// There is no published vector for "English phrase + Japanese passphrase", so rather than invent
/// an expected address this asserts the property the spec mandates, using two strings whose
/// relationship is a fact about Unicode rather than a fact about this crate:
///
/// 1. the composed and decomposed forms must derive the **same** address (what NFKD means);
/// 2. that address must differ from the no-passphrase one (the passphrase reaches the salt at all);
/// 3. and — the falsifiable half — the *un-normalized* derivation must give a **different** key.
///    Point 3 is asserted against `bip32`'s own non-normalizing `to_seed` over the 24-word phrase
///    (the only length it parses), which is precisely the code path that was live before this
///    change. If normalization were silently dropped again, 1 would fail and 3 would stop failing.
#[test]
fn non_ascii_passphrase_is_nfkd_normalized_through_derive() {
    assert_ne!(NFKD_COMPOSED.as_bytes(), NFKD_DECOMPOSED.as_bytes());
    assert_eq!(NFKD_COMPOSED.len(), 45);
    assert_eq!(NFKD_DECOMPOSED.len(), 78);

    let btc = hd::lookup("btc").unwrap();
    let composed = hd::derive(ABANDON_12, NFKD_COMPOSED, btc, hd::Purpose::Bip84, 0, 0).unwrap();
    let decomposed =
        hd::derive(ABANDON_12, NFKD_DECOMPOSED, btc, hd::Purpose::Bip84, 0, 0).unwrap();
    let plain = hd::derive(ABANDON_12, "", btc, hd::Purpose::Bip84, 0, 0).unwrap();

    assert_eq!(
        composed.address, decomposed.address,
        "a passphrase and its NFKD normal form must derive the same address"
    );
    assert_eq!(
        composed.secret_str(),
        decomposed.secret_str(),
        "…and the same key, not just the same address"
    );
    assert_ne!(
        composed.address, plain.address,
        "the passphrase must reach PBKDF2's salt"
    );

    // Point 3: the old, un-normalized behaviour really does diverge. 24 words, because that is the
    // only length `bip32` will parse — which is why defect 2 could only ever be shown there.
    let unnormalized = bip32::Mnemonic::new(ABANDON, Default::default())
        .expect("bip32 parses 24-word phrases")
        .to_seed(NFKD_COMPOSED);
    let normalized = bip39::seed(ABANDON, NFKD_COMPOSED).expect("valid phrase");
    assert_ne!(
        hex(unnormalized.as_bytes()),
        hex(normalized.as_bytes()),
        "if these agree, the passphrase was not normalized and defect 2 is back"
    );

    // The corollary that makes this change safe: NFKD is the identity on ASCII, so no ASCII
    // passphrase moved. The TREZOR-passphrase address is pinned above in
    // `passphrase_changes_derivation`; re-assert it here as the direct counterpart.
    let ascii = hd::derive(ABANDON, "TREZOR", btc, hd::Purpose::Bip44, 0, 0).unwrap();
    assert_eq!(ascii.address, "12Wr5H8qyTZ3XwpwZDJDjdimS1doBoj19u");
}

// ---------------------------------------------------------------------------
// Error specificity — the user-facing product of the whole change.
// ---------------------------------------------------------------------------

/// A 13-word phrase is a word-*count* error that names the count, not a blanket rejection.
#[test]
fn thirteen_words_reports_the_word_count() {
    let phrase = vec!["abandon"; 13].join(" ");
    assert_eq!(
        hd::validate_mnemonic(&phrase),
        Err(hd::HdError::InvalidMnemonic(bip39::Bip39Error::WordCount {
            found: 13
        }))
    );

    let msg = hd::validate_mnemonic(&phrase).unwrap_err().to_string();
    assert!(msg.contains("13"), "must report the count found: {msg}");
    for legal in ["12", "15", "18", "21", "24"] {
        assert!(msg.contains(legal), "must list {legal}: {msg}");
    }

    // `derive` must surface the identical error — the specificity cannot survive validation only
    // to be flattened on the path that actually spends the phrase.
    let btc = hd::lookup("btc").unwrap();
    assert_eq!(
        hd::derive(&phrase, "", btc, hd::Purpose::Bip84, 0, 0).unwrap_err(),
        hd::HdError::InvalidMnemonic(bip39::Bip39Error::WordCount { found: 13 })
    );
}

/// One mistyped word out of twelve is named, with its 1-based position.
///
/// This is the message that matters most in practice: the user is holding a card with twelve words
/// on it and needs to know which one to look at. "check the words, length, and checksum" told them
/// to re-read all twelve.
#[test]
fn one_misspelled_word_is_named_with_its_position() {
    // `abandom` — one letter off `abandon`, in the 6th slot.
    let phrase = "abandon abandon abandon abandon abandon abandom \
                  abandon abandon abandon abandon abandon about";
    let expected = hd::HdError::InvalidMnemonic(bip39::Bip39Error::UnknownWord {
        word: "abandom".to_string(),
        position: 6,
    });
    assert_eq!(hd::validate_mnemonic(phrase), Err(expected));

    let msg = hd::validate_mnemonic(phrase).unwrap_err().to_string();
    assert!(msg.contains("abandom"), "must name the word: {msg}");
    assert!(msg.contains('6'), "must give the position: {msg}");

    // A phrase whose every word is legal but whose checksum fails is a *different*, equally
    // specific error — not the same message with a different word in it.
    let bad_checksum = "abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon abandon";
    assert_eq!(
        hd::validate_mnemonic(bad_checksum),
        Err(hd::HdError::InvalidMnemonic(bip39::Bip39Error::Checksum))
    );

    // And the BIP39 cause is reachable through the standard `source` chain, for a caller that
    // wants to branch on it rather than reformat the string.
    let err = hd::validate_mnemonic(phrase).unwrap_err();
    assert!(std::error::Error::source(&err).is_some());
}
