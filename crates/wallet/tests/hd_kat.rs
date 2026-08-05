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
//! Anchor (b) used to be an *out-of-band* claim — the oracle had been checked against BIP32 vector
//! 1 during development, but nothing in the repository re-asserted it.  It is now asserted here,
//! together with vectors 2, 3 and 4, so the claim the rest of this file leans on is checked by
//! `cargo test` rather than by a comment.  See `bip32_official_test_vectors` below for exactly what
//! that does and does not prove, and for why vector 5 is *not* asserted (see the section comment
//! above `bip32_vector_1_reproduces_the_published_extended_keys`).
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

// ---- Anchor #2: the official BIP-32 test vectors ----
//
// Source for every `xprv`/`xpub` literal in this section: bitcoin/bips, `bip-0032.mediawiki`,
// section "Test Vectors".  Nothing here was computed by this repository or by any oracle it uses.
//
// What this section pins, and what it does not.  `hd::derive` delegates master-key generation and
// CKDpriv to the `bip32` crate (see the "Provenance" section of `hd.rs`), so these vectors exercise
// exactly the code path every per-coin KAT below runs through — but none of the arithmetic they
// cover was written here.  They are not a tautology: the expected strings come from the BIP-32
// document, which predates and is independent of both this crate and the `bip32` crate, so the
// value being checked was not produced by the code doing the checking.  Their job is to keep the
// delegation honest.  `bip32` ships its own copy of these vectors, but that copy tests `bip32`'s
// default configuration, not the feature set this workspace selects, and it would vanish the moment
// the dependency were swapped or vendored — while every per-coin expectation below would silently
// keep assuming BIP32 derivation is correct.
//
// Vectors 3 and 4 are the ones that catch real bugs: both exist because a derived private key can
// have a leading zero byte, and an implementation that carries keys as big integers rather than
// fixed-width 32-byte strings passes vector 1 and fails these.
// `a_leading_zero_private_key_keeps_its_zero_byte_through_this_crates_wif_encoder` carries that
// edge case across the boundary into code this crate does own.
//
// Vector 5 — a list of invalid extended keys that MUST be rejected — is deliberately NOT asserted.
// It exercises an extended-key *parser*, and this crate has none: `hd::derive` only ever runs
// mnemonic -> seed -> child key -> address, and no `xprv`/`xpub` string is parsed, serialized, or
// accepted from a user anywhere in `forager-wallet`.  The only parser those strings could be aimed
// at is `bip32::XPrv::from_str`, a dependency entry point this crate never calls; asserting it
// would pin behaviour no shipped code path can reach, and adding an importer purely to have
// something to reject would be inventing API surface rather than testing it.  If xprv import is
// ever added, vector 5 is the test to add alongside it.

/// Decode a lowercase hex literal.  Test-local: the crate's own hex decoder is `pub(crate)`.
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex literal"))
        .collect()
}

/// One published chain of a BIP-32 test vector: derivation path, `xprv`, `xpub`.
struct Chain(&'static str, &'static str, &'static str);

/// Assert every published chain of one BIP-32 vector, starting from that vector's raw seed.
///
/// Both directions are checked at each node: the private serialization and the `xpub` derived from
/// it.  A wrong chain code shows up in the `xpub` even when the private scalar happens to be right.
fn check_bip32_vector(vector: &str, seed_hex: &str, chains: &[Chain]) {
    let seed = unhex(seed_hex);
    for Chain(path, xprv, xpub) in chains {
        let parsed: bip32::DerivationPath = path.parse().expect("BIP-32 path literal");
        let key = bip32::XPrv::derive_from_path(&seed, &parsed)
            .unwrap_or_else(|e| panic!("{vector} {path}: {e}"));
        assert_eq!(
            key.to_string(bip32::Prefix::XPRV).as_str(),
            *xprv,
            "{vector} {path} xprv"
        );
        assert_eq!(
            key.public_key().to_string(bip32::Prefix::XPUB),
            *xpub,
            "{vector} {path} xpub"
        );
    }
}

/// BIP-32 vector 1 (seed `000102…0f`) — the anchor this file's module docs have always claimed,
/// now actually asserted. Covers hardened and non-hardened CKDpriv and a large child index.
#[test]
fn bip32_vector_1_reproduces_the_published_extended_keys() {
    check_bip32_vector(
        "BIP-32 vector 1",
        "000102030405060708090a0b0c0d0e0f",
        &[
            Chain(
                "m",
                "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
                "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
            ),
            Chain(
                "m/0'",
                "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
                "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
            ),
            Chain(
                "m/0'/1",
                "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
                "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
            ),
            Chain(
                "m/0'/1/2'",
                "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
                "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
            ),
            Chain(
                "m/0'/1/2'/2",
                "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
                "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
            ),
            Chain(
                "m/0'/1/2'/2/1000000000",
                "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
                "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
            ),
        ],
    );
}

/// BIP-32 vector 2 (64-byte seed) — the hardened indices here sit at the very top of the range
/// (`2147483647'` = `0xffffffff`), so an off-by-one in the `0x80000000` hardening offset that
/// vector 1's small indices tolerate shows up as a wrong key.
#[test]
fn bip32_vector_2_reproduces_the_published_extended_keys() {
    check_bip32_vector(
        "BIP-32 vector 2",
        "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2\
         9f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
        &[
            Chain(
                "m",
                "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
                "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
            ),
            Chain(
                "m/0",
                "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
                "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
            ),
            Chain(
                "m/0/2147483647'",
                "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
                "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
            ),
            Chain(
                "m/0/2147483647'/1",
                "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
                "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon",
            ),
            Chain(
                "m/0/2147483647'/1/2147483646'",
                "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
                "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
            ),
            Chain(
                "m/0/2147483647'/1/2147483646'/2",
                "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j",
                "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt",
            ),
        ],
    );
}

/// BIP-32 vector 3 — published specifically to pin **retention of leading zeros** (the BIP cites
/// bitpay/bitcore-lib#47 and iancoleman/bip39#58, both bugs where a 32-byte key whose first byte is
/// `0x00` was carried as a 31-byte integer). The master private key here begins `0x00`.
#[test]
fn bip32_vector_3_retains_a_leading_zero_in_the_master_private_key() {
    check_bip32_vector(
        "BIP-32 vector 3",
        "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4ac\
         ba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
        &[
            Chain(
                "m",
                "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6",
                "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13",
            ),
            Chain(
                "m/0'",
                "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L",
                "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y",
            ),
        ],
    );
}

/// BIP-32 vector 4 — the same leading-zero concern, but reached through *hardened* derivation
/// (the BIP cites btcsuite/btcutil#172). Here it is the child at `m/0'` whose private key begins
/// `0x00`, so hardened CKDpriv must feed the parent key in zero-padded to 32 bytes.
#[test]
fn bip32_vector_4_retains_leading_zeros_under_hardened_derivation() {
    check_bip32_vector(
        "BIP-32 vector 4",
        "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678",
        &[
            Chain(
                "m",
                "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv",
                "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa",
            ),
            Chain(
                "m/0'",
                "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G",
                "xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m",
            ),
            Chain(
                "m/0'/1'",
                "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1",
                "xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt",
            ),
        ],
    );
}

/// The leading-zero edge case that vectors 3 and 4 exist for must survive the hand-off from the
/// BIP32 layer into **this crate's own** encoders — the step the vectors above cannot reach.
///
/// `hd::derive` takes the child key as `PrivateKey::to_bytes` (a fixed `[u8; 32]`) and hands it
/// straight to `secret::wif`, so if either end treated the scalar as a big integer the `0x00` would
/// vanish and the exported WIF would be a 51-character key for a *different*, 31-byte secret — an
/// address the user could never spend from. Both keys below start with `0x00`.
///
/// Provenance of the literals. The private keys are not published as hex in BIP-32, only inside the
/// vector's `xprv`; each was recovered by base58check-decoding the exact `xprv` string asserted
/// above (bytes 46..78 of the payload) with an independent Python oracle, and the test re-derives
/// them here so a wrong constant cannot pass. The WIFs were computed by that same independent
/// oracle as `base58check(0x80 ‖ key ‖ 0x01)` (Bitcoin compressed WIF) and separately reproduced by
/// this repository's own generator (`forager-wallet restore <key-hex> --coin btc`) — they agree.
#[test]
fn a_leading_zero_private_key_keeps_its_zero_byte_through_this_crates_wif_encoder() {
    // (vector label, seed, path, private key hex, expected mainnet compressed WIF)
    let cases = [
        (
            "BIP-32 vector 3 m",
            "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4ac\
             ba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
            "m",
            "00ddb80b067e0d4993197fe10f2657a844a384589847602d56f0c629c81aae32",
            "KwFPqAq9SKx1sPg15Qk56mqkHwrfGPuywtLUxoWPkiTSBoxCs8am",
        ),
        (
            "BIP-32 vector 4 m/0'",
            "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678",
            "m/0'",
            "00d948e9261e41362a688b916f297121ba6bfb2274a3575ac0e456551dfd7f7e",
            "KwFMsuZ3pmk7ebtbTiPirTpdcPkS6wvnSazU3bvixwiCw1bNQLhG",
        ),
    ];

    for (label, seed_hex, path, key_hex, wif) in cases {
        let parsed: bip32::DerivationPath = path.parse().unwrap();
        let xprv = bip32::XPrv::derive_from_path(unhex(seed_hex), &parsed).unwrap();
        // Fully-qualified to pick the `bip32` trait method (`[u8; 32]`) — exactly the call
        // `hd::derive` makes to obtain the scalar it encodes.
        let key: [u8; 32] = bip32::PrivateKey::to_bytes(xprv.private_key());
        assert_eq!(key[0], 0x00, "{label} must be the leading-zero case");
        assert_eq!(hex(&key), key_hex, "{label} private key");

        let w =
            forager_wallet::address_from_secret("btc", key_hex, forager_wallet::Network::Mainnet)
                .unwrap();
        match &w.secret_std {
            forager_wallet::SecretStd::Wif(s) => {
                assert_eq!(s, wif, "{label} wif");
                // A dropped leading zero shortens the base58check payload from 34 bytes to 33 and
                // the WIF from 52 characters to 51 (and flips the `K`/`L` prefix to `5`), so the
                // length is an independent witness that the zero byte was carried through.
                assert_eq!(s.len(), 52, "{label} wif length");
                assert!(s.starts_with('K') || s.starts_with('L'), "{label}");
            }
            other => panic!("{label}: expected a WIF, got {other:?}"),
        }
    }
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
