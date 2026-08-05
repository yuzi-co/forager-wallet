//! Detection tests that need the *generator*.
//!
//! These live here rather than beside the rest of the detection tests in `validate.rs` because
//! they mint their inputs with `address_from_secret`. Address classification is moving into the
//! `forager-addr` crate, which deliberately depends on no curve, entropy or mnemonic code, so a
//! test that calls the generator cannot travel with it. See
//! `the repository README`.

use forager_wallet::{check, detect_family, Family, Network, Verdict};

/// A CryptoNote fork with a multi-byte network prefix is detected as CryptoNote — the case a
/// first-character `4`/`8` test could not see.  The addresses are minted from the coin rows
/// themselves, so this cannot drift from what the generator emits.
#[test]
fn detects_multibyte_prefix_cryptonote_forks() {
    const PRIV1: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    for (ticker, tag) in [("zeph", "ZEPHYR"), ("sal", "SaLv")] {
        let w = forager_wallet::address_from_secret(ticker, PRIV1, Network::Mainnet).unwrap();
        assert!(w.address.starts_with(tag), "{ticker}: {}", w.address);
        assert_eq!(
            detect_family(&w.address),
            Some(Family::CryptoNote),
            "{ticker}: {}",
            w.address
        );
    }
}

/// Every Ergo address the generator emits is detected as `Family::Ergo`, on both networks.
///
/// Detection used to answer this family from shape alone — a leading `9`, a 40..=60 length window
/// and the base58 charset — which had two consequences. A corrupted mainnet address was still
/// answered `Ergo`, and a *correct testnet* address was answered nothing at all, because testnet's
/// prefix byte is 0x11 and renders `3…`. The arm now decodes and verifies the Blake2b-256 checksum,
/// so both halves are closed by the same change; this is the generator-side counterpart, minting
/// its inputs through the real derivation path rather than hand-assembling them.
#[test]
fn every_generated_ergo_address_round_trips_through_detection() {
    for network in [Network::Mainnet, Network::Testnet] {
        for i in 1u32..=32 {
            let secret = format!("{i:064x}");
            let w = forager_wallet::address_from_secret("erg", &secret, network).unwrap();
            assert_eq!(
                detect_family(&w.address),
                Some(Family::Ergo),
                "{network:?} key {secret}: {}",
                w.address
            );
            assert_eq!(
                check(&w.address, Family::Ergo),
                Verdict::Ok,
                "{}",
                w.address
            );

            // One flipped character in the middle: same length, same leading character, same
            // charset. Only the checksum separates it from the address above.
            let mut bytes = w.address.clone().into_bytes();
            let i = bytes.len() / 2;
            bytes[i] = if bytes[i] == b'A' { b'B' } else { b'A' };
            let bad = String::from_utf8(bytes).unwrap();
            assert_ne!(detect_family(&bad), Some(Family::Ergo), "{bad}");
        }
    }

    // The two networks really do render differently, so the loop above is not silently testing
    // mainnet twice.
    let main = forager_wallet::address_from_secret("erg", &format!("{:064x}", 1), Network::Mainnet)
        .unwrap()
        .address;
    let test = forager_wallet::address_from_secret("erg", &format!("{:064x}", 1), Network::Testnet)
        .unwrap()
        .address;
    assert!(main.starts_with('9'), "{main}");
    assert!(test.starts_with('3'), "{test}");
}

/// Every XDAG address the generator emits is detected as `Family::Xdag`.
///
/// XDAG is `Base58Check(HASH160(compressed_pubkey))` with **no** version byte, so its payload is a
/// bare 20-byte hash160 while a P2PKH payload is `version ‖ hash160`, 21 or 22 bytes. Detection
/// used to discriminate on the leading bytes alone and ignore the length, which produced both
/// halves of one bug: no XDAG arm existed at all, and ~5% of XDAG addresses — those whose hash160
/// happened to open with one of the 13 one-byte version prefixes the coin table models, 13/256 —
/// were answered `P2pkh` instead, warning a user off a correctly configured payout address.
///
/// The sweep is what makes this the generator-side counterpart to `validate.rs`'s synthetic
/// regression test: 64 keys over an effectively uniform leading byte will, at 13/256 each, contain
/// several of the collisions on average, and every one of them is minted by the real derivation
/// path rather than hand-assembled, so this cannot drift from what the generator emits.
#[test]
fn every_generated_xdag_address_round_trips_through_detection() {
    // The xdagj `SampleKeys.java` KAT key — the same vector `families/xdag.rs` pins the address
    // string against, so a change to either side shows up here.
    let w = forager_wallet::address_from_secret(
        "xdag",
        "a392604efc2fad9c0b3da43b5f698a2e3f270f170d859912be0d54742275c5f6",
        Network::Mainnet,
    )
    .unwrap();
    assert_eq!(w.address, "N3RC53vbaDNrziTdWmctBEeQ4fo38moXu");
    assert_eq!(detect_family(&w.address), Some(Family::Xdag));

    for i in 1u32..=64 {
        let secret = format!("{i:064x}");
        let w = forager_wallet::address_from_secret("xdag", &secret, Network::Mainnet).unwrap();
        assert_eq!(
            detect_family(&w.address),
            Some(Family::Xdag),
            "key {secret}: {}",
            w.address
        );
        assert_eq!(
            check(&w.address, Family::Xdag),
            Verdict::Ok,
            "{}",
            w.address
        );
    }
}

/// Every KAD address the generator emits classifies as the form the live chain issues.
///
/// Kadikama is the coin table's one row where the chain params and the network's practice
/// disagree: Kadikama Core activates SegWit at height 0 and Taproot from genesis with
/// `bech32_hrp = "kad"`, yet the network issues base58 `K…` addresses — the project's own site
/// names "K-addresses" as a defining property, and every miner address on the official pool
/// decodes to version 45. The row resolves that in favour of P2PKH so a generated payout address
/// is one a pool credits. This asserts the two halves of that decision still agree: the generator
/// emits the base58 form, and detection answers `P2pkh` for it.
///
/// Both networks, because version 45 (mainnet) and 46 (testnet) render adjacent base58 ranges that
/// both open with `K` — a leading character cannot tell them apart, so a swapped pair of version
/// bytes would survive any test that only looked at the first character.
#[test]
fn every_generated_kad_address_round_trips_through_detection() {
    // The privkey=1 vector `lib.rs` pins the address string against, so a change to either side
    // shows up here.
    const PRIV1: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    let w = forager_wallet::address_from_secret("kad", PRIV1, Network::Mainnet).unwrap();
    assert_eq!(w.address, "KHtQs3JaKBiBwpTtKf6feVfPSp3131uG3M");

    for network in [Network::Mainnet, Network::Testnet] {
        for i in 1u32..=32 {
            let secret = format!("{i:064x}");
            let w = forager_wallet::address_from_secret("kad", &secret, network).unwrap();
            assert!(w.address.starts_with('K'), "key {secret}: {}", w.address);
            assert_eq!(w.address.len(), 34, "key {secret}: {}", w.address);
            assert_eq!(
                detect_family(&w.address),
                Some(Family::P2pkh),
                "key {secret}: {}",
                w.address
            );
            assert_eq!(
                check(&w.address, Family::P2pkh),
                Verdict::Ok,
                "{}",
                w.address
            );
        }
    }
}
