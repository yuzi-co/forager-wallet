//! `bech32::verify` — the SegWit v0 / Taproot gate.
//!
//! `Some` from this function is what makes `detect_family` return `SegwitV0` or `Taproot`, so the
//! properties worth pinning are about what a `Some` is allowed to claim: the HRP it hands back has
//! to be a real, lower-case prefix of the string it was given, because the caller matches that HRP
//! against the coin table.

#![no_main]

use forager_addr::codec::bech32;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    let Some((hrp, variant)) = bech32::verify(s) else {
        return;
    };

    // `verify` rejects mixed case, lower-cases what is left, finds the last `1`, and takes the HRP
    // from in front of it after checking that position is neither 0 nor within six characters of
    // the end. Every clause below is one of those checks read back out.
    let lower = s.to_ascii_lowercase();
    assert!(!hrp.is_empty(), "empty HRP accepted");
    assert_eq!(hrp, hrp.to_ascii_lowercase(), "HRP is not lower-cased");
    assert!(
        lower.starts_with(&hrp),
        "HRP {hrp:?} is not a prefix of {lower:?}"
    );
    // Separator plus the six-character checksum.
    assert!(
        lower.len() >= hrp.len() + 7,
        "accepted a string with no room for a checksum"
    );

    // BIP173 "Bech32" bounds a bech32 string at 90 characters and its HRP at 1 to 83 US-ASCII
    // characters, each in the range [33-126]. `verify` enforces the total length and the character
    // range directly; the HRP's 83-character ceiling then follows from those two plus the check
    // above, so asserting it here tests the arithmetic rather than restating a check. All three
    // were missing until the BIPs' invalid vectors were asserted, and the out-of-range-HRP and
    // over-length vectors verified: their checksums were computed over exactly the bytes the BIP
    // forbids, so no amount of polymod can notice — only an explicit rule can.
    assert!(
        lower.len() <= 90,
        "accepted a string longer than 90 characters"
    );
    assert!(hrp.len() <= 83, "accepted an HRP longer than 83 characters");
    assert!(
        hrp.bytes().all(|b| (33..=126).contains(&b)),
        "HRP {hrp:?} has a character outside the BIP173 range [33-126]"
    );

    // A string `verify` accepted is single-case by construction — the mixed-case guard is the first
    // thing it does — and `verify` lower-cases internally before touching anything else. So
    // lower-casing an accepted string cannot change what it computes. (The converse does not hold:
    // lower-casing a *rejected* mixed-case string can turn it into a valid address, which is why
    // this is asserted in one direction only.)
    assert_eq!(
        bech32::verify(&lower),
        Some((hrp, variant)),
        "case normalisation changed the result"
    );
});
