//! The primary entry point: `detect_family`, and `check` layered on top of it.
//!
//! This is the surface the closed miner actually calls, on a payout address the user typed into a
//! config file. `detect_family` fans out into every decoder the crate owns — bech32, base58check,
//! CashAddr prefix matching, CryptoNote block-base58 — so one target here exercises all of them in
//! the combination that reaches production, rather than each in isolation.

#![no_main]

use forager_addr::{check, detect_family, family_name, Family, Verdict};
use libfuzzer_sys::fuzz_target;

/// Every family `check` can be asked about. Listed rather than iterated because `Family` is a plain
/// enum with no `IntoIterator`; a variant added without a line here would silently stop being
/// fuzzed, which the `family_name` call below at least keeps honest at compile time.
const FAMILIES: [Family; 9] = [
    Family::P2pkh,
    Family::SegwitV0,
    Family::Taproot,
    Family::Ethereum,
    Family::CryptoNote,
    Family::KaspaAddr,
    Family::Ergo,
    Family::Alephium,
    Family::Xdag,
];

fuzz_target!(|data: &[u8]| {
    // Taking the bytes as a string rather than via `Arbitrary` keeps a corpus file byte-identical
    // to the address it seeds, so the checked-in seeds mean what they look like.
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    let detected = detect_family(s);

    // `detect_family` trims its argument on the first line and never consults the untrimmed string
    // again, so surrounding whitespace cannot change the answer. Cheap, and it would catch a future
    // rewrite that re-reads `addr` instead of the trimmed `a`.
    assert_eq!(
        detected,
        detect_family(s.trim()),
        "surrounding whitespace changed the verdict for {s:?}"
    );

    if let Some(f) = detected {
        // Total over the enum, but calling it keeps the arm on the fuzzed path.
        let _ = family_name(f);
    }

    for expected in FAMILIES {
        let verdict = check(s, expected);
        match (detected, verdict) {
            // `check` is `detect_family` plus a verdict, nothing more: an address detection cannot
            // classify is `Unrecognized` for every expected family, and never anything else.
            (None, Verdict::Unrecognized) => {}
            // The converse: a classified address is never `Unrecognized`. `Ok` means the detected
            // family was accepted for the expected one.
            (Some(_), Verdict::Ok) => {}
            // A `Mismatch` must report back exactly what was detected and what was asked for —
            // this is the string a user sees in the warning, and a swapped pair would tell them to
            // fix the wrong end of the misconfiguration.
            (
                Some(d),
                Verdict::Mismatch {
                    detected: reported,
                    expected: asked,
                },
            ) => {
                assert_eq!(d, reported, "mismatch reported the wrong detected family");
                assert_eq!(
                    asked, expected,
                    "mismatch reported the wrong expected family"
                );
                // Family compatibility is reflexive (`detected == expected ||` …), so a family can
                // never mismatch against itself.
                assert_ne!(d, expected, "{d:?} mismatched against itself");
            }
            (d, v) => panic!("detect_family({s:?}) = {d:?} but check(_, {expected:?}) = {v:?}"),
        }
    }
});
