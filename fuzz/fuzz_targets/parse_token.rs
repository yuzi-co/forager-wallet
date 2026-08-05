//! `coins::parse_token` — the `family:params` custom-coin grammar.
//!
//! This is the escape hatch that lets a user drive a KAT-gated encoder with hand-supplied bytes, so
//! its failure mode is not a crash but a *silent acceptance*: a token that parses into parameters
//! the user did not mean mints a valid-looking address that misdirects the payout. The assertions
//! below are therefore about what an `Ok` is allowed to say about the token it came from.
//!
//! **This target leaks memory by design of the API under test.** Every successful parse calls
//! `Box::leak` on the ticker, the name and the version prefix — bounded in the one-shot CLI it was
//! written for, unbounded in a fuzzing loop. Run it with `-detect_leaks=0` and an `-rss_limit_mb`;
//! see `fuzz/README.md`.

#![no_main]

use forager_addr::coins;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    let Ok(spec) = coins::parse_token(s) else {
        // The error path is the interesting one for coverage; there is nothing to assert about a
        // `String` message beyond it having been produced without panicking.
        return;
    };

    // The spec carries the token verbatim as its ticker, so a later `lookup` or log line names what
    // the user typed rather than a normalised rewrite of it.
    assert_eq!(spec.ticker, s, "ticker is not the token it was parsed from");

    // A runtime token names no chain, so no SLIP-44 coin type is knowable and HD must never be
    // offered for one. `parse_token` hard-codes `None`; this pins that it stays hard-coded.
    assert!(spec.hd_slip44.is_none(), "a runtime token offered HD");

    // Acceptance implies the token split on a `:` whose left side is a family the grammar table
    // carries — the lookup that rejects everything else is the first thing `parse_token` does. This
    // is the property that keeps the grammar table the single source of truth: a family reachable
    // by parsing but absent from `TOKEN_GRAMMAR` would be invisible to `forager wallet list`.
    let (family, _) = s
        .split_once(':')
        .expect("accepted a token with no ':' separator");
    assert!(
        coins::TOKEN_GRAMMAR.iter().any(|g| g.family == family),
        "accepted family {family:?}, which the grammar does not list"
    );

    // `family()` is derived from `params`, never stored. Exercise it: the whole point of deriving it
    // is that a token cannot claim one family while encoding another.
    let _ = spec.family();
});
