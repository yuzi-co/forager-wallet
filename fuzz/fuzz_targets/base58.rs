//! `base58::decode` and `base58::decode_check`.
//!
//! The riskiest decoder in the crate: it is the only one that runs bignum arithmetic over untrusted
//! input, and `decode_check` is what `detect_family` leans on to tell a real P2PKH address from a
//! lookalike, so a wrong answer here misroutes a payout rather than merely mislabelling it.
//!
//! Note on running this one: `decode` is superlinear in the input length (one bignum multiply per
//! character, against a number that grows with the input), so a long input is slow by construction
//! rather than by bug. Run it with `-max_len=256` — see `fuzz/README.md`.

#![no_main]

use forager_addr::codec::base58;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    let decoded = base58::decode(s);

    if let Some(payload) = base58::decode_check(s) {
        // `decode_check` begins by calling `decode` with `?`, requires at least five bytes, and
        // splits the trailing four off as the checksum. So anything it accepts must also decode,
        // and the payload it returns is exactly that decode output minus its last four bytes.
        // Straight from the control flow — the strongest of the invariants here.
        let raw = decoded
            .clone()
            .expect("decode_check accepted a string that decode rejected");
        assert_eq!(
            raw.len(),
            payload.len() + 4,
            "checksum is not four bytes wide"
        );
        assert!(raw.starts_with(&payload), "payload is not a prefix of raw");
    }

    let Some(raw) = decoded else {
        return;
    };

    // base58 encoding is canonical, so decode/encode is an exact round trip:
    //
    // * `decode` counts leading `1`s and emits that many leading `0x00` bytes; `encode` counts
    //   leading `0x00` bytes and emits that many leading `1`s. Same count both ways.
    // * The remaining characters accumulate into a `BigUint`. A non-zero `BigUint`'s `to_bytes_be`
    //   has no leading zero byte and its base58 expansion has no leading zero *digit*, and the
    //   input's first non-`1` character is by definition not the zero digit — so neither side can
    //   gain or lose a leading symbol.
    // * Zero is handled identically at both ends: `decode` appends nothing, `encode` pushes
    //   nothing, and the empty string round-trips to the empty vector.
    //
    // If this ever fires it is a real defect, not a mis-stated property.
    assert_eq!(
        base58::encode(&raw),
        s,
        "base58 decode/encode is not a round trip"
    );
});
