//! `hexbytes::decode` and `hexbytes::decode_n::<N>`.
//!
//! `hexbytes::hex32` is deliberately **not** fuzzed. It is documented to panic on malformed input —
//! it is a known-answer-test helper whose literals are fixed at compile time, and a panic is the
//! intended response to a typo in a vector. Fuzzing it would rediscover that documented panic and
//! nothing else.

#![no_main]

use forager_addr::hexbytes;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    let decoded = hexbytes::decode(s);

    if let Some(bytes) = &decoded {
        // `decode` rejects an odd byte length up front and then consumes exactly two bytes per
        // output byte via `str::get`, which returns `None` rather than slicing a multi-byte
        // character in half. So an accepted string is all-ASCII and exactly twice as long.
        assert_eq!(
            bytes.len() * 2,
            s.len(),
            "decoded length does not match the input"
        );
    }

    // `decode_n::<N>` is literally `decode(s)?.try_into().ok()`, so it must succeed exactly when
    // `decode` succeeds with N bytes, and return the same bytes. Two widths, because those are the
    // two the crate actually uses: a 20-byte HASH160 and a 32-byte key.
    check_width::<20>(s, decoded.as_deref());
    check_width::<32>(s, decoded.as_deref());

    // Deliberately NOT asserted: that `encode(decode(s)) == s.to_ascii_lowercase()`. It is false.
    // `decode` delegates each pair to `u8::from_str_radix(_, 16)`, which accepts a leading `+`, so
    // `decode("+f")` is `Some([0x0f])` and re-encoding yields `"0f"`. Asserting the round trip here
    // would turn this target into a machine for rediscovering that one quirk.
});

fn check_width<const N: usize>(s: &str, decoded: Option<&[u8]>) {
    let n = hexbytes::decode_n::<N>(s);
    assert_eq!(
        n.is_some(),
        decoded.is_some_and(|b| b.len() == N),
        "decode_n::<{N}> disagrees with decode about {s:?}"
    );
    if let Some(bytes) = n {
        assert_eq!(
            Some(bytes.as_slice()),
            decoded,
            "decode_n::<{N}> returned different bytes than decode"
        );
    }
}
