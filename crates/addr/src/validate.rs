//! Payout-address **detection** — the inverse of derivation. Given an arbitrary address string,
//! sniff which [`Family`] it belongs to, using the same prefixes / HRPs / version bytes / checksums
//! the [`crate::coins`] table encodes. Advisory only: a caller compares the detected family against
//! what a pool expects and *warns* on a mismatch — nothing here rejects an address or blocks mining
//! (a valid-but-unrecognized address must still run).
//!
//! Detection is checksum-verified where the scheme has one we can reuse (base58check double-SHA256,
//! bech32/bech32m polymod), so a random string doesn't get mislabelled; the remaining schemes
//! (Ergo Blake2b, Monero block-base58, Alephium unchecked) fall back to structural shape.

use std::sync::OnceLock;

use crate::codec::{base58, bech32, cashaddr, cryptonote};
use crate::coins::{Family, FamilyParams, COINS};

/// Longest address string detection will look at, in bytes.
///
/// This is a deliberate guard on untrusted input, not a validity rule. Most of what
/// [`detect_family`] does below is linear, but steps 4 and 6 reach [`base58::decode`], which is
/// quadratic in the input length — one bignum multiply-accumulate per character over an
/// accumulator that grows with the input. The strings arriving here are payout addresses out of a
/// miner's configuration, so their length is chosen by whoever wrote that file, and an unbounded
/// quadratic on input somebody else chooses is a denial-of-service shape.
///
/// 128 is the smallest round number comfortably clear of everything detection can legitimately
/// classify. The longest is a 95-character CryptoNote address
/// (`varint(prefix) ‖ spend(32) ‖ view(32) ‖ checksum(4)` through the block-base58 scheme — see
/// [`cryptonote_tag`]); a `karlsentest:` version-1 Kaspa address is 75, a bech32m Taproot address
/// 62, a base58check P2PKH address 35. The margin leaves room for a longer prefix a future coin row
/// might bring without anyone having to revisit this number, and still bounds the worst case to a
/// few thousand limb operations.
///
/// Measured in bytes rather than characters: a multi-byte string only trips the cap sooner, and
/// nothing detection models is non-ASCII, so it would have been classified `None` regardless.
const MAX_ADDR_LEN: usize = 128;

/// Detection's cap must sit at or below the one [`base58::decode`] enforces, so that base58's cap
/// can never be what silently stops classifying a string detection was still willing to look at.
/// Checked at compile time — the two constants live in different modules for different reasons, and
/// this is the relationship between them.
const _: () = assert!(MAX_ADDR_LEN <= base58::MAX_INPUT_LEN);

/// Best-effort classification of `addr` into an address [`Family`]. `None` when nothing we model
/// matches — the caller treats that as "can't tell", not "invalid".
pub fn detect_family(addr: &str) -> Option<Family> {
    let a = addr.trim();
    // Nothing to classify, and — see [`MAX_ADDR_LEN`] — nothing worth spending quadratic time on.
    if a.is_empty() || a.len() > MAX_ADDR_LEN {
        return None;
    }

    // 1. Ethereum: `0x` + 40 hex nibbles (EIP-55 mixed-case checksum not required for a warn).
    if let Some(rest) = a.strip_prefix("0x").or_else(|| a.strip_prefix("0X")) {
        if rest.len() == 40 && rest.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Some(Family::Ethereum);
        }
    }

    // 2. Kaspa-family CashAddr: `<prefix>:<payload>` where the CashAddr checksum verifies and the
    //    prefix is a modelled Kaspa prefix. The `prefix:` shape is unambiguous, but shape alone is
    //    not enough to answer confidently: this arm used to test only that the prefix matched and
    //    the payload used the bech32 charset, which meant a Kaspa address with one mistyped
    //    character was reported as a valid Kaspa address — from the very check whose job is to
    //    notice that. Every other arm below verifies a checksum before committing; this one now
    //    does too. The prefix is folded into the checksum, so this also separates the forks, which
    //    are otherwise byte-for-byte identical.
    if let Some(decoded) = cashaddr::decode(a) {
        if kaspa_prefixes().any(|p| p == decoded.prefix) {
            return Some(Family::KaspaAddr);
        }
    }

    // 3. bech32 (SegWit v0) / bech32m (Taproot), keyed on a modelled HRP + checksum variant.
    if let Some((hrp, variant)) = bech32::verify(a) {
        if hrp_is_modelled(&hrp) {
            return Some(match variant {
                bech32::Variant::Bech32 => Family::SegwitV0,
                bech32::Variant::Bech32m => Family::Taproot,
            });
        }
    }

    // 4. The plain-base58 families, all decoded **once**. base58 decoding is a bignum
    //    multiply-accumulate per character, quadratic in the length; the base58check arm and the
    //    unchecked arm below it used to call it separately on the same string, paying that twice
    //    for one classification.
    if let Some(raw) = base58::decode(a) {
        // 4a. Base58check: verify the double-SHA256 checksum, which rules out lookalikes. Two
        //     modelled families share it, and the *payload length* is what separates them — both
        //     wrap the same 20-byte hash160, and only one puts a version byte in front of it:
        //       P2PKH — `version(1 or 2) ‖ hash160(20)` → payload is 21 or 22 bytes.
        //       XDAG  — bare `hash160(20)`, no version  → payload is exactly 20 bytes.
        //     Discriminating on the leading bytes alone cannot tell them apart, and used to get it
        //     actively wrong 5% of the time; see [`version_is_modelled`].
        if let Some(payload) = base58::verify_check(&raw) {
            if version_is_modelled(payload) {
                return Some(Family::P2pkh);
            }
            // XDAG's modern account address is `Base58Check(HASH160(compressed_pubkey))` with
            // **no** version byte — its one deviation from P2PKH. Source: XDagger/xdagj (MIT)
            // `crypto/keys/AddressUtils.toBytesAddress` + `crypto/encoding/Base58.encodeCheck`; the
            // derivation side is `forager-wallet`'s `families/xdag.rs`.
            //
            // A 20-byte checksum-valid payload is unambiguous against everything else modelled
            // here. P2PKH is 21 or 22 by the rule above. A WIF is `wif ‖ key(32)[‖ 0x01]`, 33 or 34
            // (`forager-wallet` `secret.rs`). Alephium is plain base58 with no checksum at all, and
            // Ergo's checksum is Blake2b, not double-SHA256, so neither reaches this arm except by
            // a 2^-32 accident — and if one did, its payload would be 29 and 34 bytes respectively.
            // CryptoNote uses the block-base58 scheme, a different encoding entirely.
            if payload.len() == HASH160_LEN {
                return Some(Family::Xdag);
            }
        }

        // 4b. Alephium: `Base58(0x00 ‖ Blake2b256(pubkey))` — 33 bytes, leading 0x00, no checksum.
        //     Comes after base58check so a real BTC/LTC P2PKH (25 bytes, valid checksum) is caught
        //     above.
        if raw.len() == ALEPHIUM_LEN && raw[0] == 0x00 {
            return Some(Family::Alephium);
        }
    }

    // 5. Ergo P2PK: base58, leading '9', Blake2b checksum (not reused here) — structural shape.
    if a.starts_with('9') && (40..=60).contains(&a.len()) && a.bytes().all(is_base58_char) {
        return Some(Family::Ergo);
    }

    // 6. CryptoNote / Monero: base58 (block scheme) whose length and leading characters match what a
    //    modelled network prefix forces. Keyed on the coin table, so a fork with a multi-byte prefix
    //    (Zephyr `ZEPHYR…`, Salvium `SaLv…`) is recognised too — a first-character `4`/`8` test could
    //    only ever see Monero.
    if a.bytes().all(is_base58_char) {
        for (tag, len) in cryptonote_tags() {
            if a.len() == *len && a.starts_with(tag.as_str()) {
                return Some(Family::CryptoNote);
            }
        }
    }

    None
}

/// The outcome of checking one address against the family a pool is expected to pay out in. The
/// caller decides how loud to be: `Mismatch` is a real, actionable warning; `Unrecognized` is a
/// soft "couldn't classify" note; `Ok` is silent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The address matches the expected family (or a compatible one).
    Ok,
    /// The address parses cleanly as a *different* family than expected — almost always a real
    /// misconfiguration (mining to nowhere).
    Mismatch { detected: Family, expected: Family },
    /// Couldn't classify the address as anything modelled — warn softly, never block.
    Unrecognized,
}

/// Check `addr` against the `expected` family. Advisory: see [`Verdict`]. Never fails/blocks —
/// the caller turns a `Mismatch`/`Unrecognized` into a log warning and keeps mining.
pub fn check(addr: &str, expected: Family) -> Verdict {
    match detect_family(addr) {
        Some(f) if families_compatible(f, expected) => Verdict::Ok,
        Some(detected) => Verdict::Mismatch { detected, expected },
        None => Verdict::Unrecognized,
    }
}

/// Whether a detected family should be accepted for an expected one. The three Bitcoin-script
/// families (P2PKH / SegWit v0 / Taproot) are interchangeable for a given coin — a user may paste a
/// legacy address for a segwit-capable coin — so we don't warn across them. Everything else must
/// match exactly.
fn families_compatible(detected: Family, expected: Family) -> bool {
    detected == expected || (is_bitcoin_script(detected) && is_bitcoin_script(expected))
}

fn is_bitcoin_script(f: Family) -> bool {
    matches!(f, Family::P2pkh | Family::SegwitV0 | Family::Taproot)
}

/// Human-readable family name for warnings.
pub fn family_name(f: Family) -> &'static str {
    match f {
        Family::P2pkh => "Bitcoin-style legacy (base58)",
        Family::SegwitV0 => "SegWit v0 (bech32)",
        Family::Taproot => "Taproot (bech32m)",
        Family::Ethereum => "Ethereum (0x)",
        Family::CryptoNote => "CryptoNote/Monero",
        Family::KaspaAddr => "Kaspa-family (CashAddr)",
        Family::Ergo => "Ergo P2PK",
        Family::Alephium => "Alephium",
        Family::Xdag => "XDAG",
    }
}

fn kaspa_prefixes() -> impl Iterator<Item = &'static str> {
    COINS.iter().filter_map(|c| match c.params {
        FamilyParams::KaspaAddr { prefix, .. } => Some(prefix),
        _ => None,
    })
}

/// Monero's subaddress network prefix.  A subaddress is a legitimate payout target, so detection
/// accepts it alongside the standard prefix each modelled row carries.  Source:
/// monero-project/monero `src/cryptonote_config.h` —
/// `CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = 42` (renders `8…`).
const MONERO_SUBADDRESS_PREFIX: u64 = 42;

/// Every CryptoNote network prefix detection models: each modelled row's mainnet and testnet
/// prefixes, plus Monero's subaddress prefix.
fn cryptonote_prefixes() -> impl Iterator<Item = u64> {
    COINS
        .iter()
        .flat_map(|c| match c.params {
            FamilyParams::CryptoNote {
                network_byte,
                network_byte_testnet,
            } => [Some(network_byte), network_byte_testnet],
            _ => [None, None],
        })
        .flatten()
        .chain(std::iter::once(MONERO_SUBADDRESS_PREFIX))
}

/// Every `(tag, address length)` pair the CryptoNote arm of [`detect_family`] tests against,
/// derived once.
///
/// [`cryptonote_tag`] is a pure function of a network prefix, and the prefixes come from the static
/// [`COINS`] table, so the whole set is fixed for the life of the process. Detection nonetheless
/// rebuilt it on every call: five modelled prefixes, two block-base58 encodings of ~70 bytes each
/// to bracket the range, ten encodings per classification. Measured at 8.9µs per call against 726ns
/// for the same function on an address that reaches the bech32 arm — a twelvefold difference, all
/// of it recomputing a constant.
///
/// The cost only lands on inputs that fall through every earlier arm and are entirely base58
/// characters, which is exactly the shape an unrecognized string tends to have, so the slow path
/// was the one taken by input nobody vouched for.
///
/// Empty tags are dropped here rather than skipped per call: a prefix wide enough that the two
/// bracketing encodings share no leading character produces one, and it would match every string of
/// the right length. Sorting and deduplicating collapses the rows that model the same prefix twice
/// (a coin whose testnet prefix equals another row's, Monero's subaddress prefix alongside a fork
/// that reuses it).
fn cryptonote_tags() -> &'static [(String, usize)] {
    static TAGS: OnceLock<Vec<(String, usize)>> = OnceLock::new();
    TAGS.get_or_init(|| {
        let mut tags: Vec<(String, usize)> = cryptonote_prefixes()
            .map(cryptonote_tag)
            .filter(|(tag, _)| !tag.is_empty())
            .collect();
        tags.sort();
        tags.dedup();
        tags
    })
}

/// The leading characters **every** address with CryptoNote network prefix `nb` shares, and the
/// exact character length such an address has.
///
/// Both are a function of the prefix alone. The payload is
/// `varint(nb) ‖ pub_spend(32) ‖ pub_view(32) ‖ checksum(4)`, so the varint width fixes the byte
/// length and therefore the base58 length. The base58 blocks are fixed-width big-endian and the
/// alphabet is in ASCII order, so encoding is monotonic: encoding the 68 key-and-checksum bytes as
/// all-`0x00` and all-`0xff` brackets every real address, and the common prefix of those two
/// extremes is the common prefix of every address in between. A fork picks its prefix precisely to
/// make that shared prefix a human tag — Zephyr's `0x6241d18c0` yields `ZEPHYR…`.
fn cryptonote_tag(nb: u64) -> (String, usize) {
    let mut lo = Vec::new();
    cryptonote::write_varint(nb, &mut lo);
    let mut hi = lo.clone();
    lo.extend_from_slice(&[0x00; 68]);
    hi.extend_from_slice(&[0xff; 68]);
    let (lo, hi) = (cryptonote::encode(&lo), cryptonote::encode(&hi));
    // base58 is ASCII, so a byte count is a character count.
    let common = lo
        .bytes()
        .zip(hi.bytes())
        .take_while(|(a, b)| a == b)
        .count();
    (lo[..common].to_string(), lo.len())
}

fn hrp_is_modelled(hrp: &str) -> bool {
    COINS.iter().any(|c| match c.params {
        FamilyParams::SegwitV0 { hrp: h, .. } | FamilyParams::Taproot { hrp: h, .. } => h == hrp,
        _ => false,
    })
}

/// Width of the RIPEMD160(SHA256(pubkey)) digest every base58check family here is built around.
/// P2PKH puts a version prefix in front of it; XDAG does not.
const HASH160_LEN: usize = 20;

/// Length of a decoded Alephium address: `0x00 ‖ Blake2b256(pubkey)`, with no checksum.
const ALEPHIUM_LEN: usize = 33;

/// Whether a decoded base58check payload is `version ‖ hash160` for a version prefix the coin table
/// models.
///
/// Matches on the *prefix*, not just the first byte, so a Zcash-family two-byte prefix
/// (`0x1C,0xB8`) is distinguished from a hypothetical one-byte `0x1C` coin.
///
/// The length test is not belt-and-braces — it is the whole discriminator's other half. This was
/// once a bare `payload.starts_with(v)` with no constraint on how long the payload was, which meant
/// *any* checksum-valid base58check payload opening with one of the 13 distinct one-byte version
/// prefixes the table models (`0x00 0x1e 0x26 0x30 0x32 0x3c 0x41 0x47 0x4a 0x52 0x6d 0x6f 0x71`)
/// was answered `P2pkh`. An XDAG address is a bare 20-byte hash160, whose leading byte is
/// effectively uniform, so 13/256 ≈ 5.1% of correct XDAG addresses were confidently mislabelled —
/// a `Mismatch` warning fired at a user who had configured their payout correctly, which is exactly
/// the failure this module exists to prevent. A P2PKH payload is `version ‖ hash160` and nothing
/// else, so pinning the length to `version.len() + 20` costs nothing and closes it.
fn version_is_modelled(payload: &[u8]) -> bool {
    COINS
        .iter()
        .flat_map(|c| c.params.p2pkh_version_prefixes())
        .any(|v| payload.len() == v.len() + HASH160_LEN && payload.starts_with(v))
}

fn is_base58_char(b: u8) -> bool {
    b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(&b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_bitcoin_legacy_p2pkh() {
        // base58check, version 0x00 (BTC P2PKH) — the derivation KAT's own vector.
        assert_eq!(
            detect_family("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"),
            Some(Family::P2pkh)
        );
    }

    #[test]
    fn detects_bitcoin_bech32_segwit_v0() {
        // BIP173 example P2WPKH.
        assert_eq!(
            detect_family("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"),
            Some(Family::SegwitV0)
        );
    }

    #[test]
    fn detects_bitcoin_taproot_bech32m() {
        // BIP350 example P2TR (bech32m).
        assert_eq!(
            detect_family("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"),
            Some(Family::Taproot)
        );
    }

    #[test]
    fn detects_ethereum() {
        assert_eq!(
            detect_family("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"),
            Some(Family::Ethereum)
        );
    }

    #[test]
    fn detects_monero() {
        let xmr = "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A";
        assert_eq!(detect_family(xmr), Some(Family::CryptoNote));
    }

    /// Monero's tags are *derived* from its prefixes, not hard-coded: prefix 18 fixes exactly the
    /// leading `4` and a 95-character address, and the subaddress prefix 42 fixes `8`.  Those are the
    /// two cases the previous hard-coded first-character test covered, so this pins that nothing was
    /// lost when detection moved to the coin table.
    #[test]
    fn monero_tags_are_derived_from_its_prefixes() {
        assert_eq!(cryptonote_tag(18), ("4".to_string(), 95));
        assert_eq!(
            cryptonote_tag(MONERO_SUBADDRESS_PREFIX),
            ("8".to_string(), 95)
        );
    }

    /// The cached tag set classifies exactly what deriving per call did.
    ///
    /// Caching is only safe because [`cryptonote_tag`] is a pure function of a network prefix and
    /// the prefixes come from the static [`COINS`] table. This asserts that directly: every
    /// modelled prefix's tag survives into the cache, and the cache holds nothing a prefix did not
    /// put there. A row added to the table later is covered without editing this test.
    #[test]
    fn the_cached_cryptonote_tags_are_the_derived_ones() {
        let derived: std::collections::HashSet<(String, usize)> = cryptonote_prefixes()
            .map(cryptonote_tag)
            .filter(|(tag, _)| !tag.is_empty())
            .collect();
        let cached: std::collections::HashSet<(String, usize)> =
            cryptonote_tags().iter().cloned().collect();
        assert_eq!(cached, derived);

        // Deduplication must not have emptied it, and Monero's two tags must be in there — the
        // detection this cache serves is only as good as its contents.
        assert!(cached.contains(&("4".to_string(), 95)), "{cached:?}");
        assert!(cached.contains(&("8".to_string(), 95)), "{cached:?}");
    }

    /// An empty tag would match every base58 string of the right length, so it must never reach the
    /// comparison. Nothing in the table produces one today; the filter exists for the prefix wide
    /// enough that its two bracketing encodings share no leading character, and this pins that the
    /// filter is what stands between such a row and a family answered on length alone.
    #[test]
    fn no_cached_cryptonote_tag_is_empty() {
        for (tag, len) in cryptonote_tags() {
            assert!(!tag.is_empty(), "empty tag for length {len}");
        }
    }

    #[test]
    fn corrupted_checksum_is_not_a_confident_family() {
        // Flip a char in a valid bech32 address → checksum fails → not detected as SegwitV0.
        let bad = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5";
        assert_ne!(detect_family(bad), Some(Family::SegwitV0));
    }

    #[test]
    fn junk_and_empty_are_unrecognized() {
        assert_eq!(detect_family(""), None);
        assert_eq!(detect_family("not an address"), None);
        assert_eq!(detect_family("   "), None);
    }

    #[test]
    fn check_flags_cross_family_mismatch() {
        // An Ethereum address where a Kaspa address is expected → actionable mismatch.
        match check(
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            Family::KaspaAddr,
        ) {
            Verdict::Mismatch { detected, expected } => {
                assert_eq!(detected, Family::Ethereum);
                assert_eq!(expected, Family::KaspaAddr);
            }
            v => panic!("expected mismatch, got {v:?}"),
        }
    }

    #[test]
    fn check_accepts_matching_family() {
        assert_eq!(
            check(
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
                Family::SegwitV0
            ),
            Verdict::Ok
        );
    }

    #[test]
    fn check_is_lenient_within_bitcoin_script_families() {
        // A legacy P2PKH address for a coin expected as SegWit v0 must not warn (same coin, user
        // pasted a legacy address).
        assert_eq!(
            check("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", Family::SegwitV0),
            Verdict::Ok
        );
    }

    #[test]
    fn check_warns_softly_on_unrecognized() {
        assert_eq!(
            check("totally-custom-pool-token", Family::Ethereum),
            Verdict::Unrecognized
        );
    }

    #[test]
    fn detects_alephium() {
        // The launch coin. `Base58(0x00 ‖ Blake2b256(pubkey))` → 33 bytes, leading 0x00, no
        // checksum — distinguished from a BTC P2PKH by length + the absent base58check checksum.
        assert_eq!(
            detect_family("1DrDyTr9RpRsQnDnXo2YRiPzPW4ooHX5LLoqXrqfMrpQH"),
            Some(Family::Alephium)
        );
    }

    /// The Kaspa-family address for privkey=1 — the x-only key
    /// `79be667e…16f81798` under version 0 (`PubKey`). Reproducible from this crate alone:
    /// `codec::cashaddr::encode("kaspa", 0, &x_only)`, which the sibling `forager-wallet` crate
    /// asserts its `kas` derivation against (`kas_address_matches_manual_xonly_plus_cashaddr`).
    ///
    /// The previous vector here was a hand-made string that only *looked* like a Kaspa address —
    /// 62 data characters, which no version can produce (version 0 gives 61, version 1 gives 63),
    /// and a checksum that does not verify. It passed because detection tested shape alone. That
    /// it survived review is the defect in miniature, so the vector is now a real address.
    const KASPA_PRIVKEY1: &str =
        "kaspa:qpumuen7l8wthtz45p3ftn58pvrs9xlumvkuu2xet8egzkcklqtes4ypce9sf";

    #[test]
    fn detects_kaspa() {
        assert_eq!(detect_family(KASPA_PRIVKEY1), Some(Family::KaspaAddr));
        // The upstream all-zero KAT from `codec/cashaddr.rs`, for a second, independently sourced
        // string.
        assert_eq!(
            detect_family("kaspa:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkx9awp4e"),
            Some(Family::KaspaAddr)
        );
    }

    /// The Kaspa arm of `corrupted_checksum_is_not_a_confident_family` below, and the point of the
    /// whole exercise: a Kaspa-family address with a typo used to be classified confidently,
    /// because the arm checked the `prefix:` shape and nothing else. A `Verdict::Ok` on a corrupted
    /// address defeats the only check standing between a user and mining to an unspendable string.
    #[test]
    fn corrupted_kaspa_family_address_is_not_a_confident_family() {
        for prefix in ["kaspa", "karlsen", "spectre"] {
            let good = crate::codec::cashaddr::encode(prefix, 0, &[0x11u8; 32]);
            assert_eq!(detect_family(&good), Some(Family::KaspaAddr), "{good}");

            // Flip one payload character. Everything else — prefix, charset, length — still looks
            // exactly like a valid address.
            let mut bytes = good.clone().into_bytes();
            let i = prefix.len() + 1;
            bytes[i] = if bytes[i] == b'q' { b'p' } else { b'q' };
            let bad = String::from_utf8(bytes).unwrap();
            assert_ne!(detect_family(&bad), Some(Family::KaspaAddr), "{bad}");

            // And a truncated paste.
            let bad = &good[..good.len() - 1];
            assert_ne!(detect_family(bad), Some(Family::KaspaAddr), "{bad}");
        }
    }

    /// A Karlsen address must not be classified under the `kaspa:` prefix. The three forks share the
    /// address format byte for byte, so only the checksum's prefix folding separates them.
    #[test]
    fn a_kaspa_family_payload_under_a_sibling_forks_prefix_is_not_confident() {
        let karlsen = crate::codec::cashaddr::encode("karlsen", 0, &[0x11u8; 32]);
        let data = karlsen.split_once(':').unwrap().1;
        assert_ne!(
            detect_family(&format!("kaspa:{data}")),
            Some(Family::KaspaAddr)
        );
    }

    /// A pathologically long string must be rejected promptly, not decoded.
    ///
    /// The bound is deliberately loose — this is a guard against the quadratic path coming back,
    /// not a benchmark. Without the cap the same input runs `base58::decode`'s bignum
    /// multiply-accumulate 100_000 times over a number that grows to ~73 KB, which takes minutes in
    /// a debug build; with it the call is a length comparison.
    #[test]
    fn pathologically_long_input_is_rejected_promptly() {
        // `z`, not `1`: a run of `1`s is base58's leading-zero case, which short-circuits to a
        // zero accumulator and never does the expensive multiply. A high-value character makes the
        // accumulator grow, which is the case the cap exists for.
        let long = "z".repeat(100_000);
        let start = std::time::Instant::now();
        assert_eq!(detect_family(&long), None);
        assert!(
            start.elapsed() < std::time::Duration::from_secs(5),
            "detection took {:?} — the length cap is not doing its job",
            start.elapsed()
        );
    }

    /// The cap must not be so tight that it clips a real address. The longest thing detection
    /// classifies is a 95-character CryptoNote address.
    #[test]
    fn the_cap_clears_the_longest_address_detection_models() {
        let xmr = "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A";
        assert!(xmr.len() < MAX_ADDR_LEN);
        assert_eq!(detect_family(xmr), Some(Family::CryptoNote));
        // The longest Kaspa-family shape a modelled row can produce: the longest prefix, `:`, and a
        // version-1 (33-byte) payload.
        let longest_kaspa = crate::codec::cashaddr::encode("karlsentest", 1, &[0u8; 33]);
        assert!(longest_kaspa.len() < MAX_ADDR_LEN, "{longest_kaspa}");
    }

    #[test]
    fn detects_ergo_p2pk() {
        assert_eq!(
            detect_family("9f4QF8AD1nQ3nJahQVkMj8hFSVVzVom77b52JU7EW71Zexg6N8v"),
            Some(Family::Ergo)
        );
    }

    /// XDAG's known-answer address, lifted from the generator's own KAT (`forager-wallet`
    /// `families/xdag.rs`, derived from xdagj's `SampleKeys.java` keypair). The round-trip against
    /// what the generator actually emits lives in `forager-wallet`'s `tests/validate_roundtrip.rs`,
    /// which can call the generator; this crate cannot.
    const XDAG_SAMPLE_KEYS: &str = "N3RC53vbaDNrziTdWmctBEeQ4fo38moXu";

    #[test]
    fn detects_xdag() {
        assert_eq!(detect_family(XDAG_SAMPLE_KEYS), Some(Family::Xdag));
        assert_eq!(check(XDAG_SAMPLE_KEYS, Family::Xdag), Verdict::Ok);
    }

    /// XDAG and P2PKH are different chains, so a paste of one where the other is expected is a
    /// real, actionable warning — not something [`families_compatible`] should wave through the way
    /// it does the three Bitcoin-script families.
    #[test]
    fn xdag_and_p2pkh_are_not_compatible() {
        assert!(matches!(
            check(XDAG_SAMPLE_KEYS, Family::P2pkh),
            Verdict::Mismatch {
                detected: Family::Xdag,
                expected: Family::P2pkh
            }
        ));
        assert!(matches!(
            check("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", Family::Xdag),
            Verdict::Mismatch {
                detected: Family::P2pkh,
                expected: Family::Xdag
            }
        ));
    }

    /// The regression the XDAG arm was written for, pinned deliberately so it cannot be lost again.
    ///
    /// [`version_is_modelled`] used to ask only whether the decoded payload *started with* a
    /// modelled version prefix, with no constraint on its length. An XDAG payload is a bare 20-byte
    /// hash160 with no version byte, and a hash160's leading byte is effectively uniform, so a
    /// perfectly good XDAG address matched whenever that byte was one of the 13 distinct one-byte
    /// prefixes the table models — 13/256 ≈ 5.1%, measured at 5.06% over 20_000 pseudorandom
    /// hash160s. Those addresses were reported as `P2pkh`: a *confident wrong answer* telling a
    /// user that their correctly configured payout address was a misconfiguration, which is the
    /// exact failure the pre-flight check exists to prevent.
    ///
    /// The prefixes come straight out of the coin table rather than a hand-written list, so a row
    /// added later is covered without anyone remembering to extend this test. Copying the whole
    /// prefix in — not just its first byte — also exercises the two-byte Zcash-family `0x1C,0xB8`
    /// case, the only shape for which the length rule has to distinguish 22 bytes from 20.
    #[test]
    fn an_xdag_hash160_that_opens_with_a_p2pkh_version_prefix_is_still_xdag() {
        let prefixes: Vec<&[u8]> = COINS
            .iter()
            .flat_map(|c| c.params.p2pkh_version_prefixes())
            .collect();
        // The two cheapest collisions to reason about, asserted present so the loop below is known
        // to be exercising the case this test is named for.
        assert!(prefixes.contains(&&[0x00u8][..]), "{prefixes:?}");
        assert!(prefixes.contains(&&[0x1eu8][..]), "{prefixes:?}");

        for v in prefixes {
            let mut hash160 = [0x11u8; 20];
            hash160[..v.len()].copy_from_slice(v);
            let addr = crate::codec::base58::encode_check(&hash160);
            assert_eq!(detect_family(&addr), Some(Family::Xdag), "{v:02x?}: {addr}");
            assert_eq!(check(&addr, Family::Xdag), Verdict::Ok, "{v:02x?}: {addr}");
        }
    }

    /// A checksum-valid base58check payload of exactly 20 bytes belongs to XDAG and to nothing else
    /// this crate models — no other arm may claim one. Swept over every leading byte, so the answer
    /// does not depend on which value the hash160 happens to start with (the thing that used to
    /// decide it).
    #[test]
    fn a_twenty_byte_base58check_payload_is_claimed_only_by_xdag() {
        for b in 0..=u8::MAX {
            let mut hash160 = [0x5au8; 20];
            hash160[0] = b;
            // A second byte that varies too, so the sweep is not 256 near-identical strings.
            hash160[1] = b.wrapping_mul(31).wrapping_add(7);
            let addr = crate::codec::base58::encode_check(&hash160);
            assert_eq!(detect_family(&addr), Some(Family::Xdag), "{b:#04x}: {addr}");
        }
    }

    /// Detection is checksum-verified for XDAG the same way it is for every other base58check
    /// family: a typo'd or truncated paste must not come back as a confident `Xdag`.
    #[test]
    fn corrupted_xdag_address_is_not_a_confident_family() {
        let mut bytes = XDAG_SAMPLE_KEYS.as_bytes().to_vec();
        let i = bytes.len() - 1;
        bytes[i] = if bytes[i] == b'u' { b'v' } else { b'u' };
        let bad = String::from_utf8(bytes).unwrap();
        assert_ne!(detect_family(&bad), Some(Family::Xdag), "{bad}");

        let truncated = &XDAG_SAMPLE_KEYS[..XDAG_SAMPLE_KEYS.len() - 1];
        assert_ne!(detect_family(truncated), Some(Family::Xdag), "{truncated}");
    }

    /// The tightened length rule must not have cost the P2PKH arm anything: both payload widths a
    /// modelled row can produce still classify. 21 bytes is the one-byte-version case (the
    /// derivation KAT's own BTC vector); 22 is the Zcash-family two-byte `0x1C,0xB8` prefix, minted
    /// here over the privkey=1 hash160 that `codec/base58.rs`'s own KAT pins.
    #[test]
    fn both_p2pkh_payload_widths_still_detect() {
        assert_eq!(
            detect_family("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"),
            Some(Family::P2pkh)
        );

        let hash160: [u8; 20] =
            crate::hexbytes::decode_n("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        let mut payload = vec![0x1cu8, 0xb8];
        payload.extend_from_slice(&hash160);
        let t_addr = crate::codec::base58::encode_check(&payload);
        assert!(t_addr.starts_with("t1"), "{t_addr}");
        assert_eq!(detect_family(&t_addr), Some(Family::P2pkh), "{t_addr}");
    }

    #[test]
    fn alephium_expected_accepts_alephium_and_flags_ethereum() {
        // The launch-path guard: an Alephium payout on an Alephium pool is Ok; a pasted ETH
        // address is a real mismatch worth warning about.
        assert_eq!(
            check(
                "1DrDyTr9RpRsQnDnXo2YRiPzPW4ooHX5LLoqXrqfMrpQH",
                Family::Alephium
            ),
            Verdict::Ok
        );
        assert!(matches!(
            check(
                "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
                Family::Alephium
            ),
            Verdict::Mismatch { .. }
        ));
    }
}
