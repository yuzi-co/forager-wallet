//! Payout-address **detection** — the inverse of derivation. Given an arbitrary address string,
//! sniff which [`Family`] it belongs to, using the same prefixes / HRPs / version bytes / checksums
//! the [`crate::coins`] table encodes. Advisory only: a caller compares the detected family against
//! what a pool expects and *warns* on a mismatch — nothing here rejects an address or blocks mining
//! (a valid-but-unrecognized address must still run).
//!
//! Detection is checksum-verified where the scheme has one we can reuse (base58check double-SHA256,
//! bech32/bech32m polymod), so a random string doesn't get mislabelled; the remaining schemes
//! (Ergo Blake2b, Monero block-base58, Alephium unchecked) fall back to structural shape.

use crate::codec::{base58, bech32, cryptonote};
use crate::coins::{Family, FamilyParams, COINS};

/// Best-effort classification of `addr` into an address [`Family`]. `None` when nothing we model
/// matches — the caller treats that as "can't tell", not "invalid".
pub fn detect_family(addr: &str) -> Option<Family> {
    let a = addr.trim();
    if a.is_empty() {
        return None;
    }

    // 1. Ethereum: `0x` + 40 hex nibbles (EIP-55 mixed-case checksum not required for a warn).
    if let Some(rest) = a.strip_prefix("0x").or_else(|| a.strip_prefix("0X")) {
        if rest.len() == 40 && rest.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Some(Family::Ethereum);
        }
    }

    // 2. Kaspa-family CashAddr: `<prefix>:<payload>` where the prefix is a modelled Kaspa prefix
    //    and the payload uses the bech32 charset. The `prefix:` shape is unambiguous.
    if let Some((prefix, payload)) = a.split_once(':') {
        if !payload.is_empty()
            && payload.bytes().all(is_bech32_char)
            && kaspa_prefixes().any(|p| p == prefix)
        {
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

    // 4. Bitcoin-style base58check (P2PKH): decode + verify the double-SHA256 checksum, then match
    //    the leading version byte against a modelled coin. A valid checksum rules out lookalikes.
    if let Some(payload) = base58::decode_check(a) {
        if version_is_modelled(&payload) {
            return Some(Family::P2pkh);
        }
    }

    // 5. Alephium: `Base58(0x00 ‖ Blake2b256(pubkey))` — 33 bytes, leading 0x00, no checksum. Comes
    //    after base58check so a real BTC/LTC P2PKH (25 bytes, valid checksum) is caught above.
    if let Some(raw) = base58::decode(a) {
        if raw.len() == 33 && raw[0] == 0x00 {
            return Some(Family::Alephium);
        }
    }

    // 6. Ergo P2PK: base58, leading '9', Blake2b checksum (not reused here) — structural shape.
    if a.starts_with('9') && (40..=60).contains(&a.len()) && a.bytes().all(is_base58_char) {
        return Some(Family::Ergo);
    }

    // 7. CryptoNote / Monero: base58 (block scheme) whose length and leading characters match what a
    //    modelled network prefix forces. Keyed on the coin table, so a fork with a multi-byte prefix
    //    (Zephyr `ZEPHYR…`, Salvium `SaLv…`) is recognised too — a first-character `4`/`8` test could
    //    only ever see Monero.
    if a.bytes().all(is_base58_char) {
        for nb in cryptonote_prefixes() {
            let (tag, len) = cryptonote_tag(nb);
            if !tag.is_empty() && a.len() == len && a.starts_with(&tag) {
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

/// Whether a decoded base58check payload starts with a version prefix the coin table models.
///
/// Matches on the *prefix*, not just the first byte, so a Zcash-family two-byte prefix
/// (`0x1C,0xB8`) is distinguished from a hypothetical one-byte `0x1C` coin.
fn version_is_modelled(payload: &[u8]) -> bool {
    COINS
        .iter()
        .flat_map(|c| c.params.p2pkh_version_prefixes())
        .any(|v| payload.starts_with(v))
}

fn is_bech32_char(b: u8) -> bool {
    b"qpzry9x8gf2tvdw0s3jn54khce6mua7l".contains(&b.to_ascii_lowercase())
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

    #[test]
    fn detects_kaspa() {
        assert_eq!(
            detect_family("kaspa:qyp9sfrku0d9gd5xw7cntd7hc3d0myk3edts8u8vj0vfl2h9jjr4uggcnyv2rd"),
            Some(Family::KaspaAddr)
        );
    }

    #[test]
    fn detects_ergo_p2pk() {
        assert_eq!(
            detect_family("9f4QF8AD1nQ3nJahQVkMj8hFSVVzVom77b52JU7EW71Zexg6N8v"),
            Some(Family::Ergo)
        );
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
