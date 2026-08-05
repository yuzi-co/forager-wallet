//! Payout-address **detection** — the inverse of derivation. Given an arbitrary address string,
//! sniff which [`Family`] it belongs to, using the same prefixes / HRPs / version bytes / checksums
//! the [`crate::coins`] table encodes. Advisory only: a caller compares the detected family against
//! what a pool expects and *warns* on a mismatch — nothing here rejects an address or blocks mining
//! (a valid-but-unrecognized address must still run).
//!
//! Detection is checksum-verified wherever the scheme has a checksum at all — base58check
//! double-SHA256, bech32/bech32m polymod, the CashAddr polymod for the Kaspa family, Blake2b-256
//! for Ergo, Keccak-256 for CryptoNote and for Ethereum's EIP-55 — so a corrupted address is not
//! answered confidently.
//!
//! One family rests on structural shape, and it is marked at its arm. Alephium has no checksum to
//! verify: it is `Base58(0x00 ‖ Blake2b256(pubkey))` with nothing appended, so a length and a
//! leading byte are all there is to test. That is a property of the scheme, not a gap here.
//!
//! Ethereum is a partial case, and honestly so. A `0x` address is 40 hex nibbles with no appended
//! checksum; EIP-55 adds one by choosing the *case* of the hex letters, so an address written in
//! mixed case carries a checksum and is verified, while one written all-lower or all-upper carries
//! none and is accepted as it stands. That is not this crate declining to check — an all-lowercase
//! address is valid and common, and rejecting it would warn a user off a correctly configured
//! payout. What is checked is checked; what carries nothing cannot be.

use std::sync::OnceLock;

use crate::codec::{base58, bech32, cashaddr, cryptonote};
use crate::coins::{Family, FamilyParams, COINS};

/// Longest address string detection will look at, in bytes.
///
/// This is a deliberate guard on untrusted input, not a validity rule. Most of what
/// [`detect_family`] does below is linear, but step 4 reaches [`base58::decode`], which is
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

    // 1. Ethereum: `0x` + 40 hex nibbles, with the EIP-55 case checksum verified when the address
    //    carries one. See [`eip55_case_checksum_holds`] for what "carries one" means and why an
    //    address that does not is still accepted.
    if let Some(rest) = a.strip_prefix("0x").or_else(|| a.strip_prefix("0X")) {
        if rest.len() == ETH_HEX_LEN
            && rest.bytes().all(|b| b.is_ascii_hexdigit())
            && eip55_case_checksum_holds(rest)
        {
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

        // 4b. Ergo P2PK: `Base58(prefix ‖ compressed_pubkey(33) ‖ Blake2b256(prefix ‖ pubkey)[..4])`
        //     — 38 bytes, and the only modelled family whose checksum is Blake2b rather than
        //     double-SHA256. Verified, for the reason the Kaspa arm above is: this used to test
        //     `starts_with('9')`, a 40..=60 length window and the base58 charset, so a mistyped or
        //     truncated Ergo address came back as a confident `Ergo` — and so did any base58 string
        //     that happened to open with a `9`, which is one character in 58. Detection exists to
        //     notice exactly that, and shape alone cannot.
        if let Some(family) = ergo_family(&raw) {
            return Some(family);
        }

        // 4c. Alephium: `Base58(0x00 ‖ Blake2b256(pubkey))` — 33 bytes, leading 0x00, no checksum.
        //     Comes after base58check so a real BTC/LTC P2PKH (25 bytes, valid checksum) is caught
        //     above. Alephium is the one family left with no checksum to verify: it has none to
        //     reuse, so its answer rests on the length and leading byte alone.
        if raw.len() == ALEPHIUM_LEN && raw[0] == 0x00 {
            return Some(Family::Alephium);
        }
    }

    // 5. CryptoNote / Monero: block-base58, `varint(prefix) ‖ spend(32) ‖ view(32) ‖ checksum(4)`,
    //    with the Keccak-256 checksum verified. Keyed on the coin table, so a fork with a
    //    multi-byte prefix (Zephyr `ZEPHYR…`, Salvium `SaLv…`) is recognised too — a
    //    first-character `4`/`8` test could only ever see Monero.
    if let Some(family) = cryptonote_family(a) {
        return Some(family);
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

/// Characters in the hex body of an Ethereum address: 20 bytes, two nibbles each.
const ETH_HEX_LEN: usize = 40;

/// Whether the EIP-55 checksum an Ethereum address body carries — if it carries one — holds.
///
/// EIP-55 does not append anything. It writes the checksum into the *case* of the hex letters: hash
/// the 40 lower-case ASCII characters with Keccak-256, and hex character `i` is upper-case exactly
/// when nibble `i` of that digest is `>= 8`. Source: EIP-55 itself, and the generator's own
/// `families/ethereum.rs`, which is the encoder this inverts.
///
/// Three cases, and the distinction between them is the whole point of this function:
///
/// - **Mixed case** — the address carries a checksum, and a single wrong character (or a single
///   wrongly-cased letter) breaks it. Verified. This is the case that used to be answered
///   confidently on shape alone.
/// - **All lower-case or all upper-case** — no checksum is carried. EIP-55 is backwards-compatible
///   by construction: the case-insensitive form predates it, wallets still emit it, and it is a
///   perfectly valid address. Accepted unchanged. Rejecting it would warn a user off a correctly
///   configured payout, which is the failure this module exists to prevent.
/// - **No letters at all** — 40 hex digits with no `a`–`f`. Digits have no case, so no checksum can
///   be encoded in them and none can be checked. Falls into the case above and is accepted.
///
/// Deciding "carries a checksum" by the presence of both cases is what EIP-55's own reference
/// implementations do, and it is the only test available: the checksum lives in the case, so a
/// string with one case throughout is indistinguishable from an un-checksummed address. The cost is
/// that an address whose correct EIP-55 form happens to be entirely lower-case is accepted twice
/// over, which is not a false answer, just an unexercised check.
fn eip55_case_checksum_holds(body: &str) -> bool {
    let has_lower = body.bytes().any(|b| b.is_ascii_lowercase());
    let has_upper = body.bytes().any(|b| b.is_ascii_uppercase());
    if !(has_lower && has_upper) {
        return true;
    }

    let digest = crate::hash::keccak256(body.to_ascii_lowercase().as_bytes());
    body.bytes().enumerate().all(|(i, c)| {
        if c.is_ascii_digit() {
            return true; // no case to carry a bit
        }
        // Nibble `i` of the digest: the high half of byte `i/2` for even `i`, the low half for odd.
        let nibble = (digest[i / 2] >> if i % 2 == 0 { 4 } else { 0 }) & 0x0f;
        (nibble >= 8) == c.is_ascii_uppercase()
    })
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

/// The two public keys a CryptoNote address carries: `pub_spend(32) ‖ pub_view(32)`.
const CRYPTONOTE_KEYS_LEN: usize = 64;

/// Width of the truncated Keccak-256 checksum appended to a CryptoNote address payload.
const CRYPTONOTE_CHECKSUM_LEN: usize = 4;

/// Whether `a` is a CryptoNote address for a network prefix the coin table models, checksum
/// verified.
///
/// The payload is `varint(prefix) ‖ spend(32) ‖ view(32) ‖ keccak256(everything before it)[..4]`,
/// so every input to the checksum is inside the address — nothing external is needed to verify it,
/// and this arm used not to. The consequence was the one this module exists to prevent: a Monero
/// address with a mistyped character kept its length and its leading `4`, so it was answered
/// `CryptoNote` with confidence by the very check whose job is to notice the typo.
///
/// The tag-and-length test is kept in front of the decode as a prescreen, not as the answer. It is
/// cheap, it is derived from the coin table (see [`cryptonote_tag`]), and by the monotonicity
/// argument there it never rejects a real address for a modelled prefix — so putting it first costs
/// no recall and skips the decode for the overwhelming majority of strings that reach this far.
///
/// The decoded prefix is then matched against the table directly rather than inferred from the tag
/// it matched: two prefixes can in principle share a leading tag and a length, and the varint is
/// the authority on which one an address actually names.
fn cryptonote_family(a: &str) -> Option<Family> {
    if !a.bytes().all(is_base58_char) {
        return None;
    }
    if !cryptonote_tags()
        .iter()
        .any(|(tag, len)| a.len() == *len && a.starts_with(tag.as_str()))
    {
        return None;
    }

    let raw = cryptonote::decode(a)?;
    let (body, checksum) = raw.split_at(raw.len().checked_sub(CRYPTONOTE_CHECKSUM_LEN)?);
    let (prefix, keys) = cryptonote::read_varint(body)?;
    if keys.len() != CRYPTONOTE_KEYS_LEN || !cryptonote_prefixes().any(|p| p == prefix) {
        return None;
    }
    (crate::hash::keccak256(body)[..CRYPTONOTE_CHECKSUM_LEN] == *checksum)
        .then_some(Family::CryptoNote)
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
/// An **empty** tag is kept, and that is a change the checksum paid for. A prefix whose two
/// bracketing encodings share no leading character produces one, and an empty tag matches every
/// base58 string of the right length — which, while this arm answered on shape alone, would have
/// meant reporting `CryptoNote` for any 95-character base58 string. So empty tags were filtered out,
/// with a note saying nothing in the table produced one.
///
/// Something did. Monero's **testnet** prefix, 53, straddles a base58 digit boundary: the low
/// bracket's leading digit is 8 (`9`) and the high bracket's is 9 (`A`), so they agree nowhere and
/// the tag is empty. Every Monero testnet address was therefore dropped before the comparison and
/// classified `None` — the generator mints them (`--coin xmr --testnet`) and detection could not
/// read them back. Now that [`cryptonote_family`] verifies the Keccak-256 checksum, an empty tag
/// costs nothing but a decode on strings of one length, so the filter is gone and the recall with
/// it.
///
/// Sorting and deduplicating collapses the rows that model the same prefix twice (a coin whose
/// testnet prefix equals another row's, Monero's subaddress prefix alongside a fork that reuses it).
fn cryptonote_tags() -> &'static [(String, usize)] {
    static TAGS: OnceLock<Vec<(String, usize)>> = OnceLock::new();
    TAGS.get_or_init(|| {
        let mut tags: Vec<(String, usize)> = cryptonote_prefixes().map(cryptonote_tag).collect();
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
///
/// The tag can be **empty**, and one modelled prefix produces one: nothing forces a prefix to
/// straddle no base58 digit boundary, and Monero's testnet 53 straddles the very first. See
/// [`cryptonote_tags`], which used to discard that case.
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

/// Length of a decoded Ergo P2PK address: `prefix(1) ‖ compressed_pubkey(33) ‖ checksum(4)`.
const ERGO_LEN: usize = 38;

/// Width of Ergo's truncated Blake2b-256 checksum.
const ERGO_CHECKSUM_LEN: usize = 4;

/// Ergo's leading byte is `network_prefix + address_type`. Mainnet is 0x00 and testnet 0x10;
/// address type P2PK is 0x01, so a P2PK address opens with 0x01 (rendering `9…`) or 0x11 (`3…`).
///
/// Source: `ergoplatform/sigma-rust` `ergotree-ir/src/chain/address.rs` (`AddressEncoder`) — the
/// same reference the derivation side in `forager-wallet`'s `families/ergo.rs` cites.
const ERGO_P2PK_PREFIXES: [u8; 2] = [0x01, 0x11];

/// Whether `raw` — an already-base58-decoded string — is an Ergo P2PK address, checksum verified.
///
/// The checksum is `Blake2b256(prefix ‖ pubkey)[..4]`, which is why this crate carries
/// `blake2b_simd`: without it detection can only look at the shape, and looking at the shape is
/// what produced the bug this replaces.
///
/// Testnet is accepted alongside mainnet. The old shape test keyed on a leading `9`, so a testnet
/// address — which renders `3…` — was never classified at all, even though the generator mints one
/// and every other family here models both networks. The prefix byte is inside the checksummed
/// region, so accepting the second value costs nothing in confidence.
fn ergo_family(raw: &[u8]) -> Option<Family> {
    if raw.len() != ERGO_LEN || !ERGO_P2PK_PREFIXES.contains(&raw[0]) {
        return None;
    }
    let (body, checksum) = raw.split_at(ERGO_LEN - ERGO_CHECKSUM_LEN);
    (crate::hash::blake2b256(body)[..ERGO_CHECKSUM_LEN] == *checksum).then_some(Family::Ergo)
}

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

    /// Kadikama's version-45 P2PKH form, against addresses the network actually issued rather than
    /// ones this repository derived. All four are miner addresses read off the official Kadikama
    /// pool (mining.kadikama.xn--6frz82g) on 2026-08-05, and each carries a valid base58check
    /// double-SHA256 checksum, so a wrong version byte in the coin table cannot pass this.
    ///
    /// A live vector is what distinguishes a correct row from a self-consistent one. The
    /// derivation KAT in `forager-wallet` proves this crate and that one agree; only an address
    /// the chain minted proves either of them agrees with the chain.
    #[test]
    fn detects_kadikama_legacy_p2pkh() {
        for addr in [
            "KG8izpRdZy1xZyAgddDz3wgjFyQ8DpTps8",
            "KM5vzkGNB3z7VComUh6xo9ooVdz3h5HCbp",
            "KDy7Bm7HszkTVHL6pHhqiBKTYCk7yuzt1R",
            "KBpQj4K1YYqvjN9qC6sXDaPnYQzVN6t937",
        ] {
            assert_eq!(detect_family(addr), Some(Family::P2pkh), "{addr}");
        }
    }

    /// Kadikama runs SegWit and Taproot from genesis (`SegwitHeight = 0`, Taproot always active)
    /// with `bech32_hrp = "kad"`, but the coin table registers the `K…` P2PKH form, because that is
    /// what the network pays out in. So a `kad1…` address is a real address this crate does not
    /// model, and it must come back `Unrecognized` — the honest "cannot tell" — rather than be
    /// silently absorbed by another coin's HRP.
    ///
    /// Pinned because the failure it guards is invisible: `check` never blocks, so a `kad1…`
    /// address answered as some other family would only ever surface as a wrong warning.
    #[test]
    fn a_kadikama_bech32_address_is_unrecognized_not_misattributed() {
        // bech32 P2WPKH over HRP "kad" and the hash160 of the privkey=1 pubkey — the same key the
        // derivation KAT uses, encoded by hand for this test.
        let kad_bech32 = "kad1qw508d6qejxtdg4y5r3zarvary0c5xw7k9jvrdv";
        assert!(
            bech32::verify(kad_bech32).is_some(),
            "vector must be valid bech32"
        );
        assert_eq!(detect_family(kad_bech32), None);
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

    /// The four mixed-case addresses EIP-55 prints as its own worked examples, plus the one the
    /// generator mints for `privkey = 1` (`forager-wallet restore 0000…0001 --coin eth`, and the
    /// address `families/ethereum.rs` pins as its KAT). Every one of them is now checksum-verified
    /// rather than accepted for being 40 hex characters, so a wrong literal here fails the test
    /// instead of passing unnoticed.
    const ETH_EIP55: [&str; 5] = [
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
        "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf",
    ];

    #[test]
    fn detects_ethereum() {
        for addr in ETH_EIP55 {
            assert_eq!(detect_family(addr), Some(Family::Ethereum), "{addr}");
        }
    }

    /// A mixed-case Ethereum address carries a checksum in the case of its hex letters, and this is
    /// the arm that used to ignore it: `0x` plus 40 hex characters was answered `Ethereum` however
    /// those characters were cased, so an address with a typo came back confident.
    ///
    /// Both corruptions a paste actually suffers are covered. Flipping a *letter's case* leaves a
    /// string that is still 40 valid hex characters and still mixed case — the EIP-55 bit for that
    /// position is simply wrong. Changing a *character's value* re-rolls the whole digest, so the
    /// case pattern of the remaining letters no longer describes it.
    #[test]
    fn corrupted_mixed_case_ethereum_address_is_not_a_confident_family() {
        for good in ETH_EIP55 {
            let body = &good[2..];
            let letters = body.bytes().filter(|b| b.is_ascii_alphabetic()).count();
            assert!(letters > 1, "{good} must have letters to corrupt");

            // Every single-letter case flip, so this does not depend on which letter was picked.
            for i in 0..body.len() {
                let c = body.as_bytes()[i];
                if !c.is_ascii_alphabetic() {
                    continue;
                }
                let mut bytes = body.as_bytes().to_vec();
                bytes[i] = if c.is_ascii_uppercase() {
                    c.to_ascii_lowercase()
                } else {
                    c.to_ascii_uppercase()
                };
                let bad = format!("0x{}", String::from_utf8(bytes).unwrap());
                assert_ne!(detect_family(&bad), Some(Family::Ethereum), "{bad}");
            }

            // A mistyped hex digit rather than a mistyped case.
            let mut bytes = body.as_bytes().to_vec();
            let i = bytes.len() / 2;
            bytes[i] = if bytes[i] == b'1' { b'2' } else { b'1' };
            let bad = format!("0x{}", String::from_utf8(bytes).unwrap());
            assert_ne!(detect_family(&bad), Some(Family::Ethereum), "{bad}");
        }
    }

    /// An all-lower-case Ethereum address carries no checksum and must still be accepted. EIP-55 is
    /// backwards-compatible on purpose — the case-insensitive form predates it and wallets still
    /// emit it — so refusing one would warn a user off a payout address that is entirely correct,
    /// which is the failure this module exists to prevent, inverted.
    ///
    /// The all-upper-case form is the same argument. So is an address with no letters at all: the
    /// zero address is 40 digits, digits have no case, and no checksum can live in them.
    #[test]
    fn a_single_case_ethereum_address_carries_no_checksum_and_is_accepted() {
        for good in ETH_EIP55 {
            let body = &good[2..];
            let lower = format!("0x{}", body.to_ascii_lowercase());
            let upper = format!("0x{}", body.to_ascii_uppercase());
            assert_eq!(detect_family(&lower), Some(Family::Ethereum), "{lower}");
            assert_eq!(detect_family(&upper), Some(Family::Ethereum), "{upper}");
            // The two really are single-case, so this is not silently re-testing the mixed form.
            assert!(!lower.bytes().any(|b| b.is_ascii_uppercase()), "{lower}");
            assert!(
                !upper[2..].bytes().any(|b| b.is_ascii_lowercase()),
                "{upper}"
            );
        }
        assert_eq!(
            detect_family("0x0000000000000000000000000000000000000000"),
            Some(Family::Ethereum)
        );
    }

    /// A Monero mainnet address, and the multi-byte-prefix forks alongside it.
    ///
    /// The Monero string was already here and was already genuine — its Keccak-256 checksum
    /// verifies — but nothing checked that until this arm learnt to. The two forks are minted by the
    /// repository's own generator (`forager-wallet restore 0000…0001 --coin zeph|sal`), which is the
    /// only way to get a real one: this crate cannot derive an address, and a hand-written CryptoNote
    /// literal is exactly the kind of thing that survives review while being fiction.
    const XMR_MAINNET: &str = "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A";
    const XMR_PRIVKEY1: &str = "42nsXK8WbVGTNayQ6Kjw5UdgqbQY5KCCufdxdCgF7NgTfjC69Mna7DJSYyie77hZTQ8H92G2HwgFhgEUYnDzrnLnQdF28r3";
    const ZEPHYR_PRIVKEY1: &str = "ZEPHYR2LvQaFhaTiMGweEG1b39zyyYz7y8idgWcys4Ww8SJTaqQb31r31ubj36zrWh22GNtYZ8ou2cPihcgfXmUTSj6DsNXKg7o2Z";
    const SALVIUM_PRIVKEY1: &str = "SaLvdTkfXMxepPZY3xgauGNmx8EXjN8Hj74xDqyDXzb5Ld9Za7bLhBH3AusnVy7aAh5fkR8P5r1iaSQCCjC7pGq6bRPJCeoZYeH";

    /// Monero **testnet** for the same key (`--coin xmr --testnet`), which detection could not read
    /// until the empty-tag filter came out of [`cryptonote_tags`]. Prefix 53 renders addresses
    /// opening with either `9` or `A`, so the derived tag is empty.
    ///
    /// The same string is the derivation side's known-answer vector in `forager-wallet`'s
    /// `families/cryptonote.rs` (`monero_testnet_address_uses_network_byte_53`), arrived at
    /// separately, where its Keccak-256 checksum was also confirmed by hand against a from-scratch
    /// decoder. Monero's own documentation says testnet addresses start with `9`; that is a
    /// property of most keys, not of the prefix, and assuming it is what left this address
    /// unclassifiable.
    const XMR_TESTNET_PRIVKEY1: &str = "9tLR1ZnmsrNTNayQ6Kjw5UdgqbQY5KCCufdxdCgF7NgTfjC69Mna7DJSYyie77hZTQ8H92G2HwgFhgEUYnDzrnLnQeidLrM";

    #[test]
    fn detects_monero() {
        assert_eq!(detect_family(XMR_MAINNET), Some(Family::CryptoNote));
        assert_eq!(detect_family(XMR_PRIVKEY1), Some(Family::CryptoNote));
    }

    /// A Monero testnet address is CryptoNote. It was `None` before, for a reason worth stating
    /// plainly: the arm tested a *derived* leading tag, [`cryptonote_tags`] discarded prefixes whose
    /// tag came out empty, and testnet's prefix 53 is exactly such a prefix — its addresses open
    /// with `9` or with `A` depending on the key, so no character is shared by all of them. The
    /// filter existed because an empty tag, with no checksum behind it, would have matched every
    /// 95-character base58 string. With the checksum verified it matches only real addresses, so the
    /// filter is gone and every network the generator can mint for is classifiable.
    #[test]
    fn detects_monero_testnet() {
        assert_eq!(
            detect_family(XMR_TESTNET_PRIVKEY1),
            Some(Family::CryptoNote)
        );
        assert_eq!(check(XMR_TESTNET_PRIVKEY1, Family::CryptoNote), Verdict::Ok);
        // The tag really is empty, so this test is exercising the case it names.
        assert_eq!(cryptonote_tag(53), (String::new(), 95));
    }

    /// An empty tag matches on length alone, so nothing but the checksum stands between a
    /// 95-character base58 string and a confident `CryptoNote`. Pin that the checksum is in fact
    /// standing there: these are base58 strings of exactly the right length and none of them is an
    /// address.
    #[test]
    fn an_empty_tag_does_not_make_every_base58_string_of_that_length_cryptonote() {
        assert_eq!(
            cryptonote_tag(53).0,
            "",
            "the empty-tag case must still exist"
        );
        for junk in [
            "9".repeat(95),
            "A".repeat(95),
            "z".repeat(95),
            "9zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz".to_string(),
        ] {
            assert_eq!(junk.len(), 95, "{junk}");
            assert!(junk.bytes().all(is_base58_char), "{junk}");
            assert_ne!(detect_family(&junk), Some(Family::CryptoNote), "{junk}");
        }
    }

    /// The multi-byte network prefixes, which are the reason the varint is read rather than the
    /// first byte taken: Zephyr's prefix is five bytes and Salvium's three, so their addresses are
    /// longer than Monero's and the keys start further in. Getting that wrong would misalign the
    /// checksummed region and reject every fork address.
    #[test]
    fn detects_multibyte_prefix_cryptonote_forks() {
        for addr in [ZEPHYR_PRIVKEY1, SALVIUM_PRIVKEY1] {
            assert_eq!(detect_family(addr), Some(Family::CryptoNote), "{addr}");
            assert_eq!(check(addr, Family::CryptoNote), Verdict::Ok, "{addr}");
        }
        // The three lengths really do differ, so the varint width is being exercised. Each is what
        // its prefix width forces: Monero's one-byte 18 gives a 69-byte payload (8 full blocks plus
        // a 5-byte tail, 88 + 7 = 95 characters), Salvium's four-byte 0x3ef318 a 72-byte payload
        // (9 full blocks, 99), Zephyr's five-byte 0x6241d18c0 a 73-byte one (9 blocks plus a 1-byte
        // tail, 99 + 2 = 101).
        assert_eq!(XMR_PRIVKEY1.len(), 95);
        assert_eq!(SALVIUM_PRIVKEY1.len(), 99);
        assert_eq!(ZEPHYR_PRIVKEY1.len(), 101);
    }

    /// The point of the whole exercise on the CryptoNote side. The checksum is
    /// `keccak256(varint(prefix) ‖ spend ‖ view)[..4]`, computed over bytes the address itself
    /// carries — so it was always verifiable here, and was never verified, because this crate had
    /// no Keccak. A Monero address with one wrong character keeps its 95 characters and its leading
    /// `4`, and those were the whole test: it came back `CryptoNote`, confidently, from the check
    /// whose job is to notice.
    ///
    /// The flip is in the key region rather than the tag, so the prescreen still passes and only
    /// the checksum can reject it. Truncation is covered too, which the length test already caught
    /// but which must keep being caught.
    #[test]
    fn corrupted_cryptonote_address_is_not_a_confident_family() {
        for good in [XMR_MAINNET, XMR_PRIVKEY1, ZEPHYR_PRIVKEY1, SALVIUM_PRIVKEY1] {
            assert_eq!(detect_family(good), Some(Family::CryptoNote), "{good}");

            let mut bytes = good.as_bytes().to_vec();
            let i = bytes.len() / 2;
            bytes[i] = if bytes[i] == b'A' { b'B' } else { b'A' };
            let bad = String::from_utf8(bytes).unwrap();
            assert_eq!(bad.len(), good.len(), "the corruption must keep the length");
            assert_ne!(detect_family(&bad), Some(Family::CryptoNote), "{bad}");

            let truncated = &good[..good.len() - 1];
            assert_ne!(
                detect_family(truncated),
                Some(Family::CryptoNote),
                "{truncated}"
            );
        }
    }

    /// Every single-character substitution in a Monero address, swept, rather than the one flip
    /// above. 95 positions × 57 other base58 characters is 5415 near misses, none of which may come
    /// back `CryptoNote` — a four-byte checksum leaves a 2^-32 chance per string of a collision, so
    /// a sweep this size is expected to be clean and any hit is a real defect in the arm rather than
    /// bad luck.
    #[test]
    fn no_single_character_substitution_in_a_monero_address_still_detects() {
        const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        let good = XMR_PRIVKEY1.as_bytes();
        for i in 0..good.len() {
            for &c in ALPHABET {
                if c == good[i] {
                    continue;
                }
                let mut bytes = good.to_vec();
                bytes[i] = c;
                let bad = String::from_utf8(bytes).unwrap();
                assert_ne!(detect_family(&bad), Some(Family::CryptoNote), "{bad}");
            }
        }
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
        let derived: std::collections::HashSet<(String, usize)> =
            cryptonote_prefixes().map(cryptonote_tag).collect();
        let cached: std::collections::HashSet<(String, usize)> =
            cryptonote_tags().iter().cloned().collect();
        assert_eq!(cached, derived);

        // Deduplication must not have emptied it, and Monero's two tags must be in there — the
        // detection this cache serves is only as good as its contents.
        assert!(cached.contains(&("4".to_string(), 95)), "{cached:?}");
        assert!(cached.contains(&("8".to_string(), 95)), "{cached:?}");
    }

    /// The cache holds one empty tag and exactly one — Monero's testnet prefix 53. This is the
    /// assertion that used to read "no cached tag is empty", passing only because the empty ones had
    /// been filtered out one line earlier and taking a whole network's addresses with them.
    ///
    /// Pinning the count rather than merely allowing empties keeps the cost visible: each empty tag
    /// sends every base58 string of its length through a decode and a Keccak, which is affordable
    /// once and worth noticing if a future row makes it several times.
    #[test]
    fn exactly_one_cached_cryptonote_tag_is_empty() {
        let empty: Vec<_> = cryptonote_tags()
            .iter()
            .filter(|(tag, _)| tag.is_empty())
            .collect();
        assert_eq!(empty.len(), 1, "{:?}", cryptonote_tags());
        assert_eq!(
            empty[0].1, 95,
            "the empty tag is Monero testnet's, 95 chars"
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

    /// A real Ergo mainnet P2PK address. Unlike the Kaspa vector this file used to carry, this one
    /// was genuine all along — its Blake2b-256 checksum verifies — it was simply never checked,
    /// because the arm tested shape only.
    const ERGO_MAINNET: &str = "9f4QF8AD1nQ3nJahQVkMj8hFSVVzVom77b52JU7EW71Zexg6N8v";

    /// Ergo testnet P2PK for privkey=1, from `forager-wallet`'s `families/ergo.rs` KAT
    /// (`erg_testnet_privkey_one`). Testnet renders `3…` rather than `9…`, so the old
    /// `starts_with('9')` test could not classify it at all.
    const ERGO_TESTNET: &str = "3WwXpssaZwcNzaGMv3AgxBdTPJQBt5gCmqBsg3DykQ39bYdhJBsN";

    #[test]
    fn detects_ergo_p2pk() {
        assert_eq!(detect_family(ERGO_MAINNET), Some(Family::Ergo));
        // The mainnet KAT address from `forager-wallet`'s `families/ergo.rs`
        // (`erg_mainnet_privkey_one`), for a second independently sourced string.
        assert_eq!(
            detect_family("9fSgJ7BmUxBQJ454prQDQ7fQMBkXPLaAmDnimgTtjym6FYPHjAV"),
            Some(Family::Ergo)
        );
    }

    /// An Ergo testnet address is Ergo. The previous arm keyed on a leading `9`, which is the
    /// mainnet prefix byte 0x01; testnet is 0x11 and renders `3…`, so every testnet address the
    /// generator mints was classified `None`. Every other family here models both networks.
    #[test]
    fn detects_ergo_testnet() {
        assert_eq!(detect_family(ERGO_TESTNET), Some(Family::Ergo));
        assert_eq!(check(ERGO_TESTNET, Family::Ergo), Verdict::Ok);
    }

    /// The Ergo arm of the corruption sweep, and the reason this arm was rewritten: a typo'd or
    /// truncated Ergo address used to be reported as a confident `Ergo`, because the check was
    /// `starts_with('9')` plus a length window plus the base58 charset — none of which a single
    /// wrong character disturbs. A `Verdict::Ok` on a corrupted address is the one outcome this
    /// module exists to prevent.
    #[test]
    fn corrupted_ergo_address_is_not_a_confident_family() {
        for good in [ERGO_MAINNET, ERGO_TESTNET] {
            assert_eq!(detect_family(good), Some(Family::Ergo), "{good}");

            // Flip one character in the pubkey region — length, prefix and charset all unchanged.
            let mut bytes = good.as_bytes().to_vec();
            let i = bytes.len() / 2;
            bytes[i] = if bytes[i] == b'A' { b'B' } else { b'A' };
            let bad = String::from_utf8(bytes).unwrap();
            assert_ne!(detect_family(&bad), Some(Family::Ergo), "{bad}");

            // And a truncated paste, which the 40..=60 window happily accepted.
            let truncated = &good[..good.len() - 1];
            assert_ne!(detect_family(truncated), Some(Family::Ergo), "{truncated}");
        }
    }

    /// A leading `9` is one base58 character in 58, and the old arm asked for little else: any
    /// base58 string starting with `9` whose length fell in 40..=60 was answered `Ergo`. These are
    /// such strings. None of them is an address of any kind.
    #[test]
    fn a_leading_nine_is_not_an_ergo_address() {
        for junk in [
            "9zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            "9111111111111111111111111111111111111111111111",
            "9abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ",
        ] {
            assert!(junk.len() >= 40 && junk.len() <= 60, "{junk}");
            assert!(junk.bytes().all(is_base58_char), "{junk}");
            assert_ne!(detect_family(junk), Some(Family::Ergo), "{junk}");
        }
    }

    /// The prefix byte is inside the checksummed region, so a payload carrying an address type
    /// Ergo defines but this crate does not model (P2SH `0x02`, P2S `0x03`) must not be answered
    /// `Ergo` merely for having 38 bytes and a valid-looking shape. Built with a *correct*
    /// checksum, so the prefix test is the only thing that can reject them.
    #[test]
    fn only_the_p2pk_address_types_are_ergo() {
        for prefix in [0x00u8, 0x02, 0x03, 0x12, 0x13, 0xff] {
            let mut body = vec![prefix];
            body.extend_from_slice(&[0x11u8; 33]);
            let checksum = crate::hash::blake2b256(&body);
            body.extend_from_slice(&checksum[..4]);
            let addr = crate::codec::base58::encode(&body);
            assert_ne!(
                detect_family(&addr),
                Some(Family::Ergo),
                "{prefix:#04x}: {addr}"
            );
        }
        // The two that are modelled, built the same way, must classify — so the loop above is
        // rejecting on the prefix rather than on something incidental to how these are assembled.
        for prefix in ERGO_P2PK_PREFIXES {
            let mut body = vec![prefix];
            body.extend_from_slice(&[0x11u8; 33]);
            let checksum = crate::hash::blake2b256(&body);
            body.extend_from_slice(&checksum[..4]);
            let addr = crate::codec::base58::encode(&body);
            assert_eq!(
                detect_family(&addr),
                Some(Family::Ergo),
                "{prefix:#04x}: {addr}"
            );
        }
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
