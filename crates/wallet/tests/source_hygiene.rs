//! Provenance guard: the shipped wallet source must not contain identifiers lifted from the
//! reference libraries that were consulted only for algorithm constants and test vectors.
//! Covered reference sources:
//!   - `ed25519-dalek` (Edwards25519 curve arithmetic)
//!   - `ripemd` crate (RIPEMD-160 compression)
//!   - Monero / CryptoNote C++ reference (spend/view key derivation, mnemonic)
//!   - `bip39` crate (BIP-39 mnemonic — not used; `src/bip39.rs` is written from the spec text,
//!     and this guard is what keeps that claim honest)
//!
//! **This guard scans `crates/wallet/src/` and nothing else**, and the tainted list below is
//! confined to what that tree can actually contain. Two groups of entries used to sit here that it
//! could not:
//!   - the `bs58` entries, for a base58 codec that lives in `forager-addr`; this crate has no
//!     base58 of its own, it calls `forager_addr::codec::base58`;
//!   - the `tiny-keccak` entries, for a permutation that was written here and then moved down into
//!     `forager-addr`'s `src/hash.rs` when detection grew a use for it.
//!
//! A third group was considered for this list and deliberately never added, for the same reason.
//! `forager-addr`'s guard grew entries for bech32/bech32m (the `bech32` crate, Bitcoin Core's
//! `src/bech32.cpp`, Wuille's reference C) and for the cashaddr family (Bitcoin ABC's
//! `src/cashaddr.cpp`, `kaspanet/rusty-kaspa`), and none of them are mirrored here. This crate
//! writes bech32 and Kaspa addresses — `src/families/segwitv0.rs`, `src/hd.rs` and `src/lib.rs` all
//! call `codec::bech32::encode` and `codec::cashaddr::encode` — but it does not *implement* either:
//! `src/lib.rs` line 53 is `pub(crate) use forager_addr::{codec, hexbytes};`, so every one of those
//! call sites resolves into the other crate's `src/codec/`, which this scan never reads. Copying
//! the entries here would produce exactly the dead list this split was made to end.
//!
//! That is not the case for `cn_fast_hash` and `GetCheckSum`, which are in both lists: this crate
//! really does hold CryptoNote checksum code of its own. The test is always "could this tree
//! contain the name", never "does this tree use the feature".
//!
//! Both groups now live in `crates/addr/tests/source_hygiene.rs`, next to the code they describe,
//! where they can match something. They were not copied into both lists: an entry naming code the
//! scanned tree could never hold reads as coverage and is not, which is the same objection this
//! repository makes to an unused entry in a dependency allow-list. The one pair that *is* in both
//! lists — `cn_fast_hash` and `GetCheckSum` — is marked below, with the reason.
//!
//! If a Keccak, base58, bech32 or cashaddr implementation ever comes into `crates/wallet/src/`, the
//! matching entries have to come with it; nothing automated will notice that this list went quiet.
//! The `pub(crate) use forager_addr::codec` re-export is the only thing keeping those three groups
//! out of this file, and a re-export is one line away from becoming a local module.
//!
//! The reason each crate guards its own tree, rather than one test walking both, is packaging:
//! `tests/` ships inside the published tarball (`cargo package --list -p forager-wallet` lists this
//! file), so a `../addr/src` path would make `cargo test` fail for anyone building from a
//! downloaded `.crate`, where no sibling crate exists.
//!
//! The two word-list files are DATA, not code, and are excluded from the identifier scan to avoid
//! false positives on legitimate dictionary words that happen to appear in any of the above
//! codebases:
//!   - `wordlist_en.rs` — Monero's 1626-word CryptoNote list
//!   - `wordlist_bip39_en.rs` — the official BIP-39 English 2048-word list
//!
//! Both are vendored verbatim from their published sources *because* they are data: the word
//! order is consensus-critical and cannot be independently derived, so "clean-room" has no meaning
//! for them. What the guard does police is the surrounding code — in particular the BIP-39
//! implementation in `src/bip39.rs`, which is written from the specification text and must not
//! borrow the `bip39` crate's API vocabulary (see the tainted entries at the end of the list).
//!
//! What this guard cannot do, so that nobody reads more into a green run than is there: it is a
//! literal substring search. It catches a transcription that kept the reference's names, which is
//! the cheapest and commonest way to get this wrong. Code that was copied and then renamed passes
//! it. It is a tripwire, not a proof of independent authorship.

use std::fs;
use std::path::{Path, PathBuf};

/// The pure-data files excluded from the identifier scan. See the module docs.
const WORDLIST_FILES: &[&str] = &["wordlist_en.rs", "wordlist_bip39_en.rs"];

/// Each entry is a distinctive symbol that would appear in our source *only* if code
/// was copy-pasted or transcribed from the named reference.  Independently derived
/// clean-room implementations use generic names (e.g. `compress`, `scalarmult_base`).
const TAINTED: &[(&str, &str)] = &[
    // --- ed25519-dalek — `src/curves/ed25519.rs` ---
    ("ExpandedSecretKey", "ed25519-dalek struct"),
    ("CompressedEdwardsY", "ed25519-dalek struct"),
    ("RistrettoPoint", "ed25519-dalek struct"),
    // --- NaCl / Monero C reference (Edwards25519 group ops) — `src/curves/ed25519.rs` ---
    ("ge_scalarmult_base", "NaCl/Monero C Edwards25519 op"),
    ("ge_p3_tobytes", "NaCl/Monero C Edwards25519 op"),
    ("ge_p3_to_p2", "NaCl/Monero C Edwards25519 op"),
    ("ge_frombytes_vartime", "NaCl/Monero C Edwards25519 op"),
    ("ge_fromfe_frombytes_vartime", "Monero C Edwards25519 op"),
    ("ge_madd", "NaCl C Edwards25519 op"),
    ("sc_reduce32", "NaCl/Monero C scalar reduction"),
    ("sc_muladd", "NaCl/Monero C scalar multiply-add"),
    // --- ripemd crate — `src/ripemd160.rs` ---
    ("compress160", "ripemd crate internal function"),
    ("process_msg_block", "ripemd reference internal function"),
    // --- Monero / CryptoNote C++ — `src/families/cryptonote.rs`, `src/mnemonic.rs` ---
    ("slow_hash", "Monero C++ PoW function"),
    ("keccak_hash_to_ec", "Monero C++ hash-to-curve"),
    //
    // The two entries below are also in `crates/addr/tests/source_hygiene.rs`, and that is
    // deliberate rather than a leftover. Monero derives the four-byte address checksum with
    // `cn_fast_hash`, and the two crates touch that checksum from opposite ends: this crate writes
    // it in `src/families/cryptonote.rs` when it mints an address, `forager-addr` re-derives it
    // when it verifies one. A transcription could land in either tree, so the names belong in both
    // lists — each copy sits in a crate whose source really could contain it, which is exactly the
    // test the rest of this split applies.
    ("cn_fast_hash", "CryptoNote/Monero C++ fast hash"),
    (
        "GetCheckSum",
        "Monero address checksum function (Pascal-case)",
    ),
    // --- bip39 crate (must not be used in clean-room keygen) — `src/bip39.rs` ---
    ("Mnemonic::from_phrase", "bip39 crate API"),
    ("Language::English", "bip39 crate API"),
];

/// Recursively collect every `.rs` file under `src/`, as `(path, text)` pairs — word lists
/// included. [`scanned_sources`] is what drops the word lists; this one keeps them so that
/// [`every_excluded_word_list_file_is_still_there_to_exclude`] can tell "excluded" apart from
/// "renamed out from under the exclusion list".
fn all_sources() -> Vec<(PathBuf, String)> {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut out = Vec::new();
    collect_rs(&src_dir, &mut out);
    out
}

/// The source the identifier scan actually covers: everything under `src/` minus the word-list
/// data files.
///
/// Paths come back alongside the text, and not just the concatenated source, for two reasons. The
/// scan below is a `contains` check and `"".contains(id)` is `false` for every `id`, so a walk that
/// silently found nothing would report a spotless tree — the path list is what
/// [`the_scan_reads_the_whole_source_tree_and_not_an_empty_string`] checks to rule that out. And
/// when the scan does fire, naming the file it fired in saves the reader a grep.
fn scanned_sources() -> Vec<(PathBuf, String)> {
    all_sources()
        .into_iter()
        .filter(|(p, _)| !is_wordlist(p))
        .collect()
}

fn is_wordlist(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| WORDLIST_FILES.contains(&n))
}

fn collect_rs(dir: &Path, out: &mut Vec<(PathBuf, String)>) {
    for entry in fs::read_dir(dir).expect("read this crate's src/ directory") {
        let p = entry.expect("read a directory entry").path();
        if p.is_dir() {
            collect_rs(&p, out);
        } else if p.extension().and_then(|e| e.to_str()) == Some("rs") {
            let text = fs::read_to_string(&p).expect("read a source file");
            out.push((p, text));
        }
    }
}

/// Every tainted identifier present in `src`, paired with the reference it came from.
///
/// Split out from the file walk so that [`the_scan_detects_a_planted_identifier`] can drive this
/// exact code path with a synthetic input. A substring search that has been broken into always
/// returning "nothing found" is indistinguishable from a clean source tree unless something plants
/// a string in it, so the guard's own assertion is worth no more than that self-test.
fn tainted_identifiers_in(src: &str) -> Vec<(&'static str, &'static str)> {
    TAINTED
        .iter()
        .filter(|(id, _)| src.contains(id))
        .copied()
        .collect()
}

#[test]
fn source_avoids_tainted_identifiers() {
    let sources = scanned_sources();
    assert!(
        !sources.is_empty(),
        "the walk read no `.rs` files, so the scan below would pass over an empty string — that is \
         a broken walk, not a clean source tree"
    );

    let mut found = Vec::new();
    for (path, text) in &sources {
        let file = path.file_name().and_then(|n| n.to_str()).unwrap_or("?");
        for (id, source) in tainted_identifiers_in(text) {
            found.push(format!("`{id}` (from {source}) in {file}"));
        }
    }

    assert!(
        found.is_empty(),
        "tainted identifier(s) present in shipped source: {} — use a clean-room derivation, not a \
         transcription from the reference",
        found.join("; ")
    );
}

#[test]
fn the_scan_reads_the_whole_source_tree_and_not_an_empty_string() {
    let sources = scanned_sources();
    let names: Vec<&str> = sources
        .iter()
        .filter_map(|(p, _)| p.file_name()?.to_str())
        .collect();

    assert!(
        names.contains(&"lib.rs"),
        "the walk missed `src/lib.rs`; it saw {names:?}"
    );

    // The curve arithmetic and the address families live one level down, in `src/curves/` and
    // `src/families/`, and most of the list above exists for them. A walk that stopped at the top
    // level would still find `lib.rs` and `bip39.rs` and look perfectly healthy while exempting
    // exactly the files the ed25519 entries were written for, so pin the recursion rather than the
    // file count — a count would only ever be updated, never read.
    assert!(
        names.contains(&"ed25519.rs"),
        "the walk did not recurse into `src/curves/`; it saw {names:?}"
    );
    assert!(
        names.contains(&"cryptonote.rs"),
        "the walk did not recurse into `src/families/`; it saw {names:?}"
    );

    // Finding the files is not the same as reading them: `read_to_string` handing back `""` for
    // every one of them would sail through the scan just as quietly as finding none.
    assert!(
        sources.iter().all(|(_, text)| !text.trim().is_empty()),
        "the walk read a source file as empty"
    );
}

#[test]
fn every_excluded_word_list_file_is_still_there_to_exclude() {
    // `WORDLIST_FILES` is an exemption, and an exemption naming a file that no longer exists is
    // the same shape of problem as an unused entry in a dependency allow-list: it reads as a
    // decision someone made, but it gates nothing, and it would silently start gating again if a
    // file of that name ever reappeared. Assert each name still matches a real file, so a rename
    // has to be dealt with here rather than quietly widening — or narrowing — the scan.
    let present: Vec<String> = all_sources()
        .iter()
        .filter_map(|(p, _)| Some(p.file_name()?.to_str()?.to_string()))
        .collect();

    for name in WORDLIST_FILES {
        assert!(
            present.iter().any(|n| n == name),
            "`{name}` is excluded from the scan but no longer exists under `src/`. Drop it from \
             WORDLIST_FILES rather than leaving a dead exemption behind."
        );
    }

    // And the exemption has to actually be applied, not merely declared.
    assert!(
        !scanned_sources().iter().any(|(p, _)| is_wordlist(p)),
        "a word-list file reached the identifier scan; the exclusion is declared but not applied"
    );
}

#[test]
fn the_scan_detects_a_planted_identifier() {
    // Plant a name from the reference this crate's curve arithmetic is most likely to be mistaken
    // for and require a hit.
    let planted = "void ge_scalarmult_base(ge_p3 *h, const unsigned char *a) {}";
    let hits = tainted_identifiers_in(planted);
    assert!(
        hits.iter().any(|(id, _)| *id == "ge_scalarmult_base"),
        "the scan missed a planted `ge_scalarmult_base`; it reported {hits:?}"
    );

    // The other direction matters just as much. If this crate's own clean-room names tripped the
    // scan, the guard would be permanently red and would be silenced rather than read, which is a
    // slower way of having no guard at all.
    let clean = "pub(crate) fn scalarmult_base(scalar: &[u8; 32]) -> [u8; 32] { [0; 32] }";
    let clean_hits = tainted_identifiers_in(clean);
    assert!(
        clean_hits.is_empty(),
        "the scan flagged this crate's own clean-room names: {clean_hits:?}"
    );

    // This crate calls the address codecs it does not implement, so its source is full of their
    // vocabulary — `bech32`, `hrp`, `witver`, `cashaddr` all appear in `src/`. None of it may
    // become an entry here. The module docs give the reason (the codecs live in `forager-addr`);
    // this makes the consequence testable, so that a future edit which copies the sibling list
    // across wholesale fails here, on a line that says why, instead of failing as a mystery.
    let borrowed_vocabulary = "
        use crate::{codec::bech32, codec::cashaddr};
        fn address(hrp: &str, prefix: &str, program: &[u8]) -> (String, String) {
            // 3-char HRP + '1' + witver(1) + 52 + 6 checksum.
            (bech32::encode(hrp, 1, program), cashaddr::encode(prefix, 0, program))
        }
    ";
    let borrowed_hits = tainted_identifiers_in(borrowed_vocabulary);
    assert!(
        borrowed_hits.is_empty(),
        "the scan flagged codec vocabulary this crate only *calls*: {borrowed_hits:?} — those \
         entries belong in `crates/addr/tests/source_hygiene.rs`, which scans the tree that \
         actually implements them"
    );
}
