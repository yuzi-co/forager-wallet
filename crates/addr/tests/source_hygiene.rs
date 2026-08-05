//! Provenance guard: the shipped `forager-addr` source must not contain identifiers lifted from the
//! reference libraries that were consulted only for algorithm constants and test vectors.
//! Covered reference sources:
//!   - `bs58` crate and the other base58 ports (base58check alphabet and builder API)
//!   - Saarinen's `tiny_sha3`, and Monero's `src/crypto/keccak.c` which is the same code by the
//!     same author (Keccak-f[1600] permutation)
//!   - `tiny-keccak` and the RustCrypto `sha3` crate (that permutation, in Rust)
//!   - the Keccak team's own reference code, XKCP (that permutation, in C)
//!   - Monero / CryptoNote C++ reference (the four-byte address checksum)
//!
//! This is the sibling of `crates/wallet/tests/source_hygiene.rs`, and the split between the two is
//! deliberate: **each crate scans only its own `src/`.** The wallet's guard used to carry the `bs58`
//! entries, but the base58 codec they name lives here, in `src/codec/base58.rs`, which that scan
//! never reads — so those entries had never been able to match anything. The Keccak entries had the
//! mirror-image problem: the permutation was written in `forager-wallet`, then moved down into
//! `src/hash.rs` here when detection grew a use for it, which took it out of the only tree anyone
//! was scanning. A clean-room claim was being made about this crate and enforced about the other
//! one, and this crate is the half the closed miner links.
//!
//! The fix is not for one crate's test to walk the other crate's source. `tests/` ships inside the
//! published tarball — `cargo package --list -p forager-addr` lists this very file — so a relative
//! path to a sibling crate would make `cargo test` fail for anyone who builds from a downloaded
//! `.crate`: there is no sibling directory next to an extracted tarball. A crate that guards its own
//! `src/` needs no such path, and cannot fall out of the scanned set again when a module moves.
//!
//! What this guard cannot do, so that nobody reads more into a green run than is there: it is a
//! literal substring search. It catches a transcription that kept the reference's names, which is
//! the cheapest and commonest way to get this wrong. Code that was copied and then renamed passes
//! it. It is a tripwire, not a proof of independent authorship.

use std::fs;
use std::path::{Path, PathBuf};

/// Each entry is a distinctive symbol that would appear in our source *only* if code was
/// copy-pasted or transcribed from the named reference.  Independently derived clean-room
/// implementations use generic names, and this crate's do: the permutation is `keccak_f` over `RC`
/// and `ROT`, the base58 table is a bare `ALPHABET`, and no reference below spells any of those
/// that way.
///
/// Every name here was read out of the reference it is attributed to, not recalled. Entries are
/// grouped by the file in this crate they could plausibly land in, because an entry in a crate
/// whose source could never contain it is not coverage — it is a line that looks like coverage.
const TAINTED: &[(&str, &str)] = &[
    // --- base58 ports — `src/codec/base58.rs` ---
    //
    // These moved here from `crates/wallet/tests/source_hygiene.rs`. They were inert there:
    // `forager-wallet` has no base58 of its own, it calls `forager_addr::codec::base58`. The
    // alphabet constants are spelled with the `_ALPHABET` suffix by the Python `base58` package
    // and by the ports that followed it; the current Rust `bs58` crate spells the same values
    // `Alphabet::BITCOIN` and reaches them through a builder, so both vocabularies are listed.
    ("BITCOIN_ALPHABET", "Python `base58` package constant"),
    ("RIPPLE_ALPHABET", "Python `base58` package constant"),
    ("XRP_ALPHABET", "Python `base58` package constant"),
    (
        "FLICKR_ALPHABET",
        "base58 port constant, `bs58`'s `Alphabet::FLICKR`",
    ),
    ("into_vec_with_encoder", "bs58-style decoder builder method"),
    ("Alphabet::BITCOIN", "bs58 crate alphabet constant"),
    ("EncodeBuilder", "bs58 crate builder type"),
    ("DecodeBuilder", "bs58 crate builder type"),
    ("with_alphabet", "bs58 crate builder method"),
    // --- Keccak-f[1600] — `src/hash.rs` ---
    //
    // The two entries below came with the permutation when it moved out of `forager-wallet`; the
    // rest are new, because a two-name list for a hash this widely copy-pasted was thin.
    ("keccakf1600", "tiny-keccak internal function"),
    (
        "KECCAK_F_1600_ROUND_CONSTANTS",
        "tiny-keccak constant array name",
    ),
    //
    // Saarinen's `tiny_sha3` and Monero's `src/crypto/keccak.c` — the same implementation by the
    // same author, and the single most-copied Keccak in this corner of the ecosystem. It is what a
    // CryptoNote wallet reaches for, so it is the most likely thing to find transcribed here.
    // `keccakf` subsumes `keccakf1600` above as a substring; both are kept so a reader can see
    // which reference each spelling comes from.
    (
        "keccakf",
        "Saarinen `tiny_sha3` / Monero `keccak.c` permutation",
    ),
    (
        "keccakf_rndc",
        "Saarinen `tiny_sha3` / Monero round-constant array",
    ),
    ("keccakf_rotc", "Saarinen `tiny_sha3` rotation-offset array"),
    (
        "keccakf_piln",
        "Saarinen `tiny_sha3` lane-permutation array",
    ),
    ("KECCAKF_ROUNDS", "Saarinen `tiny_sha3` round-count macro"),
    (
        "sha3_keccakf",
        "Saarinen `tiny_sha3` permutation entry point",
    ),
    ("KECCAK_ROUNDS", "Monero `keccak.c` round-count macro"),
    ("KECCAK_CTX", "Monero `keccak.c` context struct"),
    ("keccak1600", "Monero `keccak.c` entry point"),
    (
        "ROTL64",
        "Saarinen/Monero C rotate macro; Rust has `rotate_left`",
    ),
    //
    // The Keccak team's own code (XKCP), including the widely reproduced
    // `Keccak-readable-and-compact.c` that most from-the-spec ports start from.
    ("KeccakF1600_StatePermute", "XKCP reference permutation"),
    (
        "KeccakP1600_Permute_24rounds",
        "XKCP reference permutation entry point",
    ),
    ("KeccakRoundConstants", "XKCP reference constant table"),
    ("KeccakRhoOffsets", "XKCP reference rotation-offset table"),
    ("LFSR86540", "XKCP round-constant LFSR"),
    ("tKeccakLane", "XKCP reference lane typedef"),
    ("ROL64", "XKCP rotate macro; Rust has `rotate_left`"),
    //
    // `tiny-keccak` and RustCrypto, the two crates a Rust author would copy from.
    //
    // Their permutation function names — `keccakf`/`keccak_p`/`keccak_f` — are a special case. The
    // C spelling `keccakf` is listed above because no Rust author writing from the spec would drop
    // the underscore. `keccak_p` and `keccak_f` are the specification's own vocabulary, this
    // crate's function is called `keccak_f`, and a guard that forbade spec vocabulary would only
    // teach the next author to pick a worse name. They are deliberately absent, and this guard
    // therefore cannot tell a `keccak_f` written from the spec from one copied out of a crate.
    ("KeccakState", "tiny-keccak state struct"),
    ("keccak_function", "tiny-keccak trait method"),
    ("xorin", "tiny-keccak absorb helper"),
    ("setout", "tiny-keccak squeeze helper"),
    ("Keccak256Full", "RustCrypto `sha3` crate type"),
    ("absorb_u64_le", "RustCrypto `sha3` crate internal"),
    // --- Monero / CryptoNote C++ — `src/codec/cryptonote.rs`, `src/validate.rs` ---
    //
    // These two are the one place this split duplicates `crates/wallet/tests/source_hygiene.rs`,
    // and the duplication is the point rather than an oversight. Monero derives the four-byte
    // address checksum with `cn_fast_hash`, and the two crates touch that checksum from opposite
    // ends: `forager-wallet` writes it when it mints an address, this crate re-derives it when it
    // verifies one. A transcription could land in either tree, so the name has to be in both lists.
    // That is not the dead-entry problem the rest of the split exists to avoid — each copy sits in
    // a crate whose source really could contain the name.
    ("cn_fast_hash", "CryptoNote/Monero C++ fast hash"),
    (
        "GetCheckSum",
        "Monero address checksum function (Pascal-case)",
    ),
];

/// Recursively collect every `.rs` file under this crate's `src/`, as `(path, text)` pairs.
///
/// Paths come back alongside the text, and not just the concatenated source, for two reasons. The
/// scan below is a `contains` check and `"".contains(id)` is `false` for every `id`, so a walk that
/// silently found nothing would report a spotless tree — the path list is what
/// [`the_scan_reads_the_whole_source_tree_and_not_an_empty_string`] checks to rule that out. And
/// when the scan does fire, naming the file it fired in saves the reader a grep.
fn scanned_sources() -> Vec<(PathBuf, String)> {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut out = Vec::new();
    collect_rs(&src_dir, &mut out);
    out
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

    // The codecs live one level down, in `src/codec/`, and the base58 entries above exist for one
    // of them. A walk that stopped at the top level would still find `lib.rs` and `hash.rs` and
    // look perfectly healthy while exempting exactly the file those entries were moved here for,
    // so pin the recursion rather than the file count — a count would only ever be updated, never
    // read.
    assert!(
        names.contains(&"base58.rs"),
        "the walk did not recurse into `src/codec/`; it saw {names:?}"
    );

    // Finding the files is not the same as reading them: `read_to_string` handing back `""` for
    // every one of them would sail through the scan just as quietly as finding none.
    assert!(
        sources.iter().all(|(_, text)| !text.trim().is_empty()),
        "the walk read a source file as empty"
    );
}

#[test]
fn the_scan_detects_a_planted_identifier() {
    // Plant a name from the reference this crate's Keccak is most likely to be mistaken for and
    // require a hit. `keccakf_rndc` also matches the shorter `keccakf` entry, which is why this
    // looks for the specific name among the hits rather than asserting on the whole list.
    let planted = "static const uint64_t keccakf_rndc[24] = { 1 };";
    let hits = tainted_identifiers_in(planted);
    assert!(
        hits.iter().any(|(id, _)| *id == "keccakf_rndc"),
        "the scan missed a planted `keccakf_rndc`; it reported {hits:?}"
    );

    // The other direction matters just as much. If this crate's own clean-room names tripped the
    // scan, the guard would be permanently red and would be silenced rather than read, which is a
    // slower way of having no guard at all.
    let clean = "fn keccak_f(state: &mut [u64; 25]) { for &rc in &RC { let _ = rc; } }";
    let clean_hits = tainted_identifiers_in(clean);
    assert!(
        clean_hits.is_empty(),
        "the scan flagged this crate's own clean-room names: {clean_hits:?}"
    );
}
