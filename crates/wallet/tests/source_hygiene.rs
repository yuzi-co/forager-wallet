//! Provenance guard: the shipped wallet source must not contain identifiers lifted from the
//! reference libraries that were consulted only for algorithm constants and test vectors.
//! Covered reference sources:
//!   - `ed25519-dalek` (Edwards25519 curve arithmetic)
//!   - `tiny-keccak` (Keccak-f[1600] permutation)
//!   - `ripemd` crate (RIPEMD-160 compression)
//!   - `bs58` crate (base58check encoding)
//!   - Monero / CryptoNote C++ reference (spend/view key derivation, mnemonic)
//!   - `bip39` crate (BIP-39 mnemonic — not used; `src/bip39.rs` is written from the spec text,
//!     and this guard is what keeps that claim honest)
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

use std::fs;
use std::path::Path;

/// The pure-data files excluded from the identifier scan. See the module docs.
const WORDLIST_FILES: &[&str] = &["wordlist_en.rs", "wordlist_bip39_en.rs"];

/// Recursively collect all `.rs` source text under `src/`, skipping the word-list data files.
fn read_src_excluding_wordlist() -> String {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut out = String::new();
    collect_rs(&src_dir, &mut out);
    out
}

fn collect_rs(dir: &Path, out: &mut String) {
    for entry in fs::read_dir(dir).unwrap() {
        let p = entry.unwrap().path();
        if p.is_dir() {
            collect_rs(&p, out);
        } else if p.extension().and_then(|e| e.to_str()) == Some("rs") {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if WORDLIST_FILES.contains(&name) {
                continue; // skip the word-list data files
            }
            out.push_str(&fs::read_to_string(&p).unwrap());
        }
    }
}

#[test]
fn source_avoids_tainted_identifiers() {
    let src = read_src_excluding_wordlist();

    // Each entry is a distinctive symbol that would appear in our source *only* if code
    // was copy-pasted or transcribed from the named reference.  Independently derived
    // clean-room implementations use generic names (e.g. `compress`, `keccak_f`).
    let tainted: &[(&str, &str)] = &[
        // --- ed25519-dalek ---
        ("ExpandedSecretKey", "ed25519-dalek struct"),
        ("CompressedEdwardsY", "ed25519-dalek struct"),
        ("RistrettoPoint", "ed25519-dalek struct"),
        // --- NaCl / Monero C reference (Edwards25519 group ops) ---
        ("ge_scalarmult_base", "NaCl/Monero C Edwards25519 op"),
        ("ge_p3_tobytes", "NaCl/Monero C Edwards25519 op"),
        ("ge_p3_to_p2", "NaCl/Monero C Edwards25519 op"),
        ("ge_frombytes_vartime", "NaCl/Monero C Edwards25519 op"),
        ("ge_fromfe_frombytes_vartime", "Monero C Edwards25519 op"),
        ("ge_madd", "NaCl C Edwards25519 op"),
        ("sc_reduce32", "NaCl/Monero C scalar reduction"),
        ("sc_muladd", "NaCl/Monero C scalar multiply-add"),
        // --- tiny-keccak ---
        ("keccakf1600", "tiny-keccak internal function"),
        (
            "KECCAK_F_1600_ROUND_CONSTANTS",
            "tiny-keccak constant array name",
        ),
        // --- ripemd crate ---
        ("compress160", "ripemd crate internal function"),
        ("process_msg_block", "ripemd reference internal function"),
        // --- bs58 crate ---
        ("BITCOIN_ALPHABET", "bs58 crate constant"),
        ("FLICKR_ALPHABET", "bs58 crate constant"),
        ("RIPPLE_ALPHABET", "bs58 crate constant"),
        ("into_vec_with_encoder", "bs58 crate method"),
        // --- Monero / CryptoNote C++ ---
        ("cn_fast_hash", "CryptoNote/Monero C++ fast hash"),
        ("slow_hash", "Monero C++ PoW function"),
        ("keccak_hash_to_ec", "Monero C++ hash-to-curve"),
        (
            "GetCheckSum",
            "Monero address checksum function (Pascal-case)",
        ),
        // --- bip39 crate (must not be used in clean-room keygen) ---
        ("Mnemonic::from_phrase", "bip39 crate API"),
        ("Language::English", "bip39 crate API"),
    ];

    for (id, source) in tainted {
        assert!(
            !src.contains(id),
            "tainted identifier `{id}` (from {source}) present in shipped source — \
             use a clean-room derivation, not a transcription from the reference"
        );
    }
}
