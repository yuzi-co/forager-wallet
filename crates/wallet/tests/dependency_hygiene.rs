//! Structural guard on this crate's dependency list.
//!
//! This is the crate that ships the binary, and the crate that makes the loudest claim: both
//! `README.md` and `crates/wallet/README.md` name this dependency list verbatim, tell the reader
//! that none of it can open a socket, and invite them to confirm that from `Cargo.toml` without
//! reading a line of code. A dependency added here quietly falsifies a claim printed in two
//! READMEs, so assert the list rather than trusting review to notice.
//!
//! This guard is the crate-local half of the check. The other half is the `[bans] deny` list in
//! the repository's `deny.toml`, which catches network-capable crates arriving *transitively*,
//! under any feature combination. This test catches the direct declaration; that one catches what
//! the direct declaration drags in. Neither subsumes the other.
//!
//! `crates/addr` has the same guard for its own, tighter reasons (see `crates/addr/tests/
//! hygiene.rs`) — there, the property being protected is that the closed miner links no
//! key-generation code.

/// The complete allowed direct dependency set.
///
/// `k256` is secp256k1 point arithmetic; `bip32` is BIP32/BIP44 derivation for `--hd`; `pbkdf2`
/// and `sha2` are the BIP-39 phrase→seed KDF and the hashes; `unicode-normalization` is the NFKD
/// BIP-39 mandates on the phrase and passphrase; `blake2b_simd` and `num-bigint`/`num-traits` are
/// the remaining hash and the base58 bignum arithmetic the address codecs need; `getrandom` is the
/// entropy source; `zeroize` wipes key material on drop; `forager-addr` is the workspace's
/// classification half. None of them carries a network stack.
///
/// `pbkdf2` was already in the tree transitively via `bip32`, at the same version and feature
/// selection, so declaring it directly added no crate. `unicode-normalization` is genuinely new:
/// it is a pure-Rust Unicode data table with no I/O, and hand-rolling NFKD would be strictly worse
/// than depending on it.
///
/// This is deliberately one flat `const` so that a legitimate dependency change is a one-line
/// edit. If this test fails because the dependency list genuinely moved, update this list — and,
/// in the same commit, the two READMEs, whose "Offline by construction" sections spell out exactly
/// this data in prose.
const ALLOWED: &[&str] = &[
    "k256",
    "num-bigint",
    "num-traits",
    "sha2",
    "forager-addr",
    "blake2b_simd",
    "getrandom",
    "bip32",
    "pbkdf2",
    "unicode-normalization",
    "zeroize",
];

/// Parse the crate's own `[dependencies]` section into a list of dependency names.
///
/// Reading the manifest text rather than `cargo metadata` keeps the guard dependency-free — a test
/// that defends a dependency list should not need a dependency to run.
///
/// Two manifest shapes, because `cargo package` does not ship the one that was written. Publishing
/// rewrites the manifest, normalizing every dependency into its own `[dependencies.<name>]` table,
/// so a parser that only understands the inline `[dependencies]` form panics on an extracted
/// `.crate` — the one situation where this guard matters most, since a user verifying the
/// no-network claim from a published tarball is exactly who it is written for. The sibling guard in
/// `crates/addr/tests/hygiene.rs` had the same defect and carries the same fix.
fn declared_dependencies(manifest: &str) -> Vec<String> {
    let mut names = Vec::new();

    // Shape 1 — an inline `[dependencies]` table. Terminated by the next section header or by the
    // end of the file. `[dev-dependencies]`, `[build-dependencies]` and `[dependencies.name]` all
    // fail to contain the literal `[dependencies]`, so none of them opens this section by mistake.
    if let Some(rest) = manifest.split("[dependencies]").nth(1) {
        let section = rest.split("\n[").next().unwrap_or(rest);
        names.extend(
            section
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .filter_map(|l| l.split(['=', ' ']).next())
                .filter(|n| !n.is_empty())
                .map(str::to_string),
        );
    }

    // Shape 2 — one `[dependencies.name]` table per dependency, which is what publishing writes.
    names.extend(
        manifest
            .lines()
            .map(str::trim)
            .filter_map(|l| l.strip_prefix("[dependencies.")?.strip_suffix(']'))
            .map(str::to_string),
    );

    names
}

#[test]
fn dependency_list_is_exactly_the_allowed_set() {
    let manifest = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .expect("read own Cargo.toml");

    let found = declared_dependencies(&manifest);
    assert!(
        !found.is_empty(),
        "parsed no dependencies — the parser is broken, not the manifest"
    );

    for name in &found {
        assert!(
            ALLOWED.contains(&name.as_str()),
            "forager-wallet grew a dependency on `{name}`. This crate ships the offline binary, \
             and README.md states that none of its dependencies can open a socket. If `{name}` \
             can, that claim is now false and the README is wrong. If it cannot, add it to \
             ALLOWED in this file and to the dependency lists in README.md and \
             crates/wallet/README.md."
        );
    }

    // The reverse direction: an entry removed from the manifest but left in ALLOWED turns the
    // allow-list into a stale wish. Catch that here rather than letting it rot.
    for allowed in ALLOWED {
        assert!(
            found.iter().any(|n| n == allowed),
            "ALLOWED lists `{allowed}`, which is no longer a dependency. Drop it here and from \
             the dependency lists in README.md and crates/wallet/README.md."
        );
    }
}

#[test]
fn parser_rejects_a_disallowed_dependency() {
    // Pin the guard's own behaviour, so a future edit to the parser cannot silently make the
    // assertion above unfalsifiable. `tokio` is the canonical thing this guard exists to stop.
    let fake = "[dependencies]\nk256 = \"0.13\"\ntokio = { version = \"1\" }\n\n[lints]\n";
    let found = declared_dependencies(fake);
    assert_eq!(found, vec!["k256", "tokio"]);
    assert!(!found.iter().all(|n| ALLOWED.contains(&n.as_str())));
}

#[test]
fn the_parser_reads_the_manifest_shape_cargo_package_writes() {
    // The tarball's manifest, in miniature. Pinned synthetically rather than only by the real run
    // above, because the real run never sees this shape: `cargo package -p forager-wallet` cannot
    // even resolve until `forager-addr` 0.2.0 is on crates.io, so nothing here would exercise the
    // packaged form until the day someone publishes — and a guard that starts working only after
    // release is not a guard.
    let packaged = concat!(
        "[package]\nname = \"forager-wallet\"\n\n",
        "[dependencies.k256]\nversion = \"0.13\"\n\n",
        "[dependencies.zeroize]\nversion = \"1\"\n\n",
        "[lints.rust]\n",
    );
    let found = declared_dependencies(packaged);
    assert_eq!(found, vec!["k256", "zeroize"]);

    // A network stack has to be caught in this shape too; that the gate holds for a tarball build
    // is the entire reason for parsing it.
    let grown = format!("{packaged}[dependencies.tokio]\nversion = \"1\"\n");
    let found = declared_dependencies(&grown);
    assert!(found.iter().any(|n| n == "tokio"));
    assert!(!found.iter().all(|n| ALLOWED.contains(&n.as_str())));
}

#[test]
fn crate_forbids_unsafe() {
    let lib = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"))
        .expect("read own lib.rs");
    assert!(
        lib.contains("#![forbid(unsafe_code)]"),
        "forager-wallet must forbid unsafe: it handles private key material and both READMEs \
         state that it forbids unsafe"
    );
}
