//! Structural guard on this crate's dependency list.
//!
//! `forager-addr` is the half the closed miner links. The claim in the repository README is that
//! the shipped miner contains no key-generation code, and that a user can check that from the
//! manifest. The claim holds only while this crate's dependency list stays minimal, so assert it
//! rather than trusting review to notice.
//!
//! The claim is about key generation only. The miner does link a curve and an entropy source, for
//! reasons unrelated to wallets, so do not widen this comment into a "no curve anywhere" claim.
//!
//! This file guards *what this crate depends on*. Its sibling `tests/source_hygiene.rs` guards
//! *what this crate's own source was written from* — the clean-room provenance of the base58 codec
//! and the Keccak permutation. Neither subsumes the other, and both scan only this crate, so both
//! keep working inside the published tarball.

/// The complete allowed external dependency set.
///
/// `sha2` computes the base58check checksum and `blake2b_simd` the Ergo P2PK one. `num-bigint` and
/// `num-traits` do base58's decode arithmetic — base58's alphabet is not a power of two, so the
/// conversion needs bignums. None of the four carries an entropy source, curve arithmetic or a
/// network.
///
/// Adding to this list is a deliberate decision, not an accident. Read the spec before changing it.
const ALLOWED: &[&str] = &["sha2", "blake2b_simd", "num-bigint", "num-traits"];

/// Parse the crate's declared dependencies out of a manifest, in either shape a manifest for this
/// crate comes in.
///
/// There are two, and both have to work, because two different files are called `Cargo.toml` here:
///
///   - the one in the repository, which writes the table inline — `[dependencies]` followed by one
///     `name = …` line per entry;
///   - the one `cargo package` synthesizes into the published tarball, which normalizes every
///     dependency into its own `[dependencies.name]` table.
///
/// This file ships *inside* that tarball — `cargo package --list -p forager-addr` lists it — so it
/// is compiled and run by anyone who builds from a downloaded `.crate`, against a manifest that
/// never appears in the repository. A parser that understood only the first shape did not fail
/// there, it panicked there on "crate has a `[dependencies]` section", which is worse than either
/// passing or failing: it reads as a broken test rather than as a broken claim, and the first thing
/// anyone does with a test that panics on their machine is stop running it.
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

    // Shape 2 — one `[dependencies.name]` table per dependency.
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
            "wallet-addr grew a dependency on `{name}`. The closed miner links this crate; adding \
             a curve, entropy or mnemonic crate here breaks the no-keygen claim. See \
             the repository README."
        );
    }

    // The reverse direction, mirroring the sibling guard in `crates/wallet/tests/
    // dependency_hygiene.rs`: an entry left in ALLOWED after the manifest dropped it is not
    // harmless. An allow-list is a gate, so an unused entry is a pre-authorized slot — that crate
    // could come back later and clear the gate with nobody deciding anything.
    for allowed in ALLOWED {
        assert!(
            found.iter().any(|n| n == allowed),
            "ALLOWED lists `{allowed}`, which is no longer a dependency. Drop it here rather than \
             leaving a pre-authorized slot behind."
        );
    }
}

#[test]
fn parser_rejects_a_disallowed_dependency() {
    // Pin the guard's own behaviour, so a future edit to the parser cannot silently make the
    // assertion above unfalsifiable.
    let fake = "[dependencies]\nsha2 = \"0.10\"\ngetrandom = \"0.2\"\n\n[lints]\n";
    let found = declared_dependencies(fake);
    assert_eq!(found, vec!["sha2", "getrandom"]);
    assert!(!found.iter().all(|n| ALLOWED.contains(&n.as_str())));
}

#[test]
fn the_parser_reads_the_manifest_shape_cargo_package_writes() {
    // The tarball's manifest, in miniature. Pinned with a synthetic input rather than only by the
    // real run above, because the real run only sees this shape when someone happens to be testing
    // an extracted `.crate` — which is exactly the case nobody was checking when the parser
    // panicked there.
    let packaged = concat!(
        "[package]\nname = \"forager-addr\"\n\n",
        "[dependencies.blake2b_simd]\nversion = \"1\"\n\n",
        "[dependencies.sha2]\nversion = \"0.10\"\n\n",
        "[lints.rust]\n",
    );
    let found = declared_dependencies(packaged);
    assert_eq!(found, vec!["blake2b_simd", "sha2"]);

    // A dependency that is not on the allow-list still has to be caught in this shape; the whole
    // point of parsing it is that the gate holds for a tarball build too.
    let grown = format!("{packaged}[dependencies.getrandom]\nversion = \"0.2\"\n");
    let found = declared_dependencies(&grown);
    assert!(found.iter().any(|n| n == "getrandom"));
    assert!(!found.iter().all(|n| ALLOWED.contains(&n.as_str())));
}

#[test]
fn crate_forbids_unsafe() {
    let lib = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"))
        .expect("read own lib.rs");
    assert!(
        lib.contains("#![forbid(unsafe_code)]"),
        "wallet-addr must forbid unsafe: it is linked by the miner and audited by users"
    );
}
