//! Structural guard on this crate's dependency list.
//!
//! `forager-addr` is the half the closed miner links. The claim in the repository README is that
//! the shipped miner contains no key-generation code, and that a user can check that from the
//! manifest. The claim holds only while this crate's dependency list stays minimal, so assert it
//! rather than trusting review to notice.
//!
//! The claim is about key generation only. The miner does link a curve and an entropy source, for
//! reasons unrelated to wallets, so do not widen this comment into a "no curve anywhere" claim.

/// The complete allowed external dependency set.
///
/// `sha2` computes the base58check checksum. `num-bigint` and `num-traits` do base58's decode
/// arithmetic — base58's alphabet is not a power of two, so the conversion needs bignums. None of
/// the three carries an entropy source, curve arithmetic or a network.
///
/// Adding to this list is a deliberate decision, not an accident. Read the spec before changing it.
const ALLOWED: &[&str] = &["sha2", "num-bigint", "num-traits"];

/// Parse the crate's own `[dependencies]` section into a list of dependency names.
fn declared_dependencies(manifest: &str) -> Vec<String> {
    let section = manifest
        .split("[dependencies]")
        .nth(1)
        .expect("crate has a [dependencies] section")
        .split("\n[")
        .next()
        .expect("the dependencies section is terminated by another section or end of file");

    section
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split(['=', ' ']).next())
        .filter(|n| !n.is_empty())
        .map(str::to_string)
        .collect()
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
fn crate_forbids_unsafe() {
    let lib = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"))
        .expect("read own lib.rs");
    assert!(
        lib.contains("#![forbid(unsafe_code)]"),
        "wallet-addr must forbid unsafe: it is linked by the miner and audited by users"
    );
}
