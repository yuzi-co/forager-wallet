//! `COINS.md` must document every coin the table actually supports.
//!
//! A coin table and a hand-written list drift the moment someone adds a row and forgets the doc.
//! The failure is quiet and user-facing: the tool supports a coin nobody can discover, or the doc
//! promises one that does not exist. Assert both directions.

use forager_wallet::{coins, hd};

fn doc() -> String {
    std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/COINS.md"))
        .expect("COINS.md must exist next to Cargo.toml")
}

#[test]
fn every_coin_is_documented() {
    let md = doc();
    let missing: Vec<&str> = coins::COINS
        .iter()
        .map(|c| c.ticker)
        .filter(|t| !md.contains(&format!("`{t}`")))
        .collect();
    assert!(
        missing.is_empty(),
        "these coins are in the table but not in COINS.md: {missing:?}"
    );
}

#[test]
fn every_documented_coin_exists() {
    let md = doc();
    // Scan ONLY the coin table's section. Other tables in the file (HD purposes, families) also
    // start rows with a backticked token, and `--purpose` is not a coin.
    let section = md
        .split("## The coin table")
        .nth(1)
        .expect("COINS.md has a '## The coin table' section")
        .split("\n## ")
        .next()
        .expect("the section is terminated by the next heading");
    let claimed: Vec<String> = section
        .lines()
        .filter_map(|l| l.strip_prefix("| `"))
        .filter_map(|l| l.split('`').next())
        .map(str::to_string)
        .collect();
    assert!(!claimed.is_empty(), "parsed no rows — the parser is broken");
    for t in &claimed {
        assert!(
            coins::lookup(t).is_some(),
            "COINS.md documents `{t}`, which is not in the coin table"
        );
    }
}

#[test]
fn every_hd_coin_documents_its_path() {
    let md = doc();
    for c in hd::supported() {
        let slip44 = c.hd_slip44.expect("an HD row carries a slip44");
        let purpose = hd::native_purpose(c).expect("an HD row has a native purpose");
        let path = format!("`m/{}'/{slip44}'`", purpose.number());
        assert!(
            md.contains(&path),
            "COINS.md is missing the HD path {path} for `{}`",
            c.ticker
        );
    }
}

/// Every custom-token family the CLI accepts must appear in the grammar section, or a user cannot
/// discover the one family that would have covered their coin.
#[test]
fn every_token_family_is_documented() {
    let md = doc();
    for g in coins::TOKEN_GRAMMAR {
        assert!(
            md.contains(g.family),
            "COINS.md does not document the `{}` custom-token family",
            g.family
        );
    }
}
