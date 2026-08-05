//! `COINS.md` must document every coin the table actually supports.
//!
//! A coin table and a hand-written list drift the moment someone adds a row and forgets the doc.
//! The failure is quiet and user-facing: the tool supports a coin nobody can discover, or the doc
//! promises one that does not exist. Assert both directions.

use forager_wallet::{address_from_secret, address_from_secret_kind, coins, hd, Family, Network};

/// Privkey = 1, the canonical fixed key every known-answer test in this repository mints from
/// (`src/lib.rs`, `tests/cli.rs`, `tests/validate_roundtrip.rs` all declare it the same way).
/// Reusing it means the addresses this file checks against are the ones already pinned elsewhere.
const PRIV1: &str = "0000000000000000000000000000000000000000000000000000000000000001";

/// Privkey = 2. Needed only to *disprove* a prefix: one key can never show that a coin's leading
/// characters vary, so the `no fixed prefix` rows are checked against two keys.
const PRIV2: &str = "0000000000000000000000000000000000000000000000000000000000000002";

/// The character the table writes for the key-dependent tail of an address: U+2026 HORIZONTAL
/// ELLIPSIS, one char — **not** three periods. Matching the wrong one would silently stop stripping
/// the suffix, and every prefix comparison would then be against a prefix ending in `…`.
const ELLIPSIS: char = '…';

/// What the `Default address` cell must read when a coin has no stable leading characters at all
/// (`xdag`: base58check over a hash with no version byte). Spelled out rather than left blank so
/// the row states the fact instead of merely omitting it — and so
/// [`a_row_that_documents_no_fixed_prefix_really_has_none`] can hold it to that claim.
const NO_PREFIX: &str = "no fixed prefix";

fn doc() -> String {
    std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/COINS.md"))
        .expect("COINS.md must exist next to Cargo.toml")
}

/// One parsed row of the coin table.
struct Row {
    /// The `Ticker` cell with its backticks removed.
    ticker: String,
    /// The `Default address` cell verbatim, backticks and all — the assertions below distinguish a
    /// backticked prefix from bare prose, so the quoting is part of the value.
    default_address: String,
}

/// Parse the rows of the coin table.
///
/// Scan ONLY the coin table's section. Other tables in the file (HD purposes, families) also start
/// rows with a backticked token, and `--purpose` is not a coin.
fn coin_table_rows(md: &str) -> Vec<Row> {
    let section = md
        .split("## The coin table")
        .nth(1)
        .expect("COINS.md has a '## The coin table' section")
        .split("\n## ")
        .next()
        .expect("the section is terminated by the next heading");
    let rows: Vec<Row> = section
        .lines()
        .filter(|l| l.starts_with("| `"))
        .map(|l| {
            // A five-column row splits into seven parts: the empty strings either side of the
            // leading and trailing pipe, then the cells. Assert the shape rather than index blindly,
            // so a reordered or extra column fails here instead of comparing the wrong cell.
            let cells: Vec<&str> = l.split('|').map(str::trim).collect();
            assert_eq!(
                cells.len(),
                7,
                "coin table row has an unexpected shape: {l}"
            );
            Row {
                ticker: cells[1].trim_matches('`').to_string(),
                default_address: cells[4].to_string(),
            }
        })
        .collect();
    assert!(!rows.is_empty(), "parsed no rows — the parser is broken");
    rows
}

/// Mint `ticker`'s mainnet address from `secret`, or fail naming the row that could not be minted.
fn mint(ticker: &str, secret: &str) -> String {
    address_from_secret(ticker, secret, Network::Mainnet)
        .unwrap_or_else(|e| panic!("COINS.md documents `{ticker}`, which does not mint: {e}"))
        .address
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
    for row in coin_table_rows(&md) {
        assert!(
            coins::lookup(&row.ticker).is_some(),
            "COINS.md documents `{}`, which is not in the coin table",
            row.ticker
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

/// The `Default address` column is what a user reads before pasting an address into a miner config,
/// so it must be minted, not remembered.
///
/// It went unchecked for a long time and drifted: the `scash` row read `sc1q…` while the coin
/// deliberately keeps Bitcoin's HRP and mints `bc1q…`, and three rows said only "base58". Prose
/// inside a file the rest of which *is* machine-checked is worse than prose on its own, because a
/// reader trusts it for the company it keeps.
///
/// The assertion is a prefix, because the cell holds a prefix: a documented `bc1q…` claims that the
/// minted address *starts with* `bc1q`. It therefore cannot catch a prefix that is merely shorter
/// than it could be (`b…` would pass for Bitcoin) — only one that is wrong. Nor can it prove the
/// prefix holds for *every* key; that is a fact about the coin's version bytes, which the
/// `families::*` known-answer tests pin. What it does catch is the failure that actually happened:
/// a row describing a coin other than the one it names.
#[test]
fn every_documented_default_address_is_the_prefix_the_generator_mints() {
    let md = doc();
    for row in coin_table_rows(&md) {
        let minted = mint(&row.ticker, PRIV1);
        let cell = &row.default_address;

        // `` `bc1q…` `` -> `bc1q`. Anything that is not a backticked, ellipsis-terminated prefix
        // must be the one sanctioned prose value, so a row cannot go vague by accident.
        let Some(prefix) = cell
            .strip_prefix('`')
            .and_then(|c| c.strip_suffix('`'))
            .and_then(|c| c.strip_suffix(ELLIPSIS))
        else {
            assert_eq!(
                cell.as_str(),
                NO_PREFIX,
                "COINS.md row `{}`: the Default address cell must be either a backticked prefix \
                 ending in the ellipsis '{ELLIPSIS}' (one character, U+2026 — for example \
                 `bc1q{ELLIPSIS}`) or the exact words \"{NO_PREFIX}\". It reads {cell:?}. The \
                 address minted from privkey {PRIV1} is {minted}",
                row.ticker
            );
            continue;
        };
        assert!(
            !prefix.is_empty(),
            "COINS.md row `{}` documents an empty prefix, which asserts nothing. The address \
             minted from privkey {PRIV1} is {minted}",
            row.ticker
        );
        assert!(
            minted.starts_with(prefix),
            "COINS.md row `{}` documents the prefix `{prefix}{ELLIPSIS}`, but the address minted \
             from privkey {PRIV1} is {minted}. Reproduce it with `forager-wallet restore {PRIV1} \
             --coin {}` and write down what it actually prints — do not guess the prefix from the \
             coin's name, which is how this column drifted before",
            row.ticker,
            row.ticker
        );
    }
}

/// A row may only claim `no fixed prefix` if that is true, or the phrase becomes a way to opt a row
/// out of the check above.
///
/// One key can never establish that a coin's leading characters vary, so this mints two. XDAG is
/// the case in the table: `base58check(HASH160(pubkey))` with no version byte leaves the first
/// character — and the length — entirely up to the hash.
#[test]
fn a_row_that_documents_no_fixed_prefix_really_has_none() {
    let md = doc();
    for row in coin_table_rows(&md)
        .iter()
        .filter(|r| r.default_address == NO_PREFIX)
    {
        let (a, b) = (mint(&row.ticker, PRIV1), mint(&row.ticker, PRIV2));
        assert_ne!(
            a.chars().next(),
            b.chars().next(),
            "COINS.md row `{}` says \"{NO_PREFIX}\", but privkeys 1 and 2 mint {a} and {b}, which \
             begin with the same character. If the coin does have a stable prefix, document it",
            row.ticker
        );
    }
}

/// The `--legacy` sentence names a closed list of coins, which makes it a claim about the table:
/// exactly the SegWit-default rows have a second, base58 address form. A SegWit coin added without
/// touching that sentence leaves a user unable to discover the form their pool may require.
///
/// This is the only assertion the sentence below the table supports. The neighbouring `--testnet`
/// claim names no coins, and the table documents no testnet prefixes, so there is nothing there to
/// check that `lib.rs`'s per-coin testnet tests do not already cover.
#[test]
fn the_legacy_sentence_names_exactly_the_coins_with_a_second_address_form() {
    let md = doc();
    let mut listed: Vec<String> = md
        .split("SegWit-default coin (")
        .nth(1)
        .expect("COINS.md explains `--legacy` with a parenthesised coin list")
        .split(')')
        .next()
        .expect("the list is closed by a ')'")
        .split(',')
        .map(|t| t.trim().trim_matches('`').to_string())
        .collect();
    let mut segwit: Vec<String> = coins::COINS
        .iter()
        .filter(|c| c.family() == Family::SegwitV0)
        .map(|c| c.ticker.to_string())
        .collect();
    listed.sort();
    segwit.sort();
    assert_eq!(
        listed, segwit,
        "COINS.md says `--legacy` applies to {listed:?}, but the SegWit-default rows are {segwit:?}"
    );

    const BASE58: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    for ticker in &listed {
        let legacy = address_from_secret_kind(ticker, PRIV1, Network::Mainnet, true)
            .unwrap_or_else(|e| panic!("`{ticker} --legacy` must mint: {e}"))
            .address;
        assert_ne!(
            legacy,
            mint(ticker, PRIV1),
            "`{ticker} --legacy` returned the default address, so the sentence promises a form the \
             tool does not render"
        );
        assert!(
            legacy.chars().all(|c| BASE58.contains(c)),
            "COINS.md calls `{ticker} --legacy` the base58 form, but it minted {legacy}, which is \
             not base58"
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
