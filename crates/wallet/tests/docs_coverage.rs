//! `COINS.md` must document every coin the table actually supports.
//!
//! A coin table and a hand-written list drift the moment someone adds a row and forgets the doc.
//! The failure is quiet and user-facing: the tool supports a coin nobody can discover, or the doc
//! promises one that does not exist. Assert both directions.

use forager_addr::codec::{base58, bech32, cryptonote};
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

/// The two markers a `Default address` cell may carry after its prefix.
///
/// An **unmarked** cell makes the strong claim, and [`leading_characters`] proves it: *every* key
/// mints an address beginning with those characters. That is a fact about the coin's fixed leading
/// bytes, and it is derived from them — not sampled, not remembered.
///
/// The markers are the only two ways a row can fail to make that claim, which is what lets a
/// reader trust a bare cell:
///
/// - [`MOST_KEYS`] — the prefix is known *not* to hold for every key.
///   [`MAJORITY_ONLY_COUNTEREXAMPLES`] must carry a key that mints something else, so the marker
///   rests on a minted address rather than on a note.
/// - [`SAMPLED`] — no procedure here decides the row either way. The reason goes in
///   [`UNDECIDED_BY_ANALYSIS`] and the prefix is swept over [`SWEEP`] distinct keys, which can
///   refute it but can never establish it.
///
/// The point of spelling both out is that a future row cannot document a majority-only prefix as
/// though it were guaranteed: an unmarked row that [`leading_characters`] cannot prove fails the
/// build, and neither marker can be applied to a row that does not earn it.
const MOST_KEYS: &str = " (most keys)";
/// See [`MOST_KEYS`].
const SAMPLED: &str = " (sampled)";

/// How strongly a row's `Default address` cell claims its prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mark {
    /// Unmarked: the prefix holds for every key.
    EveryKey,
    /// [`MOST_KEYS`].
    MostKeys,
    /// [`SAMPLED`].
    Sampled,
}

impl Mark {
    /// How the marker reads in the table, for error messages. `EveryKey` is the absence of one.
    fn as_written(self) -> &'static str {
        match self {
            Mark::EveryKey => "",
            Mark::MostKeys => MOST_KEYS,
            Mark::Sampled => SAMPLED,
        }
    }
}

/// Split a `Default address` cell into the prefix it documents and how strongly it claims it.
///
/// `` `bc1q…` `` -> `("bc1q", EveryKey)`; `` `a…` (most keys) `` -> `("a", MostKeys)`. `None` for
/// anything that is not a backticked, ellipsis-terminated prefix with at most one known marker —
/// so a row cannot go vague, and cannot invent a marker, by accident.
fn documented_prefix(cell: &str) -> Option<(&str, Mark)> {
    let (body, mark) = match cell {
        c if c.ends_with(MOST_KEYS) => (&c[..c.len() - MOST_KEYS.len()], Mark::MostKeys),
        c if c.ends_with(SAMPLED) => (&c[..c.len() - SAMPLED.len()], Mark::Sampled),
        c => (c, Mark::EveryKey),
    };
    let prefix = body
        .strip_prefix('`')?
        .strip_suffix('`')?
        .strip_suffix(ELLIPSIS)?;
    Some((prefix, mark))
}

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

/// What the analysis below could establish about the leading characters of a coin's addresses.
enum Leading {
    /// Every address the coin can mint begins with these characters. A proof about the coin's
    /// bytes, so it covers keys nobody will ever generate.
    Forced(String),
    /// Nothing here decides the row, for the stated reason. **Not** a claim that the prefix varies
    /// — only that no argument in this file rules that out.
    Undecided(String),
}

/// A verdict renders as the sentence a failure message needs, so that a row which fails says what
/// the analysis actually found rather than leaving the reader to re-derive it.
impl std::fmt::Display for Leading {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Leading::Forced(shared) => write!(f, "every address it mints begins `{shared}`"),
            Leading::Undecided(why) => write!(f, "nothing here forces a leading character: {why}"),
        }
    }
}

/// `head` followed by `free` copies of `fill` — one end of the space a payload can occupy.
fn payload_end(head: &[u8], fill: u8, free: usize) -> Vec<u8> {
    let mut v = head.to_vec();
    v.resize(head.len() + free, fill);
    v
}

/// The leading characters two encodings of the *ends* of a payload space must share.
///
/// `lo` and `hi` are the encodings of two byte strings that bracket every payload the coin's
/// encoder can be handed. Both base58 and CryptoNote base58 are positional numeral systems whose
/// digit order *is* their alphabet's order, so among strings of one length numeric order and
/// lexicographic order agree. If `lo` and `hi` come out the same length `L`, every value between
/// them also encodes to `L` characters, and the first `k` characters of a length-`L` encoding
/// spell `value / 58^(L-k)` — monotone in the value. So a character `lo` and `hi` agree on is a
/// character every payload in the bracket agrees on.
///
/// A bracket may be **loose**: contain byte strings no key can produce. That can only cost the
/// analysis a proof, never make it prove something false — the reachable payloads are a subset of
/// the bracket either way. So [`Leading::Forced`] is sound, while [`Leading::Undecided`] means no
/// more than "not established here". Ergo is the row where the difference bites; see below.
fn shared_leading_characters(lo: &str, hi: &str) -> Leading {
    // Both alphabets are ASCII, so byte length is character length.
    if lo.len() != hi.len() {
        return Leading::Undecided(format!(
            "the ends of the payload space encode to different lengths — {} characters ({lo}) and \
             {} characters ({hi}) — so they bracket no leading character",
            lo.len(),
            hi.len(),
        ));
    }
    let shared: String = lo
        .chars()
        .zip(hi.chars())
        .take_while(|(a, b)| a == b)
        .map(|(a, _)| a)
        .collect();
    if shared.is_empty() {
        return Leading::Undecided(format!(
            "the ends of the payload space encode to {lo} and {hi}, which share no leading \
             character"
        ));
    }
    Leading::Forced(shared)
}

/// The characters every address of this coin must begin with, or why that was not established.
///
/// Two sound arguments are available, and a row is decided by whichever applies:
///
/// 1. **A constant lead-in.** bech32, bech32m and the CashAddr-style Kaspa encoding all emit the
///    coin's prefix verbatim before any key-dependent character, and EIP-55 emits a literal `0x`.
///    The row's own parameters supply the constant, so a coin added with a new HRP is checked
///    rather than trusted.
/// 2. **The ends of the payload space**, via [`shared_leading_characters`].
///
/// The `match` is deliberately exhaustive: adding a [`coins::FamilyParams`] variant must not
/// inherit an argument made about some other family, and will not compile until it states its own.
fn leading_characters(spec: &coins::CoinSpec) -> Leading {
    /// HASH160 output width, in bytes.
    const HASH160: usize = 20;
    /// The base58check checksum, `SHA256d(payload)[..4]`.
    const CHECKSUM: usize = 4;
    /// A SEC1 compressed secp256k1 point: one parity byte plus the x-coordinate.
    const SEC1_COMPRESSED: usize = 33;
    /// CryptoNote base58 encodes independent 8-byte blocks as exactly 11 characters each.
    const CRYPTONOTE_BLOCK: usize = 8;
    /// Alephium's address-type byte for P2PKH, the one fixed byte an Alephium address carries.
    const ALEPHIUM_P2PKH: u8 = 0x00;

    match spec.params {
        // bech32/bech32m emit `hrp ‖ '1' ‖ CHARSET[witness_version] ‖ …`: the HRP verbatim, the
        // separator, then the witness version as the first data character (BIP-173 §Bech32,
        // BIP-350, and `codec::bech32::encode`, which pushes exactly that sequence). SegWit v0
        // renders `CHARSET[0]`, Taproot key-path is witness v1 and renders `CHARSET[1]`. Nothing
        // key-dependent precedes either, whatever the key or the HRP.
        coins::FamilyParams::SegwitV0 { hrp, .. } => {
            Leading::Forced(format!("{hrp}1{}", bech32::CHARSET[0] as char))
        }
        coins::FamilyParams::Taproot { hrp, .. } => {
            Leading::Forced(format!("{hrp}1{}", bech32::CHARSET[1] as char))
        }
        // `prefix ‖ ':' ‖ …` (`codec::cashaddr::encode`). The payload after the colon is
        // key-dependent; the colon and everything before it is not.
        coins::FamilyParams::KaspaAddr { prefix, .. } => Leading::Forced(format!("{prefix}:")),
        // EIP-55 renders a literal `0x` before the twenty checksummed hex bytes.
        coins::FamilyParams::Ethereum => Leading::Forced("0x".to_string()),
        // `base58check(version ‖ HASH160(pubkey))` = `base58(version ‖ 20 free bytes ‖ 4 checksum
        // bytes)`. The checksum is a function of the hash rather than free, so bracketing it as
        // free only widens the bracket — safe in the direction that matters, see
        // `shared_leading_characters`.
        coins::FamilyParams::P2pkh { version, .. } => shared_leading_characters(
            &base58::encode(&payload_end(version, 0x00, HASH160 + CHECKSUM)),
            &base58::encode(&payload_end(version, 0xff, HASH160 + CHECKSUM)),
        ),
        // `base58(0x01 ‖ SEC1-compressed pubkey ‖ Blake2b256[..4])` — `families::ergo`, mainnet
        // network byte 0x00 plus address type 0x01.
        //
        // The bracket is narrowed by one byte, and it has to be. Over the full byte range the ends
        // encode to `9adaAMuB…` and `JAG9KioM…`, which share nothing, and Ergo's `9` would read as
        // unprovable. But the pubkey's first byte is not free: SEC 1 v2.0 §2.3.3 encodes a
        // compressed point as 0x02 (even y) or 0x03 (odd y), and `secp256k1::pubkey_compressed`
        // emits nothing else — so 0x02 and 0x03 *are* that byte's ends. With them the ends encode
        // to `9eX4WpoE…` and `9iQYsHhJ…`, and the `9` is proved. This is what "the remaining
        // payload space" means: whatever the coin's own construction leaves free, which is not
        // always the full byte range.
        coins::FamilyParams::Ergo => shared_leading_characters(
            &base58::encode(&payload_end(
                &[0x01, 0x02],
                0x00,
                SEC1_COMPRESSED - 1 + CHECKSUM,
            )),
            &base58::encode(&payload_end(
                &[0x01, 0x03],
                0xff,
                SEC1_COMPRESSED - 1 + CHECKSUM,
            )),
        ),
        // `varint(network prefix) ‖ spend(32) ‖ view(32) ‖ Keccak[..4]`, encoded by CryptoNote
        // base58 in independent 8-byte blocks of exactly 11 characters each (`codec::cryptonote`).
        // The first block therefore *is* the address's first 11 characters, and it holds the
        // varint plus whatever spend-key bytes it leaves room for — 7 for Monero's one-byte
        // prefix, 3 for Zephyr's five-byte one. Fixed-width blocks cannot change length with the
        // value, which is exactly what lets these rows be decided where Alephium's cannot.
        coins::FamilyParams::CryptoNote { network_byte, .. } => {
            let mut lo = Vec::new();
            cryptonote::write_varint(network_byte, &mut lo);
            let mut hi = lo.clone();
            // `resize` also truncates, which is what a prefix wider than one block would need.
            lo.resize(CRYPTONOTE_BLOCK, 0x00);
            hi.resize(CRYPTONOTE_BLOCK, 0xff);
            shared_leading_characters(&cryptonote::encode(&lo), &cryptonote::encode(&hi))
        }
        // `base58(0x00 ‖ Blake2b256(pubkey))` — no checksum, no fixed width.
        //
        // The ends of the payload space decide nothing here, and this is the one row where they
        // cannot: an all-zero digest encodes to 33 characters and an all-ones digest to 45, so the
        // address is 44 or 45 characters long and `shared_leading_characters` would report only a
        // length mismatch. A sweep of 50 000 keys bears the variation out — 2 719 of them minted
        // the 44-character form.
        //
        // The leading character is nonetheless forced, by the encoder rather than by the bytes.
        // `codec::base58::encode` counts the input's leading zero bytes and pushes one
        // `ALPHABET[0]` for each *before* encoding anything else, so a payload that begins 0x00
        // begins with that character whatever follows. Alephium's address-type byte is a literal
        // 0x00 (`families::alephium`, `alephium/alephium-web3` `AddressType.P2PKH = 0x00`), so the
        // count is at least one for every key. Asking the encoder what a single 0x00 renders as,
        // rather than writing `1` here, keeps the claim tied to the code that makes it true.
        coins::FamilyParams::Alephium => Leading::Forced(base58::encode(&[ALEPHIUM_P2PKH])),
        // `base58check(HASH160(pubkey))` with no version byte: nothing is fixed, so there is
        // nothing to bracket and the analysis says so. The row documents `no fixed prefix`, and
        // `a_row_that_documents_no_fixed_prefix_really_has_none` holds it to that with two keys.
        coins::FamilyParams::Xdag => shared_leading_characters(
            &base58::encode(&payload_end(&[], 0x00, HASH160 + CHECKSUM)),
            &base58::encode(&payload_end(&[], 0xff, HASH160 + CHECKSUM)),
        ),
    }
}

/// Rows marked [`MOST_KEYS`], each with a key that mints an address the documented prefix does not
/// cover, and the address it mints.
///
/// A marker backed by prose is a marker nothing checks. This is the counterexample itself: the
/// test mints it and fails if it either stops reproducing or starts matching the prefix.
///
/// `firo`'s version byte 0x52 puts the 25-byte payload astride the base58 boundary between digit
/// 32 (`Z`) and digit 33 (`a`): the interval `[0x52·256²⁴, 0x53·256²⁴)` sits 1.222% below
/// `33·58³³` and 98.778% above it. `0x3e` = 62 is the *smallest* private key on the low side —
/// every key from 1 to 61 mints `a…`.
const MAJORITY_ONLY_COUNTEREXAMPLES: &[(&str, &str, &str)] = &[(
    "firo",
    "000000000000000000000000000000000000000000000000000000000000003e",
    "ZzzAu2nHnHNxMea5vbLyeD4nejtXDW57wY",
)];

/// Rows marked [`SAMPLED`]: those [`leading_characters`] decides neither way, with the reason.
///
/// **Empty, and that is the goal state** — every row in the table is currently proved outright
/// except `firo`, which is refuted outright. The list exists because the alternative is the
/// failure this file is here to prevent: a row no argument covers quietly passing on one lucky
/// key, with the doubt recorded in prose the build cannot fail on. An entry is an admission, not
/// an exemption — the row still carries a visible marker in `COINS.md` and is still swept by
/// [`a_prefix_that_is_not_proved_for_every_key_is_swept_over_many_keys`].
const UNDECIDED_BY_ANALYSIS: &[(&str, &str)] = &[];

/// How many distinct keys the sweep mints per row it cannot prove.
///
/// A sweep can **refute** a prefix and can never establish one: 1024 keys out of a 2²⁵⁶ key space
/// is evidence of nothing about the keys it did not try. It is here to catch a marker that is
/// simply wrong — a `(most keys)` prefix that is in fact the minority, or a `(sampled)` prefix
/// with a counterexample lying in easy reach — not to stand in for the proofs above. 1024 keys is
/// roughly one second per row in a debug build, which is the reason the number is not larger.
const SWEEP: u32 = 1024;

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
        // — optionally carrying one of the two markers — must be the one sanctioned prose value,
        // so a row cannot go vague by accident.
        let Some((prefix, _)) = documented_prefix(cell) else {
            assert_eq!(
                cell.as_str(),
                NO_PREFIX,
                "COINS.md row `{}`: the Default address cell must be either a backticked prefix \
                 ending in the ellipsis '{ELLIPSIS}' (one character, U+2026 — for example \
                 `bc1q{ELLIPSIS}`), optionally followed by \"{MOST_KEYS}\" or \"{SAMPLED}\", or \
                 the exact words \"{NO_PREFIX}\". It reads {cell:?}. The address minted from \
                 privkey {PRIV1} is {minted}",
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

/// An unmarked `Default address` cell claims its prefix holds for **every** key, so every unmarked
/// cell must be provable — from the coin's fixed leading bytes, not from a key that happened to
/// land the right side of a boundary.
///
/// This is the hole that [`every_documented_default_address_is_the_prefix_the_generator_mints`]
/// cannot close. That test mints from one key, so it cannot tell a prefix no key can escape
/// (Dogecoin's `D`: version byte 0x1e leaves both ends of the payload space encoding to `D…`) from
/// a prefix most keys merely happen to hit (Firo's `a`: version byte 0x52 straddles the base58
/// boundary between `Z` and `a`, and roughly one key in eighty mints `Z…`). It passed for Firo
/// only because privkey 1 falls in the 98.8%. Until now the difference lived in a footnote, and a
/// footnote does not fail a build — which is this repository's stated objection to prose.
///
/// So: each row is classified by [`leading_characters`], and the verdict must match what the cell
/// claims. A row that cannot be proved and is not marked fails, naming both honest ways out. That
/// is the property worth having — not that today's table is right, but that a *future* row cannot
/// document a majority-only prefix as though it were guaranteed by doing nothing.
#[test]
fn an_unmarked_documented_prefix_is_proved_to_hold_for_every_key() {
    let md = doc();
    let rows = coin_table_rows(&md);
    for row in &rows {
        let spec = coins::lookup(&row.ticker).expect("every_documented_coin_exists checks this");
        let leading = leading_characters(spec);
        let Some((prefix, mark)) = documented_prefix(&row.default_address) else {
            // `no fixed prefix` — the reverse claim, and it must be just as true. If the analysis
            // can force a leading character, the row is hiding one a user could have relied on.
            assert!(
                matches!(leading, Leading::Undecided(_)),
                "COINS.md row `{}` says \"{NO_PREFIX}\", but the analysis proves {leading}. \
                 Document that prefix",
                row.ticker
            );
            continue;
        };
        let proved = match &leading {
            Leading::Forced(forced) => forced.starts_with(prefix),
            Leading::Undecided(_) => false,
        };
        match mark {
            Mark::EveryKey => assert!(
                proved,
                "COINS.md row `{}` documents `{prefix}{ELLIPSIS}` with no marker, which claims \
                 every possible key mints an address starting with it. That is not established — \
                 {leading}. Either it is genuinely true for every key — in which case the \
                 argument for it belongs in `leading_characters`, next to the family it is about \
                 — or it is not, and the row must say so: append \"{MOST_KEYS}\" and record a key \
                 that mints something else in MAJORITY_ONLY_COUNTEREXAMPLES, or append \
                 \"{SAMPLED}\" and record why the analysis cannot decide it in \
                 UNDECIDED_BY_ANALYSIS. Do not widen the prefix until it passes; a prefix short \
                 enough to be safe is still a prefix a user cannot rely on",
                row.ticker
            ),
            // A marker on a row the analysis proves understates what is known, and understating is
            // not harmless here: it tells a reader to double-check something they need not.
            Mark::MostKeys | Mark::Sampled => assert!(
                !proved,
                "COINS.md row `{}` marks `{prefix}{ELLIPSIS}` \"{}\", but the analysis proves \
                 {leading}, so the prefix holds for every key. Drop the marker",
                row.ticker,
                mark.as_written(),
            ),
        }
        let counterexample = MAJORITY_ONLY_COUNTEREXAMPLES
            .iter()
            .any(|(t, ..)| *t == row.ticker);
        let undecided = UNDECIDED_BY_ANALYSIS.iter().any(|(t, _)| *t == row.ticker);
        assert_eq!(
            (mark == Mark::MostKeys, mark == Mark::Sampled),
            (counterexample, undecided),
            "COINS.md row `{}` is marked {:?} but its entries say counterexample={counterexample}, \
             undecided={undecided}. A \"{MOST_KEYS}\" row needs exactly one \
             MAJORITY_ONLY_COUNTEREXAMPLES entry and a \"{SAMPLED}\" row exactly one \
             UNDECIDED_BY_ANALYSIS entry; an unmarked row needs neither",
            row.ticker,
            mark,
        );
    }

    // The cross-check above runs per row, so it cannot see an entry that names no row at all. A
    // stale one exempts nothing, but it is a lie about the table sitting in the file that decides
    // what the table may claim.
    let orphans: Vec<&str> = MAJORITY_ONLY_COUNTEREXAMPLES
        .iter()
        .map(|(ticker, ..)| *ticker)
        .chain(UNDECIDED_BY_ANALYSIS.iter().map(|(ticker, _)| *ticker))
        .filter(|ticker| !rows.iter().any(|r| r.ticker == *ticker))
        .collect();
    assert!(
        orphans.is_empty(),
        "MAJORITY_ONLY_COUNTEREXAMPLES and UNDECIDED_BY_ANALYSIS between them name {orphans:?}, \
         which are not rows of the COINS.md coin table"
    );
}

/// A row marked `(most keys)` must carry the key that proves the marker, and that key must still
/// mint the address recorded for it.
///
/// The marker is a claim that a counterexample exists. Recording one turns the claim into
/// something the build can lose: if the encoder changes and Firo starts minting `a…` for
/// `0000…003e` too, this fails rather than quietly leaving `COINS.md` warning about a boundary
/// nothing crosses any more.
#[test]
fn a_prefix_marked_as_holding_for_most_keys_has_a_counterexample_that_still_mints() {
    let md = doc();
    let rows = coin_table_rows(&md);
    for (ticker, secret, expected) in MAJORITY_ONLY_COUNTEREXAMPLES {
        let row = rows
            .iter()
            .find(|r| r.ticker == *ticker)
            .unwrap_or_else(|| {
                panic!(
                    "MAJORITY_ONLY_COUNTEREXAMPLES names `{ticker}`, which is \
                                       not a row of the COINS.md table"
                )
            });
        let (prefix, _) = documented_prefix(&row.default_address).unwrap_or_else(|| {
            panic!(
                "MAJORITY_ONLY_COUNTEREXAMPLES names `{ticker}`, whose Default address cell \
                 documents no prefix to be a counterexample to: {:?}",
                row.default_address
            )
        });
        let minted = mint(ticker, secret);
        assert_eq!(
            &minted, expected,
            "`forager-wallet restore {secret} --coin {ticker}` now mints {minted}, not the \
             {expected} recorded for it. If the change is intended, re-derive the counterexample \
             and update COINS.md, which quotes this address"
        );
        assert!(
            !minted.starts_with(prefix),
            "COINS.md row `{ticker}` marks `{prefix}{ELLIPSIS}` \"{MOST_KEYS}\", but the key \
             recorded as its counterexample mints {minted}, which starts with `{prefix}` after \
             all. The marker now rests on nothing"
        );
    }
}

/// Every prefix the analysis does not prove is swept over many distinct keys.
///
/// **A sweep proves nothing.** [`SWEEP`] keys out of a 2²⁵⁶ key space say nothing whatever about
/// the keys they did not try, and no number of passing samples would turn a `(sampled)` row into
/// an unmarked one. What a sweep can do is *refute*: it catches a marker that is simply wrong —
/// a `(most keys)` prefix that turns out to be the minority, or a `(sampled)` prefix with a
/// counterexample lying in easy reach — which is worth the second it costs.
///
/// The keys are 1, 2, 3, … rather than random, so a failure names a key that reproduces it.
#[test]
fn a_prefix_that_is_not_proved_for_every_key_is_swept_over_many_keys() {
    let md = doc();
    for row in coin_table_rows(&md) {
        let Some((prefix, mark)) = documented_prefix(&row.default_address) else {
            continue;
        };
        if mark == Mark::EveryKey {
            continue;
        }
        let matched = (1..=SWEEP)
            .filter(|i| mint(&row.ticker, &format!("{i:064x}")).starts_with(prefix))
            .count();
        match mark {
            // `(most keys)` says the majority, so a sweep that finds the prefix in a minority of
            // keys refutes the word "most" even though it cannot confirm any particular share.
            Mark::MostKeys => assert!(
                matched * 2 > SWEEP as usize,
                "COINS.md row `{}` marks `{prefix}{ELLIPSIS}` \"{MOST_KEYS}\", but only \
                 {matched} of {SWEEP} keys minted it, which is not most of them",
                row.ticker
            ),
            // `(sampled)` says no counterexample is known, so any key that mints something else
            // refutes it — and, better, promotes the row to `(most keys)` with that key as its
            // recorded counterexample.
            Mark::Sampled => {
                let reason = UNDECIDED_BY_ANALYSIS
                    .iter()
                    .find(|(t, _)| *t == row.ticker)
                    .map_or("(none recorded)", |(_, why)| why);
                assert_eq!(
                    matched,
                    SWEEP as usize,
                    "COINS.md row `{}` marks `{prefix}{ELLIPSIS}` \"{SAMPLED}\" because {reason} \
                     — but {} of {SWEEP} keys minted something else. The prefix is majority-only, \
                     not merely unproved: mark it \"{MOST_KEYS}\" and record one of those keys in \
                     MAJORITY_ONLY_COUNTEREXAMPLES",
                    row.ticker,
                    SWEEP as usize - matched,
                );
            }
            Mark::EveryKey => unreachable!("filtered out above"),
        }
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
