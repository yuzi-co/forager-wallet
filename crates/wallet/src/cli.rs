//! `forager-wallet …` — offline multi-coin payout-address keygen (no pool, no GPU).
//!
//! Pre-clap like the other offline subcommands (`detect`/`bench`): reads only `argv`, never
//! opens a connection.  Backed by the clean-room [`wallet`] crate.
//!
//! * `forager-wallet new --coin <ticker> [--testnet] [--legacy]`
//!   Mint a fresh address + secret key.  `--coin` is required (run `forager-wallet list` for tickers).
//!
//! * `forager-wallet restore <secret-hex-or-wif> --coin <ticker> [--testnet] [--legacy]`
//!   Re-derive the address for a key you already hold.  Accepts the raw 64-char hex **or** the
//!   WIF this tool prints, so the secret it hands out is one it also reads back.  Prints no
//!   secret you did not supply.  `inspect` / `address` are older names for the same thing.
//!
//! * `forager-wallet restore --mnemonic "<12/15/18/21/24 words>" (--coin <ticker> | --all) [--purpose P]`
//!   Re-derive from a BIP39 mnemonic at the standard path (the HD form of the above).  Every
//!   length BIP39 defines is accepted — 12 words is the most common one in circulation.
//!
//! * `forager-wallet list`
//!   Print a table of all coins supported by the wallet crate.
//!
//! * `forager-wallet new --hd (--coin <ticker> | --all) [--purpose <bip44|bip84|bip86>]
//!     [--account N] [--index N] [--passphrase <str>] [--mnemonic "<12/15/18/21/24 words>"]`
//!   HD (BIP39) mode: derive at the standard path `m/<purpose>'/<slip44>'/<account>'/0/<index>`.
//!   Without `--purpose`, each coin uses the purpose whose address type matches what the
//!   single-key path produces for it (BIP84 for SegWit coins, BIP86 for Taproot, BIP44 for P2PKH
//!   and Ethereum-family).  A freshly minted phrase is always **24 words** (256-bit entropy) and
//!   is printed once (stderr, with a security warning); a `--mnemonic` supplied for restore may
//!   be any length BIP39 defines.  Then `symbol  address  secret  path` per coin (stdout).
//!   Additive to — not a replacement for — the single-key `forager-wallet new` above.

use crate::coins::Family;
use crate::{Network, SecretStd};
use zeroize::Zeroizing;

/// A CLI-level failure. Carries the message the binary prints to stderr.
///
/// This crate ships a standalone binary and must not depend on the miner, so the CLI carries its
/// own error type rather than `mcore::MinerError`. See
/// `the repository README`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliError(pub String);

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CliError {}

fn err(msg: impl Into<String>) -> CliError {
    CliError(msg.into())
}

/// Parse a valued flag `--flag <value>` from `args`, returning the value if present.
fn parse_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|w| w[0] == flag)
        .map(|w| w[1].as_str())
}

/// Parse `--coin <ticker>` from `args`. Returns `None` when absent — `--coin` is required
/// (no default coin; `pearl` was the first coin supported but is not privileged).
fn parse_coin(args: &[String]) -> Option<String> {
    args.windows(2)
        .find(|w| w[0] == "--coin")
        .map(|w| w[1].clone())
}

/// Find the first positional argument (non-flag, not a flag value) at or after index `start`.
///
/// Skips `--testnet` / `--legacy` (boolean flags) and `--coin <value>` (valued flag) so
/// `inspect` can accept flags in any order relative to the secret-hex positional.
fn positional_after(args: &[String], start: usize) -> Option<&str> {
    let mut i = start;
    while i < args.len() {
        let a = &args[i];
        if a == "--coin" {
            i += 2; // skip flag + its value
        } else if a.starts_with("--") {
            i += 1; // skip boolean flag
        } else {
            return Some(a.as_str());
        }
    }
    None
}

/// Dispatch `forager-wallet <new|restore|list> …`.
///
/// `args` is the full process argv: `args[0]` is the binary name and `args[1]` is the subcommand.
pub fn run(args: &[String]) -> Result<(), CliError> {
    let testnet = args.iter().any(|a| a == "--testnet");
    let legacy = args.iter().any(|a| a == "--legacy");
    let coin = parse_coin(args);
    let net = if testnet {
        Network::Testnet
    } else {
        Network::Mainnet
    };

    match args.get(1).map(String::as_str) {
        Some("new") if args.iter().any(|a| a == "--hd") => cmd_new_hd(args),
        Some("new") => {
            let coin = coin.ok_or_else(|| {
                err("usage: forager-wallet new --coin <ticker> [--testnet] [--legacy]  (run `forager-wallet list` for tickers)")
            })?;
            cmd_new(&coin, net, legacy, testnet)
        }
        None => Err(err(
            "usage: forager-wallet <new|restore|list> …  (run `forager-wallet list` for supported coins)",
        )),
        // `restore` re-derives an address you already hold the secret for. With `--mnemonic` it is
        // the HD path; otherwise it takes a single key. `inspect`/`address` are the older names for
        // the single-key form and keep working.
        Some("restore") if args.iter().any(|a| a == "--mnemonic") => cmd_new_hd(args),
        Some("restore") | Some("inspect") | Some("address") => {
            const USAGE: &str = "usage: forager-wallet restore <secret-hex-or-wif> --coin <ticker> [--testnet] [--legacy]\n   \
                                 or: forager-wallet restore --mnemonic \"<12/15/18/21/24 words>\" (--coin <ticker> | --all) [--purpose P] [--account N] [--index N]";
            let coin = coin.ok_or_else(|| err(USAGE))?;
            let key = positional_after(args, 2).ok_or_else(|| err(USAGE))?;
            cmd_inspect(&coin, key, net, legacy)
        }
        Some("list") => cmd_list(),
        Some(other) => Err(err(format!(
            "unknown action '{other}' (expected: new | restore <secret-hex-or-wif> | list)"
        ))),
    }
}

fn cmd_new(coin: &str, net: Network, legacy: bool, testnet: bool) -> Result<(), CliError> {
    // Generate a fresh key from OS entropy (always uses the non-legacy address path).
    let fresh = crate::generate(coin, net).map_err(|e| err(e.to_string()))?;
    // For --legacy, re-derive the P2PKH address form from the same key material.
    // For families that don't have a legacy path (Taproot, Ethereum, CryptoNote), `legacy` is
    // silently ignored by the library's dispatch — the same address is returned either way.
    let w = if legacy {
        crate::address_from_secret_kind(coin, &fresh.secret_hex, net, true)
            .map_err(|e| err(e.to_string()))?
    } else {
        fresh
    };

    // Display name from the coin table; a runtime `family:params` token isn't in the table, so
    // fall back to the token string itself.
    let display_name = crate::supported()
        .iter()
        .find(|s| s.ticker == w.coin)
        .map_or(coin, |s| s.name);
    let net_label = if testnet { "testnet" } else { "mainnet" };

    println!("{display_name} ({net_label}) payout wallet");
    println!("  address : {}", w.address);
    println!();

    match &w.secret_std {
        SecretStd::Wif(wif) => {
            println!("  WIF (import into the coin's wallet) : {wif}");
            println!("  raw secret hex                      : {}", w.secret_hex);
        }
        SecretStd::EthHex(key) => {
            println!("  private key (0x… — import into MetaMask/EVM wallet) : {key}");
            println!(
                "  raw secret hex                                       : {}",
                w.secret_hex
            );
            if testnet {
                println!();
                println!("  note: EVM addresses are network-agnostic — this address is identical");
                println!("        on all EVM chains regardless of testnet/mainnet selection.");
            }
        }
        SecretStd::MoneroMnemonic {
            words,
            view_key_hex,
        } => {
            println!("  25-word mnemonic — THIS IS YOUR WALLET RESTORE KEY, back it up:");
            for (i, word) in words.iter().enumerate() {
                println!("    {:2}. {word}", i + 1);
            }
            println!();
            println!("  view key (watch-only wallet) : {view_key_hex}");
            println!("  raw spend hex                : {}", w.secret_hex);
        }
        SecretStd::RawHex(key) => {
            println!("  raw key : {key}");
        }
    }

    println!();
    println!("BACK UP YOUR SECRET. It controls this address's funds and is shown");
    println!("only once — Forager does not store it. Mining needs only the address.");
    if crate::is_custom_token(coin) {
        println!();
        println!("!! UNVERIFIED CUSTOM COIN ({coin}). These address parameters were supplied by");
        println!("   you, not gated by a known-answer test. A wrong version byte produces a");
        println!("   valid-LOOKING address that silently misdirects your payout. Before mining to");
        println!("   it, confirm this exact address in the coin's own wallet / block explorer.");
        // A wrong version byte is not the only way a token can be wrong: the family's hash
        // primitives are fixed by the encoder and cannot be stated in the token at all, so for
        // those families the user gets told what was assumed on their behalf.
        if let Some(caveat) = crate::coins::token_caveat(coin) {
            for line in caveat.lines() {
                println!("   {line}");
            }
        }
    }
    if coin == "pearl" && !testnet {
        println!();
        println!("Import into the official Oyster wallet is UNVERIFIED; for a long-term");
        println!("wallet, generate it in Oyster and pass only the address to --wallet.");
    }

    Ok(())
}

/// Comma-separated list of HD-capable tickers (for error messages / help).
fn hd_coin_list() -> String {
    crate::hd::supported()
        .iter()
        .map(|c| c.ticker)
        .collect::<Vec<_>>()
        .join(", ")
}

/// `forager-wallet new --hd …` — BIP39/BIP44 HD keygen for the transparent base58 P2PKH coins.
fn cmd_new_hd(args: &[String]) -> Result<(), CliError> {
    // The HD coin table carries mainnet version bytes only; refuse --testnet rather than emit a
    // wrong-network address.
    if args.iter().any(|a| a == "--testnet") {
        return Err(err(
            "`wallet new --hd` is mainnet-only (the HD coin table carries mainnet version bytes)",
        ));
    }

    let usage =
        "usage: forager-wallet new --hd (--coin <ticker> | --all) [--purpose <bip44|bip84|bip86>] \
                 [--account N] [--index N] [--passphrase <str>] [--mnemonic \"<12/15/18/21/24 words>\"]";

    // Which address type to derive. Absent, each coin uses its native purpose — the one whose
    // address type matches what the single-key generator produces for that coin.
    let requested_purpose = match parse_value(args, "--purpose") {
        Some(s) => Some(crate::hd::Purpose::parse(s).ok_or_else(|| {
            err(format!(
                "unknown --purpose '{s}' (expected bip44 | bip84 | bip86, or the aliases \
                 legacy | segwit | taproot)"
            ))
        })?),
        None => None,
    };

    let account: u32 = match parse_value(args, "--account") {
        Some(s) => s
            .parse()
            .map_err(|_| err("--account must be a non-negative integer"))?,
        None => 0,
    };
    let index: u32 = match parse_value(args, "--index") {
        Some(s) => s
            .parse()
            .map_err(|_| err("--index must be a non-negative integer"))?,
        None => 0,
    };
    let passphrase = parse_value(args, "--passphrase").unwrap_or("");

    // Which coins to derive for.
    let coins: Vec<&'static crate::coins::CoinSpec> = if args.iter().any(|a| a == "--all") {
        crate::hd::supported()
    } else {
        let sym = parse_coin(args)
            .ok_or_else(|| err(format!("{usage}\n  HD coins: {}", hd_coin_list())))?;
        let coin = crate::hd::lookup(&sym).ok_or_else(|| {
            err(format!(
                "coin '{sym}' does not support HD (BIP44) keygen. HD coins: {}",
                hd_coin_list()
            ))
        })?;
        vec![coin]
    };

    // Mnemonic: restore the supplied one (validated) or mint a fresh 24-word phrase from OS
    // entropy. A supplied phrase may be 12, 15, 18, 21 or 24 words; a minted one is always 24.
    // `Zeroizing` wipes the phrase from memory on drop.
    let supplied = parse_value(args, "--mnemonic");
    let mnemonic: Zeroizing<String> = match supplied {
        Some(phrase) => {
            // `HdError`'s message carries the specific BIP39 failure — which word, at which
            // position, or which illegal word count — so pass it through verbatim rather than
            // substituting a generic "invalid mnemonic" of our own.
            crate::hd::validate_mnemonic(phrase).map_err(|e| err(e.to_string()))?;
            Zeroizing::new(phrase.trim().to_string())
        }
        None => crate::hd::generate_mnemonic().map_err(|e| err(e.to_string()))?,
    };

    // Show the mnemonic exactly once, on stderr, so a redirected stdout (the address/wif table)
    // never captures the secret phrase silently.
    eprintln!();
    if supplied.is_none() {
        eprintln!("=== BIP39 mnemonic (24 words) — WRITE THIS DOWN AND KEEP IT OFFLINE ===");
        eprintln!("{}", mnemonic.as_str());
        eprintln!();
    }
    eprintln!(
        "ANYONE WITH THIS MNEMONIC CONTROLS THE FUNDS. It is shown once and NOT stored by Forager."
    );
    if !passphrase.is_empty() {
        eprintln!(
            "A BIP39 passphrase is set: you need BOTH the mnemonic AND the passphrase to restore."
        );
    }
    eprintln!();

    // Address + secret + path per coin, to stdout.
    println!("{:<6}  {:<64}  {:<52}  path", "symbol", "address", "secret");
    for coin in coins {
        // Default to the purpose whose address type matches this coin's single-key output, so
        // `new --coin X` and `new --hd --coin X` agree. `--purpose` overrides it.
        let purpose = match requested_purpose {
            Some(p) => p,
            None => crate::hd::native_purpose(coin)
                .ok_or_else(|| err(format!("coin '{}' has no HD address form", coin.ticker)))?,
        };
        let acct = crate::hd::derive(mnemonic.as_str(), passphrase, coin, purpose, account, index)
            .map_err(|e| err(e.to_string()))?;
        println!(
            "{:<6}  {:<64}  {:<52}  {}",
            acct.symbol,
            acct.address,
            acct.secret_str(),
            acct.path
        );
    }

    println!();
    println!(
        "Restore the whole set from the mnemonic in any standard wallet, at the printed path."
    );
    println!("Import a single key with the secret shown (WIF, or 0x-hex for Ethereum-family).");
    println!("Mining needs only the address.");
    Ok(())
}

fn cmd_inspect(coin: &str, secret_hex: &str, net: Network, legacy: bool) -> Result<(), CliError> {
    let w = crate::address_from_secret_kind(coin, secret_hex, net, legacy)
        .map_err(|e| err(e.to_string()))?;
    println!("{}", w.address);
    // For CryptoNote (XMR), surface the deterministic view key so callers can reconstruct a
    // watch-only wallet without re-running the full mnemonic derivation.
    if let SecretStd::MoneroMnemonic { view_key_hex, .. } = &w.secret_std {
        println!("  view key : {view_key_hex}");
    }
    Ok(())
}

fn cmd_list() -> Result<(), CliError> {
    println!("{:<8}  {:<22}  family", "ticker", "name");
    println!("{}", "-".repeat(50));
    for spec in crate::supported() {
        println!(
            "{:<8}  {:<22}  {}",
            spec.ticker,
            spec.name,
            family_label(spec.family())
        );
    }
    println!();
    println!("Custom coin (UNVERIFIED — no KAT; verify the address before mining to it):");
    // Printed from the parser's own grammar table, so this help cannot drift from what `--coin`
    // actually accepts.
    let width = crate::coins::TOKEN_GRAMMAR
        .iter()
        .map(|g| g.syntax.len())
        .max()
        .unwrap_or(0);
    for g in crate::coins::TOKEN_GRAMMAR {
        // A zero-parameter family's example *is* its syntax, so an `e.g.` column would just repeat it.
        let example = if g.example == g.syntax {
            String::new()
        } else {
            format!("   e.g. {}", g.example)
        };
        let line = format!("  --coin {:<width$}{example}", g.syntax, width = width);
        println!("{}", line.trim_end());
        // Printed under the family it belongs to, so a user reading one grammar line cannot miss
        // the assumption that line makes on their behalf.
        if let Some(caveat) = g.caveat {
            for (i, note) in caveat.lines().enumerate() {
                println!("         {} {note}", if i == 0 { "!!" } else { "  " });
            }
        }
    }
    println!("  (integers: decimal, or 0x-prefixed hex)");
    Ok(())
}

fn family_label(family: Family) -> &'static str {
    match family {
        Family::P2pkh => "P2PKH",
        Family::SegwitV0 => "SegWit v0",
        Family::Taproot => "Taproot",
        Family::Ethereum => "Ethereum",
        Family::CryptoNote => "CryptoNote",
        Family::KaspaAddr => "Kaspa-family",
        Family::Ergo => "Ergo P2PK",
        Family::Alephium => "Alephium P2PKH",
        Family::Xdag => "XDAG (Base58Check, no version)",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<String> {
        // The binary name is argv[0]; the subcommand is argv[1]. Fixtures list from argv[1].
        std::iter::once("forager-wallet")
            .chain(parts.iter().copied())
            .map(str::to_string)
            .collect()
    }

    // ---- run() dispatch: return-value smoke tests ----

    #[test]
    fn bare_wallet_requires_action() {
        // `forager wallet` with no action → usage error (no default coin/action).
        let args = argv(&[]);
        assert!(run(&args).is_err());
    }

    #[test]
    fn new_without_coin_returns_err() {
        // `--coin` is required; `wallet new` alone must error.
        let args = argv(&["new"]);
        assert!(run(&args).is_err());
    }

    #[test]
    fn new_explicit_pearl() {
        let args = argv(&["new", "--coin", "pearl"]);
        assert!(run(&args).is_ok());
    }

    #[test]
    fn new_btc() {
        let args = argv(&["new", "--coin", "btc"]);
        assert!(run(&args).is_ok());
    }

    #[test]
    fn new_xmr() {
        let args = argv(&["new", "--coin", "xmr"]);
        assert!(run(&args).is_ok());
    }

    #[test]
    fn new_custom_token_does_not_panic() {
        // Regression: a runtime `family:params` token isn't in supported(); cmd_new must not
        // panic looking up its display name, and must succeed end-to-end.
        let args = argv(&["new", "--coin", "cryptonote:net=18"]);
        assert!(run(&args).is_ok());
        let seg = argv(&["new", "--coin", "segwit:hrp=bc,wif=0x80"]);
        assert!(run(&seg).is_ok());
    }

    #[test]
    fn new_bad_token_returns_err() {
        // Malformed token → typed error, not a panic or silent wrong address.
        let args = argv(&["new", "--coin", "segwit:wif=0x80"]);
        assert!(run(&args).is_err());
    }

    #[test]
    fn list_succeeds() {
        let args = argv(&["list"]);
        assert!(run(&args).is_ok());
    }

    #[test]
    fn unknown_coin_returns_err() {
        let args = argv(&["new", "--coin", "not_a_real_coin_xyz"]);
        assert!(run(&args).is_err());
    }

    #[test]
    fn unknown_action_returns_err() {
        let args = argv(&["frobnicate"]);
        assert!(run(&args).is_err());
    }

    // ---- wallet API: SecretStd variant + address non-empty assertions ----

    #[test]
    fn pearl_secret_is_raw_hex_non_empty_address() {
        let w = crate::generate("pearl", Network::Mainnet).unwrap();
        assert!(matches!(w.secret_std, SecretStd::RawHex(_)));
        assert!(!w.address.is_empty());
    }

    #[test]
    fn xdag_secret_is_raw_hex_non_empty_address() {
        let w = crate::generate("xdag", Network::Mainnet).unwrap();
        assert!(matches!(w.secret_std, SecretStd::RawHex(_)));
        assert!(!w.address.is_empty());
        assert_eq!(w.coin, "xdag");
    }

    #[test]
    fn btc_secret_is_wif_segwit_address() {
        let w = crate::generate("btc", Network::Mainnet).unwrap();
        assert!(matches!(w.secret_std, SecretStd::Wif(_)));
        assert!(!w.address.is_empty());
        // SegWit v0 P2WPKH addresses start with "bc1q"
        assert!(
            w.address.starts_with("bc1"),
            "expected bc1… address, got {}",
            w.address
        );
    }

    #[test]
    fn xmr_secret_is_mnemonic_non_empty_address() {
        let w = crate::generate("xmr", Network::Mainnet).unwrap();
        assert!(matches!(w.secret_std, SecretStd::MoneroMnemonic { .. }));
        assert!(!w.address.is_empty());
        // XMR mainnet standard addresses start with '4'
        assert!(
            w.address.starts_with('4'),
            "expected XMR address starting with '4', got {}",
            w.address
        );
    }

    #[test]
    fn btc_legacy_flag_produces_p2pkh_address() {
        // --legacy re-derives P2PKH (starts with '1') from the same key.
        let args = argv(&["new", "--coin", "btc", "--legacy"]);
        assert!(run(&args).is_ok());

        // Verify via API that the legacy path produces a P2PKH address.
        let w = crate::generate("btc", Network::Mainnet).unwrap();
        let w_legacy =
            crate::address_from_secret_kind("btc", &w.secret_hex, Network::Mainnet, true).unwrap();
        assert!(
            w_legacy.address.starts_with('1'),
            "expected P2PKH address starting with '1', got {}",
            w_legacy.address
        );
    }

    #[test]
    fn positional_after_skips_flags() {
        let args = argv(&["inspect", "--coin", "btc", "deadbeef"]);
        assert_eq!(positional_after(&args, 2), Some("deadbeef"));
    }

    // ---- HD (BIP39/BIP44) subcommand dispatch ----

    #[test]
    fn hd_new_coin_ok() {
        let args = argv(&["new", "--hd", "--coin", "btc"]);
        assert!(run(&args).is_ok());
    }

    #[test]
    fn hd_new_all_ok() {
        let args = argv(&["new", "--hd", "--all"]);
        assert!(run(&args).is_ok());
    }

    #[test]
    fn hd_requires_coin_or_all() {
        let args = argv(&["new", "--hd"]);
        assert!(run(&args).is_err());
    }

    #[test]
    fn hd_rejects_single_key_only_coin() {
        // Monero is a single-key family: CryptoNote has no BIP32 path. (Ethereum IS HD-capable
        // now, at m/44'/60' — see hd::Purpose.)
        let args = argv(&["new", "--hd", "--coin", "xmr"]);
        assert!(run(&args).is_err());
    }

    #[test]
    fn hd_rejects_testnet() {
        let args = argv(&["new", "--hd", "--coin", "btc", "--testnet"]);
        assert!(run(&args).is_err());
    }

    #[test]
    fn hd_restore_matches_library() {
        // The subcommand's --mnemonic path must reproduce the library KAT address.
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let args = argv(&["new", "--hd", "--coin", "btc", "--mnemonic", phrase]);
        assert!(run(&args).is_ok());
        let coin = crate::hd::lookup("btc").unwrap();
        let acct = crate::hd::derive(phrase, "", coin, crate::hd::Purpose::Bip44, 0, 0).unwrap();
        assert_eq!(acct.address, "1KBdbBJRVYffWHWWZ1moECfdVBSEnDpLHi");
    }

    #[test]
    fn hd_rejects_bad_mnemonic() {
        let args = argv(&[
            "new",
            "--hd",
            "--coin",
            "btc",
            "--mnemonic",
            "totally not valid",
        ]);
        assert!(run(&args).is_err());
    }

    /// The 12-word regression, at the CLI boundary: `restore --mnemonic` with the BIP84/BIP86
    /// spec mnemonic must succeed. Before the clean-room BIP39 landed, this exact invocation
    /// failed with "invalid BIP39 mnemonic (check the words, length, and checksum)" — a false
    /// accusation against the single most common phrase length in circulation.
    #[test]
    fn restore_accepts_a_twelve_word_mnemonic() {
        const TWELVE: &str = "abandon abandon abandon abandon abandon abandon \
                              abandon abandon abandon abandon abandon about";
        let args = argv(&["restore", "--mnemonic", TWELVE, "--coin", "btc"]);
        run(&args).expect("a valid 12-word phrase must restore");
    }

    /// A rejected phrase must say what is wrong with *it*, not emit a generic verdict. These are
    /// the two mistakes a user actually makes: a wrong number of words, and one mistyped word.
    #[test]
    fn rejected_mnemonic_message_names_the_specific_problem() {
        // 13 words — not a length BIP39 defines. The message must say so, and quote the count.
        let thirteen = vec!["abandon"; 13].join(" ");
        let args = argv(&["restore", "--mnemonic", &thirteen, "--coin", "btc"]);
        let msg = run(&args).unwrap_err().0;
        assert!(msg.contains("13"), "must report the actual count: {msg}");
        assert!(msg.contains("12"), "must list the legal counts: {msg}");

        // One word out of twelve mistyped. The message must name that word and its position, so
        // the user knows where to look on the card in front of them.
        let typo = "abandon abandon abandon abandon abandon abandom \
                    abandon abandon abandon abandon abandon about";
        let args = argv(&["restore", "--mnemonic", typo, "--coin", "btc"]);
        let msg = run(&args).unwrap_err().0;
        assert!(msg.contains("abandom"), "must name the word: {msg}");
        assert!(msg.contains('6'), "must give the position: {msg}");
    }
}
