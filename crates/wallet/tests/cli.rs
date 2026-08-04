//! CLI dispatch tests for the standalone `forager-wallet` binary.
//!
//! These assert the argv contract only. Address correctness is covered by the per-family
//! known-answer tests in the crate itself.

use forager_wallet::cli::{run, CliError};

fn argv(rest: &[&str]) -> Vec<String> {
    std::iter::once("forager-wallet")
        .chain(rest.iter().copied())
        .map(str::to_string)
        .collect()
}

#[test]
fn list_succeeds() {
    assert_eq!(run(&argv(&["list"])), Ok(()));
}

#[test]
fn new_requires_a_coin() {
    let err = run(&argv(&["new"])).expect_err("--coin is required; there is no default coin");
    assert!(
        err.to_string().contains("--coin"),
        "unhelpful message: {err}"
    );
}

#[test]
fn new_mints_for_a_known_coin() {
    assert_eq!(run(&argv(&["new", "--coin", "btc"])), Ok(()));
}

#[test]
fn inspect_rederives_a_known_key() {
    // privkey = 1 on BTC mainnet, legacy P2PKH — the vector the crate's own KATs use.
    let priv1 = "0000000000000000000000000000000000000000000000000000000000000001";
    assert_eq!(
        run(&argv(&["inspect", priv1, "--coin", "btc", "--legacy"])),
        Ok(())
    );
}

#[test]
fn unknown_coin_is_an_error_not_a_panic() {
    let err = run(&argv(&["new", "--coin", "definitely-not-a-coin"]))
        .expect_err("an unknown ticker must be rejected");
    assert!(err.to_string().contains("definitely-not-a-coin"), "{err}");
}

#[test]
fn unknown_subcommand_is_an_error_not_a_panic() {
    assert!(matches!(run(&argv(&["frobnicate"])), Err(CliError(_))));
}

#[test]
fn no_subcommand_prints_usage() {
    let err = run(&argv(&[])).expect_err("bare invocation must explain itself");
    assert!(err.to_string().contains("new"), "unhelpful usage: {err}");
}
