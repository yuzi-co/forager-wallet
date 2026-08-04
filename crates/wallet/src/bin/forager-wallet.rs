//! `forager-wallet` — offline multi-coin payout-address keygen.
//!
//! No pool, no GPU, no network. The crate depends on nothing that can open a socket, so the
//! offline guarantee is checkable from the manifest rather than taken on trust.
//!
//! Back up the secret this prints. It is shown once and never stored. Before you mine to a
//! generated address, re-derive it independently — `forager-wallet inspect <secret-hex> --coin
//! <ticker>`, or any standard BIP39 tool for `--hd` mnemonics — and confirm the two agree.

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match forager_wallet::cli::run(&args) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
