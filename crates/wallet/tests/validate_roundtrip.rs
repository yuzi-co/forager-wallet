//! Detection tests that need the *generator*.
//!
//! These live here rather than beside the rest of the detection tests in `validate.rs` because
//! they mint their inputs with `address_from_secret`. Address classification is moving into the
//! `forager-addr` crate, which deliberately depends on no curve, entropy or mnemonic code, so a
//! test that calls the generator cannot travel with it. See
//! `the repository README`.

use forager_wallet::{detect_family, Family, Network};

/// A CryptoNote fork with a multi-byte network prefix is detected as CryptoNote — the case a
/// first-character `4`/`8` test could not see.  The addresses are minted from the coin rows
/// themselves, so this cannot drift from what the generator emits.
#[test]
fn detects_multibyte_prefix_cryptonote_forks() {
    const PRIV1: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    for (ticker, tag) in [("zeph", "ZEPHYR"), ("sal", "SaLv")] {
        let w = forager_wallet::address_from_secret(ticker, PRIV1, Network::Mainnet).unwrap();
        assert!(w.address.starts_with(tag), "{ticker}: {}", w.address);
        assert_eq!(
            detect_family(&w.address),
            Some(Family::CryptoNote),
            "{ticker}: {}",
            w.address
        );
    }
}
