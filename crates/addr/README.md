# forager-addr

Cryptocurrency payout-address **classification**: decode an address and report which family it
belongs to.

```rust
use forager_addr::{check, detect_family, Family, Verdict};

assert_eq!(
    detect_family("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"),
    Some(Family::P2pkh)
);

// Advisory, never fatal: an address that cannot be classified is reported, not rejected.
assert!(matches!(check("not-an-address", Family::P2pkh), Verdict::Unrecognized));
```

Families: Taproot (bech32m), SegWit v0 (bech32), P2PKH (base58check), Ethereum (EIP-55),
CryptoNote, Kaspa-family (CashAddr), Ergo, Alephium and XDAG, across 30 coins.

## What this crate deliberately does not contain

No key material, no entropy source, no curve arithmetic, no mnemonic wordlist. Classification only
decodes and checksums — it never touches a private key.

That is enforced, not merely intended: `tests/hygiene.rs` asserts the external dependency list is
exactly `sha2`, `blake2b_simd`, `num-bigint` and `num-traits`. The two hash crates compute the
address checksums — `sha2` for base58check, `blake2b_simd` for Ergo — and the two arithmetic crates
do base58's decode, whose alphabet is not a power of two. The test fails the build if a curve,
entropy or mnemonic crate is ever added, and equally if an entry stops being used, so the list
cannot become a set of pre-authorized slots.

The crate is `#![forbid(unsafe_code)]`.

## Why the split exists

The closed-source Forager miner links this crate — and only this crate — so it can warn a user whose
configured payout address belongs to a different family than the one the pool pays out in. Payouts
sent to an address the pool cannot credit are lost, so the warning is worth a dependency; minting
keys is not. Because key generation lives in the separate
[`forager-wallet`](https://crates.io/crates/forager-wallet) crate, the miner contains no
key-generation code — no mnemonic wordlist, no address minting, and no path that handles a private
key — and a user can verify that from its dependency list.

Read that claim narrowly. It says the miner cannot generate or handle a key. It does not say the
miner links no curve and no entropy source, because it links both, for reasons unrelated to
wallets: one of its proof-of-work algorithms needs secp256k1 point arithmetic, which pulls a
transitive `getrandom`.

## License

Licensed under the [Apache License, Version 2.0](LICENSE); a copy ships in this crate, alongside
the [`NOTICE`](NOTICE) file. Please keep both intact when you redistribute.

**Trademark.** Apache-2.0 §6 grants no trademark rights. Forager is a trademark; this license does
not permit you to publish a fork under the Forager name.
