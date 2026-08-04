# Forager Wallet

**Offline payout-address and key generation for 29 cryptocurrencies.** No pool, no GPU, no network.

```sh
cargo install forager-wallet

forager-wallet list                              # supported coins
forager-wallet new --coin btc                    # mint an address + secret
forager-wallet new --hd --coin btc               # BIP39 mnemonic, native SegWit (m/84')
forager-wallet new --hd --all --purpose taproot  # every HD coin at m/86'
forager-wallet restore <secret-or-wif> --coin btc # re-derive from a key you hold
forager-wallet restore --mnemonic "<24 words>" --coin btc
```

---

## Verify the address before you mine to it

**A wrong address means unspendable funds, and no software can undo that.**

Every address family here is clean-room — re-derived from the published standard — and locked by a
known-answer test. That proves the *scheme*. It does not prove *your* address. Only an independent
re-derivation does that.

1. Generate an address and back up the secret. It is printed once and never stored.
2. Re-derive the same address in software that is not this tool — any standard WIF importer for a
   single key, any standard BIP39 wallet for an `--hd` mnemonic. (`forager-wallet restore` re-derives
   it too, from either the hex, the WIF, or the mnemonic — useful as a first check, but it is not
   independent of this tool.)
3. Confirm the two match character for character.
4. Only then point a miner at it.

Run `cargo test` to check the known-answer vectors yourself.

## Offline by construction

The dependency list is `k256`, `bip32`, `zeroize`, `sha2`, `blake2b_simd`, `getrandom`,
`num-bigint`, `num-traits`. **None of them can open a socket.** You can confirm the no-network claim
by reading `Cargo.toml`, without reading a line of code.

Private keys and seeds are zeroed on drop. Both crates are `#![forbid(unsafe_code)]`.

## The two crates

| Crate | What it does |
|---|---|
| [`forager-wallet`](crates/wallet) | Key generation: curves, BIP39/BIP44, the address families, and the CLI binary. |
| [`forager-addr`](crates/addr) | Address **classification** only: decode an address, report its family. No key material, no entropy source, no curve arithmetic. |

The split is the point. The closed-source Forager miner links `forager-addr` and **only**
`forager-addr`, so it can warn a user whose configured payout address belongs to a different family
than the one the pool pays out in — while containing no key-generation code and no entropy path at
all.

That is not a promise you have to trust. It is checkable from the miner's dependency list, and
`forager-addr`'s own `tests/hygiene.rs` fails the build if a curve, entropy or mnemonic crate is
ever added to it.

## Why this is open and the miner is not

The miner's value is its optimized kernels. This tool's value is that you can read it.

Key generation is the one thing a user should never run closed-source: a backdoored entropy source
is undetectable from the outside and would steal every coin ever mined to the resulting address.
Nothing here is proprietary — BIP32/39/44, secp256k1, Ed25519, bech32/bech32m, base58check,
CashAddr and EIP-55 are public standards — so publishing costs nothing and buys a claim that can
actually be verified.

## Supported coins

29 coins across nine address families and two curves: Taproot (bech32m), SegWit v0 (bech32), P2PKH
(base58check), Ethereum (EIP-55), CryptoNote/Monero, Kaspa-family (CashAddr), Ergo, Alephium and
XDAG.

**[crates/wallet/COINS.md](crates/wallet/COINS.md)** documents every coin with its address form and
HD path, the three HD purposes (BIP44 / BIP84 / BIP86), and how to generate for a coin that is not
in the table yet — the `--coin family:params` token grammar, how to read the parameters out of a
coin's `chainparams.cpp`, worked examples for Dash, DigiByte, Neoxa and others, and the cases where
a custom token will *not* work.

Run `forager-wallet list` for the live table.

### HD derivation

`--hd` derives from a 24-word BIP39 mnemonic. Each coin defaults to the purpose whose address type
matches its single-key output, so `new --coin btc` and `new --hd --coin btc` give the same kind of
address:

| `--purpose` | Path | Address |
|---|---|---|
| `bip44` (`legacy`) | `m/44'` | base58check P2PKH, or EIP-55 for Ethereum-family |
| `bip84` (`segwit`) | `m/84'` | native SegWit v0 — the default for BTC, LTC, VTC |
| `bip86` (`taproot`) | `m/86'` | Taproot key-path |

## License

[Apache License, Version 2.0](LICENSE).

Section 4(b) asks you to mark modified files as changed. Please keep [`NOTICE`](NOTICE) intact when
you redistribute.

**Trademark.** Apache-2.0 §6 grants no trademark rights. Forager is a trademark; this license does
not permit publishing a fork under the Forager name.
