# forager-wallet

An **offline** multi-coin payout-address and key generator. No pool, no GPU, no network.

```sh
forager-wallet list                                       # supported coins
forager-wallet new --coin btc                             # mint an address + secret
forager-wallet new --hd --coin btc                        # BIP39 mnemonic, 24 words
forager-wallet new --hd --all --purpose taproot           # every HD coin at m/86'
forager-wallet restore <secret-or-wif> --coin btc         # re-derive from a key you hold
forager-wallet restore --mnemonic "<24 words>" --coin btc
```

`--hd` derives from a 24-word BIP39 mnemonic. Each coin defaults to the purpose whose address type
it actually pays out in, so `--hd` and single-key mode hand out the same kind of address.

| `--purpose` | Path | Address |
|---|---|---|
| `bip44` (`legacy`) | `m/44'` | P2PKH — the default for most coins |
| `bip84` (`segwit`) | `m/84'` | native SegWit v0 — the default for BTC, LTC, VTC |
| `bip86` (`taproot`) | `m/86'` | Taproot bech32m |

**[COINS.md](COINS.md)** — every supported coin, its address form and HD path, plus how to
generate for a coin that is not in the table yet, with worked examples.

## Verify the address before you mine to it

**A wrong address means unspendable funds, and no software can undo that.** Verify, then mine.

Every address family here is clean-room — re-derived from the published standard — and locked by a
known-answer test. That proves the *scheme* is right. It does not prove *your* address is right.
Only an independent re-derivation does that.

1. Generate an address and back up the secret. It is printed once and never stored.
2. Re-derive the same address from the same secret, in software that is not this tool:
   - single-key: any standard WIF importer;
   - `--hd`: any standard BIP39 wallet, from the same 24-word mnemonic and the same path.

   `forager-wallet restore` is a cheap first check, but it is **not independent** — it re-runs the
   same code that minted the address. Only other software proves the address.
3. Confirm the two addresses are identical, character for character.
4. Only then point a miner at it.

The known-answer vectors are in this crate's tests, so you can check the scheme yourself:
`cargo test`.

## Offline by construction

The crate depends on `k256`, `bip32`, `zeroize`, `sha2`, `blake2b_simd`, `getrandom`, `num-bigint`,
`num-traits` and `forager-addr`. **None of them can open a socket.** You can confirm the
no-network claim by reading `Cargo.toml`, without reading any code.

Private keys and seeds are zeroed on drop, and the crate is `#![forbid(unsafe_code)]`.

## Relationship to the Forager miner

Key generation used to live inside the Forager miner. It was split out so that the miner links no
key-generation code and no entropy source at all — a property a user can check from the miner's
dependency list rather than take on trust. The miner keeps only
[`forager-addr`](https://crates.io/crates/forager-addr), which classifies an address and warns when
a configured payout address does not match what a pool pays out in.

`src/ripemd160.rs` is a copy of the implementation the closed miner uses, not a third-party file.
RIPEMD-160 was finalized in 1996 and cannot change, and both copies are gated against the standard
vectors, so the two cannot drift silently.

## License

Licensed under the [Apache License, Version 2.0](LICENSE); a copy ships in this crate.

Apache-2.0 §4(b) requires modified files to carry a notice that you changed them. Please keep the
[`NOTICE`](NOTICE) file intact when you redistribute.

**Trademark.** Apache-2.0 §6 grants no trademark rights. Forager is a trademark; this license does
not permit you to publish a fork under the Forager name.
