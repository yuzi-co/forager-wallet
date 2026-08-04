# Supported coins, address forms and custom coins

Run `forager-wallet list` for the live table — this file documents it, and a test
(`tests/docs_coverage.rs`) fails the build if the two drift apart.

> **Verify before you mine.** Whatever you generate here — a listed coin or a custom token —
> re-derive the address independently before pointing a miner at it. `forager-wallet inspect
> <secret-hex> --coin <ticker>` re-derives from the secret; for `--hd`, any standard BIP39 wallet
> reproduces the address from the mnemonic at the printed path. A wrong address means unspendable
> funds, and no software can undo that.

## Address families

| Family | Encoding | Curve |
|---|---|---|
| Taproot | bech32m, witness v1, BIP340/341/350 key-path | secp256k1 |
| SegWit v0 | bech32, witness v0 P2WPKH | secp256k1 |
| P2PKH | base58check(version ‖ HASH160(pubkey)) | secp256k1 |
| Ethereum | EIP-55 checksummed keccak160 of the uncompressed pubkey | secp256k1 |
| CryptoNote | dual spend/view keys, varint network prefix, 25-word seed | ed25519 |
| Kaspa-family | CashAddr-style `<prefix>:<payload><8-char checksum>`, x-only pubkey, no tweak | secp256k1 |
| Ergo P2PK | base58(prefix ‖ compressed pubkey ‖ Blake2b256[..4]) | secp256k1 |
| Alephium | base58(0x00 ‖ Blake2b256(compressed pubkey)), no checksum | secp256k1 |
| XDAG | base58check(HASH160(pubkey)) with **no** version byte | secp256k1 |

## The coin table

`default address` is what `new --coin <ticker>` produces. `HD` is the path `new --hd` uses by
default; coins with no registered SLIP-44 coin type have no HD row, because inventing one would
produce a path no other wallet reproduces.

| Ticker | Coin | Family | Default address | HD path (`--hd`) |
|---|---|---|---|---|
| `pearl` | Pearl | Taproot | `prl1p…` | — |
| `btc` | Bitcoin | SegWit v0 | `bc1q…` | `m/84'/0'` |
| `ltc` | Litecoin | SegWit v0 | `ltc1q…` | `m/84'/2'` |
| `vtc` | Vertcoin | SegWit v0 | `vtc1q…` | `m/84'/28'` |
| `scash` | Scash | SegWit v0 | `sc1q…` | — |
| `alpha` | Unicity Alpha | SegWit v0 | bech32 | — |
| `doge` | Dogecoin | P2PKH | `D…` | `m/44'/3'` |
| `rvn` | Ravencoin | P2PKH | `R…` | `m/44'/175'` |
| `firo` | Firo | P2PKH | `a…` | `m/44'/136'` |
| `mewc` | Meowcoin | P2PKH | `M…` | `m/44'/1669'` |
| `zec` | Zcash (transparent) | P2PKH | `t1…` | `m/44'/133'` |
| `btg` | Bitcoin Gold | P2PKH | `G…` | `m/44'/156'` |
| `kmd` | Komodo | P2PKH | `R…` | `m/44'/141'` |
| `btcz` | BitcoinZ | P2PKH | `t1…` | `m/44'/177'` |
| `zer` | Zero | P2PKH | `t1…` | `m/44'/323'` |
| `eth` | Ethereum | Ethereum | `0x…` | `m/44'/60'` |
| `etc` | Ethereum Classic | Ethereum | `0x…` | `m/44'/61'` |
| `ubq` | Ubiq | Ethereum | `0x…` | `m/44'/108'` |
| `ethw` | EthereumPoW | Ethereum | `0x…` | — |
| `octa` | OctaSpace | Ethereum | `0x…` | — |
| `xmr` | Monero | CryptoNote | `4…` | — |
| `zeph` | Zephyr | CryptoNote | `ZEPHYR…` | — |
| `sal` | Salvium | CryptoNote | `SaLv…` | — |
| `kas` | Kaspa | Kaspa-family | `kaspa:…` | — |
| `kls` | Karlsen | Kaspa-family | `karlsen:…` | — |
| `spr` | Spectre | Kaspa-family | `spectre:…` | — |
| `erg` | Ergo | Ergo P2PK | base58 | — |
| `alph` | Alephium | Alephium | base58 | — |
| `xdag` | XDAG | XDAG | base58check | — |

**Testnet.** `--testnet` works where the coin defines one. `--legacy` renders the base58 form for a
SegWit-default coin (`btc`, `ltc`, `vtc`, `scash`, `alpha`).

## HD purposes

`--hd` derives from a 24-word BIP39 mnemonic at `m/<purpose>'/<slip44>'/<account>'/0/<index>`.

| `--purpose` | Aliases | Path | Address | Applies to |
|---|---|---|---|---|
| `bip44` | `44`, `legacy`, `p2pkh` | `m/44'` | base58check P2PKH, or EIP-55 for Ethereum-family | every HD coin |
| `bip84` | `84`, `segwit`, `p2wpkh` | `m/84'` | native SegWit v0 | SegWit-family coins |
| `bip86` | `86`, `taproot`, `p2tr` | `m/86'` | Taproot key-path | SegWit- and Taproot-family coins |

Without `--purpose`, each coin uses the purpose whose address type matches its single-key output —
so `new --coin btc` and `new --hd --coin btc` return the same **kind** of address.

```sh
forager-wallet new --hd --coin btc                    # m/84'/0'/0'/0/0  → bc1q…
forager-wallet new --hd --coin btc --purpose taproot  # m/86'/0'/0'/0/0  → bc1p…
forager-wallet new --hd --coin btc --purpose legacy   # m/44'/0'/0'/0/0  → 1…
forager-wallet new --hd --all --account 1 --index 5   # every HD coin, one mnemonic
```

Asking for a purpose a coin's family cannot encode is an error, never a wrong address:

```
$ forager-wallet new --hd --coin doge --purpose bip84
error: coin 'doge' has no bip84 address form
```

## Coins not in the table: custom tokens

`--coin <family>:<params>` builds an address with a KAT-gated encoder and **your** parameters. Use
it for any coin whose address scheme is one of the families above.

> **A custom token is UNVERIFIED.** No known-answer test covers your parameters, so nothing checks
> that you read them correctly. The tool prints a warning and you must verify the address before
> mining to it.

### Grammar

```
--coin p2pkh:ver=<byte>,wif=<byte>[,uncompressed]
--coin segwit:hrp=<str>,wif=<byte>[,ver=<byte>]
--coin taproot:hrp=<str>
--coin cryptonote:net=<int>[,net_test=<int>]
--coin kaspa:prefix=<str>
--coin ethereum:
--coin ergo:
--coin alephium:
--coin xdag:
```

Integers are decimal or `0x`-prefixed hex. An unrecognised parameter is rejected rather than
ignored:

```
$ forager-wallet new --coin p2pkh:ver=0x4c,bogus=1
error: bad coin token: family 'p2pkh' has no 'bogus=' parameter
```

### Finding the parameters

For any Bitcoin-derived coin, read them from the project's own `chainparams.cpp` — never from a
block explorer or a forum post:

```
base58Prefixes[PUBKEY_ADDRESS] → ver=   (the P2PKH version byte)
base58Prefixes[SECRET_KEY]     → wif=   (the WIF byte)
bech32_hrp                     → hrp=   (SegWit / Taproot human-readable part)
```

Modern Bitcoin Core forks moved these to `src/kernel/chainparams.cpp`. Read the **mainnet** class
(`CMainParams`), not testnet.

### Worked examples

Each address below is for the test key
`0000000000000000000000000000000000000000000000000000000000000001` and was produced by the command
shown, so you can reproduce them exactly.

**Dash** — `PUBKEY_ADDRESS=76 (0x4c)`, `SECRET_KEY=204 (0xcc)`, `dashpay/dash`:

```sh
$ forager-wallet inspect 0000…0001 --coin p2pkh:ver=0x4c,wif=0xcc
XmN7PQYWKn5MJFna5fRYgP6mxT2F7xpekE
```

**DigiByte** — `bech32_hrp="dgb"`, `SECRET_KEY=128 (0x80)`, `PUBKEY_ADDRESS=30 (0x1e)`,
`DigiByte-Core/digibyte` (`src/kernel/chainparams.cpp`):

```sh
$ forager-wallet inspect 0000…0001 --coin segwit:hrp=dgb,wif=0x80,ver=0x1e
dgb1qw508d6qejxtdg4y5r3zarvary0c5xw7kmudfnm
```

**Neoxa** — `PUBKEY_ADDRESS=38 (0x26)`, `SECRET_KEY=112 (0x70)`, `NeoxaChain/Neoxa`:

```sh
$ forager-wallet inspect 0000…0001 --coin p2pkh:ver=0x26,wif=0x70
GUXByHDZLvU4DnVH9imSFckt3HEQ5cFgE5
```

**A CryptoNote fork** — the network prefix is `CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX` in the
project's `cryptonote_config.h`:

```sh
$ forager-wallet inspect 0000…0001 --coin cryptonote:net=197
ZxByaM2T8UWfjxvvnypP2e8LU1ibmAxDkKYti8jNkuseccSWJnHcz3jSh5gFDmazLoSxLuKU6G8pr6WL4cJDTrAk1cmKr5MF5
```

**Bitcoin Taproot** — the `taproot:` family with Bitcoin's HRP:

```sh
$ forager-wallet inspect 0000…0001 --coin taproot:hrp=bc
bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sspknck9
```

### When a custom token will NOT work

A token reuses an existing family's **framing**, not just its alphabet. If the coin's address
construction differs in any way beyond the parameters above, the token produces a well-formed
string that is not a valid address for that chain.

- **Nexa** looks CashAddr-like, but its payload framing differs from the Kaspa family, so
  `kaspa:prefix=nexa` yields a valid-looking address that Nexa will not credit.
- **Radiant**, **Zano**, **Xelis**, **Iron Fish** and **Quai** each use a scheme no family here
  models. Quai additionally scopes addresses to a shard, so an EIP-55 address from `ethereum:` can
  land in the wrong zone.
- A coin whose legacy P2PKH parameters equal Bitcoin's (Radiant is `ver=0`, `wif=128`) produces
  addresses indistinguishable from Bitcoin's, which also defeats the payout-address pre-flight
  check in the Forager miner.

For those, the address family has to be implemented and KAT-gated. Open an issue rather than
guessing a token.
