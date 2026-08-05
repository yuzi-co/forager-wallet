# Fuzzing `forager-addr`

`forager-addr` exists to parse strings nobody trustworthy wrote. A miner links it and hands it a
payout address out of a user's config file; the crate's whole job is to decode that string and say
which family it belongs to. Everything else in this repository is driven by known-answer tests,
which prove the *right* input produces the right output. These targets cover the other half: that no
input, however malformed, produces a panic or a self-contradictory answer.

One target per logical parser:

| Target | Covers |
| --- | --- |
| `detect_family` | `validate::detect_family` and `validate::check` — the primary entry point, plus the verdict layer on top of it |
| `base58` | `codec::base58::decode` and `decode_check` |
| `bech32` | `codec::bech32::verify` |
| `hexbytes` | `hexbytes::decode` and `decode_n::<N>` |
| `parse_token` | `coins::parse_token` — the `family:params` custom-coin grammar |

Each target takes the raw input bytes and rejects non-UTF-8 rather than going through `Arbitrary`,
so a corpus file is byte-identical to the string it feeds. That is what lets the checked-in seeds be
read as what they look like.

`hexbytes::hex32` is deliberately **not** fuzzed: it is documented to panic on malformed input, being
a known-answer-test helper whose literals are fixed at compile time. A target for it would rediscover
that documented panic and nothing else.

## Running

`cargo-fuzz` needs a nightly toolchain — libFuzzer instrumentation is passed through `-Z` flags that
stable does not accept.

```sh
cargo install cargo-fuzz
rustup toolchain install nightly

cargo +nightly fuzz build                 # compile every target
cargo +nightly fuzz run detect_family     # run one, until you stop it
cargo +nightly fuzz list                  # the target names
```

Two targets want a flag. Everything after `--` goes to libFuzzer:

```sh
# `base58::decode` does one bignum multiply per character against a number that grows with the
# input, so it is superlinear by construction. Cap the length or libFuzzer reports the timeout as
# a finding, which it is not.
cargo +nightly fuzz run base58 -- -max_len=256

# `parse_token` calls `Box::leak` on the ticker, the name and the version prefix of every token it
# accepts. That is bounded and correct in the one-shot CLI it was written for, and unbounded in a
# fuzzing loop — so turn the leak detector off and give the process a ceiling.
cargo +nightly fuzz run parse_token -- -detect_leaks=0 -rss_limit_mb=4096
```

### On Windows

`x86_64-pc-windows-msvc` builds and runs these targets, but the Rust toolchain does not ship the
AddressSanitizer runtime for it — the instrumented binary links `clang_rt.asan_dynamic-x86_64.dll`
dynamically and dies at startup with `STATUS_DLL_NOT_FOUND` (`0xc0000135`) if it is not on `PATH`.
The DLL comes with the MSVC build tools; put its directory on `PATH` first:

```pwsh
$env:PATH = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\<ver>\bin\Hostx64\x64;$env:PATH"
```

`cargo fuzz build` succeeds without this — only running does. The version directory changes with the
build tools; an LLVM install has the same DLL under `lib\clang\<major>\lib\windows`.

## Reproducing a crash

libFuzzer writes the offending input to `fuzz/artifacts/<target>/`. The file is the exact bytes that
triggered it, so you can read it:

```sh
cat fuzz/artifacts/detect_family/crash-2b1f…       # what was fed in
cargo +nightly fuzz run detect_family fuzz/artifacts/detect_family/crash-2b1f…
cargo +nightly fuzz fmt detect_family fuzz/artifacts/detect_family/crash-2b1f…   # as a Rust literal
```

`fuzz fmt` prints the input in a form you can paste straight into a `#[test]` in the crate — which is
where a reproducer belongs once it is understood, so the regression is caught by `cargo test` and not
only by a fuzzing run nobody remembers to start.

To shrink a large reproducer first:

```sh
cargo +nightly fuzz tmin detect_family fuzz/artifacts/detect_family/crash-2b1f…
```

## The seed corpus

`corpus/<target>/*.seed` is checked in, and it matters more than the harness does. A fuzzer that
starts from a valid bech32m address reaches the checksum-verified branch on its first mutation; one
that starts from nothing spends hours learning the base58 alphabet before it gets anywhere
interesting.

None of the seeds are invented. They are the address literals already asserted on in this
repository's tests, plus addresses minted from the well-known `privkey = 1` by the repo's own
KAT-gated generator (`forager-wallet restore 0000…0001 --coin <ticker>`) — which is how the corpus
covers every family, mainnet and testnet, including the multi-byte CryptoNote prefixes (`ZEPHYR…`,
`SaLv…`), the two-byte Zcash-family version prefix (`t1…`), and Spectre, for which no literal appears
anywhere in the tests. The `parse_token` corpus is every `TOKEN_GRAMMAR` worked example plus the
tokens `coins.rs` pins as rejections.

Alongside the valid addresses sit the near misses, which are the inputs that actually find bugs: a
corrupted bech32 checksum, a WIF (valid base58check, unmodelled version byte), an empty CashAddr
payload, a bare `0x`.

libFuzzer writes the inputs it discovers back into the same directories, named by SHA-1. Those are
generated and `.gitignore`d; the hand-picked seeds are un-ignored by their `.seed` suffix. libFuzzer
reads every file in the directory whatever it is called, so the suffix costs nothing at runtime.

## What the targets assert

Beyond "does not panic" — which is most of the value, since a panic in a miner's config path is a
crash on startup — each target pins invariants that were read back out of the source, not guessed:

* **`detect_family`** — `check` is `detect_family` plus a verdict and nothing else, so the two must
  agree for every expected family: an unclassifiable address is `Unrecognized` for all of them and a
  classified one for none of them, and a `Mismatch` reports back exactly the pair it was given.
  Family compatibility is reflexive, so a family never mismatches against itself. Separately,
  `detect_family` trims its argument on its first line and never looks at the untrimmed string
  again, so surrounding whitespace cannot change the answer.
* **`base58`** — `decode_check` opens by calling `decode` with `?`, so anything it accepts must also
  decode, and its payload is the decode output minus its trailing four checksum bytes. And base58 is
  canonical, so `encode(decode(s)) == s` exactly: leading `1`s and leading `0x00` bytes correspond
  one-to-one in both directions, and a non-zero `BigUint` has neither a leading zero byte nor a
  leading zero digit.
* **`bech32`** — a `Some` hands the caller an HRP that it will match against the coin table, so that
  HRP must be a non-empty, lower-case prefix of the lower-cased input with room left for the
  separator and a six-character checksum. Lower-casing a string `verify` already accepted cannot
  change what it returns, because it rejects mixed case first and lower-cases internally anyway. The
  converse is not asserted: lower-casing a *rejected* mixed-case string can legitimately turn it
  into a valid address.
* **`hexbytes`** — an accepted string is exactly twice as long as its output, and `decode_n::<N>`,
  being `decode` plus a width check, must agree with `decode` for every `N`. The round trip is
  deliberately **not** asserted, and this is not caution: it is false. `decode` delegates to
  `u8::from_str_radix(_, 16)`, which accepts a leading `+`, so `decode("+f")` is `Some([0x0f])` and
  re-encoding gives `"0f"`.
* **`parse_token`** — an accepted token is carried through verbatim as the spec's ticker, never
  offers HD derivation (a runtime token names no chain, so no SLIP-44 type is knowable), and split
  on its first `:` yields a family the `TOKEN_GRAMMAR` table lists. That last one is what keeps the
  grammar table the single source of truth: a family reachable by parsing but missing from the table
  would be invisible to `forager wallet list`.

Nothing is asserted that was not traced through the source first. A wrong invariant does not make a
fuzzer stricter, it makes it useless — every run ends in a false alarm and the harness gets ignored.
