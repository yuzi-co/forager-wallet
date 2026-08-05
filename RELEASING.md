# Releasing

Two crates, published in a fixed order, plus a tag that builds the binaries. The order is not a
preference — the second publish cannot resolve until the first is on the index.

## The order

`forager-wallet` depends on `forager-addr` by both `path` and `version`. Publishing strips the
path, so crates.io must already hold a `forager-addr` matching the requirement before
`forager-wallet` can even be packaged. Verified, not assumed:

```console
$ cargo package -p forager-wallet
error: failed to select a version for the requirement `forager-addr = "^0.2.0"`
  candidate versions found which didn't match: 0.1.1, 0.1.0
  location searched: crates.io index
```

So:

1. Bump both `version` fields and `crates/wallet/Cargo.toml`'s `forager-addr` requirement in one
   commit. Cargo will not let these disagree — a `path` dependency whose real version does not
   satisfy the stated requirement fails to resolve locally, immediately, before any test runs. That
   is why no test in this repository guards the pair: the compiler already does, and a guard for a
   failure that cannot happen is the decorative kind this repository argues against elsewhere.
2. `cargo publish -p forager-addr`
3. Wait for the index to carry it. `cargo package -p forager-wallet` succeeding is the signal.
4. `cargo publish -p forager-wallet`
5. Tag and push. `.github/workflows/release.yml` fires on the tag and is independent of the two
   steps above — it builds, tests, attests and uploads binaries to a GitHub release. It does not
   publish to crates.io, and crates.io publishing does not build binaries.

## What cannot be checked before step 2

`cargo package -p forager-wallet` is unavailable for the whole window between bumping the version
and publishing `forager-addr`. Anything that depends on inspecting the *packaged* wallet crate is
therefore unavailable too — most importantly the packaged manifest shape, which is not the shape
that was written: `cargo package` rewrites every dependency into its own `[dependencies.<name>]`
table.

Both dependency guards parse that shape, because both once did not and panicked on an extracted
`.crate` — the exact situation a reader verifying the no-network claim from a published tarball is
in. Since a real packaged wallet manifest first exists on release day, and a guard that starts
working only after release is not a guard, `the_parser_reads_the_manifest_shape_cargo_package_writes`
in `crates/wallet/tests/dependency_hygiene.rs` pins that shape synthetically instead of waiting.

`forager-addr` has no such gap: it depends on nothing in this workspace, so `cargo package -p
forager-addr` works at any time, and its guard can be exercised for real against an extracted
tarball.

## Before publishing anything

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked
cargo deny check
```

All four are what CI runs. `cargo deny check` should report `advisories ok, bans ok, licenses ok,
sources ok` with no warnings at all — the zero-warning state is deliberate and is the subject of its
own commit; see the comments in `deny.toml`.
