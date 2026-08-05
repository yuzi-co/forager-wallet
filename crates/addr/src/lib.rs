//! Payout-address classification for the Forager coin table.
//!
//! Decodes an address and reports which family it belongs to — see [`validate::detect_family`] and
//! [`validate::check`]. Classification is advisory: it never blocks, and an address it cannot
//! classify is reported as [`validate::Verdict::Unrecognized`] rather than rejected.
//!
//! This crate holds no key material, no entropy source and no curve arithmetic. Key generation
//! lives in the separate `forager-wallet` crate. Its external dependencies are `sha2` and
//! `blake2b_simd`, for the base58check and Ergo address checksums, and `num-bigint`/`num-traits`,
//! for base58's non-power-of-two decode; `tests/hygiene.rs` enforces that list. The fourth checksum
//! hash, Keccak-256, is written out in [`hash`] rather than taken from a crate, so that verifying
//! the Ethereum and CryptoNote checksums costs the dependency list nothing. See
//! `the repository README`.

#![forbid(unsafe_code)]

pub mod codec;
pub mod coins;
pub mod hash;
pub mod hexbytes;
pub mod validate;

pub use coins::Family;
pub use validate::{check, detect_family, family_name, Verdict};
