//! Payout-address classification for the Forager coin table.
//!
//! Decodes an address and reports which family it belongs to — see [`validate::detect_family`] and
//! [`validate::check`]. Classification is advisory: it never blocks, and an address it cannot
//! classify is reported as [`validate::Verdict::Unrecognized`] rather than rejected.
//!
//! This crate holds no key material, no entropy source and no curve arithmetic. Key generation
//! lives in the separate `forager-wallet` crate. Its external dependencies are `sha2`, for the
//! base58check checksum, and `num-bigint`/`num-traits`, for base58's non-power-of-two decode;
//! `tests/hygiene.rs` enforces that list. See
//! `the repository README`.

#![forbid(unsafe_code)]

pub mod codec;
pub mod coins;
pub(crate) mod hash;
pub mod hexbytes;
pub mod validate;

pub use coins::Family;
pub use validate::{check, detect_family, family_name, Verdict};
