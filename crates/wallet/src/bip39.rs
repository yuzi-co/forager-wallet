//! **Clean-room BIP-39**: entropy ↔ mnemonic phrase, and phrase + passphrase → 64-byte seed.
//!
//! Implemented directly from the BIP-39 specification text
//! (`bitcoin/bips/bip-0039.mediawiki`), against the official
//! `trezor/python-mnemonic` `vectors.json` known-answer tests.  The English word list lives in
//! [`crate::wordlist_bip39_en`] — **not** [`crate::wordlist_en`], which is Monero's unrelated
//! 1626-word CryptoNote list.
//!
//! ## Why this is not delegated
//!
//! The `bip32` crate (still used here for BIP-32 CKDpriv derivation) ships a BIP-39 module with
//! two defects that reach the user, both confirmed by reading `bip32-0.5.3/src/mnemonic/phrase.rs`:
//!
//! 1. **12-word phrases are rejected.**  `Phrase::new` requires `entropy.len() == KEY_SIZE + 1`
//!    with `KEY_SIZE == 32`, so only 256-bit (24-word) phrases parse.  A perfectly valid 12-word
//!    phrase — the most common length in circulation — comes back as a generic error, which this
//!    crate then reported as "invalid BIP39 mnemonic (check the words, length, and checksum)".
//!    That is a false accusation against a valid phrase, in a tool whose headline feature is
//!    restore.
//!
//! 2. **The passphrase is not NFKD-normalized.**  `to_seed` runs PBKDF2 over
//!    `self.phrase.as_bytes()` and `format!("mnemonic{}", password).as_bytes()` — raw UTF-8, no
//!    normalization.  BIP-39 §"From mnemonic to seed" mandates NFKD on *both* the mnemonic and the
//!    passphrase.  The English word list is ASCII, so the phrase side is harmless; a **non-ASCII
//!    passphrase**, however, silently derives a seed that no spec-compliant wallet reproduces, and
//!    the funds land at an address the user cannot restore anywhere else.
//!
//! Both defects are data-correctness bugs in the one place this crate cannot tolerate one, so the
//! ~150 lines below are cheaper than the risk.  This also matches how the rest of the crate is
//! built: RIPEMD-160, Keccak, Edwards25519 and the Monero word list are all local for the same
//! reason.
//!
//! ## The spec, in brief
//!
//! * **Entropy → phrase.**  `ENT` bits of entropy (128/160/192/224/256) get a checksum of the
//!   first `ENT/32` bits of `SHA256(entropy)` appended.  The resulting `ENT + ENT/32` bits split
//!   evenly into 11-bit groups, each an index into the 2048-word list — 12/15/18/21/24 words.
//! * **Phrase → entropy.**  The inverse, re-deriving the checksum and comparing.
//! * **Phrase → seed.**  `PBKDF2-HMAC-SHA512`, 2048 iterations, 64 bytes out, with
//!   `password = NFKD(phrase)` and `salt = "mnemonic" ‖ NFKD(passphrase)`.  Note the seed
//!   derivation is deliberately independent of the word list: it never looks a word up, which is
//!   what lets [`seed_unchecked`] reproduce the published foreign-language vectors.

use sha2::{Digest, Sha256, Sha512};
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

use crate::wordlist_bip39_en::WORDS;

/// PBKDF2 iteration count fixed by BIP-39 §"From mnemonic to seed".
const PBKDF2_ITERATIONS: u32 = 2048;

/// Salt prefix fixed by BIP-39: the salt is this string followed by the NFKD passphrase.
const SALT_PREFIX: &str = "mnemonic";

/// Each word encodes exactly 11 bits (`2^11 == 2048 == WORDS.len()`).
const BITS_PER_WORD: usize = 11;

/// Length of a BIP-39 seed in bytes (PBKDF2 output length).
pub const SEED_LEN: usize = 64;

/// The five legal phrase lengths, in words.
pub const WORD_COUNTS: [usize; 5] = [12, 15, 18, 21, 24];

/// The five legal entropy lengths, in bytes — 128/160/192/224/256 bits, index-aligned with
/// [`WORD_COUNTS`].
pub const ENTROPY_LENGTHS: [usize; 5] = [16, 20, 24, 28, 32];

// ---------------------------------------------------------------------------
// Errors.
// ---------------------------------------------------------------------------

/// Why a phrase (or an entropy buffer) was rejected.
///
/// The variants are deliberately specific.  Collapsing them into one opaque "invalid mnemonic"
/// is the bug this module exists to fix: a user who mistyped one word out of 24 needs to be told
/// *which* word, and a user holding a valid 12-word phrase must never be told their words are
/// wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bip39Error {
    /// A word is not in the BIP-39 English list.  `position` is 1-based, as a human counts.
    UnknownWord {
        /// The offending word, exactly as the user wrote it.
        word: String,
        /// 1-based index of that word within the phrase.
        position: usize,
    },
    /// The phrase has a word count BIP-39 does not define.
    WordCount {
        /// How many words were actually found.
        found: usize,
    },
    /// Every word is in the list, but the trailing checksum bits do not match `SHA256(entropy)`.
    Checksum,
    /// [`entropy_to_phrase`] was handed a byte length that is not one of [`ENTROPY_LENGTHS`].
    EntropyLength {
        /// How many bytes were actually supplied.
        found: usize,
    },
}

impl core::fmt::Display for Bip39Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Bip39Error::UnknownWord { word, position } => write!(
                f,
                "word {position} (\"{word}\") is not in the BIP-39 English word list \
                 (words are lowercase, and only these 2048 are valid)"
            ),
            Bip39Error::WordCount { found } => write!(
                f,
                "a BIP-39 phrase has 12, 15, 18, 21 or 24 words; this one has {found}"
            ),
            Bip39Error::Checksum => f.write_str(
                "every word is in the BIP-39 list, but the phrase checksum does not match — \
                 a word is most likely mistyped or in the wrong position",
            ),
            Bip39Error::EntropyLength { found } => write!(
                f,
                "BIP-39 entropy must be 16, 20, 24, 28 or 32 bytes; got {found}"
            ),
        }
    }
}

impl std::error::Error for Bip39Error {}

// ---------------------------------------------------------------------------
// Seed.
// ---------------------------------------------------------------------------

/// A 64-byte BIP-39 seed.  Zeroized on drop; [`core::fmt::Debug`] redacts it.
///
/// This is the master secret for every key derived from the phrase, so it is deliberately not
/// `Clone` and does not expose an owned-`Vec` accessor — callers borrow the bytes, feed them to a
/// derivation, and let the value drop.
pub struct Seed([u8; SEED_LEN]);

impl Seed {
    /// Borrow the raw 64 seed bytes (secret).
    pub fn as_bytes(&self) -> &[u8; SEED_LEN] {
        &self.0
    }
}

impl Drop for Seed {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl core::fmt::Debug for Seed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Seed(<redacted>)")
    }
}

// ---------------------------------------------------------------------------
// Bit plumbing.
// ---------------------------------------------------------------------------

/// Read bit `i` (0 = most-significant bit of `data[0]`) as 0 or 1.
///
/// BIP-39 numbers its bit stream big-endian across the whole buffer, so the index arithmetic here
/// is MSB-first rather than the usual little-endian byte view.
fn bit_at(data: &[u8], i: usize) -> u8 {
    (data[i / 8] >> (7 - (i % 8))) & 1
}

/// Set bit `i` (MSB-first, as in [`bit_at`]) of `data`.
fn set_bit(data: &mut [u8], i: usize) {
    data[i / 8] |= 1 << (7 - (i % 8));
}

// ---------------------------------------------------------------------------
// Public API.
// ---------------------------------------------------------------------------

/// Encode `entropy` as its BIP-39 English phrase.
///
/// `entropy` must be one of [`ENTROPY_LENGTHS`] (16/20/24/28/32 bytes), giving the corresponding
/// entry of [`WORD_COUNTS`] (12/15/18/21/24 words).
///
/// Per BIP-39 §"Generating the mnemonic": append the first `ENT/32` bits of `SHA256(entropy)` to
/// the entropy, then read the result as consecutive 11-bit big-endian groups, each an index into
/// the word list.
///
/// The returned phrase zeroizes on drop — it is equivalent to the private key.
pub fn entropy_to_phrase(entropy: &[u8]) -> Result<Zeroizing<String>, Bip39Error> {
    if !ENTROPY_LENGTHS.contains(&entropy.len()) {
        return Err(Bip39Error::EntropyLength {
            found: entropy.len(),
        });
    }

    // ENT/32 checksum bits. At the maximum ENT of 256 this is 8, so a single digest byte always
    // covers it and no more of the digest is ever read.
    let checksum_bits = entropy.len() * 8 / 32;
    let total_bits = entropy.len() * 8 + checksum_bits;

    let mut buf = Zeroizing::new(entropy.to_vec());
    buf.push(Sha256::digest(entropy)[0]);

    let mut phrase = Zeroizing::new(String::new());
    for group in (0..total_bits).step_by(BITS_PER_WORD) {
        let mut index = 0usize;
        for offset in 0..BITS_PER_WORD {
            index = (index << 1) | bit_at(&buf, group + offset) as usize;
        }
        if !phrase.is_empty() {
            phrase.push(' ');
        }
        phrase.push_str(WORDS[index]);
    }
    Ok(phrase)
}

/// Decode a BIP-39 English phrase back to its entropy, verifying the checksum.
///
/// Words may be separated by any run of whitespace, and leading/trailing whitespace is ignored:
/// a phrase pasted with sloppy spacing is still the user's phrase, and rejecting it would be the
/// same class of false accusation this module exists to remove. Case, however, is **not** folded —
/// the word list is lowercase, so `"Abandon"` is reported as [`Bip39Error::UnknownWord`] rather
/// than silently reinterpreted.
///
/// Errors distinguish an unknown word (naming it and its 1-based position), an illegal word count,
/// and a checksum mismatch, so the caller can tell the user what is actually wrong.
pub fn phrase_to_entropy(phrase: &str) -> Result<Zeroizing<Vec<u8>>, Bip39Error> {
    let words: Vec<&str> = phrase.split_whitespace().collect();
    if !WORD_COUNTS.contains(&words.len()) {
        return Err(Bip39Error::WordCount { found: words.len() });
    }

    // MS = ENT + CS and CS = ENT/32, so MS = ENT * 33/32. Inverting: ENT = MS * 32/33 bits, which
    // is `MS * 4 / 33` bytes, and CS = MS/33 bits. Every legal word count divides exactly.
    let total_bits = words.len() * BITS_PER_WORD;
    let entropy_len = total_bits * 4 / 33;
    let checksum_bits = total_bits / 33;

    let mut buf = Zeroizing::new(vec![0u8; total_bits.div_ceil(8)]);
    for (i, word) in words.iter().enumerate() {
        // The list is sorted (gated by `wordlist_is_strictly_sorted_and_unique`), so a binary
        // search is exact — no linear scan, and no hash map to build on every call.
        let index = WORDS
            .binary_search_by(|candidate| (**candidate).cmp(word))
            .map_err(|_| Bip39Error::UnknownWord {
                word: (*word).to_string(),
                position: i + 1,
            })?;
        for offset in 0..BITS_PER_WORD {
            if (index >> (BITS_PER_WORD - 1 - offset)) & 1 == 1 {
                set_bit(&mut buf, i * BITS_PER_WORD + offset);
            }
        }
    }

    let entropy = Zeroizing::new(buf[..entropy_len].to_vec());
    let expected = Sha256::digest(&*entropy)[0] >> (8 - checksum_bits);
    let mut actual = 0u8;
    for offset in 0..checksum_bits {
        actual = (actual << 1) | bit_at(&buf, entropy_len * 8 + offset);
    }
    if actual != expected {
        return Err(Bip39Error::Checksum);
    }
    Ok(entropy)
}

/// Validate a phrase (word list, length, checksum) without retaining the entropy.
pub fn validate(phrase: &str) -> Result<(), Bip39Error> {
    phrase_to_entropy(phrase).map(|_| ())
}

/// Derive the 64-byte BIP-39 seed from a **validated** phrase plus a (possibly empty) passphrase.
///
/// The phrase is validated first, so a typo surfaces as a specific error instead of as a valid
/// seed for a wallet the user does not own. It is then canonicalized to its words separated by
/// single spaces before hashing: BIP-39 derives the seed from the mnemonic *sentence*, so feeding
/// the raw input through would let a stray double space produce a seed no other wallet computes —
/// the same failure mode as the missing NFKD, arrived at from a different direction.
pub fn seed(phrase: &str, passphrase: &str) -> Result<Seed, Bip39Error> {
    validate(phrase)?;
    let canonical = Zeroizing::new(phrase.split_whitespace().collect::<Vec<_>>().join(" "));
    Ok(seed_unchecked(&canonical, passphrase))
}

/// BIP-39 §"From mnemonic to seed", applied to the strings exactly as given.
///
/// `PBKDF2-HMAC-SHA512`, 2048 iterations, 64 bytes out, with `password = NFKD(phrase)` and
/// `salt = "mnemonic" ‖ NFKD(passphrase)`.
///
/// This step is deliberately word-list-agnostic — the spec defines it over the phrase as *text*,
/// never looking a word up — which is why it is exposed separately: it is what lets the published
/// Japanese vectors be reproduced here without shipping a Japanese word list, and those vectors
/// are the strongest available evidence that the NFKD handling is right.
///
/// Prefer [`seed`]. This entry point performs no validation at all, so a mistyped phrase yields a
/// perfectly well-formed seed for the wrong wallet.
pub fn seed_unchecked(phrase: &str, passphrase: &str) -> Seed {
    let password = Zeroizing::new(phrase.nfkd().collect::<String>());
    let mut salt = Zeroizing::new(String::from(SALT_PREFIX));
    salt.extend(passphrase.nfkd());

    let mut out = [0u8; SEED_LEN];
    pbkdf2::pbkdf2_hmac::<Sha512>(
        password.as_bytes(),
        salt.as_bytes(),
        PBKDF2_ITERATIONS,
        &mut out,
    );
    Seed(out)
}

// ---------------------------------------------------------------------------
// Tests.
//
// The official known-answer vectors live in `tests/bip39_kat.rs` (they only need the public API).
// What is here is what needs to reach inside: the word-list integrity gates, and the internals.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wordlist_bip39_en::WORDS;

    /// SHA-256 of the canonical `bip-0039/english.txt`: the 2048 words joined with `\n`, with a
    /// trailing newline.
    ///
    /// Provenance: computed from the file as published, and cross-checked byte-for-byte against a
    /// second independent upstream copy — `bitcoin/bips` `bip-0039/english.txt` and
    /// `trezor/python-mnemonic` `src/mnemonic/wordlist/english.txt` hash identically. Treat it as
    /// a reproducible pin on *this* vendored copy rather than as a digest quoted from the BIP
    /// text, which publishes no checksum of its own.
    const WORDLIST_SHA256: &str =
        "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda";

    /// Exactly 2048 words — the count is load-bearing, since a word index is 11 bits.
    #[test]
    fn wordlist_has_2048_words() {
        assert_eq!(WORDS.len(), 1 << BITS_PER_WORD);
        assert_eq!(WORDS.len(), 2048);
    }

    /// Every word is lowercase ASCII letters only. A stray uppercase letter or non-ASCII character
    /// would make lookups fail for phrases that are actually valid.
    #[test]
    fn wordlist_is_lowercase_ascii() {
        for w in WORDS {
            assert!(
                !w.is_empty() && w.chars().all(|c| c.is_ascii_lowercase()),
                "word {w:?} is not lowercase ASCII"
            );
            // BIP-39 constrains English words to 3..=8 characters.
            assert!(
                (3..=8).contains(&w.len()),
                "word {w:?} has length {}",
                w.len()
            );
        }
    }

    /// Strictly sorted, therefore also unique. `phrase_to_entropy` binary-searches the list, so
    /// sortedness is a correctness precondition, not a stylistic nicety — and a duplicate word
    /// would make one 11-bit index unreachable and another ambiguous.
    #[test]
    fn wordlist_is_strictly_sorted_and_unique() {
        for pair in WORDS.windows(2) {
            assert!(
                pair[0] < pair[1],
                "word list is not strictly sorted at {:?} / {:?}",
                pair[0],
                pair[1]
            );
        }
    }

    /// BIP-39 specifies that the first four letters unambiguously identify a word, which is what
    /// makes truncated backups and word-completion UIs safe.
    #[test]
    fn wordlist_first_four_characters_are_unique() {
        let mut prefixes: Vec<&str> = WORDS.iter().map(|w| &w[..4.min(w.len())]).collect();
        prefixes.sort_unstable();
        let before = prefixes.len();
        prefixes.dedup();
        assert_eq!(
            before,
            prefixes.len(),
            "two words share a 4-character prefix"
        );
    }

    /// Pin the whole list at once. The property tests above would all pass on a list with two
    /// words transposed; only a digest catches that, and a transposition is precisely the silent
    /// corruption that would mint unspendable addresses.
    #[test]
    fn wordlist_digest_matches_canonical_file() {
        let mut canonical = WORDS.join("\n");
        canonical.push('\n');
        let digest = Sha256::digest(canonical.as_bytes());
        assert_eq!(crate::hexbytes::encode(&digest), WORDLIST_SHA256);
    }

    /// The two word lists in this crate must never be confused: different lengths, and they do not
    /// even agree on their first word.
    #[test]
    fn bip39_and_monero_wordlists_are_different_lists() {
        assert_eq!(WORDS.len(), 2048);
        assert_eq!(crate::wordlist_en::WORDS.len(), 1626);
        assert_ne!(WORDS[0], crate::wordlist_en::WORDS[0]);
    }

    /// `bit_at` and `set_bit` agree, MSB-first.
    #[test]
    fn bit_helpers_round_trip_msb_first() {
        let mut buf = [0u8; 2];
        set_bit(&mut buf, 0);
        assert_eq!(buf[0], 0b1000_0000);
        set_bit(&mut buf, 15);
        assert_eq!(buf[1], 0b0000_0001);
        assert_eq!(bit_at(&buf, 0), 1);
        assert_eq!(bit_at(&buf, 1), 0);
        assert_eq!(bit_at(&buf, 15), 1);
    }

    /// The all-zero 128-bit entropy is the first official vector; asserting it here keeps the
    /// module self-checking even if the integration test is not run.
    #[test]
    fn first_official_vector_round_trips_in_module() {
        const PHRASE: &str = "abandon abandon abandon abandon abandon abandon \
                              abandon abandon abandon abandon abandon about";
        let phrase = entropy_to_phrase(&[0u8; 16]).unwrap();
        assert_eq!(*phrase, PHRASE);
        assert_eq!(*phrase_to_entropy(PHRASE).unwrap(), vec![0u8; 16]);
    }

    /// Every legal entropy length maps to the matching word count, and the checksum width follows
    /// `ENT/32` — the arithmetic that `phrase_to_entropy` inverts.
    #[test]
    fn lengths_and_word_counts_are_index_aligned() {
        for (i, &len) in ENTROPY_LENGTHS.iter().enumerate() {
            let phrase = entropy_to_phrase(&vec![0xa5; len]).unwrap();
            assert_eq!(phrase.split_whitespace().count(), WORD_COUNTS[i]);
            assert_eq!(WORD_COUNTS[i] * BITS_PER_WORD, len * 8 + len * 8 / 32);
        }
    }

    /// The error messages are the user-facing product of this module, so pin their content.
    #[test]
    fn error_messages_say_what_is_wrong() {
        let unknown = Bip39Error::UnknownWord {
            word: "frobnicate".into(),
            position: 7,
        }
        .to_string();
        assert!(
            unknown.contains("frobnicate") && unknown.contains('7'),
            "{unknown}"
        );

        let count = Bip39Error::WordCount { found: 13 }.to_string();
        assert!(count.contains("13") && count.contains("12"), "{count}");

        let checksum = Bip39Error::Checksum.to_string();
        assert!(checksum.contains("checksum"), "{checksum}");

        let entropy = Bip39Error::EntropyLength { found: 17 }.to_string();
        assert!(
            entropy.contains("17") && entropy.contains("16"),
            "{entropy}"
        );
    }

    /// NFKD is the identity on ASCII, so every phrase and passphrase this crate can generate is
    /// byte-identical before and after normalization. That is why fixing defect 2 moves no
    /// existing address: only a non-ASCII passphrase was ever affected.
    #[test]
    fn nfkd_is_the_identity_on_the_english_wordlist() {
        for w in WORDS {
            assert_eq!(w.nfkd().collect::<String>(), *w);
        }
        assert_eq!("TREZOR".nfkd().collect::<String>(), "TREZOR");
    }
}
