//! Monero (CryptoNote) 25-word **English** seed-phrase encoding.
//!
//! The 25-word phrase is the full-wallet restore key: it encodes the 32-byte private spend
//! seed exactly, plus one checksum word.  Encoding follows the Monero reference
//! (`src/mnemonics/`):
//!
//! 1. The 32-byte secret is read as eight little-endian `u32` words.  Each `u32 x` expands to
//!    three word indices in base 1626 (the English word-list length):
//!    `w1 = x % 1626`, `w2 = (x / 1626 + w1) % 1626`, `w3 = (x / 1626² + w2) % 1626`.
//!    That yields 24 words.
//! 2. The 25th (checksum) word is selected from the 24 by taking each word's first
//!    `unique_prefix_length` (3 for English) characters, concatenating them, computing the
//!    IEEE CRC-32 of that byte string, and reducing it mod 24 to pick one of the 24 words.

use crate::wordlist_en::WORDS;

/// Monero English `unique_prefix_length` — the checksum hashes each word's first 3 chars.
const PREFIX_LEN: usize = 3;

/// IEEE CRC-32 (polynomial `0xEDB88320`, reflected) over `data`.
fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Encode a 32-byte Monero private **spend** seed as its 25-word English mnemonic.
///
/// `spend_secret` must already be the canonical (`sc_reduce`'d) spend scalar — the same value
/// used to derive the address — so the phrase and the address agree.
pub(crate) fn monero_25(spend_secret: &[u8; 32]) -> [String; 25] {
    let n = WORDS.len() as u32; // 1626
    let mut words: Vec<&'static str> = Vec::with_capacity(25);

    for chunk in spend_secret.chunks_exact(4) {
        let x = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let w1 = x % n;
        let w2 = (x / n + w1) % n;
        let w3 = (x / n / n + w2) % n;
        words.push(WORDS[w1 as usize]);
        words.push(WORDS[w2 as usize]);
        words.push(WORDS[w3 as usize]);
    }

    // Checksum word: CRC-32 of the concatenated 3-char prefixes, mod 24, indexes the 24 words.
    let mut prefixes = String::with_capacity(words.len() * PREFIX_LEN);
    for w in &words {
        prefixes.extend(w.chars().take(PREFIX_LEN));
    }
    let idx = (crc32_ieee(prefixes.as_bytes()) as usize) % words.len();
    words.push(words[idx]);

    core::array::from_fn(|i| words[i].to_string())
}

#[cfg(test)]
mod tests {
    use super::{crc32_ieee, monero_25, PREFIX_LEN};
    use crate::hexbytes::hex32;

    // ---- Vetted, independent Monero spend-key <-> 25-word mnemonic vector ----
    // Source: moneroexamples "Recover Monero address using the private spend key"
    //   https://moneroexamples.github.io/spendkey/  — the page's default example pairs this
    //   private spend key with this exact 25-word English seed phrase (and the page states its
    //   results agree with the independent xmrtests "Address Generation Tests" site).  It is the
    //   same spend key used by the address KAT in `families::cryptonote`, so the phrase and the
    //   address are derived from one canonical seed.
    const SPEND_HEX: &str = "af6082af29108abda69cc385dfed2102b892a871695367cb22a4b9b6df8b3206";
    const PHRASE_EXPECTED: &str = "spout midst duckling tepid odds glass enhanced avatar ocean \
        rarest eavesdrop egotistic oxygen trying future airport session nanny tedious guru asylum \
        superior cement cunning eavesdrop";

    #[test]
    fn monero_mnemonic_kat() {
        let words = monero_25(&hex32(SPEND_HEX));
        assert_eq!(words.join(" "), PHRASE_EXPECTED);
    }

    /// The phrase is exactly 25 words.
    #[test]
    fn monero_mnemonic_has_25_words() {
        let words = monero_25(&hex32(SPEND_HEX));
        assert_eq!(words.len(), 25);
        assert!(words.iter().all(|w| !w.is_empty()));
    }

    /// The 25th word equals the checksum word selected by `crc32(prefixes) % 24` over the
    /// first 24 words — re-deriving the checksum independently of `monero_25`'s internals.
    #[test]
    fn monero_mnemonic_checksum_word_is_consistent() {
        let words = monero_25(&hex32(SPEND_HEX));
        let first24 = &words[..24];
        let prefixes: String = first24
            .iter()
            .flat_map(|w| w.chars().take(PREFIX_LEN))
            .collect();
        let idx = (crc32_ieee(prefixes.as_bytes()) as usize) % 24;
        assert_eq!(words[24], first24[idx]);
    }

    /// CRC-32 IEEE smoke vector: crc32("123456789") == 0xCBF43926.
    #[test]
    fn crc32_known_vector() {
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926);
    }
}
