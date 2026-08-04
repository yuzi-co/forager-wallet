//! CryptoNote **base58** — the address encoding used by Monero (XMR) and other CryptoNote coins.
//!
//! This is **not** the Bitcoin base58 in [`super::base58`].  The input is split into 8-byte
//! big-endian blocks; each block of `k` bytes is converted to a full-base58 number and emitted as
//! a *fixed* number of characters per the standard length table `ENC_LEN` (index = bytes in the
//! block), left-padded with the leading `'1'` character.  A trailing partial block uses its own
//! `ENC_LEN[k]` entry.  The 69-byte Monero payload → 8 full blocks (8·11 = 88 chars) + a 5-byte
//! tail (`ENC_LEN[5]` = 7 chars) = **95 chars**.

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// base58 character count emitted for a block of `index` bytes (the CryptoNote standard table).
/// A full 8-byte block → 11 chars; sizes 4 and 8 (which could ambiguously round) are skipped by
/// the protocol, but the full table is kept for completeness.
const ENC_LEN: [usize; 9] = [0, 2, 3, 5, 6, 7, 9, 10, 11];

const FULL_BLOCK_SIZE: usize = 8;
const FULL_ENCODED_SIZE: usize = 11;

/// Encode one big-endian block of 1..=8 bytes into exactly `ENC_LEN[block.len()]` base58 chars,
/// left-padded with the leading `'1'` character, appending to `out`.
fn encode_block(block: &[u8], out: &mut Vec<u8>) {
    let mut num: u64 = 0;
    for &b in block {
        num = (num << 8) | u64::from(b);
    }
    let want = ENC_LEN[block.len()];
    // Pre-fill with the leading '1' so unused high positions are the base58 padding char.
    let mut buf = [ALPHABET[0]; FULL_ENCODED_SIZE];
    let mut i = want;
    while num > 0 {
        i -= 1;
        buf[i] = ALPHABET[(num % 58) as usize];
        num /= 58;
    }
    out.extend_from_slice(&buf[..want]);
}

/// Append `n` as a CryptoNote/Monero `write_varint` — unsigned LEB128, 7 payload bits per byte with
/// the high bit set on every byte but the last.  A value `< 0x80` emits a single byte (so Monero's
/// prefix 18 is unchanged), while a multi-byte fork prefix like Zephyr's `0x6241d18c0` emits the five
/// bytes the address tag requires.  A bare `n as u8` truncation would silently misencode every
/// multi-byte-prefix coin into a Monero-shaped `4…` address.
pub fn write_varint(mut n: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
}

/// Encode `data` as CryptoNote base58 (8-byte big-endian blocks, fixed per-block length).
pub fn encode(data: &[u8]) -> String {
    let mut out = Vec::new();
    let full = data.len() / FULL_BLOCK_SIZE;
    for i in 0..full {
        encode_block(
            &data[i * FULL_BLOCK_SIZE..(i + 1) * FULL_BLOCK_SIZE],
            &mut out,
        );
    }
    let rem = data.len() % FULL_BLOCK_SIZE;
    if rem > 0 {
        encode_block(&data[full * FULL_BLOCK_SIZE..], &mut out);
    }
    String::from_utf8(out).unwrap()
}

#[cfg(test)]
mod tests {
    use super::{encode, write_varint, ENC_LEN};

    /// Unsigned LEB128, checked three ways: Monero's prefix 18 stays a single bare byte, the width
    /// is `ceil(significant_bits / 7)`, and every value round-trips through the 7-bit groups.  The
    /// continuation bit is set on every byte but the last.
    #[test]
    fn varint_is_unsigned_leb128() {
        let mut v = Vec::new();
        write_varint(18, &mut v);
        assert_eq!(v, [18], "a value below 0x80 must emit one bare byte");

        // 0x3ef318 (Salvium) is 22 significant bits → 4 groups; 0x6241d18c0 (Zephyr) is 35 → 5.
        for (value, want_len) in [(0x7fu64, 1), (0x80, 2), (0x3ef318, 4), (0x6241d18c0, 5)] {
            v.clear();
            write_varint(value, &mut v);
            assert_eq!(v.len(), want_len, "{value:#x} → {v:02x?}");
            let (last, head) = v.split_last().unwrap();
            assert!(head.iter().all(|b| b & 0x80 != 0), "{value:#x} → {v:02x?}");
            assert!(last & 0x80 == 0, "{value:#x} → {v:02x?}");
            let back = v
                .iter()
                .enumerate()
                .fold(0u64, |acc, (i, b)| acc | u64::from(b & 0x7f) << (7 * i));
            assert_eq!(back, value, "lossless round-trip");
        }
    }

    /// The 69-byte Monero payload → 8 full blocks (88 chars) + a 5-byte tail (`ENC_LEN[5]` = 7).
    #[test]
    fn encode_69_byte_payload_is_95_chars() {
        let payload = [0u8; 69];
        let enc = encode(&payload);
        assert_eq!(enc.len(), 95);
        assert_eq!(8 * ENC_LEN[8] + ENC_LEN[5], 95);
        // An all-zero buffer encodes to all leading-'1' padding.
        assert!(enc.chars().all(|c| c == '1'), "{enc}");
    }

    /// A single full 8-byte block always emits exactly 11 chars; a 5-byte tail exactly 7.
    #[test]
    fn block_length_table() {
        assert_eq!(encode(&[0xffu8; 8]).len(), 11);
        assert_eq!(encode(&[0xffu8; 5]).len(), 7);
        assert_eq!(encode(&[0x01u8]).len(), 2);
    }

    /// Big-endian, full base58 within a block: 0x0000000000000001 → "11111111112" (10×'1' + '2').
    #[test]
    fn block_is_big_endian_full_base58() {
        let mut b = [0u8; 8];
        b[7] = 1;
        assert_eq!(encode(&b), "11111111112");
    }
}
