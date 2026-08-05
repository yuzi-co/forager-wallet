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

/// The inverse of [`write_varint`]: read one unsigned LEB128 value off the front of `data` and
/// return it with the bytes that follow it.
///
/// Rejects everything [`write_varint`] cannot emit, because detection calls this on strings nobody
/// vouched for: a value wider than 64 bits, a run of continuation bytes that never terminates, and
/// the non-canonical spelling that pads a number with groups it does not need. `write_varint` emits
/// the shortest form only, so a longer encoding of the same number is a *different* address string,
/// and accepting it would let two strings claim one network prefix.
pub fn read_varint(data: &[u8]) -> Option<(u64, &[u8])> {
    let mut value: u64 = 0;
    for (i, &byte) in data.iter().enumerate() {
        let shift = 7 * i;
        if shift >= u64::BITS as usize {
            return None; // wider than the u64 a network prefix is held in
        }
        let bits = u64::from(byte & 0x7f);
        if bits << shift >> shift != bits {
            return None; // this group's high bits would fall off the end
        }
        value |= bits << shift;
        if byte & 0x80 == 0 {
            // A final group of zero after at least one continuation byte contributes nothing: it is
            // the padded spelling of a number the encoder would have written shorter.
            if i > 0 && byte == 0 {
                return None;
            }
            return Some((value, &data[i + 1..]));
        }
    }
    None // ran out of input with the continuation bit still set
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

/// Decode one base58 block back into the big-endian bytes it encodes, appending to `out`.
///
/// `None` for anything [`encode_block`] could not have produced: a character outside the alphabet,
/// a block length the standard `ENC_LEN` table does not list, or a value too large for the byte
/// width that length stands for.
fn decode_block(block: &[u8], out: &mut Vec<u8>) -> Option<()> {
    // `ENC_LEN` is strictly increasing, so a length appears at most once and this inverse is exact.
    // The lengths it omits (1, 4 and 8 characters) are the ambiguous ones the protocol skips.
    let want = ENC_LEN.iter().position(|&l| l == block.len())?;
    let mut num: u64 = 0;
    for &c in block {
        let digit = ALPHABET.iter().position(|&a| a == c)? as u64;
        // A full 11-character block can spell numbers above 2^64 (58^11 > 2^64), which no 8-byte
        // block can hold, so the accumulation itself has to be checked.
        num = num.checked_mul(58)?.checked_add(digit)?;
    }
    // The same range test one block down: `want` bytes cannot hold a larger number, so a string
    // that spells one is not something `encode` produced. Skipped for the 8-byte case, where the
    // bound is the u64 the accumulation above already enforced.
    if want < FULL_BLOCK_SIZE && num >= 1u64 << (8 * want) {
        return None;
    }
    out.extend_from_slice(&num.to_be_bytes()[FULL_BLOCK_SIZE - want..]);
    Some(())
}

/// The inverse of [`encode`].
///
/// `None` for any string [`encode`] could not have produced — see [`decode_block`] — which is what
/// makes this usable on untrusted input: detection reads the network prefix and verifies the
/// Keccak-256 checksum out of the bytes this returns, and both are meaningless if the decoder
/// invents a payload for a string that is not an address.
///
/// The scheme is not self-delimiting the way Bitcoin base58 is, so the *length* carries meaning:
/// character counts of 1, 4 and 8 in the trailing partial block are rejected rather than rounded,
/// because two different byte counts would encode to them.
pub fn decode(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    let full = bytes.len() / FULL_ENCODED_SIZE;
    let rem = bytes.len() % FULL_ENCODED_SIZE;
    let mut out = Vec::with_capacity(full * FULL_BLOCK_SIZE + FULL_BLOCK_SIZE);
    for i in 0..full {
        decode_block(
            &bytes[i * FULL_ENCODED_SIZE..(i + 1) * FULL_ENCODED_SIZE],
            &mut out,
        )?;
    }
    if rem > 0 {
        decode_block(&bytes[full * FULL_ENCODED_SIZE..], &mut out)?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::{decode, encode, read_varint, write_varint, ENC_LEN, FULL_ENCODED_SIZE};

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

    /// `decode` is `encode`'s inverse for every payload width an address can have. The widths swept
    /// are the real ones: a CryptoNote address is `varint(prefix) ‖ keys(64) ‖ checksum(4)`, so its
    /// payload runs 69 bytes (Monero's one-byte prefix) through 73 (Zephyr's five-byte one).
    #[test]
    fn decode_inverts_encode_for_every_address_width() {
        for len in 69..=73 {
            // A payload that is neither all-zero nor all-`0xff`, and differs per byte, so a block
            // swapped with its neighbour would show up.
            let payload: Vec<u8> = (0..len)
                .map(|i| (i as u8).wrapping_mul(37).wrapping_add(11))
                .collect();
            let encoded = encode(&payload);
            assert_eq!(decode(&encoded).as_deref(), Some(&payload[..]), "{encoded}");
        }
    }

    /// The character counts the standard table omits — 1, 4 and 8 in the trailing partial block —
    /// are ambiguous, and `encode` never emits them. `decode` must reject rather than round: an
    /// address that decoded to a payload of a length no encoder produces would hand detection a
    /// prefix and a checksum read out of the wrong bytes.
    #[test]
    fn the_ambiguous_tail_lengths_are_rejected() {
        for tail in [1usize, 4, 8] {
            let s = "1".repeat(FULL_ENCODED_SIZE + tail);
            assert_eq!(decode(&s), None, "{tail}-character tail was accepted");
        }
        // The lengths either side of each are fine, so the rejection is about the table and not
        // about the length being unusual.
        for tail in [2usize, 3, 5, 6, 7, 9, 10] {
            let s = "1".repeat(FULL_ENCODED_SIZE + tail);
            assert!(decode(&s).is_some(), "{tail}-character tail was rejected");
        }
    }

    /// A block whose value exceeds what its byte width holds is not something `encode` produced.
    /// `zzzzzzzzzzz` is 58^11 - 1, well above 2^64, and `zzz` is 58^3 - 1 = 195111, above the
    /// 2^16 a 2-byte tail can hold.
    #[test]
    fn a_block_that_overflows_its_byte_width_is_rejected() {
        assert_eq!(decode("zzzzzzzzzzz"), None);
        assert_eq!(decode("zzz"), None);
        // The largest value each really does hold still decodes.
        assert!(decode(&encode(&[0xffu8; 8])).is_some());
        assert!(decode(&encode(&[0xffu8; 2])).is_some());
    }

    /// Characters outside the base58 alphabet — including the four excluded look-alikes — are not
    /// digits, so a string carrying one is not an address.
    #[test]
    fn a_character_outside_the_alphabet_is_rejected() {
        for c in ['0', 'O', 'I', 'l', '+', '/', ' '] {
            let s = format!("{c}1111111111");
            assert_eq!(decode(&s), None, "{c} was accepted as a base58 digit");
        }
    }

    /// `read_varint` inverts `write_varint` for every prefix the coin table models, and returns the
    /// bytes that follow untouched — which is how detection separates the prefix from the keys.
    #[test]
    fn read_varint_inverts_write_varint() {
        for value in [0u64, 1, 18, 53, 0x7f, 0x80, 0x3ef318, 0x6241d18c0, u64::MAX] {
            let mut buf = Vec::new();
            write_varint(value, &mut buf);
            buf.extend_from_slice(b"tail");
            let (back, rest) = read_varint(&buf).expect("round-trips");
            assert_eq!(back, value, "{value:#x}");
            assert_eq!(rest, b"tail", "{value:#x}");
        }
    }

    /// The three shapes `write_varint` cannot produce. Accepting any of them would give one network
    /// prefix two spellings, so two different address strings would classify identically.
    #[test]
    fn read_varint_rejects_what_write_varint_cannot_emit() {
        // Continuation bit set on the last byte: the value never terminates.
        assert_eq!(read_varint(&[0x80]), None);
        assert_eq!(read_varint(&[0x80, 0x80, 0x80]), None);
        // Ten groups is 70 bits — wider than the u64 a prefix lives in.
        assert_eq!(read_varint(&[0x80; 10]), None);
        // A tenth group whose bits fall off the top of the u64.
        assert_eq!(
            read_varint(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]),
            None
        );
        // Non-canonical: 18 padded with a group that contributes nothing.
        assert_eq!(read_varint(&[0x92, 0x00]), None);
        // The canonical spelling of the same number is accepted, so the rejection above is about
        // the padding rather than the value.
        assert_eq!(read_varint(&[18]), Some((18, &[][..])));
    }
}
