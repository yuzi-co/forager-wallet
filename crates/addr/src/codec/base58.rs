const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub fn encode(input: &[u8]) -> String {
    use num_bigint::BigUint;
    use num_traits::Zero;
    let zeros = input.iter().take_while(|&&b| b == 0).count();
    let mut num = BigUint::from_bytes_be(input);
    let mut out = Vec::new();
    let base = BigUint::from(58u32);
    while !num.is_zero() {
        let rem = (&num % &base).to_bytes_le().first().copied().unwrap_or(0) as usize;
        out.push(ALPHABET[rem]);
        num /= &base;
    }
    for _ in 0..zeros {
        out.push(ALPHABET[0]);
    }
    out.reverse();
    String::from_utf8(out).unwrap()
}

pub fn encode_check(payload: &[u8]) -> String {
    let mut v = payload.to_vec();
    v.extend_from_slice(&crate::hash::double_sha256(payload)[..4]);
    encode(&v)
}

/// Decode a base58 string to bytes (no checksum). `None` on any non-alphabet character. Leading
/// `1`s decode to leading `0x00` bytes, matching [`encode`]. Used by address *detection*, the
/// inverse of derivation.
pub fn decode(s: &str) -> Option<Vec<u8>> {
    use num_bigint::BigUint;
    use num_traits::Zero;
    let mut num = BigUint::zero();
    let base = BigUint::from(58u32);
    for c in s.bytes() {
        let idx = ALPHABET.iter().position(|&a| a == c)?;
        num = num * &base + BigUint::from(idx as u32);
    }
    let zeros = s.bytes().take_while(|&c| c == ALPHABET[0]).count();
    let mut out = vec![0u8; zeros];
    if !num.is_zero() {
        out.extend_from_slice(&num.to_bytes_be());
    }
    Some(out)
}

/// Decode base58check and verify the trailing 4-byte double-SHA256 checksum. Returns the payload
/// (`version ‖ data`) without the checksum, or `None` if the string is invalid, too short, or the
/// checksum does not match — i.e. `Some` proves a well-formed Bitcoin-style address.
pub fn decode_check(s: &str) -> Option<Vec<u8>> {
    let raw = decode(s)?;
    if raw.len() < 5 {
        return None;
    }
    let (payload, checksum) = raw.split_at(raw.len() - 4);
    (crate::hash::double_sha256(payload)[..4] == *checksum).then(|| payload.to_vec())
}

#[cfg(test)]
mod tests {
    use super::{encode, encode_check};

    #[test]
    fn base58_leading_zero_and_value() {
        assert_eq!(encode(&[0x00, 0x00, 0x61]), "112g"); // two leading 0x00 -> "11" + value "2g"
        assert_eq!(encode(&[0x61]), "2g");
    }

    #[test]
    fn base58check_p2pkh_privkey_one() {
        // version 0x00 ‖ HASH160(compressed G) -> mainnet P2PKH address for privkey=1.
        let mut payload = vec![0x00u8];
        let hash160: [u8; 20] =
            crate::hexbytes::decode_n("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        payload.extend_from_slice(&hash160);
        assert_eq!(encode_check(&payload), "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
    }

    #[test]
    fn decode_roundtrips_encode_including_leading_zeros() {
        use super::{decode, encode};
        for v in [
            vec![0x61u8],
            vec![0x00, 0x00, 0x61],
            vec![0xde, 0xad, 0xbe, 0xef],
            vec![0x00; 5],
        ] {
            assert_eq!(decode(&encode(&v)), Some(v));
        }
        assert_eq!(decode("0OIl"), None); // characters outside the base58 alphabet
    }

    #[test]
    fn decode_check_accepts_valid_rejects_tampered() {
        use super::{decode_check, encode_check};
        let payload = vec![0x00u8, 1, 2, 3, 4, 5];
        let addr = encode_check(&payload);
        assert_eq!(decode_check(&addr), Some(payload));
        // Corrupt one character → checksum fails → None.
        let mut bad: Vec<char> = addr.chars().collect();
        bad[addr.len() - 1] = if bad[addr.len() - 1] == 'A' { 'B' } else { 'A' };
        let bad: String = bad.into_iter().collect();
        assert_eq!(decode_check(&bad), None);
    }
}
