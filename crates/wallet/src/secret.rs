pub(crate) fn eth_hex(secret: &[u8; 32]) -> String {
    format!("0x{}", crate::hexbytes::encode(secret))
}

pub(crate) fn wif(secret: &[u8; 32], wif_byte: u8, compressed: bool) -> String {
    let mut payload = Vec::with_capacity(34);
    payload.push(wif_byte);
    payload.extend_from_slice(secret);
    if compressed {
        payload.push(0x01);
    }
    crate::codec::base58::encode_check(&payload)
}

/// Decode a Wallet Import Format secret back to its 32-byte key.
///
/// Accepts both the compressed form (33-byte payload ending in `0x01`) and the uncompressed form
/// (32-byte payload), and any version byte — the caller already knows which coin it asked for, and
/// rejecting a mismatched version here would only stop a user re-deriving a key they hold.
///
/// Returns `None` for anything that is not a base58check string with a valid checksum and one of
/// those two payload shapes.
pub(crate) fn from_wif(s: &str) -> Option<[u8; 32]> {
    let payload = crate::codec::base58::decode_check(s.trim())?;
    let key = match payload.len() {
        // version ‖ key ‖ 0x01
        34 if payload[33] == 0x01 => &payload[1..33],
        // version ‖ key
        33 => &payload[1..33],
        _ => return None,
    };
    let mut out = [0u8; 32];
    out.copy_from_slice(key);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::{from_wif, wif};

    /// A WIF this crate prints must be readable back. Without this the tool hands the user a
    /// secret in a format it then refuses to accept.
    #[test]
    fn wif_round_trips() {
        let mut key = [0u8; 32];
        key[31] = 1;
        for (byte, compressed) in [(0x80u8, true), (0x80, false), (0xb0, true), (0xd2, true)] {
            let encoded = wif(&key, byte, compressed);
            assert_eq!(from_wif(&encoded), Some(key), "wif byte {byte:#x}");
        }
    }

    #[test]
    fn from_wif_rejects_junk_and_bad_checksum() {
        assert_eq!(from_wif("not a wif"), None);
        assert_eq!(from_wif(""), None);
        // Valid base58check for an ADDRESS, not a key: 21-byte payload.
        assert_eq!(from_wif("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"), None);
        // Flip the last character of a real WIF -> checksum fails.
        assert_eq!(
            from_wif("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWm"),
            None
        );
    }

    #[test]
    fn wif_privkey_one_compressed_mainnet() {
        let key = {
            let mut k = [0u8; 32];
            k[31] = 1;
            k
        };
        assert_eq!(
            wif(&key, 0x80, true),
            "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
        );
    }
}
