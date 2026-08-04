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

#[cfg(test)]
mod tests {
    use super::wif;

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
