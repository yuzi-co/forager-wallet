use crate::{curves::secp256k1, hash::keccak256};

/// EIP-55 mixed-case checksum over a 40-char lowercase hex address (no 0x).
pub(crate) fn eip55(lower_hex: &str) -> String {
    let h = keccak256(lower_hex.as_bytes());
    lower_hex
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if c.is_ascii_digit() {
                c
            } else {
                let nibble = (h[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0xf;
                if nibble >= 8 {
                    c.to_ascii_uppercase()
                } else {
                    c
                }
            }
        })
        .collect()
}

pub(crate) fn address(d: &secp256k1::Secret) -> String {
    let pk = secp256k1::pubkey_uncompressed(d); // 0x04 ‖ x ‖ y
    let addr20 = &keccak256(&pk[1..])[12..]; // keccak of x‖y, last 20 bytes
    format!("0x{}", eip55(&crate::hexbytes::encode(addr20)))
}

#[cfg(test)]
mod tests {
    use super::address;
    use crate::curves::secp256k1::secret_from_hex;

    #[test]
    fn eth_privkey_one() {
        // privkey=1 -> well-known address (checksummed).
        assert_eq!(
            address(&secret_from_hex("01")),
            "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
        );
    }

    #[test]
    fn eip55_reference_mixed_case() {
        // EIP-55 example: the all-lower input must round-trip to this mixed case.
        assert_eq!(
            super::eip55("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"),
            "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        );
    }
}
