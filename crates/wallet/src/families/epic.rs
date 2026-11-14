use crate::coins::{EPICBOX_DEFAULT_DOMAIN, EPICBOX_VERSION};
use crate::{codec::base58, curves::secp256k1};

/// The 52-character base58check part of a mainnet epicbox address:
/// `Base58Check([0x01, 0x00] ‖ compressed_pubkey)`.
///
/// Pinned to `EpicCash/epic-wallet` `libwallet/src/epicbox_address.rs` (`EpicboxAddress`, version
/// bytes `[1, 0]` mainnet / `[1, 136]` floonet, 33-byte compressed pubkey) and
/// `libwallet/src/base58.rs` (Bitcoin alphabet, `SHA256d` checksum, first four bytes).
pub(crate) fn base58_part(pubkey: &[u8; 33]) -> String {
    let mut payload = EPICBOX_VERSION.to_vec();
    payload.extend_from_slice(pubkey);
    base58::encode_check(&payload)
}

/// Full printed address: `<52 base58 chars>@epicbox.epiccash.com`. The default relay is written
/// without a port, because the pool accepts only an absent port or 443.
///
/// The key is a random secp256k1 key. epic-wallet derives its own epicbox key from the wallet
/// seed, so this address is format-valid and owned by whoever holds the secret, but it cannot be
/// restored from an Epic wallet seed.
pub(crate) fn address(d: &secp256k1::Secret) -> String {
    let pk = secp256k1::pubkey_compressed(d);
    format!("{}@{EPICBOX_DEFAULT_DOMAIN}", base58_part(&pk))
}

#[cfg(test)]
mod tests {
    use super::{address, base58_part};
    use crate::codec::base58;
    use crate::curves::secp256k1;
    use crate::hexbytes::encode as hex;

    /// Independent derivation: a Python stdlib script (`hashlib.sha256` twice for the checksum, a
    /// hand-written base58 over the Bitcoin alphabet) applied to `01 00 ‖ pubkey`, where the
    /// pubkeys are the generator point (`0279be66…1798`, key = 1) and Warthog's test key's pubkey
    /// (`02916a39…e705`). The Rust code was not used to produce these strings.
    #[test]
    fn epic_addresses_match_an_independent_python_derivation() {
        let cases = [
            (
                "0000000000000000000000000000000000000000000000000000000000000001",
                "esXEUSzaQgaEtFRx69W8DnErs9R6Q6UwgR52Qc2c6mAFtfCu8sku",
            ),
            (
                "966a71a98bb5d13e9116c0dffa3f1a7877e45c6f563897b96cfd5c59bf0803e0",
                "esXQu6crNvJWdkVCD5qMbACYUib6Wt86FyTgEXx9jTKNDPwPriJD",
            ),
        ];
        for (key, b58) in cases {
            let d = secp256k1::secret_from_hex(key);
            assert_eq!(address(&d), format!("{b58}@epicbox.epiccash.com"));
        }
        let d = secp256k1::secret_from_hex(cases[0].0);
        assert_eq!(
            hex(&secp256k1::pubkey_compressed(&d)),
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
    }

    /// A real published address: the epic-nodejs-pool donation address. Decoding it and
    /// re-encoding the 33-byte pubkey reproduces it exactly.
    #[test]
    fn the_published_pool_address_round_trips() {
        let published = "esYd2vznULSZPn8yQG1SpViF1xEdSs4Fa4n91tkhdSxZCNVdkBt4";
        let payload = base58::decode_check(published).expect("valid base58check");
        assert_eq!(payload.len(), 35);
        assert_eq!(&payload[..2], &[0x01, 0x00]);
        let pk: [u8; 33] = payload[2..].try_into().unwrap();
        assert_eq!(base58_part(&pk), published);
    }
}
