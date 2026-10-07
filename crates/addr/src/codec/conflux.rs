//! Conflux Core Space address encoding, CIP-37.
//!
//! CIP-37 is the BCH CashAddr scheme with one substitution: the charset. It keeps the 5-bit
//! packing, the 40-bit BCH checksum, the 8-character checksum field, the `:` separator and the
//! masked-prefix expansion, all of which [`super::cashaddr`] already implements for the
//! Kaspa family. Only the alphabet differs, so this module borrows that checksum rather than
//! restating the polynomial.
//!
//! Two further differences from the Kaspa form, both in the payload rather than the checksum:
//!
//! - The leading byte is CIP-37's **version byte**, which the specification fixes at `0x00` and
//!   reserves for future use. It is not an address type. The type lives in the *address's own*
//!   leading four bits (`0x1…` user, `0x8…` contract, `0x0…` builtin), which is why a Conflux
//!   address derived from a public key has its first nibble forced to `1`.
//! - The payload is always the 20-byte Core Space address, so an encoded address is always 42
//!   characters after the `:`.
//!
//! Re-derived from CIP-37 (`Conflux-Chain/CIPs/CIPs/cip-37.md`) and locked by every encode vector
//! that document publishes, mainnet and testnet.

use super::bech32::{convertbits_5_to_8, convertbits_8_to_5};
use super::cashaddr::{checksum, polymod};

/// CIP-37's base32 alphabet: the digits and lower-case letters with `i`, `l`, `o` and `q` removed.
///
/// Deliberately **not** bech32's `CHARSET`. The two schemes agree on everything except this
/// table, so the one difference is the one thing this module must not share.
const CHARSET: &[u8; 32] = b"abcdefghjkmnprstuvwxyz0123456789";

/// Characters the checksum occupies at the end of the data part: 40 bits at 5 bits each.
const CHECKSUM_CHARS: usize = 8;

/// The version byte CIP-37 fixes for every address it defines.
const VERSION_BYTE: u8 = 0x00;

/// Length of a Core Space address in bytes.
const ADDR_LEN: usize = 20;

/// The value [`polymod`] takes over a well-formed address. Same scheme, so the same residual
/// [`super::cashaddr`] derives and checks; `tests::decode_round_trips_every_cip37_vector` is what
/// pins it here.
const VALID_CHECKSUM_RESIDUAL: u64 = 0;

/// What a Conflux address says once its checksum has been verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    /// The network prefix as it appeared before the `:` — `cfx` for mainnet, `cfxtest` for the
    /// testnet, `net<id>` for a custom network.
    pub prefix: String,
    /// The 20-byte Core Space address.
    pub addr: [u8; ADDR_LEN],
}

impl Decoded {
    /// The address type CIP-37 reads out of the leading four bits: `"type.user"`,
    /// `"type.contract"`, `"type.builtin"` or `"type.null"` for the null address.
    pub fn address_type(&self) -> &'static str {
        if self.addr == [0u8; ADDR_LEN] {
            return "type.null";
        }
        match self.addr[0] & 0xf0 {
            0x00 => "type.builtin",
            0x10 => "type.user",
            0x80 => "type.contract",
            _ => "type.unknown",
        }
    }
}

/// Encode a 20-byte Core Space address as `<prefix>:<payload><8-char checksum>`.
pub fn encode(prefix: &str, addr: &[u8; ADDR_LEN]) -> String {
    let mut full = Vec::with_capacity(1 + ADDR_LEN);
    full.push(VERSION_BYTE);
    full.extend_from_slice(addr);
    let payload_5bit = convertbits_8_to_5(&full);

    let chk = checksum(&payload_5bit, prefix);
    // The checksum is 40 bits (8 five-bit groups): the low 5 bytes of the 8-byte big-endian repr.
    let chk_5bit = convertbits_8_to_5(&chk.to_be_bytes()[3..]);
    debug_assert_eq!(chk_5bit.len(), CHECKSUM_CHARS);

    let mut s = String::with_capacity(prefix.len() + 1 + payload_5bit.len() + chk_5bit.len());
    s.push_str(prefix);
    s.push(':');
    for &d in payload_5bit.iter().chain(chk_5bit.iter()) {
        s.push(CHARSET[d as usize] as char);
    }
    s
}

/// Decode and **checksum-verify** a Conflux address, the inverse of [`encode`].
///
/// `Some` means the BCH checksum closed, so a single mistyped character cannot reach the caller.
/// `None` means the string is not a Conflux Core Space address, for any reason.
///
/// Case is significant. Masking the prefix to five bits makes the checksum itself blind to case,
/// but CIP-37 defines the charset in lower case and the mixed-case form it allows is the optional
/// `type.user:` middle field, not the payload. Folding case here would accept strings the network
/// does not.
pub fn decode(s: &str) -> Option<Decoded> {
    // CIP-37 allows an optional address-type field between the prefix and the payload, as in
    // `cfx:type.user:aarc9…`. Drop it before decoding: it is redundant with the leading nibble of
    // the address, and the checksum is not computed over it.
    let (prefix, rest) = s.split_once(':')?;
    let data = match rest.split_once(':') {
        Some((declared, payload)) => {
            if !declared.starts_with("type.") {
                return None;
            }
            payload
        }
        None => rest,
    };

    // The prefix has to be constrained, not merely non-empty: masking a byte to five bits maps
    // eight different bytes onto each value, so `CFX` or `+fx` would checksum exactly as `cfx`
    // does.
    if prefix.is_empty()
        || !prefix
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return None;
    }

    let mut data_5bit = Vec::with_capacity(data.len());
    for c in data.bytes() {
        let i = CHARSET.iter().position(|&x| x == c)?;
        data_5bit.push(i as u8);
    }
    if data_5bit.len() <= CHECKSUM_CHARS {
        return None;
    }

    let prefix_5bit = prefix.bytes().map(|c| c & 0x1f);
    let residual = polymod(prefix_5bit.chain([0u8]).chain(data_5bit.iter().copied()));
    if residual != VALID_CHECKSUM_RESIDUAL {
        return None;
    }

    let payload = convertbits_5_to_8(&data_5bit[..data_5bit.len() - CHECKSUM_CHARS])?;
    // One version byte and exactly 20 address bytes. CIP-37's version byte also encodes the hash
    // size in its three low bits, and `0` means 20 bytes, so a payload of any other length is a
    // different scheme rather than a longer Conflux address.
    if payload.len() != 1 + ADDR_LEN || payload[0] != VERSION_BYTE {
        return None;
    }
    let mut addr = [0u8; ADDR_LEN];
    addr.copy_from_slice(&payload[1..]);
    Some(Decoded {
        prefix: prefix.to_string(),
        addr,
    })
}

#[cfg(test)]
mod tests {
    use super::{decode, encode, ADDR_LEN};

    fn hex20(h: &str) -> [u8; ADDR_LEN] {
        let h = h.strip_prefix("0x").unwrap_or(h);
        let mut out = [0u8; ADDR_LEN];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    /// Every encode vector CIP-37 publishes, mainnet and testnet, builtin/user/contract alike.
    /// Source: `Conflux-Chain/CIPs` `CIPs/cip-37.md`, "Test vectors".
    const VECTORS: &[(&str, &str, &str)] = &[
        (
            "0x1a2f80341409639ea6a35bbcab8299066109aa55",
            "cfx",
            "cfx:aarc9abycue0hhzgyrr53m6cxedgccrmmyybjgh4xg",
        ),
        (
            "0x1a2f80341409639ea6a35bbcab8299066109aa55",
            "cfxtest",
            "cfxtest:aarc9abycue0hhzgyrr53m6cxedgccrmmy8m50bu1p",
        ),
        (
            "0x85d80245dc02f5a89589e1f19c5c718e405b56cd",
            "cfx",
            "cfx:acc7uawf5ubtnmezvhu9dhc6sghea0403y2dgpyfjp",
        ),
        (
            "0x85d80245dc02f5a89589e1f19c5c718e405b56cd",
            "cfxtest",
            "cfxtest:acc7uawf5ubtnmezvhu9dhc6sghea0403ywjz6wtpg",
        ),
        (
            "0x19c742cec42b9e4eff3b84cdedcde2f58a36f44f",
            "cfx",
            "cfx:aap6su0s2uz36x19hscp55sr6n42yr1yk6r2rx2eh7",
        ),
        (
            "0x84980a94d94f54ac335109393c08c866a21b1b0e",
            "cfx",
            "cfx:acckucyy5fhzknbxmeexwtaj3bxmeg25b2b50pta6v",
        ),
        (
            "0x1cdf3969a428a750b89b33cf93c96560e2bd17d1",
            "cfx",
            "cfx:aasr8snkyuymsyf2xp369e8kpzusftj14ec1n0vxj1",
        ),
        (
            "0x0888000000000000000000000000000000000002",
            "cfx",
            "cfx:aaejuaaaaaaaaaaaaaaaaaaaaaaaaaaaajrwuc9jnb",
        ),
    ];

    #[test]
    fn encodes_every_cip37_vector() {
        for (hex, prefix, want) in VECTORS {
            assert_eq!(&encode(prefix, &hex20(hex)), want, "{hex} on {prefix}");
        }
    }

    #[test]
    fn decode_round_trips_every_cip37_vector() {
        for (hex, prefix, addr) in VECTORS {
            let d = decode(addr).expect("vector decodes");
            assert_eq!(d.prefix, *prefix);
            assert_eq!(d.addr, hex20(hex));
            assert_eq!(&encode(&d.prefix, &d.addr), addr);
        }
    }

    #[test]
    fn reads_the_address_type_out_of_the_leading_nibble() {
        // The three types CIP-37's own vectors cover, named the way the specification names them.
        assert_eq!(
            decode("cfx:aarc9abycue0hhzgyrr53m6cxedgccrmmyybjgh4xg")
                .unwrap()
                .address_type(),
            "type.user"
        );
        assert_eq!(
            decode("cfx:acc7uawf5ubtnmezvhu9dhc6sghea0403y2dgpyfjp")
                .unwrap()
                .address_type(),
            "type.contract"
        );
        assert_eq!(
            decode("cfx:aaejuaaaaaaaaaaaaaaaaaaaaaaaaaaaajrwuc9jnb")
                .unwrap()
                .address_type(),
            "type.builtin"
        );
    }

    #[test]
    fn accepts_the_optional_address_type_field() {
        // CIP-37 allows `cfx:type.user:<payload>`, and the checksum does not cover the field.
        let plain = "cfxtest:aarc9abycue0hhzgyrr53m6cxedgccrmmy8m50bu1p";
        let verbose = "cfxtest:type.user:aarc9abycue0hhzgyrr53m6cxedgccrmmy8m50bu1p";
        assert_eq!(decode(verbose), decode(plain));
        // A field that is not an address type is not a Conflux address.
        assert!(decode("cfxtest:nonsense:aarc9abycue0hhzgyrr53m6cxedgccrmmy8m50bu1p").is_none());
    }

    /// The load-bearing half: the checksum must be *compared*, not merely present. Corrupt every
    /// position of every vector, one character at a time, and require each corruption to stop
    /// decoding. This walks the checksum characters too, so it also pins that they are checked.
    #[test]
    fn a_single_character_change_never_decodes() {
        for (_, _, addr) in VECTORS {
            let (prefix, data) = addr.split_once(':').unwrap();
            for i in 0..data.len() {
                let orig = data.as_bytes()[i];
                for &c in super::CHARSET.iter() {
                    if c == orig {
                        continue;
                    }
                    let mut bytes = data.as_bytes().to_vec();
                    bytes[i] = c;
                    let corrupted = format!("{prefix}:{}", String::from_utf8(bytes).unwrap());
                    assert!(
                        decode(&corrupted).is_none(),
                        "corruption at {i} of {addr} still decoded"
                    );
                }
            }
        }
    }

    #[test]
    fn a_wrong_prefix_never_decodes() {
        // `cfx` and `cfxtest` checksum differently, so each vector is valid on one network only.
        assert!(decode("cfxtest:aarc9abycue0hhzgyrr53m6cxedgccrmmyybjgh4xg").is_none());
        assert!(decode("cfx:aarc9abycue0hhzgyrr53m6cxedgccrmmy8m50bu1p").is_none());
        // A prefix that masks onto `cfx` must not be accepted as `cfx`.
        assert!(decode("CFX:aarc9abycue0hhzgyrr53m6cxedgccrmmyybjgh4xg").is_none());
    }

    #[test]
    fn rejects_a_malformed_string() {
        assert!(decode("").is_none());
        assert!(decode("cfx:").is_none());
        assert!(decode("no-separator").is_none());
        // `i`, `l`, `o` and `q` are not in the alphabet.
        assert!(decode("cfx:iarc9abycue0hhzgyrr53m6cxedgccrmmyybjgh4xg").is_none());
        // Checksum field only, no payload.
        assert!(decode("cfx:aaaaaaaa").is_none());
    }
}
