use zeroize::Zeroize;

use crate::coins::NOID_HRP;
use crate::poseidon2b::{capacity_iv, lanes, Sponge};

/// Domain tag of the address hash. Reference: `native/domain.rs` `TAG_ADDRFIX`.
const TAG_ADDRFIX: &[u8; 8] = b"ADDRFIX_";

/// The last lane the master-to-spend derivation absorbs, the ASCII bytes `noid-deri` read as one
/// big-endian integer. Reference: `noid_node/src/wallet/keystore.rs`
/// `MasterSecret::derive_spend_secret`, which writes this literal with that comment.
const SPEND_DOMAIN: u128 = 0x6E6F69642D64657269;

/// The address index the official wallet shows after a master-secret import. The import resets
/// the wallet's cursor to `active_index: 0` (`noid_node/src/wallet/state.rs`
/// `import_generated_master_secret`), and the documentation calls it "address `0`".
const FIRST_INDEX: u32 = 0;

/// Spend secret `index` of a Parano1d wallet master secret.
///
/// `Poseidon2b sponge, zero IV: absorb(master_lo, master_hi, index, "noid-deri"), finalize()`,
/// where the master halves are its two little-endian 16-byte lanes and `finalize` adds the
/// reference's `0x80 … 0x01` padding block. Pinned to `ignotusnemo/parano1d@52938433`
/// `noid_node/src/wallet/keystore.rs` (`MasterSecret::derive_spend_secret`).
pub(crate) fn spend_secret(master: &[u8; 32], index: u32) -> [u8; 32] {
    let mut sponge = Sponge::with_iv([0, 0]);
    let (mut lo, mut hi) = lanes(master);
    sponge.absorb_block(lo, hi);
    lo.zeroize();
    hi.zeroize();
    sponge.absorb_block(u128::from(index), SPEND_DOMAIN);
    sponge.finalize()
}

/// The 32 address bytes of a spend secret: `Poseidon2b_fixed(ADDRFIX_, secret_lo, secret_hi)`,
/// one rate block under the `ADDRFIX_` capacity IV and no padding. Pinned to
/// `ignotusnemo/parano1d@52938433` `noid_poseidon2b/src/primitives.rs` (`derive_address`).
pub(crate) fn address_bytes(spend: &[u8; 32]) -> [u8; 32] {
    let mut sponge = Sponge::with_iv(capacity_iv(TAG_ADDRFIX));
    let (mut lo, mut hi) = lanes(spend);
    sponge.absorb_block(lo, hi);
    lo.zeroize();
    hi.zeroize();
    sponge.finalize_no_pad()
}

/// Parano1d (NOID) address for a wallet **master** secret: `bech32m("o", address_bytes(spend_0))`.
///
/// The secret this crate prints for `noid` is the master secret, because that is the only secret
/// the official wallet imports: its "Restore from existing key" dialog and the node's
/// `--import-wallet-secret` both take exactly 64 hexadecimal characters and install them as the
/// master (`noid_node/src/wallet/state.rs` `import_generated_master_secret`). The address the
/// wallet then shows first is index 0, so that is the one printed here.
///
/// There is no curve: the address is a hash of the secret, and ownership is proved in zero
/// knowledge. Every 32-byte string is a valid master secret, including all zeros.
pub(crate) fn address(master: &[u8; 32]) -> String {
    let mut spend = spend_secret(master, FIRST_INDEX);
    let payload = address_bytes(&spend);
    spend.zeroize();
    crate::codec::bech32::encode_bech32m_bytes(NOID_HRP, &payload)
}

/// Parse a master secret the way the official import does: drop every ASCII whitespace character,
/// then require exactly 64 hexadecimal characters (`import_generated_master_secret`). A WIF is not
/// accepted, because the official wallet does not accept one.
pub(crate) fn parse_master_secret(input: &str) -> Option<[u8; 32]> {
    let mut compact: String = input.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let out = crate::hexbytes::decode_n::<32>(&compact);
    compact.zeroize();
    out
}

#[cfg(test)]
mod tests {
    use super::{address, address_bytes, parse_master_secret, spend_secret};
    use crate::hexbytes::{encode as hex, hex32};

    /// Captured from the reference crates by the `kat-addr` harness (`D:\fw\_ref\kat-addr`, run in
    /// Docker against `ignotusnemo/parano1d@52938433` with `rust:1.96`): `derive_address` of
    /// `noid_poseidon2b::primitives`, called on `SpendSecret::from_bytes(secret)`.
    ///
    /// `(spend secret, address bytes, address)`. The mixed secret is byte `i` = `37 i + 11`; the
    /// last one is from `openssl rand`.
    const SPEND_VECTORS: &[(&str, &str, &str)] = &[
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "ce26bb184080764568cbf9fee066c3b973e2e143999b05bfe4aa4d7e84be5035",
            "o1ecntkxzqspmy26xtl8lwqekrh9e79c2rnxdst0ly4fxhap972q6say5v5k",
        ),
        (
            "0b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186",
            "4b6bad5cebb203fbfdfc048f969f94990e442d84ae045747cc526814eb353edb",
            "o1fd466h8tkgplhl0uqj8ed8u5ny8ygtvy4cz9w37v2f5pf6e48mdswa47t0",
        ),
        (
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "8a86bdfd341e5811d76c35ec3b4f45045cad636db9348e1571c55e7543994274",
            "o132rtmlf5revpr4mvxhkrkn69q3w26cmdhy6gu9t3c4082suegf6q0f5rfh",
        ),
        (
            "e65d6fb6fce6b76067de3a017cf7128bad27abf71b910ac77a89959d0b067097",
            "53f3f528736fc8d78d9cfdab105a5f7b516af2d04ffa9e92215ed9cac9d37e58",
            "o120el22rndlyd0rvulk43qkjl0dgk4uksflafay3ptmvu4jwn0evqydl9yd",
        ),
    ];

    /// Captured by the same harness, end to end through the reference node's own key store: the
    /// harness compiles `noid_node/src/wallet/keystore.rs` verbatim, writes each master secret into
    /// a `wallet.key` with `Keystore::encode_plain_file` (what `--import-wallet-secret` installs),
    /// loads it back with `Keystore::load_plain`, and calls `MasterSecret::derive_spend_secret` and
    /// `MasterSecret::derive_address`.
    ///
    /// `(master secret, index, spend secret, address)`.
    const MASTER_VECTORS: &[(&str, u32, &str, &str)] = &[
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            0,
            "ca5a191039b96c650aa5cd85e23552449aed606e83e35546c7cc8b0e7744a074",
            "o1rujxarvejc9jhfgwnh7hxf9kg2s94hhky2hrsjf4hwfep543y7lsl4x52t",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            1,
            "80624917337c83a63a2bd4555318023db574a67ee24ff60b2b90acc91f1e3656",
            "o1cc6ycskf7gwj7rrtvru5zs3lkr99qhuj8ecwtkuyjjq9xyl7qvqq5r8fzn",
        ),
        (
            "0b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186",
            0,
            "e9d95fce962e8ce49770628a2e7a6048c471262e5309fb9f2268322a831785e3",
            "o1w88x9sgcdn0a6dcm3mvf5fp535rh7mwm74ulpzd4grz5z0yanc8qlrnlyq",
        ),
        (
            "0b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186",
            1,
            "11e5919278975c13948ea6e87bbf6f7d3c958debad8646152f08aba4d58075d3",
            "o17uqle5frdg4n36cd8zwhvft6qzhsvq9fedtr6tdqw3lrau3x3gcqv6wxrl",
        ),
        (
            "d008285e7bbc3fc1374e12978cbb5a434a5e9e8129e26b883761f6ec6f2b385a",
            0,
            "4177f6f88b2d2a4c3b3ba35dbf77b31ed7803b049965ccbad27485f3878d6110",
            "o1vckl9ly5walhz8p5yzze98s5t6y6ruaeck236npdvx0dkxfcj25sl74e5v",
        ),
        (
            "d008285e7bbc3fc1374e12978cbb5a434a5e9e8129e26b883761f6ec6f2b385a",
            1,
            "2d9b88e771b6880cae8db0eeef73b0eb219e8fe161d6dd2edbb887a6c65e9369",
            "o1klutremulvzvmgw6793yqavevfwpt0mvs88jgv5rwu28zwp4ky5sklmtvh",
        ),
        (
            "440f02d28ea7f7b12760300a5e7acc39fbebf8879067384168177c1d07ad151b",
            0,
            "b010134443574c25bf1db909513facfae0cba703b15cabef1a8dc32665c6eb6e",
            "o1jjwkymay9368ayx0vs4qhgedzafg7mt6rfynsge3pwca0e8zrz0sh84j7h",
        ),
        (
            "440f02d28ea7f7b12760300a5e7acc39fbebf8879067384168177c1d07ad151b",
            1,
            "85ba04d06d3f543603c4785e6b7a8316ffeaabbaddc9f5b95c31e91601d9e709",
            "o16g885yza3uxtm6whds6e7xc3yqczznkdt0ld9ku0zhhhnahtjvzqkh2u8q",
        ),
    ];

    #[test]
    fn address_from_spend_secret_matches_the_reference() {
        for &(spend, bytes, addr) in SPEND_VECTORS {
            let got = address_bytes(&hex32(spend));
            assert_eq!(hex(&got), bytes, "spend {spend}");
            assert_eq!(
                crate::codec::bech32::encode_bech32m_bytes("o", &got),
                addr,
                "spend {spend}"
            );
        }
    }

    #[test]
    fn master_to_spend_to_address_matches_the_reference_key_store() {
        for &(master, index, spend, addr) in MASTER_VECTORS {
            let s = spend_secret(&hex32(master), index);
            assert_eq!(hex(&s), spend, "master {master} index {index}");
            assert_eq!(
                crate::codec::bech32::encode_bech32m_bytes("o", &address_bytes(&s)),
                addr,
                "master {master} index {index}"
            );
            if index == 0 {
                assert_eq!(address(&hex32(master)), addr, "master {master}");
            }
        }
    }

    /// The import normalisation the official node applies: whitespace anywhere is dropped and
    /// either hex case is accepted. Anything that is not then 64 hex characters is refused.
    #[test]
    fn master_secret_parses_like_the_official_import() {
        let m = "d008285e7bbc3fc1374e12978cbb5a434a5e9e8129e26b883761f6ec6f2b385a";
        let spaced_upper =
            "D008285E 7BBC3FC1 374E1297 8CBB5A43\n4A5E9E81 29E26B88 3761F6EC 6F2B385A";
        assert_eq!(parse_master_secret(m), Some(hex32(m)));
        assert_eq!(parse_master_secret(spaced_upper), Some(hex32(m)));
        assert_eq!(parse_master_secret(&m[..62]), None);
        assert_eq!(parse_master_secret(&format!("{m}00")), None);
        assert_eq!(parse_master_secret(&m.replace('d', "g")), None);
        // A WIF is not a master secret.
        assert_eq!(
            parse_master_secret("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"),
            None
        );
    }
}
