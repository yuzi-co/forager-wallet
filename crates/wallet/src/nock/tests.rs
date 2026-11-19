//! Known-answer tests, every one taken from the reference repository
//! (`zorp-corp/nockchain@ed1edfcc`), none generated here.
//!
//! - `kat/*.txt` are the Hoon vectors of `hoon/tests/crypto/mod/{tip5,cheetah}.hoon`, transcribed
//!   mechanically (decimal, `.` separators removed). The cheetah files and `tip5_fixlen.txt` keep
//!   the first 25 of the 100 vectors each; `tip5_varlen.txt` keeps all of them.
//! - The key-derivation vector is `hoon/tests/wallet/mod/keygen.hoon` with the seed phrase of
//!   `hoon/tests/wallet/helpers.hoon`.
//! - The noun-framing vector is `hash_noun_varlen_digest_uses_public_shape_encoding` in
//!   `crates/lib/nockchain-math/src/tip5/hash.rs`.
//! - The Tip5 public vectors are `tip5_hash_varlen_public_vectors` in the same file.
//!
//! - The address-level vectors, mnemonic to v1 address from the official wallet, are
//!   [`WALLET_VECTORS`], at the end of this file.

use super::curve::{self, Point, GENERATOR, IDENTITY};
use super::field::{self, Fp6, P};
use super::tip5::{self, Noun};
use super::{hmac_sha512, master_from_seed, public_key, public_key_hash, serialize_public_key};
use crate::hexbytes;

fn nums(s: &str) -> Vec<u64> {
    s.split_whitespace()
        .map(|n| n.parse().expect("decimal"))
        .collect()
}

fn f6(s: &str) -> Fp6 {
    nums(s).try_into().expect("six limbs")
}

fn affine(x: &str, y: &str) -> Point {
    Point {
        x: f6(x),
        y: f6(y),
        inf: false,
    }
}

/// A scalar given as big-endian hex, as little-endian limbs.
fn scalar(hex: &str) -> Vec<u64> {
    let n = num_bigint::BigUint::parse_bytes(hex.as_bytes(), 16).expect("hex scalar");
    n.iter_u64_digits().collect()
}

fn lines(data: &'static str) -> impl Iterator<Item = Vec<&'static str>> {
    data.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.split(';').map(str::trim).collect())
}

#[test]
fn tip5_varlen_hoon_vectors() {
    let mut n = 0;
    for f in lines(include_str!("kat/tip5_varlen.txt")) {
        assert_eq!(
            tip5::hash_varlen_with(&nums(f[0]), &tip5::ROUND_CONSTANTS_MONT_5).to_vec(),
            nums(f[1]),
            "{}",
            f[0]
        );
        n += 1;
    }
    assert_eq!(n, 100);
}

#[test]
fn tip5_fixlen_hoon_vectors() {
    let mut n = 0;
    for f in lines(include_str!("kat/tip5_fixlen.txt")) {
        let input: [u64; 10] = nums(f[0]).try_into().expect("ten elements");
        assert_eq!(
            tip5::hash_ten_cell(&input, &tip5::ROUND_CONSTANTS_MONT_5).to_vec(),
            nums(f[1])
        );
        n += 1;
    }
    assert_eq!(n, 25);
}

#[test]
fn tip5_public_vectors_of_the_reference_crate() {
    assert_eq!(
        tip5::hash_varlen(&[]),
        [
            11_048_995_573_592_393_898,
            6_655_187_932_135_147_625,
            8_573_492_257_662_932_655,
            4_379_820_112_787_053_727,
            3_881_663_824_627_898_703,
        ]
    );
    assert_eq!(
        tip5::hash_varlen(&[2]),
        [
            8_342_164_316_692_288_712,
            12_061_287_490_523_852_513,
            4_038_969_618_836_824_144,
            5_830_796_451_787_599_265,
            468_390_350_313_364_562,
        ]
    );
    assert_eq!(
        tip5::hash_varlen(&[5, 26]),
        [
            4_045_697_570_544_439_560,
            13_674_194_094_340_317_530,
            13_743_008_867_885_290_460,
            6_020_910_684_025_273_897,
            3_362_765_570_390_427_021,
        ]
    );
}

#[test]
fn noun_framing_is_leaf_count_leaves_then_dyck_word() {
    // The reference's `hash_noun_varlen_digest_uses_public_shape_encoding`: the noun `[2 5 0]`
    // hashes as `[3, 2, 5, 0, 0, 1, 0, 1]`.
    let noun = Noun::tuple(&[Noun::Atom(2), Noun::Atom(5), Noun::Atom(0)]);
    assert_eq!(
        tip5::hash_noun_varlen(&noun),
        tip5::hash_varlen(&[3, 2, 5, 0, 0, 1, 0, 1])
    );
}

#[test]
fn the_public_key_noun_frames_as_thirteen_leaves_and_a_24_word_dyck_sequence() {
    // `a-pt-dyck-word` in `three.hoon`: `0 (0 1)^5 1 0 (0 1)^5 1`, the `[x y inf]` of two
    // six-tuples and the flag.
    let p = affine("1 2 3 4 5 6", "7 8 9 10 11 12");
    let mut expected = vec![13u64];
    expected.extend(1..=12);
    expected.push(1); // `inf` is `%.n`, the loobean 1.
    expected.push(0);
    expected.extend([0, 1].repeat(5));
    expected.push(1);
    expected.push(0);
    expected.extend([0, 1].repeat(5));
    expected.push(1);
    assert_eq!(expected.len(), 1 + 13 + 24);
    assert_eq!(public_key_hash(&p), tip5::hash_varlen(&expected));
}

#[test]
fn cheetah_generator_is_on_the_curve() {
    // `y^2 = x^3 + x + b` with `b = [395 1 0 0 0 0]` (`three.hoon`, `++  b`).
    let g = GENERATOR;
    let lhs = field::f6_mul(&g.y, &g.y);
    let x3 = field::f6_mul(&field::f6_mul(&g.x, &g.x), &g.x);
    let b: Fp6 = [395, 1, 0, 0, 0, 0];
    let rhs = field::f6_add(&field::f6_add(&x3, &g.x), &b);
    assert_eq!(lhs, rhs);
}

#[test]
fn group_order_annihilates_the_generator() {
    assert_eq!(curve::scalar_mul(&curve::GROUP_ORDER, &GENERATOR), IDENTITY);
}

#[test]
fn field_inverse_round_trips() {
    for s in ["1 0 0 0 0 0", "0 1 0 0 0 0", "13724052584687643294 6944593306454870014 10082672435494154603 6450272673873704561 2898784811200916299 15463938240345685194"] {
        let f = f6(s);
        let inv = field::f6_inv(&f).expect("non-zero");
        assert_eq!(field::f6_mul(&f, &inv), field::ONE);
    }
    assert_eq!(field::f6_inv(&field::ZERO), None);
    assert_eq!(field::mul(P - 1, P - 1), 1);
}

#[test]
fn cheetah_add_hoon_vectors() {
    for f in lines(include_str!("kat/cheetah_add.txt")) {
        let sum = curve::add(&affine(f[0], f[1]), &affine(f[2], f[3]));
        assert_eq!(sum, affine(f[4], f[5]));
    }
}

#[test]
fn cheetah_varbase_mul_hoon_vectors() {
    for f in lines(include_str!("kat/cheetah_varbase.txt")) {
        let prod = curve::scalar_mul(&scalar(f[2]), &affine(f[0], f[1]));
        assert_eq!(prod, affine(f[3], f[4]));
    }
}

#[test]
fn cheetah_fixbase_mul_hoon_vectors() {
    for f in lines(include_str!("kat/cheetah_fixbase.txt")) {
        let prod = curve::scalar_mul(&scalar(f[0]), &GENERATOR);
        assert_eq!(prod, affine(f[1], f[2]));
    }
}

/// RFC 4231 test case 2 and 6 (key longer than the block) for HMAC-SHA-512.
#[test]
fn hmac_sha512_rfc4231() {
    let got = hmac_sha512(b"Jefe", b"what do ya want for nothing?");
    assert_eq!(
        hexbytes::encode(&got[..]),
        "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554\
         9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
    );
    let got = hmac_sha512(
        &[0xaa; 131],
        b"Test Using Larger Than Block-Size Key - Hash Key First",
    );
    assert_eq!(
        hexbytes::encode(&got[..]),
        "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352\
         6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"
    );
}

/// `hoon/tests/wallet/helpers.hoon` `seed-phrase`, the 24 words the reference's key-generation
/// tests import.
const SEED_PHRASE: &str = "ranch matter impact bright candy cattle quarter boost concert toilet wedding identify belt monitor honey suggest cherry cereal ribbon screen cabbage push urban glove";

/// `hoon/tests/wallet/mod/keygen.hoon` `expected-seed`: the BIP39 seed of [`SEED_PHRASE`].
const SEED: &str = "fbe1e504e14fbcac93361c9bd66317327b07bb6ab4f7e478b42d2e0403632e50be6d0fa82d433cdb12b516d2f04b386461b2c37a0eafbb5a959e3cbee8fc2ce4";

/// `expected-master-key`.
const MASTER_SK: &str = "15d912dd505f79e3edb96fa0456bd808af56dd15c91f1ce4511fe03783ed89f6";
const MASTER_CC: &str = "8f1c22588ddbad8650411f25148c60f5c7580d55c9c66d6a89c663d6a067fd9c";
/// The 97-byte `ser-a-pt` atom of the master public key. The Hoon literal has 193 hex digits (the
/// leading `0x01` byte loses its zero nibble), so it is restored here.
const MASTER_PK: &str = "01e00a5fb423377487affad4d7acc09b639cf12d478384475834945f7e70fd4f812141c920e89b8f6308a62c44cd1f38fb52104988187a6bce4cf74741bf06eeb9344f0e745d2b2626bf4c52c9b7888cffdaa098868df1a4892d899d67a5d3a752";

#[test]
fn bip39_seed_of_the_reference_phrase_is_the_reference_seed() {
    let seed = crate::bip39::seed(SEED_PHRASE, "").expect("valid phrase");
    assert_eq!(hexbytes::encode(seed.as_bytes()), SEED);
}

#[test]
fn master_key_hoon_vector() {
    let seed = hexbytes::decode(SEED).expect("hex");
    let m = master_from_seed(&seed);
    assert_eq!(hexbytes::encode(&m.secret_key[..]), MASTER_SK);
    assert_eq!(hexbytes::encode(&m.chain_code[..]), MASTER_CC);
}

#[test]
fn master_public_key_hoon_vector() {
    let sk: [u8; 32] = hexbytes::decode(MASTER_SK)
        .expect("hex")
        .try_into()
        .expect("32 bytes");
    let pk = public_key(&sk).expect("in range");
    assert_eq!(hexbytes::encode(&serialize_public_key(&pk)), MASTER_PK);
}

#[test]
fn out_of_range_secret_keys_have_no_public_key() {
    assert!(public_key(&[0u8; 32]).is_none());
    // The group order itself, and anything above.
    let n = "7af2599b3b3f22d0563fbf0f990a37b5327aa72330157722d443623eaed4accf";
    let n: [u8; 32] = hexbytes::decode(n).expect("hex").try_into().expect("32");
    assert!(public_key(&n).is_none());
    assert!(public_key(&[0xff; 32]).is_none());
    let mut below = n;
    below[31] -= 1;
    assert!(public_key(&below).is_some());
}

/// `test_f6inv` of `crypto/cheetah.rs` in the reference crate.
#[test]
fn field_inverse_reference_vectors() {
    let inv = field::f6_inv(&[1; 6]).expect("non-zero");
    assert_eq!(
        inv,
        [
            3_074_457_344_902_430_720,
            15_372_286_724_512_153_601,
            0,
            0,
            0,
            0
        ]
    );
    let f: Fp6 = [
        13_724_052_584_687_643_294,
        6_944_593_306_454_870_014,
        10_082_672_435_494_154_603,
        6_450_272_673_873_704_561,
        2_898_784_811_200_916_299,
        15_463_938_240_345_685_194,
    ];
    assert_eq!(
        field::f6_inv(&f).expect("non-zero"),
        [
            129_083_178_215_983_407,
            16_804_250_925_345_184_998,
            6_447_171_951_354_165_736,
            16_181_730_381_532_049_633,
            9_179_768_094_922_373_417,
            8_139_613_426_717_722_210,
        ]
    );
}

/// `test_ch_scal` of `crypto/cheetah.rs` in the reference crate: `3 G`.
#[test]
fn three_times_the_generator_reference_vector() {
    let expected = Point {
        x: [
            12_461_929_372_724_418_873,
            16_567_359_094_004_701_986,
            18_139_376_982_535_661_051,
            3_904_128_592_858_427_998,
            1_409_597_492_055_585_669,
            10_004_445_677_131_924_957,
        ],
        y: [
            11_902_197_035_441_682_466,
            5_072_010_750_673_887_563,
            16_590_571_040_514_665_822,
            11_686_652_568_553_538_253,
            9_569_866_106_958_470_758,
            6_839_548_852_764_696_901,
        ],
        inf: false,
    };
    assert_eq!(curve::scalar_mul(&[3], &GENERATOR), expected);
}

/// Mnemonic to address vectors captured from the official wallet, `nockchain-wallet` built from
/// `zorp-corp/nockchain@ed1edfcc` (`import-keys --seedphrase --version 1`, then
/// `list-master-addresses` and `show-master-prv`; and `--version 0` for the legacy address). The
/// phrases are the BIP39 test phrases; the passphrase is empty.
///
/// Per line: `mnemonic ; master secret key ; chain code ; public key (97 bytes) ; v1 address ; v0
/// address`, hex and base58 as the wallet prints them. The chain code and public key are sliced out
/// of the printed extended keys, not printed directly; the secret key and both addresses are.
pub(crate) const WALLET_VECTORS: &str = include_str!("kat/wallet_vectors.txt");

#[test]
fn official_wallet_vectors_derive_end_to_end() {
    use forager_addr::codec::{base58, nock};

    let mut n = 0;
    for f in lines(WALLET_VECTORS) {
        let (phrase, sk, cc, pk, v1, v0) = (f[0], f[1], f[2], f[3], f[4], f[5]);
        let seed = crate::bip39::seed(phrase, "").expect("valid phrase");
        let master = master_from_seed(seed.as_bytes());
        assert_eq!(hexbytes::encode(&master.secret_key[..]), sk, "{phrase}");
        assert_eq!(hexbytes::encode(&master.chain_code[..]), cc, "{phrase}");

        let point = public_key(&master.secret_key).expect("in range");
        let serialized = serialize_public_key(&point);
        assert_eq!(hexbytes::encode(&serialized), pk, "{phrase}");
        // The v0 address is the base58 of those 97 bytes.
        assert_eq!(base58::encode(&serialized), v0, "{phrase}");

        // The v1 address is the Tip5 hash of the public key noun.
        let digest = public_key_hash(&point);
        assert_eq!(nock::encode_digest(&digest), v1, "{phrase}");
        assert_eq!(nock::decode_digest(v1), Some(digest), "{phrase}");
        assert_eq!(
            super::address_of_secret_key(&master.secret_key).as_deref(),
            Some(v1)
        );
        assert_eq!(
            forager_addr::detect_family(v1),
            Some(forager_addr::Family::Nock)
        );
        n += 1;
    }
    assert_eq!(n, 4);
}
