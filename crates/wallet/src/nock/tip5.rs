//! Tip5 (ePrint 2023/107) as Nockchain parameterises it: the 7-round permutation over Goldilocks,
//! the variable-length sponge, and the `hash-noun-varlen` framing of a noun.
//!
//! Ported from `zorp-corp/nockchain@ed1edfcc` (MIT OR Apache-2.0): the lookup table, round
//! constants and MDS column are the `tip5/mod.rs` literals, and the sponge and noun framing follow
//! `tip5/hash.rs`, `shape.rs` and the Hoon `hash-noun-varlen` in `hoon/common/ztd/three.hoon`.
//! See the repository `NOTICE`.
//!
//! Speed is not a goal: an address costs one hash of 38 field elements. The MDS layer is the plain
//! circulant product rather than the reference's Karatsuba form, and the known-answer tests pin it.

use super::field::{self, P};

const STATE_SIZE: usize = 16;
const RATE: usize = 10;
const DIGEST_LENGTH: usize = 5;
const NUM_ROUNDS: usize = 7;
const NUM_SPLIT_AND_LOOKUP: usize = 4;

/// `R mod p` for `R = 2^64`: the Montgomery form of 1, and the capacity lanes of the fixed-length
/// sponge.
const MONT_ONE: u64 = 4_294_967_295;
/// `R^2 mod p`, to enter Montgomery form.
const R2: u128 = 18_446_744_065_119_617_025;
const RP: u128 = 0xffff_ffff_0000_0001_0000_0000_0000_0000;

const LOOKUP_TABLE: [u8; 256] = [
    0, 7, 26, 63, 124, 215, 85, 254, 214, 228, 45, 185, 140, 173, 33, 240, 29, 177, 176, 32, 8,
    110, 87, 202, 204, 99, 150, 106, 230, 14, 235, 128, 213, 239, 212, 138, 23, 130, 208, 6, 44,
    71, 93, 116, 146, 189, 251, 81, 199, 97, 38, 28, 73, 179, 95, 84, 152, 48, 35, 119, 49, 88,
    242, 3, 148, 169, 72, 120, 62, 161, 166, 83, 175, 191, 137, 19, 100, 129, 112, 55, 221, 102,
    218, 61, 151, 237, 68, 164, 17, 147, 46, 234, 203, 216, 22, 141, 65, 57, 123, 12, 244, 54, 219,
    231, 96, 77, 180, 154, 5, 253, 133, 165, 98, 195, 205, 134, 245, 30, 9, 188, 59, 142, 186, 197,
    181, 144, 92, 31, 224, 163, 111, 74, 58, 69, 113, 196, 67, 246, 225, 10, 121, 50, 60, 157, 90,
    122, 2, 250, 101, 75, 178, 159, 24, 36, 201, 11, 243, 132, 198, 190, 114, 233, 39, 52, 21, 209,
    108, 238, 91, 187, 18, 104, 194, 37, 153, 34, 200, 143, 126, 155, 236, 118, 64, 80, 172, 89,
    94, 193, 135, 183, 86, 107, 252, 13, 167, 206, 136, 220, 207, 103, 171, 160, 76, 182, 227, 217,
    158, 56, 174, 4, 66, 109, 139, 162, 184, 211, 249, 47, 125, 232, 117, 43, 16, 42, 127, 20, 241,
    25, 149, 105, 156, 51, 53, 168, 145, 247, 223, 79, 78, 226, 15, 222, 82, 115, 70, 210, 27, 41,
    1, 170, 40, 131, 192, 229, 248, 255,
];

const ROUND_CONSTANTS_MONT_7: [u64; NUM_ROUNDS * STATE_SIZE] = [
    6813007285744613222,
    9538108458283805344,
    8266796718228611711,
    10279833152781686635,
    16136178252164695712,
    11678500968092896548,
    18177224533631314584,
    8519208882353197867,
    15278933395031186751,
    5605030382266121712,
    3266079902019342405,
    16977155338689078860,
    575533378161618286,
    14008024146379968822,
    16952256074650551489,
    10699818153468018415,
    16274322239097854776,
    16277174423203830480,
    15551543598572731978,
    17734447432847017984,
    10634644696612177250,
    14223629804877666866,
    9951585614956111842,
    13410522825507264153,
    15504271780310363158,
    15788426030062030790,
    7247426745733321025,
    15545848059337170693,
    7257327654080199927,
    2632620606461733813,
    5468949404670321892,
    3408181798280532022,
    6407521478186447124,
    10532483258532500040,
    9962573180077511189,
    14997058441937336819,
    8347291381276979462,
    1834710304424753372,
    8919127106750279878,
    17952692726686580444,
    10425759383842794244,
    3571063091305112274,
    11196674225031209104,
    17831978239644188755,
    7386054759687923415,
    49233562557975441,
    15763370708992892484,
    7042466268943341941,
    14925546578125121441,
    5737865664192390903,
    6112071640890712275,
    7093386846491465789,
    12933769084390453308,
    840431699266909703,
    2593502341286518015,
    805532971224672190,
    662776811092263083,
    1082592850076858062,
    2260713232066289719,
    18161814497919979745,
    11436170062534698819,
    9156670326168191466,
    13690674722453603930,
    16450526946025880915,
    3443037901035637703,
    13512956751884108002,
    12765464435334038877,
    16857582347068713433,
    4403818324750733470,
    16327824648413653612,
    9624633671524957693,
    11798148227002487001,
    4806282851616964758,
    13789375745913111929,
    8048230392833675591,
    15394445679479006170,
    5381819560221452561,
    4546720664034456941,
    17286163612312122987,
    16936562784938244714,
    11067749825657848638,
    5556080822347806028,
    3866118074743041663,
    2201009632364155631,
    10808969316669713964,
    9312983943061336112,
    17369380183573126906,
    12953586427039891533,
    16564382082196301935,
    6117018641086235131,
    2379948990303454544,
    9900641007991965131,
    14289331750432136160,
    12105488135916678431,
    14113550218116986428,
    13441194625000926086,
    8346758232352358445,
    13109503806329090541,
    16233458644157342064,
    3717000905522992223,
    4028024080310608291,
    16928904978228437531,
    486523272751840851,
    17746229827600458028,
    4231774801891550196,
    11401341037617516726,
    12004481761165906799,
    1880237553532135241,
    7506757868197934780,
    1656439004520781315,
    7739084580576441604,
    17945328382079677663,
];

/// `ROUND_CONSTANTS_MONT_5`: the 5-round variant of the Hoon `round-constants`, montified, for
/// the Hoon known-answer tests only.
#[cfg(test)]
pub(super) const ROUND_CONSTANTS_MONT_5: [u64; 5 * STATE_SIZE] = [
    7037825344483254583,
    15660281237101973268,
    11663766947456533322,
    9758322335534608651,
    9844019505645103858,
    4857588499203253814,
    8183281691101684811,
    15181868196341541705,
    15313308792798519638,
    4938243538257252168,
    11477857560977070644,
    8733479459723616501,
    5964369093314834808,
    5237032791768927641,
    18359039010129826068,
    18116588813135677237,
    2373119002936405740,
    6609692170274203878,
    2821639470223165353,
    5627586457204135930,
    12211487165911217099,
    7204661105156636001,
    12626318814627363213,
    6427516477865291713,
    13821391005533853229,
    14722843308708254034,
    17831147802219528369,
    218913218967027617,
    2837053027518735973,
    3210943779430037835,
    7054336531172598568,
    6670615253073215499,
    6215281670845392714,
    6900256161834717452,
    4440316076963652853,
    6676740671006861280,
    3322554067925148283,
    3612069913603013341,
    5442068317028031748,
    16971511550198711839,
    13562874907509462005,
    5867006965543663558,
    8326918008935674480,
    16918029521751963400,
    5474468139859308386,
    2454012399801889149,
    569589873975678404,
    17507424082632478709,
    9038225550794018841,
    16660859940746912489,
    17257844725184629383,
    3706016801679531593,
    17566486224421590314,
    7708791552397413124,
    2689521333672664497,
    4064165436802017842,
    15141471530346796595,
    1364174733976751532,
    18217692388866001096,
    15503489087998329673,
    12679114765070559102,
    1725321575593133848,
    12693023640037744607,
    16382987239139532379,
    6953765660023409218,
    831521851918920482,
    12582394124858434573,
    15701134258274330528,
    3257079200028190136,
    13253780642593168972,
    6475583681330976806,
    6838199851576533613,
    17771771274180351592,
    4281487964531026568,
    3163387549720473023,
    16140694131354242855,
    6867950304952209227,
    10934976704992317137,
    1446938313484247691,
    17506129961070749385,
];

/// First column of the 16x16 circulant MDS matrix.
const MDS_FIRST_COLUMN: [u64; STATE_SIZE] = [
    61402, 1108, 28750, 33823, 7454, 43244, 53865, 12034, 56951, 27521, 41351, 40901, 12021, 59689,
    26798, 17845,
];

/// Montgomery reduction: `a * R^-1 mod p` for `a < R * p`.
fn mont_reduction(a: u128) -> u64 {
    debug_assert!(a < RP);
    let x1: u128 = (a >> 32) & 0xffff_ffff;
    let x2: u128 = a >> 64;
    let c: u128 = ((a & 0xffff_ffff) + x1) << 32;
    let f: u128 = c >> 64;
    let d: u128 = c - (x1 + f * u128::from(P));
    if x2 >= d {
        (x2 - d) as u64
    } else {
        (x2 + u128::from(P) - d) as u64
    }
}

fn montiply(a: u64, b: u64) -> u64 {
    mont_reduction(u128::from(a) * u128::from(b))
}

fn montify(a: u64) -> u64 {
    mont_reduction(u128::from(a) * R2)
}

fn sbox_layer(state: &[u64; STATE_SIZE]) -> [u64; STATE_SIZE] {
    let mut out = [0u64; STATE_SIZE];
    for i in 0..NUM_SPLIT_AND_LOOKUP {
        let mut bytes = state[i].to_le_bytes();
        for b in &mut bytes {
            *b = LOOKUP_TABLE[usize::from(*b)];
        }
        out[i] = u64::from_le_bytes(bytes);
    }
    for j in NUM_SPLIT_AND_LOOKUP..STATE_SIZE {
        let x = state[j];
        let x2 = montiply(x, x);
        let x4 = montiply(x2, x2);
        let x3 = montiply(x, x2);
        out[j] = montiply(x3, x4);
    }
    out
}

/// `out[i] = sum_j column[(i - j) mod 16] * state[j]  (mod p)`.
fn mds(state: &[u64; STATE_SIZE]) -> [u64; STATE_SIZE] {
    let mut out = [0u64; STATE_SIZE];
    for (i, o) in out.iter_mut().enumerate() {
        // 16 terms of at most 2^16 * 2^64 fit a u128 with room to spare.
        let mut acc: u128 = 0;
        for (j, s) in state.iter().enumerate() {
            acc += u128::from(MDS_FIRST_COLUMN[(i + STATE_SIZE - j) % STATE_SIZE]) * u128::from(*s);
        }
        *o = (acc % u128::from(P)) as u64;
    }
    out
}

/// One round per `STATE_SIZE` constants. Nockchain's is the 7-round table. The Hoon test vectors
/// were generated with the paper's 5-round variant (`~(hash-10 tip5 5)`), which has its own
/// constants, so the tests run that.
fn permute_with(state: &mut [u64; STATE_SIZE], constants: &[u64]) {
    for round in 0..constants.len() / STATE_SIZE {
        let b = mds(&sbox_layer(state));
        for j in 0..STATE_SIZE {
            state[j] = field::add(constants[round * STATE_SIZE + j], b[j]);
        }
    }
}

fn digest_of(state: &[u64; STATE_SIZE]) -> [u64; DIGEST_LENGTH] {
    let mut d = [0u64; DIGEST_LENGTH];
    for (o, s) in d.iter_mut().zip(state) {
        *o = mont_reduction(u128::from(*s));
    }
    d
}

/// Variable-length hash of base-field elements (Hoon `hash-varlen`, Rust `hash_belts_slice`):
/// zero state, inputs in Montgomery form overwrite the rate, padded with a Montgomery `1` and
/// zeros up to a whole block (a full extra block when the length is already a multiple of 10).
/// Every input must be a canonical field element.
pub(super) fn hash_varlen(input: &[u64]) -> [u64; DIGEST_LENGTH] {
    hash_varlen_with(input, &ROUND_CONSTANTS_MONT_7)
}

pub(super) fn hash_varlen_with(input: &[u64], constants: &[u64]) -> [u64; DIGEST_LENGTH] {
    assert!(input.iter().all(|x| *x < P), "input must be based");
    let q = input.len() / RATE;
    let mut padded = vec![0u64; input.len() + RATE - input.len() % RATE];
    for (p, x) in padded.iter_mut().zip(input) {
        *p = montify(*x);
    }
    padded[input.len()] = MONT_ONE;
    let mut state = [0u64; STATE_SIZE];
    for block in padded.as_chunks::<RATE>().0.iter().take(q + 1) {
        state[..RATE].copy_from_slice(block);
        permute_with(&mut state, constants);
    }
    digest_of(&state)
}

/// Fixed-length hash of exactly ten elements (Hoon `hash-10`): capacity lanes start at the
/// Montgomery `1`, one permutation, no padding. Only the known-answer tests use it.
#[cfg(test)]
pub(super) fn hash_ten_cell(input: &[u64; RATE], constants: &[u64]) -> [u64; DIGEST_LENGTH] {
    assert!(input.iter().all(|x| *x < P), "input must be based");
    let mut state = [MONT_ONE; STATE_SIZE];
    for (s, x) in state.iter_mut().zip(input) {
        *s = montify(*x);
    }
    permute_with(&mut state, constants);
    digest_of(&state)
}

/// A noun: an atom (a base-field element here) or a cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Noun {
    Atom(u64),
    Cell(Box<Noun>, Box<Noun>),
}

impl Noun {
    /// The right-nested tuple `[a [b [c ...]]]` Hoon writes as `[a b c ...]`.
    pub(super) fn tuple(items: &[Noun]) -> Noun {
        match items {
            [] => panic!("empty tuple"),
            [last] => last.clone(),
            [head, rest @ ..] => Noun::Cell(Box::new(head.clone()), Box::new(Noun::tuple(rest))),
        }
    }
}

/// Pre-order walk: a `0` on entering a cell, a `1` after its head, atoms collected in order. This
/// is `leaf-sequence` and `dyck` of the Hoon `shape` core in one pass.
fn walk(noun: &Noun, leaves: &mut Vec<u64>, dyck: &mut Vec<u64>) {
    match noun {
        Noun::Atom(a) => leaves.push(*a),
        Noun::Cell(head, tail) => {
            dyck.push(0);
            walk(head, leaves, dyck);
            dyck.push(1);
            walk(tail, leaves, dyck);
        }
    }
}

/// Hoon `hash-noun-varlen`: `hash-varlen([len(leaves)] ++ leaves ++ dyck)`.
pub(super) fn hash_noun_varlen(noun: &Noun) -> [u64; DIGEST_LENGTH] {
    let (mut leaves, mut dyck) = (Vec::new(), Vec::new());
    walk(noun, &mut leaves, &mut dyck);
    let mut input = Vec::with_capacity(1 + leaves.len() + dyck.len());
    input.push(leaves.len() as u64);
    input.extend(leaves);
    input.extend(dyck);
    hash_varlen(&input)
}
