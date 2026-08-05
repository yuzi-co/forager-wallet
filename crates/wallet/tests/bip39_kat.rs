//! Known-answer tests for the clean-room BIP-39 implementation in [`forager_wallet::bip39`].
//!
//! A wrong seed here is not a failing test in the abstract — it is an address whose funds cannot
//! be recovered by any other wallet. So every claim this module makes is anchored to a published
//! vector rather than to this crate's own output.
//!
//! ## Where the vectors come from
//!
//! * **English (24 rows).** The official `vectors.json` from `trezor/python-mnemonic`
//!   (<https://github.com/trezor/python-mnemonic/blob/master/vectors.json>), `"english"` key.
//!   Each row is `[entropy hex, phrase, seed hex, xprv]`; the seed column is derived with the
//!   passphrase `"TREZOR"`, which is the passphrase python-mnemonic's own test suite uses for
//!   every row of every language. The rows below carry the first three columns; the `xprv` column
//!   is BIP-32's business, not BIP-39's, and is checked by `tests/hd_kat.rs` instead. Word counts
//!   present: 12, 18 and 24 — the file has no 15- or 21-word rows, so those two lengths are
//!   covered by the round-trip test and by the structural checks in `src/bip39.rs` instead.
//!
//! * **Japanese (1 row, the NFKD anchor).** `test_JP_BIP39.json` from
//!   `bip32JP/bip32JP.github.io` (<https://github.com/bip32JP/bip32JP.github.io>), the vector set
//!   BIP-39 itself links for Japanese. Unlike the trezor file — whose Japanese rows also use the
//!   ASCII passphrase `"TREZOR"` — these rows use a genuinely non-ASCII passphrase, which is
//!   exactly the case the delegated implementation got wrong.
//!
//! ## Why the Japanese row is testable here at all
//!
//! This crate ships only the English word list, so it cannot map Japanese words to entropy. It
//! does not need to: BIP-39's "from mnemonic to seed" step never consults a word list. It is
//! PBKDF2 over the phrase *as text*. [`forager_wallet::bip39::seed_unchecked`] exposes exactly
//! that step, so the published Japanese seed is reproducible without a Japanese word list — and
//! it is a strictly better NFKD test than anything English can offer, because it exercises
//! normalization on *both* sides at once:
//!
//! * the **phrase** side, because Japanese phrases separate words with U+3000 IDEOGRAPHIC SPACE,
//!   which NFKD folds to U+0020 SPACE; and
//! * the **passphrase** side, because the passphrase leads with U+334D SQUARE MEETORU (`㍍`),
//!   a compatibility character NFKD expands to four ordinary katakana.

use forager_wallet::bip39::{self, Bip39Error, SEED_LEN};

/// Passphrase used by every row of the official `vectors.json`.
const TREZOR: &str = "TREZOR";

/// Decode a lowercase hex string. Local to the test so the KAT does not lean on crate internals.
fn unhex(s: &str) -> Vec<u8> {
    assert!(
        s.len().is_multiple_of(2),
        "hex string must have even length"
    );
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

/// Encode bytes as lowercase hex.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// All 24 English rows of the official `trezor/python-mnemonic` `vectors.json`, as
/// `(entropy hex, phrase, seed hex)`. The seed column assumes the passphrase `"TREZOR"`.
const ENGLISH_VECTORS: [(&str, &str, &str); 24] = [
    (
        "00000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
    ),
    (
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
    ),
    (
        "80808080808080808080808080808080",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
    ),
    (
        "ffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
    ),
    (
        "000000000000000000000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
        "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa",
    ),
    (
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
        "f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd",
    ),
    (
        "808080808080808080808080808080808080808080808080",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
        "107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc27fe913ffb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65",
    ),
    (
        "ffffffffffffffffffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
        "0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528",
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
    ),
    (
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
        "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87",
    ),
    (
        "8080808080808080808080808080808080808080808080808080808080808080",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
        "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f",
    ),
    (
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
        "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
    ),
    (
        "9e885d952ad362caeb4efe34a8e91bd2",
        "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
        "274ddc525802f7c828d8ef7ddbcdc5304e87ac3535913611fbbfa986d0c9e5476c91689f9c8a54fd55bd38606aa6a8595ad213d4c9c9f9aca3fb217069a41028",
    ),
    (
        "6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
        "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog",
        "628c3827a8823298ee685db84f55caa34b5cc195a778e52d45f59bcf75aba68e4d7590e101dc414bc1bbd5737666fbbef35d1f1903953b66624f910feef245ac",
    ),
    (
        "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
        "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
        "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440",
    ),
    (
        "c0ba5a8e914111210f2bd131f3d5e08d",
        "scheme spot photo card baby mountain device kick cradle pact join borrow",
        "ea725895aaae8d4c1cf682c1bfd2d358d52ed9f0f0591131b559e2724bb234fca05aa9c02c57407e04ee9dc3b454aa63fbff483a8b11de949624b9f1831a9612",
    ),
    (
        "6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3",
        "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave",
        "fd579828af3da1d32544ce4db5c73d53fc8acc4ddb1e3b251a31179cdb71e853c56d2fcb11aed39898ce6c34b10b5382772db8796e52837b54468aeb312cfc3d",
    ),
    (
        "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
        "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
        "72be8e052fc4919d2adf28d5306b5474b0069df35b02303de8c1729c9538dbb6fc2d731d5f832193cd9fb6aeecbc469594a70e3dd50811b5067f3b88b28c3e8d",
    ),
    (
        "23db8160a31d3e0dca3688ed941adbf3",
        "cat swing flag economy stadium alone churn speed unique patch report train",
        "deb5f45449e615feff5640f2e49f933ff51895de3b4381832b3139941c57b59205a42480c52175b6efcffaa58a2503887c1e8b363a707256bdd2b587b46541f5",
    ),
    (
        "8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0",
        "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access",
        "4cbdff1ca2db800fd61cae72a57475fdc6bab03e441fd63f96dabd1f183ef5b782925f00105f318309a7e9c3ea6967c7801e46c8a58082674c860a37b93eda02",
    ),
    (
        "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
        "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
        "26e975ec644423f4a4c4f4215ef09b4bd7ef924e85d1d17c4cf3f136c2863cf6df0a475045652c57eb5fb41513ca2a2d67722b77e954b4b3fc11f7590449191d",
    ),
    (
        "f30f8c1da665478f49b001d94c5fc452",
        "vessel ladder alter error federal sibling chat ability sun glass valve picture",
        "2aaa9242daafcee6aa9d7269f17d4efe271e1b9a529178d7dc139cd18747090bf9d60295d0ce74309a78852a9caadf0af48aae1c6253839624076224374bc63f",
    ),
    (
        "c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05",
        "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump",
        "7b4a10be9d98e6cba265566db7f136718e1398c71cb581e1b2f464cac1ceedf4f3e274dc270003c670ad8d02c4558b2f8e39edea2775c9e232c7cb798b069e88",
    ),
    (
        "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
        "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
        "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998",
    ),
];

// ---- The Japanese NFKD anchor (bip32JP/bip32JP.github.io, test_JP_BIP39.json row 0) ----

/// A 12-word Japanese phrase, U+3000-separated. NFKD folds U+3000 to U+0020.
const JP_PHRASE: &str = "\u{3042}\u{3044}\u{3053}\u{304f}\u{3057}\u{3093}\u{3000}\u{3042}\u{3044}\u{3053}\u{304f}\u{3057}\u{3093}\u{3000}\u{3042}\u{3044}\u{3053}\u{304f}\u{3057}\u{3093}\u{3000}\u{3042}\u{3044}\u{3053}\u{304f}\u{3057}\u{3093}\u{3000}\u{3042}\u{3044}\u{3053}\u{304f}\u{3057}\u{3093}\u{3000}\u{3042}\u{3044}\u{3053}\u{304f}\u{3057}\u{3093}\u{3000}\u{3042}\u{3044}\u{3053}\u{304f}\u{3057}\u{3093}\u{3000}\u{3042}\u{3044}\u{3053}\u{304f}\u{3057}\u{3093}\u{3000}\u{3042}\u{3044}\u{3053}\u{304f}\u{3057}\u{3093}\u{3000}\u{3042}\u{3044}\u{3053}\u{304f}\u{3057}\u{3093}\u{3000}\u{3042}\u{3044}\u{3053}\u{304f}\u{3057}\u{3093}\u{3000}\u{3042}\u{304a}\u{305e}\u{3089}";

/// The published non-ASCII passphrase for that row (`㍍ガバヴァぱばぐゞちぢ十人十色`).
const JP_PASSPHRASE: &str = "\u{334d}\u{30ac}\u{30d0}\u{30f4}\u{30a1}\u{3071}\u{3070}\u{3050}\u{309e}\u{3061}\u{3062}\u{5341}\u{4eba}\u{5341}\u{8272}";

/// The published seed for that (phrase, passphrase) pair.
const JP_SEED: &str = "a262d6fb6122ecf45be09c50492b31f92e9beb7d9a845987a02cefda57a15f9c467a17872029a9e92299b5cbdf306e3a0ee620245cbd508959b6cb7ca637bd55";

/// The same passphrase as `JP_PASSPHRASE`, reused for the English-phrase NFKD test below.
const NFKD_COMPOSED: &str = JP_PASSPHRASE;

/// Its NFKD normal form, written out literally: U+334D `㍍` expands to the four
/// katakana `メートル`, and each voiced kana splits into base + U+3099/U+309A.
/// Renders as `メートルガバヴァぱばぐゞちぢ十人十色`.
const NFKD_DECOMPOSED: &str = "\u{30e1}\u{30fc}\u{30c8}\u{30eb}\u{30ab}\u{3099}\u{30cf}\u{3099}\u{30a6}\u{3099}\u{30a1}\u{306f}\u{309a}\u{306f}\u{3099}\u{304f}\u{3099}\u{309d}\u{3099}\u{3061}\u{3061}\u{3099}\u{5341}\u{4eba}\u{5341}\u{8272}";

// ---------------------------------------------------------------------------
// The official English set, in both directions plus the seed.
// ---------------------------------------------------------------------------

/// entropy → phrase, for all 24 official rows.
#[test]
fn official_vectors_entropy_to_phrase() {
    for (entropy_hex, phrase, _) in ENGLISH_VECTORS {
        let got = bip39::entropy_to_phrase(&unhex(entropy_hex)).expect("official entropy length");
        assert_eq!(*got, phrase, "entropy {entropy_hex}");
    }
}

/// phrase → entropy, for all 24 official rows. This is the direction that was broken: the
/// delegated implementation could not parse any of the 12-word rows at all.
#[test]
fn official_vectors_phrase_to_entropy() {
    for (entropy_hex, phrase, _) in ENGLISH_VECTORS {
        let got = bip39::phrase_to_entropy(phrase).expect("official phrase must parse");
        assert_eq!(hex(&got), entropy_hex, "phrase {phrase}");
    }
}

/// phrase + `"TREZOR"` → seed, for all 24 official rows.
#[test]
fn official_vectors_phrase_to_seed() {
    for (_, phrase, seed_hex) in ENGLISH_VECTORS {
        let s = bip39::seed(phrase, TREZOR).expect("official phrase must parse");
        assert_eq!(hex(s.as_bytes()), seed_hex, "phrase {phrase}");
        assert_eq!(s.as_bytes().len(), SEED_LEN);
    }
}

/// The official set covers 12-, 18- and 24-word phrases. Assert that spread explicitly, so a
/// future edit that silently drops rows cannot shrink the coverage unnoticed.
#[test]
fn official_vectors_cover_the_expected_lengths() {
    assert_eq!(ENGLISH_VECTORS.len(), 24);
    let mut lengths: Vec<usize> = ENGLISH_VECTORS
        .iter()
        .map(|(_, p, _)| p.split_whitespace().count())
        .collect();
    lengths.sort_unstable();
    lengths.dedup();
    assert_eq!(lengths, vec![12, 18, 24]);
}

// ---------------------------------------------------------------------------
// The regression that started this work.
// ---------------------------------------------------------------------------

/// A valid 12-word phrase must validate.
///
/// This is the whole point of the exercise. `bip32 0.5.3`'s `Phrase::new` requires
/// `entropy.len() == KEY_SIZE + 1` with `KEY_SIZE == 32`, so it rejects every 128-bit phrase —
/// by far the most common length in circulation — and the caller then told the user their words,
/// length or checksum were wrong. They were not.
#[test]
fn twelve_word_phrase_is_accepted() {
    let phrase = ENGLISH_VECTORS[0].1;
    assert_eq!(phrase.split_whitespace().count(), 12);
    bip39::validate(phrase).expect("a valid 12-word phrase must validate");

    // And the delegated implementation really does reject it — pin that, so this test keeps
    // documenting *why* the module exists even after the integration lands.
    assert!(
        bip32::Mnemonic::new(phrase, Default::default()).is_err(),
        "if bip32 ever accepts 12-word phrases, this module's first reason to exist is gone"
    );
}

/// Every legal length round-trips entropy → phrase → entropy, including the 15- and 21-word
/// lengths the official file has no rows for.
#[test]
fn round_trip_every_legal_length() {
    for (i, &len) in bip39::ENTROPY_LENGTHS.iter().enumerate() {
        // A non-degenerate, deterministic entropy pattern: all-zero entropy would not notice a
        // bit-ordering error, since every 11-bit group would still be zero.
        let entropy: Vec<u8> = (0..len)
            .map(|b| (b as u8).wrapping_mul(37).wrapping_add(11))
            .collect();
        let phrase = bip39::entropy_to_phrase(&entropy).expect("legal entropy length");
        assert_eq!(
            phrase.split_whitespace().count(),
            bip39::WORD_COUNTS[i],
            "{len}-byte entropy must give {} words",
            bip39::WORD_COUNTS[i]
        );
        let back = bip39::phrase_to_entropy(&phrase).expect("our own phrase must parse");
        assert_eq!(*back, entropy, "{len}-byte round trip");
    }
}

// ---------------------------------------------------------------------------
// NFKD — defect 2.
// ---------------------------------------------------------------------------

/// The published Japanese vector, reproduced through the raw "mnemonic to seed" step.
///
/// This single assertion covers both halves of the NFKD requirement, and it is an *upstream*
/// answer, not one this crate computed:
///
/// * the phrase is separated by U+3000 IDEOGRAPHIC SPACE, which NFKD folds to U+0020, so a
///   missing phrase-side normalization changes the PBKDF2 password; and
/// * the passphrase begins with U+334D `㍍`, which NFKD expands to `メートル` (4 katakana), so a
///   missing passphrase-side normalization changes the PBKDF2 salt.
///
/// Remove either normalization and the seed no longer matches the published constant.
#[test]
fn japanese_vector_exercises_nfkd_on_both_sides() {
    let s = bip39::seed_unchecked(JP_PHRASE, JP_PASSPHRASE);
    assert_eq!(hex(s.as_bytes()), JP_SEED);
}

/// The passphrase-normalization path, exercised with an **English** phrase.
///
/// The construction, and why it is not circular:
///
/// The crate ships only English words, so a user hitting defect 2 in practice types an English
/// phrase and a non-ASCII `--passphrase`. There is no published vector for that combination — so
/// instead of inventing an expected seed, this test asserts the *property* the spec requires, and
/// it does so using two passphrase strings whose relationship is a fact about Unicode rather than
/// a fact about this crate:
///
/// * `NFKD_COMPOSED` is the passphrase from the published Japanese vector above, and
/// * `NFKD_DECOMPOSED` is its NFKD normal form, written out literally as escapes.
///
/// They are 45 and 78 UTF-8 bytes respectively — genuinely different byte strings, asserted below
/// so the test cannot pass by the two being accidentally equal. BIP-39 says the seed is a function
/// of `NFKD(passphrase)`, so the same English phrase under both must give the *same* seed.
///
/// This is falsifiable in exactly the way it should be: drop the `.nfkd()` call on the passphrase
/// and PBKDF2 sees two different salts, the seeds diverge, and this test fails.
#[test]
fn passphrase_is_nfkd_normalized_with_an_english_phrase() {
    // Sanity: the two forms really are different bytes, so the assertion below has content.
    assert_ne!(
        NFKD_COMPOSED.as_bytes(),
        NFKD_DECOMPOSED.as_bytes(),
        "the two passphrase forms must differ, or this test proves nothing"
    );
    assert_eq!(NFKD_COMPOSED.len(), 45);
    assert_eq!(NFKD_DECOMPOSED.len(), 78);

    let english = ENGLISH_VECTORS[0].1;
    let a = bip39::seed(english, NFKD_COMPOSED).expect("valid English phrase");
    let b = bip39::seed(english, NFKD_DECOMPOSED).expect("valid English phrase");
    assert_eq!(
        hex(a.as_bytes()),
        hex(b.as_bytes()),
        "a passphrase and its NFKD normal form must derive the same seed"
    );

    // And an ASCII passphrase must be unaffected by normalization (NFKD is the identity on
    // ASCII), so this change cannot have moved any existing address.
    let ascii = bip39::seed(english, TREZOR).expect("valid English phrase");
    assert_eq!(hex(ascii.as_bytes()), ENGLISH_VECTORS[0].2);
}

// ---------------------------------------------------------------------------
// Backward compatibility with the `bip32` seed this crate currently derives.
// ---------------------------------------------------------------------------

/// For a 24-word phrase — the only length `bip32` supports — our seed must equal `bip32`'s.
///
/// If these ever disagree, the follow-on integration is not a bug fix but a silent migration:
/// every HD address this tool has already printed would move. They must agree exactly.
#[test]
fn seed_matches_bip32_for_a_24_word_phrase() {
    for (_, phrase, _) in ENGLISH_VECTORS {
        if phrase.split_whitespace().count() != 24 {
            continue;
        }
        let theirs = bip32::Mnemonic::new(phrase, Default::default())
            .expect("bip32 parses 24-word phrases")
            .to_seed(TREZOR);
        let ours = bip39::seed(phrase, TREZOR).expect("valid phrase");
        assert_eq!(
            hex(ours.as_bytes()),
            hex(theirs.as_bytes()),
            "seed divergence on {phrase}"
        );
    }
}

/// The follow-on integration needs to hand our 64 bytes to `XPrv::derive_from_path`, which takes a
/// `bip32::Seed`. Confirm the seam exists and produces the same key as the delegated path.
#[test]
fn seed_bytes_construct_a_bip32_seed_and_derive_the_same_key() {
    use bip32::{DerivationPath, PrivateKey, XPrv};

    let phrase = ENGLISH_VECTORS[0].1; // 12 words — unsupported by bip32, supported by us
    let ours = bip39::seed(phrase, "").expect("valid 12-word phrase");

    // `Seed::new([u8; 64])` is public, so no rewiring of the derivation is needed.
    let seed = bip32::Seed::new(*ours.as_bytes());
    let path: DerivationPath = "m/44'/0'/0'/0/0".parse().expect("valid path");
    let xprv = XPrv::derive_from_path(&seed, &path).expect("derivation succeeds");
    let key: [u8; 32] = PrivateKey::to_bytes(xprv.private_key());
    assert_eq!(key.len(), 32);

    // And the same seam over a 24-word phrase must reproduce what the current delegated path
    // derives today, end to end.
    let phrase24 = ENGLISH_VECTORS
        .iter()
        .find(|(_, p, _)| p.split_whitespace().count() == 24)
        .expect("the official set has 24-word rows")
        .1;
    let theirs = bip32::Mnemonic::new(phrase24, Default::default())
        .expect("bip32 parses 24-word phrases")
        .to_seed(TREZOR);
    let mine = bip39::seed(phrase24, TREZOR).expect("valid phrase");
    let a = XPrv::derive_from_path(&theirs, &path).expect("derivation succeeds");
    let b = XPrv::derive_from_path(bip32::Seed::new(*mine.as_bytes()), &path)
        .expect("derivation succeeds");
    assert_eq!(
        PrivateKey::to_bytes(a.private_key()),
        PrivateKey::to_bytes(b.private_key()),
        "the seam must reproduce the existing derivation byte for byte"
    );
}

// ---------------------------------------------------------------------------
// Rejection cases — each asserting the *specific* error.
// ---------------------------------------------------------------------------

/// An unknown word names itself and its position, rather than blaming the whole phrase.
#[test]
fn unknown_word_is_named_with_its_position() {
    // Row 0 with the 3rd word replaced by something not in the list.
    let phrase = "abandon abandon zzzzzz abandon abandon abandon \
                  abandon abandon abandon abandon abandon about";
    assert_eq!(
        bip39::validate(phrase),
        Err(Bip39Error::UnknownWord {
            word: "zzzzzz".to_string(),
            position: 3,
        })
    );
    let msg = bip39::validate(phrase).unwrap_err().to_string();
    assert!(
        msg.contains("zzzzzz"),
        "the message must name the word: {msg}"
    );
    assert!(
        msg.contains('3'),
        "the message must give the position: {msg}"
    );
}

/// Mixed case is an unknown word, not a checksum failure. The BIP-39 list is lowercase, and
/// silently lowercasing would be a guess about what a *different* wallet did with the same input.
#[test]
fn mixed_case_reports_the_offending_word() {
    let phrase = "Abandon abandon abandon abandon abandon abandon \
                  abandon abandon abandon abandon abandon about";
    assert_eq!(
        bip39::validate(phrase),
        Err(Bip39Error::UnknownWord {
            word: "Abandon".to_string(),
            position: 1,
        })
    );
}

/// 11, 13 and 23 words are word-count errors, and the message lists the legal counts.
#[test]
fn illegal_word_counts_are_reported_as_such() {
    for count in [11usize, 13, 23] {
        let phrase = vec!["abandon"; count].join(" ");
        assert_eq!(
            bip39::validate(&phrase),
            Err(Bip39Error::WordCount { found: count }),
            "{count} words"
        );
        let msg = bip39::validate(&phrase).unwrap_err().to_string();
        for legal in ["12", "15", "18", "21", "24"] {
            assert!(msg.contains(legal), "message must list {legal}: {msg}");
        }
    }
}

/// All words valid, checksum wrong — reported as a checksum failure, not an unknown word.
#[test]
fn corrupted_checksum_is_reported_as_a_checksum_failure() {
    // Row 0 is "abandon ×11 about". "abandon" in the last slot keeps every word legal but breaks
    // the trailing checksum bits.
    let phrase = "abandon abandon abandon abandon abandon abandon \
                  abandon abandon abandon abandon abandon abandon";
    assert_eq!(bip39::validate(phrase), Err(Bip39Error::Checksum));

    // Same for a 24-word row with two words transposed: every word is in the list, but the
    // checksum no longer matches. Row 9 is "legal winner thank year …" — the first two words
    // differ, which row 8 ("abandon abandon …") does not, so the swap is a real change.
    let mut words: Vec<&str> = ENGLISH_VECTORS[9].1.split_whitespace().collect();
    assert_eq!(words.len(), 24);
    assert_ne!(
        words[0], words[1],
        "the swap must actually change the phrase"
    );
    words.swap(0, 1);
    let swapped = words.join(" ");
    assert_eq!(bip39::validate(&swapped), Err(Bip39Error::Checksum));
}

/// The empty string is a zero-word phrase, reported as a word-count error.
#[test]
fn empty_phrase_is_a_word_count_error() {
    assert_eq!(bip39::validate(""), Err(Bip39Error::WordCount { found: 0 }));
    assert_eq!(
        bip39::validate("   \t\n  "),
        Err(Bip39Error::WordCount { found: 0 })
    );
}

/// Entropy of an unsupported length is rejected by name.
#[test]
fn illegal_entropy_lengths_are_rejected() {
    for len in [0usize, 15, 17, 31, 33, 64] {
        assert_eq!(
            bip39::entropy_to_phrase(&vec![0u8; len]),
            Err(Bip39Error::EntropyLength { found: len }),
            "{len} bytes"
        );
    }
}

/// Surrounding and repeated whitespace is *tolerated*, and — critically — cannot change the seed.
///
/// This deliberately does not reject. Rejecting a phrase that a user pasted with a stray double
/// space would reproduce, in a new form, the exact failure this module exists to fix: telling
/// someone their valid phrase is invalid. What must not happen is the looser input silently
/// producing a *different* seed, so the phrase is canonicalized to single-space-separated words
/// before PBKDF2 — and that is what is asserted here.
#[test]
fn extra_whitespace_is_tolerated_and_does_not_change_the_seed() {
    let (entropy_hex, canonical, seed_hex) = ENGLISH_VECTORS[0];
    let messy = format!("  {}  ", canonical.replace(' ', "   \t "));
    assert_ne!(messy, canonical);

    assert_eq!(hex(&bip39::phrase_to_entropy(&messy).unwrap()), entropy_hex);
    let s = bip39::seed(&messy, TREZOR).expect("valid phrase with sloppy spacing");
    assert_eq!(
        hex(s.as_bytes()),
        seed_hex,
        "sloppy spacing must not move the seed"
    );
}

/// A phrase that differs only in passphrase must give a different seed — the passphrase is
/// actually reaching PBKDF2's salt.
#[test]
fn passphrase_changes_the_seed() {
    let phrase = ENGLISH_VECTORS[0].1;
    let none = bip39::seed(phrase, "").unwrap();
    let some = bip39::seed(phrase, TREZOR).unwrap();
    assert_ne!(hex(none.as_bytes()), hex(some.as_bytes()));
    assert_eq!(hex(some.as_bytes()), ENGLISH_VECTORS[0].2);
}

/// The `Debug` impl must not leak the seed.
#[test]
fn seed_debug_is_redacted() {
    let s = bip39::seed(ENGLISH_VECTORS[0].1, TREZOR).unwrap();
    let rendered = format!("{s:?}");
    assert!(rendered.contains("redacted"), "{rendered}");
    assert!(!rendered.contains(&hex(s.as_bytes())[..16]), "{rendered}");
}
