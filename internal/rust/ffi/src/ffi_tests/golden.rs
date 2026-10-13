//! Golden (wire and storage format) compatibility tests for the DKLs23 C ABI.
//!
//! The fixtures in `testdata/golden/` were produced once by this crate and
//! committed. They stand in for keyshares and protocol messages that users
//! already persisted or have in flight. If a dependency bump (serde, k256,
//! sl-mpc-mate, ...) changes the JSON format, these tests fail instead of
//! the change silently orphaning stored keyshares.
//!
//! The fixtures are never rewritten implicitly. To regenerate them after an
//! intentional, reviewed format change:
//!
//! ```sh
//! cd internal/rust
//! UPDATE_GOLDEN=1 cargo test --locked --release -p dkls23-ffi golden
//! ```
//!
//! Regenerating breaks compatibility with every keyshare produced by the
//! previous format, so it needs a migration path and a release note.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;

use dkls23_ll::dkg::{
    KeygenMsg1, KeygenMsg2, KeygenMsg3, KeygenMsg4, Keyshare,
};
use dkls23_ll::dsg::{
    PartialSignature, SignMsg1, SignMsg2, SignMsg3, SignMsg4,
};
use serde_json::Value;

use super::common::*;
use crate::*;

/// Non-hardened: DKLs23 keyshares only support public (non-hardened) BIP32
/// derivation.
const DERIVATION_PATH: &str = "m/44/60/0/0/0";
const SIGNED_MESSAGE: &[u8] = b"golden fixture: transfer 1 ETH";

/// Each keyshare set: (name, file prefix, rank list, threshold).
const SETS: [(&str, &str, [u8; 3]); 2] = [
    ("2of3", "keyshare_2of3", [0, 0, 0]),
    ("ranked", "keyshare_ranked", [0, 1, 1]),
];
const THRESHOLD: u8 = 2;

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/golden")
}

fn updating() -> bool {
    std::env::var_os("UPDATE_GOLDEN").is_some_and(|v| v == "1")
}

/// Regenerate the fixtures once per test binary when `UPDATE_GOLDEN=1`.
fn ensure_fixtures() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        if updating() {
            generate();
        }
    });
}

fn read(name: &str) -> String {
    ensure_fixtures();
    let path = golden_dir().join(name);
    let raw = fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "missing golden fixture {}: {e}. Fixtures are committed; \
             regenerate only deliberately with UPDATE_GOLDEN=1 (see the \
             module docs)",
            path.display()
        )
    });
    raw.trim_end().to_owned()
}

fn write(name: &str, contents: &str) {
    let path = golden_dir().join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, format!("{contents}\n")).unwrap();
}

fn expected() -> Value {
    json(&read("expected.json"))
}

fn keyshare_file(prefix: &str, party: usize) -> String {
    format!("{prefix}_party{party}.json")
}

fn keyshares(prefix: &str) -> Vec<String> {
    (0..3).map(|i| read(&keyshare_file(prefix, i))).collect()
}

fn hex32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}

// -------------------- Generation (UPDATE_GOLDEN=1 only) --------------------

fn generate() {
    let mut sets = serde_json::Map::new();

    // 2-of-3 DKG, capturing one example of every message type.
    let parties = dkg_parties(3, 2);
    let msg1_raw: Vec<String> = parties
        .iter()
        .map(|p| ok(unsafe { dkls23_dkg_generate_msg1(p.0) }))
        .collect();
    let msg1: Vec<Value> = msg1_raw.iter().map(|s| json(s)).collect();

    let mut msg2_raw = Vec::new();
    for (i, p) in parties.iter().enumerate() {
        let others = to_c(&excluding(&msg1, i as u64));
        msg2_raw.push(ok(unsafe {
            dkls23_dkg_handle_msg1(p.0, others.as_ptr())
        }));
    }
    let msg2: Vec<Value> = msg2_raw.iter().flat_map(|s| array(s)).collect();

    let mut msg3_raw = Vec::new();
    for (i, p) in parties.iter().enumerate() {
        let mine = to_c(&select(&msg2, "to_id", i as u64));
        msg3_raw
            .push(ok(unsafe { dkls23_dkg_handle_msg2(p.0, mine.as_ptr()) }));
    }
    let msg3: Vec<Value> = msg3_raw.iter().flat_map(|s| array(s)).collect();

    let commitments: Vec<Value> = parties
        .iter()
        .map(|p| {
            Value::String(ok(unsafe {
                dkls23_dkg_calculate_commitment_2(p.0)
            }))
        })
        .collect();
    let commitments_c = to_c(&commitments);

    let mut msg4_raw = Vec::new();
    for (i, p) in parties.iter().enumerate() {
        let mine = to_c(&select(&msg3, "to_id", i as u64));
        msg4_raw.push(ok(unsafe {
            dkls23_dkg_handle_msg3(p.0, mine.as_ptr(), commitments_c.as_ptr())
        }));
    }
    let msg4: Vec<Value> = msg4_raw.iter().map(|s| json(s)).collect();

    let ks_2of3: Vec<String> = parties
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let others = to_c(&excluding(&msg4, i as u64));
            ok(unsafe { dkls23_dkg_handle_msg4(p.0, others.as_ptr()) })
        })
        .collect();

    write("messages/dkg_msg1.json", &msg1_raw[0]);
    write("messages/dkg_msg2.json", &msg2_raw[0]);
    write("messages/dkg_msg3.json", &msg3_raw[0]);
    write(
        "messages/dkg_commitments.json",
        &serde_json::to_string(&commitments).unwrap(),
    );
    write("messages/dkg_msg4.json", &msg4_raw[0]);

    let ks_ranked = run_dkg(&ranked_parties(&SETS[1].2, THRESHOLD as usize));

    for ((name, prefix, ranks), shares) in
        SETS.iter().zip([&ks_2of3, &ks_ranked])
    {
        let files: Vec<String> =
            (0..3).map(|i| keyshare_file(prefix, i)).collect();
        for (file, ks) in files.iter().zip(shares.iter()) {
            write(file, ks);
        }
        sets.insert(
            name.to_string(),
            serde_json::json!({
                "files": files,
                "threshold": THRESHOLD,
                "rank_list": ranks,
                "public_key": derive_public_key(&shares[0], "m"),
                "derived_public_key": derive_public_key(&shares[0], DERIVATION_PATH),
            }),
        );
    }

    // One signing session with parties 0 and 1 of the 2-of-3 set, capturing
    // party 0's messages and both partial signature responses.
    let hash = sha256(SIGNED_MESSAGE);
    let states = [dsg_init(&ks_2of3[0], "m"), dsg_init(&ks_2of3[1], "m")];
    let s1_raw: Vec<String> = states
        .iter()
        .map(|s| ok(unsafe { dkls23_dsg_generate_msg1(s.0) }))
        .collect();
    let s1: Vec<Value> = s1_raw.iter().map(|s| json(s)).collect();
    let mut s2_raw = Vec::new();
    for (i, s) in states.iter().enumerate() {
        let others = to_c(&excluding(&s1, i as u64));
        s2_raw.push(ok(unsafe {
            dkls23_dsg_handle_msg1(s.0, others.as_ptr())
        }));
    }
    let s2: Vec<Value> = s2_raw.iter().flat_map(|s| array(s)).collect();
    let mut s3_raw = Vec::new();
    for (i, s) in states.iter().enumerate() {
        let mine = to_c(&select(&s2, "to_id", i as u64));
        s3_raw
            .push(ok(unsafe { dkls23_dsg_handle_msg2(s.0, mine.as_ptr()) }));
    }
    let s3: Vec<Value> = s3_raw.iter().flat_map(|s| array(s)).collect();
    let partials_raw: Vec<String> = states
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let mine = to_c(&select(&s3, "to_id", i as u64));
            let handle = cstr(&ok(unsafe {
                dkls23_dsg_handle_msg3(s.0, mine.as_ptr())
            }));
            ok(unsafe {
                dkls23_create_partial_signature(
                    handle.as_ptr(),
                    hash.as_ptr(),
                )
            })
        })
        .collect();
    let partials: Vec<Value> = partials_raw.iter().map(|s| json(s)).collect();
    let signature = ok(combine(&partials[0], &partials[1..]));
    let public_key = derive_public_key(&ks_2of3[0], "m");
    assert!(verify(&public_key, &hash, &signature));

    write("messages/sign_msg1.json", &s1_raw[0]);
    write("messages/sign_msg2.json", &s2_raw[0]);
    write("messages/sign_msg3.json", &s3_raw[0]);
    write("messages/partial_signature_party0.json", &partials_raw[0]);
    write("messages/partial_signature_party1.json", &partials_raw[1]);

    let expected = serde_json::json!({
        "_note": "Generated by dkls23-ffi golden.rs with UPDATE_GOLDEN=1. \
                  Throwaway test keys; see README.md.",
        "derivation_path": DERIVATION_PATH,
        "sets": sets,
        "signing": {
            "keyshare_set": "2of3",
            "signers": [0, 1],
            "derivation_path": "m",
            "message_hash": hex::encode(hash),
            "partials": [
                "messages/partial_signature_party0.json",
                "messages/partial_signature_party1.json",
            ],
            "signature": signature,
        },
    });
    write(
        "expected.json",
        &serde_json::to_string_pretty(&expected).unwrap(),
    );
}

// -------------------- Assertion helpers --------------------

/// First JSON pointer at which `a` and `b` differ, if any.
fn first_diff(a: &Value, b: &Value, at: &str) -> Option<String> {
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            let keys: BTreeSet<&String> = x.keys().chain(y.keys()).collect();
            keys.into_iter().find_map(|k| match (x.get(k), y.get(k)) {
                (Some(p), Some(q)) => first_diff(p, q, &format!("{at}/{k}")),
                (p, _) => Some(format!(
                    "{at}/{k} only in {}",
                    if p.is_some() { "actual" } else { "fixture" }
                )),
            })
        }
        (Value::Array(x), Value::Array(y)) if x.len() == y.len() => {
            x.iter().zip(y).enumerate().find_map(|(i, (p, q))| {
                first_diff(p, q, &format!("{at}/{i}"))
            })
        }
        _ if a == b => None,
        _ => Some(format!("{at}: actual {a} != fixture {b}")),
    }
}

fn assert_json_eq(what: &str, actual: &Value, fixture: &Value) {
    if let Some(diff) = first_diff(actual, fixture, "") {
        panic!("{what}: re-serialized JSON differs from the golden fixture at {diff}");
    }
}

/// Parse a fixture with the type the FFI uses and check that the current
/// code writes it back identically (modulo object key order). A macro, as
/// this crate has no direct `serde` dependency to name the trait bounds.
macro_rules! assert_roundtrip {
    ($ty:ty, $name:expr) => {{
        let name: &str = $name;
        let raw = read(name);
        let parsed: $ty = serde_json::from_str(&raw).unwrap_or_else(|e| {
            panic!("{name} no longer parses with the current types: {e}")
        });
        let actual = serde_json::to_value(&parsed).unwrap();
        assert_json_eq(name, &actual, &json(&raw));
    }};
}

fn kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

// -------------------- Tests --------------------

/// Top-level keyshare fields and their JSON types. Adding, removing or
/// renaming a field changes the stored format and must fail here.
const KEYSHARE_FIELDS: [(&str, &str); 14] = [
    ("total_parties", "number"),
    ("threshold", "number"),
    ("rank_list", "array"),
    ("party_id", "number"),
    ("public_key", "string"),
    ("root_chain_code", "array"),
    ("final_session_id", "array"),
    ("seed_ot_receivers", "array"),
    ("seed_ot_senders", "array"),
    ("sent_seed_list", "array"),
    ("rec_seed_list", "array"),
    ("s_i", "string"),
    ("big_s_list", "array"),
    ("x_i_list", "array"),
];

#[test]
fn golden_keyshare_json_shape() {
    for (_, prefix, ranks) in SETS {
        for (i, raw) in keyshares(prefix).iter().enumerate() {
            let file = keyshare_file(prefix, i);
            let ks = json(raw);
            let obj = ks.as_object().unwrap_or_else(|| {
                panic!("{file}: keyshare is not a JSON object")
            });
            for (key, want) in KEYSHARE_FIELDS {
                let got = obj.get(key).unwrap_or_else(|| {
                    panic!("{file}: keyshare field {key:?} is missing")
                });
                assert_eq!(kind(got), want, "{file}: field {key:?} type");
            }
            let known: BTreeSet<&str> =
                KEYSHARE_FIELDS.iter().map(|(k, _)| *k).collect();
            for key in obj.keys() {
                assert!(
                    known.contains(key.as_str()),
                    "{file}: unexpected keyshare field {key:?}"
                );
            }
            assert_eq!(ks["party_id"], i as u64, "{file}");
            assert_eq!(ks["threshold"], THRESHOLD, "{file}");
            assert_eq!(ks["total_parties"], 3, "{file}");
            assert_eq!(ks["rank_list"], serde_json::json!(ranks), "{file}");
            // Compressed SEC1 point as hex; byte arrays as JSON arrays.
            let pk = ks["public_key"].as_str().unwrap();
            assert_eq!(hex::decode(pk).unwrap().len(), 33, "{file}");
            for key in ["root_chain_code", "final_session_id"] {
                let bytes = ks[key].as_array().unwrap();
                assert_eq!(bytes.len(), 32, "{file}: {key} length");
                assert!(
                    bytes.iter().all(|b| b.as_u64().is_some_and(|b| b < 256)),
                    "{file}: {key} must be an array of bytes"
                );
            }
        }
    }
}

#[test]
fn golden_keyshares_roundtrip() {
    for (_, prefix, _) in SETS {
        for i in 0..3 {
            let file = keyshare_file(prefix, i);
            assert_roundtrip!(Keyshare, &file);

            // Same through the C ABI: deriving at the root path re-serializes
            // the keyshare unchanged.
            let raw = read(&file);
            let (ks, path) = (cstr(&raw), cstr("m"));
            let out = ok(unsafe {
                dkls23_derive_keyshare(ks.as_ptr(), path.as_ptr())
            });
            assert_json_eq(&file, &json(&out), &json(&raw));
        }
    }
}

#[test]
fn golden_keyshares_derive_stored_public_keys() {
    let expected = expected();
    let path = expected["derivation_path"].as_str().unwrap();
    for (name, prefix, _) in SETS {
        let set = &expected["sets"][name];
        for (i, ks) in keyshares(prefix).iter().enumerate() {
            assert_eq!(
                derive_public_key(ks, "m"),
                set["public_key"].as_str().unwrap(),
                "{name} party {i}: root public key changed"
            );
            assert_eq!(
                derive_public_key(ks, path),
                set["derived_public_key"].as_str().unwrap(),
                "{name} party {i}: public key at {path} changed"
            );
        }
    }
}

#[test]
fn golden_keyshares_reject_hardened_derivation() {
    let ks = cstr(&read(&keyshare_file("keyshare_2of3", 0)));
    let path = cstr("m/44'/60'/0'/0/0");
    expect_err(
        unsafe { dkls23_derive_public_key(ks.as_ptr(), path.as_ptr()) },
        "Hardened",
    );
}

#[test]
fn golden_keyshares_sign_for_every_valid_signer_set() {
    let expected = expected();
    let path = expected["derivation_path"].as_str().unwrap();
    // Signing takes exactly `threshold` parties. For ranks [0, 1, 1] the
    // pair {1, 2} cannot interpolate (checked separately below).
    let signer_sets: [(&str, &str, &[[usize; 2]]); 2] = [
        ("2of3", "keyshare_2of3", &[[0, 1], [0, 2], [1, 2]]),
        ("ranked", "keyshare_ranked", &[[0, 1], [0, 2]]),
    ];
    for (name, prefix, pairs) in signer_sets {
        let shares = keyshares(prefix);
        let set = &expected["sets"][name];
        for pair in pairs {
            let signers: Vec<&str> =
                pair.iter().map(|&i| shares[i].as_str()).collect();
            for (p, key) in
                [("m", "public_key"), (path, "derived_public_key")]
            {
                let pubkey = set[key].as_str().unwrap();
                let hash =
                    sha256(format!("golden {name} {pair:?} {p}").as_bytes());
                let sig = sign(&signers, p, &hash);
                assert!(
                    verify(pubkey, &hash, &sig),
                    "{name} signers {pair:?} at {p}: signature does not \
                     verify against the stored public key"
                );
            }
        }
    }
}

#[test]
fn golden_ranked_keyshares_reject_unqualified_signers() {
    let shares = keyshares("keyshare_ranked");
    let states = [dsg_init(&shares[1], "m"), dsg_init(&shares[2], "m")];
    let msg1: Vec<Value> = states
        .iter()
        .map(|s| json(&ok(unsafe { dkls23_dsg_generate_msg1(s.0) })))
        .collect();
    let others = to_c(&excluding(&msg1, 1));
    expect_err(
        unsafe { dkls23_dsg_handle_msg1(states[0].0, others.as_ptr()) },
        "cannot reconstruct",
    );
}

#[test]
fn golden_dkg_messages_roundtrip() {
    assert_roundtrip!(KeygenMsg1, "messages/dkg_msg1.json");
    assert_roundtrip!(Vec<KeygenMsg2>, "messages/dkg_msg2.json");
    assert_roundtrip!(Vec<KeygenMsg3>, "messages/dkg_msg3.json");
    assert_roundtrip!(KeygenMsg4, "messages/dkg_msg4.json");

    // Commitments travel as a JSON array of 32-byte hex strings.
    let commitments: Vec<String> =
        serde_json::from_str(&read("messages/dkg_commitments.json")).unwrap();
    assert_eq!(commitments.len(), 3);
    for c in &commitments {
        assert_eq!(hex::decode(c).unwrap().len(), 32, "commitment {c}");
    }

    // Field-level addressing the transports route on.
    let m1 = json(&read("messages/dkg_msg1.json"));
    assert_eq!(id(&m1, "from_id"), 0);
    for name in ["messages/dkg_msg2.json", "messages/dkg_msg3.json"] {
        let msgs = array(&read(name));
        assert_eq!(msgs.len(), 2, "{name}");
        for m in &msgs {
            assert_eq!(id(m, "from_id"), 0, "{name}");
            assert_ne!(id(m, "to_id"), 0, "{name}");
        }
    }
    assert_eq!(id(&json(&read("messages/dkg_msg4.json")), "from_id"), 0);
}

#[test]
fn golden_signing_messages_roundtrip() {
    assert_roundtrip!(SignMsg1, "messages/sign_msg1.json");
    assert_roundtrip!(Vec<SignMsg2>, "messages/sign_msg2.json");
    assert_roundtrip!(Vec<SignMsg3>, "messages/sign_msg3.json");

    for party in 0..2u64 {
        let name = format!("messages/partial_signature_party{party}.json");
        let raw = json(&read(&name));
        let obj = raw.as_object().unwrap();
        let keys: BTreeSet<&str> = obj.keys().map(String::as_str).collect();
        assert_eq!(keys, BTreeSet::from(["partial", "msg4"]), "{name}");

        let partial: PartialSignature = serde_json::from_value(
            raw["partial"].clone(),
        )
        .unwrap_or_else(|e| panic!("{name}: partial no longer parses: {e}"));
        assert_json_eq(
            &format!("{name}#partial"),
            &serde_json::to_value(&partial).unwrap(),
            &raw["partial"],
        );
        let msg4: SignMsg4 = serde_json::from_value(raw["msg4"].clone())
            .unwrap_or_else(|e| panic!("{name}: msg4 no longer parses: {e}"));
        assert_json_eq(
            &format!("{name}#msg4"),
            &serde_json::to_value(&msg4).unwrap(),
            &raw["msg4"],
        );
        assert_eq!(id(&raw["msg4"], "from_id"), party, "{name}");
    }
}

#[test]
fn golden_partials_combine_to_stored_signature() {
    let expected = expected();
    let signing = &expected["signing"];
    let hash = hex32(signing["message_hash"].as_str().unwrap());
    let stored_sig = signing["signature"].as_str().unwrap();
    let pubkey = expected["sets"]["2of3"]["public_key"].as_str().unwrap();
    assert!(verify(pubkey, &hash, stored_sig));

    let partials: Vec<Value> = signing["partials"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| json(&read(f.as_str().unwrap())))
        .collect();
    // Combining is deterministic, so each side must reproduce the stored
    // signature exactly from the stored partials.
    for i in 0..partials.len() {
        let others: Vec<Value> = partials
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, p)| p.clone())
            .collect();
        let sig = ok(combine(&partials[i], &others));
        assert_eq!(sig, stored_sig, "combined by party {i}");
    }
}
