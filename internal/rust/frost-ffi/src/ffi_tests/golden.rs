//! Golden (wire and storage format) compatibility tests for the FROST C ABI.
//!
//! The fixtures in `testdata/golden/` were produced once by this crate and
//! committed. They stand in for keyshares and protocol messages that users
//! already persisted or have in flight. If a dependency bump (serde,
//! frost-ed25519, ...) changes the JSON format, these tests fail instead of
//! the change silently orphaning stored keyshares.
//!
//! The fixtures are never rewritten implicitly. To regenerate them after an
//! intentional, reviewed format change:
//!
//! ```sh
//! cd internal/rust
//! UPDATE_GOLDEN=1 cargo test --locked --release -p frost-ffi golden
//! ```
//!
//! Regenerating breaks compatibility with every keyshare produced by the
//! previous format, so it needs a migration path and a release note.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::common::*;
use crate::*;

/// Rejected by the FFI (SLIP-10 is not implemented) but recorded so that a
/// future implementation shows up as a deliberate format change.
const DERIVATION_PATH: &str = "m/44'/501'/0'/0'";
const SIGNED_MESSAGE: &[u8] = b"golden fixture: transfer 1 SOL";
const KEYSHARE_PREFIX: &str = "keyshare_2of3";

/// Mirror of the signing round 1 output (`CommitOut` / `CommitIn` are local
/// to the FFI functions).
#[derive(Serialize, Deserialize)]
struct Commitment {
    from: u16,
    commitments: round1::SigningCommitments,
}

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

/// Party ids are one-based.
fn keyshare_file(party: u64) -> String {
    format!("{KEYSHARE_PREFIX}_party{party}.json")
}

/// Keyshares for parties 1..=3, in order.
fn keyshares() -> Vec<String> {
    (1..=3).map(|p| read(&keyshare_file(p))).collect()
}

fn bundle_file(party: u64) -> String {
    format!("messages/signature_share_party{party}.json")
}

// -------------------- Generation (UPDATE_GOLDEN=1 only) --------------------

fn generate() {
    let parties = dkg_parties(3, 2);
    let msg1_raw: Vec<String> = parties
        .iter()
        .map(|p| ok(unsafe { frost_dkg_generate_msg1(p.ptr) }))
        .collect();
    let msg1: Vec<Value> = msg1_raw.iter().map(|s| json(s)).collect();
    let msg2_raw: Vec<String> = parties
        .iter()
        .map(|p| {
            let others = to_c(&excluding(&msg1, p.id));
            ok(unsafe { frost_dkg_handle_msg1(p.ptr, others.as_ptr()) })
        })
        .collect();
    let msg2: Vec<Value> = msg2_raw.iter().flat_map(|s| array(s)).collect();
    let shares: Vec<String> = parties
        .iter()
        .map(|p| {
            let mine = to_c(&addressed_to(&msg2, p.id));
            ok(unsafe { frost_dkg_handle_msg2(p.ptr, mine.as_ptr()) })
        })
        .collect();

    write("messages/dkg_msg1.json", &msg1_raw[0]);
    write("messages/dkg_msg2.json", &msg2_raw[0]);
    for (p, ks) in parties.iter().zip(&shares) {
        write(&keyshare_file(p.id), ks);
    }

    // One signing session with parties 1 and 2, capturing party 1's
    // commitments and both signature share bundles.
    let signers: Vec<Signer> = shares[..2]
        .iter()
        .map(|ks| signer(ks, SIGNED_MESSAGE))
        .collect();
    let commit_raw: Vec<String> = signers
        .iter()
        .map(|s| ok(unsafe { frost_signing_generate_msg1(s.ptr) }))
        .collect();
    let commits: Vec<Value> = commit_raw.iter().map(|s| json(s)).collect();
    let bundles_raw: Vec<String> = signers
        .iter()
        .map(|s| {
            let others = to_c(&excluding(&commits, s.id));
            ok(unsafe { frost_signing_handle_msg1(s.ptr, others.as_ptr()) })
        })
        .collect();
    let bundles: Vec<Value> = bundles_raw.iter().map(|s| json(s)).collect();
    let signature = ok(combine(&bundles[0], &bundles[1..]));
    let public_key = public_key_hex(&shares[0]);
    assert!(verify(&public_key, SIGNED_MESSAGE, &signature));

    write("messages/sign_msg1.json", &commit_raw[0]);
    for (s, raw) in signers.iter().zip(&bundles_raw) {
        write(&bundle_file(s.id), raw);
    }

    let ks = cstr(&shares[0]);
    let path = cstr("m");
    let derived =
        ok(unsafe { frost_derive_public_key(ks.as_ptr(), path.as_ptr()) });
    let expected = serde_json::json!({
        "_note": "Generated by frost-ffi golden.rs with UPDATE_GOLDEN=1. \
                  Throwaway test keys; see README.md.",
        "keyshares": (1..=3).map(keyshare_file).collect::<Vec<_>>(),
        "min_signers": 2,
        "max_signers": 3,
        "public_key": public_key,
        "derivation_path": DERIVATION_PATH,
        "derived_public_key": json(&derived)["derived_public_key"],
        "signing": {
            "signers": [1, 2],
            "message_hex": hex::encode(SIGNED_MESSAGE),
            "bundles": [bundle_file(1), bundle_file(2)],
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
        panic!(
            "{what}: re-serialized JSON differs from the golden fixture at \
             {diff}"
        );
    }
}

/// Parse a fixture with the type the FFI uses and check that the current
/// code writes it back identically (modulo object key order).
fn assert_roundtrip<T: Serialize + DeserializeOwned>(name: &str) -> T {
    let raw = read(name);
    let parsed: T = serde_json::from_str(&raw).unwrap_or_else(|e| {
        panic!("{name} no longer parses with the current types: {e}")
    });
    let actual = serde_json::to_value(&parsed).unwrap();
    assert_json_eq(name, &actual, &json(&raw));
    parsed
}

/// Assert `v` is an object with exactly `keys`.
fn assert_keys(what: &str, v: &Value, keys: &[&str]) {
    let obj = v
        .as_object()
        .unwrap_or_else(|| panic!("{what}: expected a JSON object, got {v}"));
    let got: BTreeSet<&str> = obj.keys().map(String::as_str).collect();
    let want: BTreeSet<&str> = keys.iter().copied().collect();
    let missing: Vec<_> = want.difference(&got).collect();
    let extra: Vec<_> = got.difference(&want).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "{what}: missing fields {missing:?}, unexpected fields {extra:?}"
    );
}

fn assert_hex(what: &str, v: &Value, bytes: usize) {
    let s = v
        .as_str()
        .unwrap_or_else(|| panic!("{what}: expected a hex string, got {v}"));
    let decoded = hex::decode(s)
        .unwrap_or_else(|e| panic!("{what}: not hex ({e}): {s}"));
    assert_eq!(decoded.len(), bytes, "{what}: byte length");
}

/// The `frost-core` serialization header carried by every package.
fn assert_header(what: &str, v: &Value) {
    assert_keys(what, v, &["version", "ciphersuite"]);
    assert_eq!(v["version"], 0, "{what}: header version");
    assert_eq!(
        v["ciphersuite"], "FROST-ED25519-SHA512-v1",
        "{what}: ciphersuite"
    );
}

// -------------------- Tests --------------------

#[test]
fn golden_keyshare_json_shape() {
    let expected = expected();
    let public_key = &expected["public_key"];
    for (i, raw) in keyshares().iter().enumerate() {
        let file = keyshare_file(i as u64 + 1);
        let ks = json(raw);
        assert_keys(
            &file,
            &ks,
            &["participant_id", "key_package", "pubkey_package"],
        );
        assert_eq!(ks["participant_id"], i as u64 + 1, "{file}");

        let kp = &ks["key_package"];
        let what = format!("{file}: key_package");
        assert_keys(
            &what,
            kp,
            &[
                "header",
                "identifier",
                "signing_share",
                "verifying_share",
                "verifying_key",
                "min_signers",
            ],
        );
        assert_header(&format!("{what}.header"), &kp["header"]);
        assert_hex(&format!("{what}.identifier"), &kp["identifier"], 32);
        assert_hex(
            &format!("{what}.signing_share"),
            &kp["signing_share"],
            32,
        );
        assert_hex(
            &format!("{what}.verifying_share"),
            &kp["verifying_share"],
            32,
        );
        assert_eq!(&kp["verifying_key"], public_key, "{what}.verifying_key");
        assert_eq!(kp["min_signers"], 2, "{what}.min_signers");

        let pp = &ks["pubkey_package"];
        let what = format!("{file}: pubkey_package");
        assert_keys(
            &what,
            pp,
            &["header", "verifying_shares", "verifying_key"],
        );
        assert_header(&format!("{what}.header"), &pp["header"]);
        assert_eq!(&pp["verifying_key"], public_key, "{what}.verifying_key");
        let shares =
            pp["verifying_shares"].as_object().unwrap_or_else(|| {
                panic!("{what}.verifying_shares: expected an object")
            });
        assert_eq!(shares.len(), 3, "{what}.verifying_shares");
        for (id, share) in shares {
            assert_eq!(hex::decode(id).unwrap().len(), 32, "{what}: id {id}");
            assert_hex(&format!("{what}.verifying_shares.{id}"), share, 32);
        }
        assert_eq!(
            shares[kp["identifier"].as_str().unwrap()],
            kp["verifying_share"],
            "{file}: own verifying share"
        );
    }
}

#[test]
fn golden_keyshares_roundtrip() {
    for p in 1..=3 {
        let file = keyshare_file(p);
        let ks: Keyshare = assert_roundtrip(&file);
        assert_eq!(u64::from(ks.participant_id), p, "{file}");

        // Same through the C ABI: frost_derive_keyshare re-serializes.
        let raw = read(&file);
        let (c_ks, path) = (cstr(&raw), cstr("m"));
        let out = ok(unsafe {
            frost_derive_keyshare(c_ks.as_ptr(), path.as_ptr())
        });
        assert_json_eq(&file, &json(&out), &json(&raw));
    }
}

#[test]
fn golden_keyshares_report_stored_public_key() {
    let expected = expected();
    let public_key = expected["public_key"].as_str().unwrap();
    // The recorded child path is rejected now that non-root paths are no
    // longer silently ignored; the root path still reports the stored key.
    let child = cstr(expected["derivation_path"].as_str().unwrap());
    let root = cstr("m");
    for (i, raw) in keyshares().iter().enumerate() {
        assert_eq!(public_key_hex(raw), public_key, "party {}", i + 1);
        let ks = cstr(raw);
        assert!(unsafe {
            frost_derive_public_key(ks.as_ptr(), child.as_ptr())
        }
        .is_null());
        let derived = ok(unsafe {
            frost_derive_public_key(ks.as_ptr(), root.as_ptr())
        });
        assert_eq!(
            json(&derived)["derived_public_key"],
            expected["derived_public_key"],
            "party {}: derived public key changed",
            i + 1
        );
    }
}

#[test]
fn golden_keyshares_sign_for_every_signer_set() {
    let public_key = expected()["public_key"].as_str().unwrap().to_owned();
    let shares = keyshares();
    let sets: [&[usize]; 4] = [&[0, 1], &[0, 2], &[1, 2], &[0, 1, 2]];
    for set in sets {
        let signers: Vec<&str> =
            set.iter().map(|&i| shares[i].as_str()).collect();
        let message = format!("golden signers {set:?}");
        let sig = sign(&signers, message.as_bytes());
        assert!(
            verify(&public_key, message.as_bytes(), &sig),
            "signers {set:?}: signature does not verify against the stored \
             public key"
        );
        assert_eq!(
            ffi_verify(&public_key, message.as_bytes(), &sig),
            Some(true),
            "signers {set:?}"
        );
    }
}

#[test]
fn golden_dkg_messages_roundtrip() {
    let m1: Round1Msg = assert_roundtrip("messages/dkg_msg1.json");
    assert_eq!(m1.from, 1);
    let m1 = json(&read("messages/dkg_msg1.json"));
    assert_keys("dkg_msg1", &m1, &["from", "package"]);
    assert_keys(
        "dkg_msg1.package",
        &m1["package"],
        &["header", "commitment", "proof_of_knowledge"],
    );
    assert_header("dkg_msg1.package.header", &m1["package"]["header"]);

    let m2: Vec<Round2Msg> = assert_roundtrip("messages/dkg_msg2.json");
    assert_eq!(m2.len(), 2);
    for m in &m2 {
        assert_eq!(m.from, 1);
        assert_ne!(m.to_id, 0, "to_id is zero-based; party 1 is 0");
    }
    for m in array(&read("messages/dkg_msg2.json")) {
        assert_keys("dkg_msg2[]", &m, &["from", "to_id", "package"]);
        assert_keys(
            "dkg_msg2[].package",
            &m["package"],
            &["header", "signing_share"],
        );
    }
}

#[test]
fn golden_signing_messages_roundtrip() {
    let c: Commitment = assert_roundtrip("messages/sign_msg1.json");
    assert_eq!(c.from, 1);
    let raw = json(&read("messages/sign_msg1.json"));
    assert_keys(
        "sign_msg1.commitments",
        &raw["commitments"],
        &["header", "hiding", "binding"],
    );

    for p in 1..=2 {
        let file = bundle_file(p);
        let b: SignatureShareBundle = assert_roundtrip(&file);
        assert_eq!(u64::from(b.participant_id), p, "{file}");
        assert_keys(
            &file,
            &json(&read(&file)),
            &[
                "participant_id",
                "signature_share",
                "signing_package",
                "pubkey_package",
            ],
        );
    }
}

#[test]
fn golden_stored_commitment_is_accepted_by_signing() {
    // Party 2 signs against party 1's stored commitments; this drives the
    // FFI's own commitment parser rather than the test mirror type.
    let shares = keyshares();
    let s = signer(&shares[1], SIGNED_MESSAGE);
    ok(unsafe { frost_signing_generate_msg1(s.ptr) });
    let stored = cstr(&format!("[{}]", read("messages/sign_msg1.json")));
    let bundle = json(&ok(unsafe {
        frost_signing_handle_msg1(s.ptr, stored.as_ptr())
    }));
    assert_eq!(bundle["participant_id"], 2);
}

#[test]
fn golden_bundles_combine_to_stored_signature() {
    let expected = expected();
    let signing = &expected["signing"];
    let message =
        hex::decode(signing["message_hex"].as_str().unwrap()).unwrap();
    let stored_sig = signing["signature"].as_str().unwrap();
    let public_key = expected["public_key"].as_str().unwrap();
    assert!(verify(public_key, &message, stored_sig));
    assert_eq!(ffi_verify(public_key, &message, stored_sig), Some(true));

    let bundles: Vec<Value> = signing["bundles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| json(&read(f.as_str().unwrap())))
        .collect();
    // Aggregation is deterministic, so each side must reproduce the stored
    // signature exactly from the stored shares.
    for i in 0..bundles.len() {
        let others: Vec<Value> = bundles
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, b)| b.clone())
            .collect();
        let sig = ok(combine(&bundles[i], &others));
        assert_eq!(sig, stored_sig, "aggregated by bundle {i}");
    }
}
