//! End-to-end DKG and signing through the DKLs23 C ABI, with signatures
//! checked by an independent ECDSA verifier.

use std::sync::OnceLock;

use super::common::*;
use crate::*;

/// 2-of-3 keyshares shared by tests in this binary (DKG is the slow part).
fn keyshares_2_of_3() -> &'static [String] {
    static KEYSHARES: OnceLock<Vec<String>> = OnceLock::new();
    KEYSHARES.get_or_init(|| run_dkg(&dkg_parties(3, 2)))
}

fn refs<'a>(keyshares: &'a [String], ids: &[usize]) -> Vec<&'a str> {
    ids.iter().map(|&i| keyshares[i].as_str()).collect()
}

#[test]
fn dkg_2_of_2_then_sign_verifies() {
    let keyshares = run_dkg(&dkg_parties(2, 2));
    let pubkey = derive_public_key(&keyshares[0], "m");
    assert_eq!(pubkey, derive_public_key(&keyshares[1], "m"));

    let hash = sha256(b"2-of-2 transfer");
    let sig = sign(&refs(&keyshares, &[0, 1]), "m", &hash);
    assert!(verify(&pubkey, &hash, &sig));
    assert!(!verify(&pubkey, &sha256(b"other message"), &sig));
}

#[test]
fn dkg_2_of_3_every_pair_can_sign() {
    let keyshares = keyshares_2_of_3();
    let pubkey = derive_public_key(&keyshares[0], "m");

    for (n, pair) in [[0, 1], [1, 2], [0, 2]].iter().enumerate() {
        let hash = sha256(format!("2-of-3 message {n}").as_bytes());
        let sig = sign(&refs(keyshares, pair), "m", &hash);
        assert!(verify(&pubkey, &hash, &sig), "pair {pair:?}");
    }
}

#[test]
fn keyshares_agree_on_public_key() {
    let keyshares = keyshares_2_of_3();
    for (i, ks) in keyshares.iter().enumerate() {
        assert_eq!(party_id(ks), i as u64);
    }
    let pubkeys: Vec<String> = keyshares
        .iter()
        .map(|ks| derive_public_key(ks, "m"))
        .collect();
    assert!(pubkeys.windows(2).all(|w| w[0] == w[1]));
    // Compressed SEC1 point.
    assert_eq!(pubkeys[0].len(), 66);
    assert!(pubkeys[0].starts_with("02") || pubkeys[0].starts_with("03"));
}

#[test]
fn dkg_rounds_return_expected_message_shapes() {
    let parties = dkg_parties(3, 2);
    let msg1 = dkg_round1(&parties);
    for (i, m) in msg1.iter().enumerate() {
        assert_eq!(id(m, "from_id"), i as u64);
    }
    // Round 2 is point-to-point: each party addresses every other party.
    let msg2 = dkg_round2(&parties, &msg1);
    assert_eq!(msg2.len(), 3 * 2);
    for m in &msg2 {
        assert_ne!(id(m, "from_id"), id(m, "to_id"));
    }
    let commitment =
        ok(unsafe { dkls23_dkg_calculate_commitment_2(parties[0].0) });
    assert_eq!(hex::decode(&commitment).unwrap().len(), 32);
}

#[test]
fn ranked_dkg_then_sign_verifies() {
    // Party 0 has rank 1 (lower authority); threshold 2 > max rank.
    let keyshares = run_dkg(&ranked_parties(&[1, 0, 0], 2));
    let pubkey = derive_public_key(&keyshares[0], "m");
    for ks in &keyshares[1..] {
        assert_eq!(derive_public_key(ks, "m"), pubkey);
    }
    assert_eq!(
        json(&keyshares[0])["rank_list"],
        serde_json::json!([1, 0, 0])
    );

    let hash = sha256(b"ranked signing");
    let sig = sign(&refs(&keyshares, &[1, 2]), "m", &hash);
    assert!(verify(&pubkey, &hash, &sig));
}

#[test]
fn bip32_derived_key_is_consistent_and_signs() {
    let keyshares = keyshares_2_of_3();
    let path = "m/0/7";
    let root = derive_public_key(&keyshares[0], "m");
    let child = derive_public_key(&keyshares[0], path);
    assert_ne!(root, child);
    for ks in &keyshares[1..] {
        assert_eq!(derive_public_key(ks, path), child);
    }

    let hash = sha256(b"derived signing");
    let sig = sign(&refs(keyshares, &[0, 2]), path, &hash);
    assert!(verify(&child, &hash, &sig));
    assert!(!verify(&root, &hash, &sig));
}

#[test]
fn derived_keyshares_sign_for_the_child_key() {
    let keyshares = keyshares_2_of_3();
    let path = cstr("m/3/5");
    let derived: Vec<String> = keyshares[..2]
        .iter()
        .map(|ks| {
            let ks = cstr(ks);
            ok(unsafe { dkls23_derive_keyshare(ks.as_ptr(), path.as_ptr()) })
        })
        .collect();

    let child = derive_public_key(&keyshares[0], "m/3/5");
    assert_eq!(derive_public_key(&derived[0], "m"), child);
    assert_eq!(derive_public_key(&derived[1], "m"), child);
    // The derived chain code supports further derivation.
    assert_eq!(
        derive_public_key(&derived[0], "m/1"),
        derive_public_key(&keyshares[0], "m/3/5/1"),
    );

    let hash = sha256(b"derived keyshare signing");
    let sig = sign(&refs(&derived, &[0, 1]), "m", &hash);
    assert!(verify(&child, &hash, &sig));
}

#[test]
fn partial_signature_response_shape() {
    let keyshares = keyshares_2_of_3();
    let hash = sha256(b"shape");
    let presigs = presign(&refs(keyshares, &[0, 1]), "m");
    let handle = json(&presigs[0].1);
    let token = handle["presignature_handle"].as_str().unwrap();
    assert_eq!(token.len(), 64, "handle is 32 random bytes as hex");

    let response = partial(&presigs[0].1, &hash);
    assert!(response["partial"].is_object());
    assert_eq!(id(&response["msg4"], "from_id"), 0);
    // Consume the other handle so the registry stays tidy.
    partial(&presigs[1].1, &hash);
}
