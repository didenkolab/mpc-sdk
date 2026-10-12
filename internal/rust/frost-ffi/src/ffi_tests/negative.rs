//! Failure handling of the FROST C ABI: invalid arguments, malformed or
//! misrouted messages, and single-use signing nonces. Every failure must
//! return NULL with a descriptive `frost_get_last_error`, never abort.

use std::os::raw::c_char;
use std::ptr;
use std::sync::OnceLock;

use super::common::*;
use crate::*;
use serde_json::{json, Value};

fn keyshares_2_of_3() -> &'static [String] {
    static KEYSHARES: OnceLock<Vec<String>> = OnceLock::new();
    KEYSHARES.get_or_init(|| run_dkg(&dkg_parties(3, 2)))
}

/// Builds a round's input from the honest messages.
type Tamper = fn(&[Value]) -> Vec<Value>;

fn with_field(msg: &Value, name: &str, value: u64) -> Value {
    let mut msg = msg.clone();
    msg[name] = json!(value);
    msg
}

/// Two signers (parties 1 and 2) after round 1, plus their commitments.
fn signing_round1(message: &[u8]) -> (Vec<Signer>, Vec<Value>) {
    let keyshares = keyshares_2_of_3();
    let signers: Vec<Signer> = keyshares[..2]
        .iter()
        .map(|ks| signer(ks, message))
        .collect();
    let commits = commitments(&signers);
    (signers, commits)
}

// -------------------- Error reporting --------------------

#[test]
fn free_functions_accept_null() {
    unsafe {
        frost_free_string(ptr::null_mut());
        frost_dkg_free_state(ptr::null_mut());
        frost_signing_free_state(ptr::null_mut());
    }
}

#[test]
fn last_error_is_cleared_once_read() {
    assert!(frost_dkg_init(0, 3, 2).is_null());
    assert!(take(frost_get_last_error()).is_some());
    assert_eq!(take(frost_get_last_error()), None);
}

// -------------------- Invalid parameters --------------------

#[test]
fn dkg_init_rejects_invalid_parameters() {
    for (id, n, t) in [
        (0, 3, 2), // ids are one-based
        (4, 3, 2), // id beyond the participant count
        (1, 1, 1), // fewer than two participants
        (1, 3, 1), // threshold below two
        (1, 3, 4), // threshold above participant count
    ] {
        expect_err(
            frost_dkg_init(id, n, t),
            "invalid party_id/participants/threshold",
        );
    }
}

#[test]
fn signing_init_rejects_invalid_arguments() {
    let message = b"msg";
    let bad = cstr("{not json");
    unsafe {
        expect_err(
            frost_signing_init(ptr::null(), message.as_ptr(), message.len()),
            "null params",
        );
        let ks = cstr(&keyshares_2_of_3()[0]);
        expect_err(frost_signing_init(ks.as_ptr(), ptr::null(), 0), "null");
        expect_err(
            frost_signing_init(bad.as_ptr(), message.as_ptr(), message.len()),
            "parse keyshare",
        );
    }

    let mut zero_id = json(&keyshares_2_of_3()[0]);
    zero_id["participant_id"] = json!(0);
    let zero_id = cstr(&zero_id.to_string());
    expect_err(
        unsafe {
            frost_signing_init(
                zero_id.as_ptr(),
                message.as_ptr(),
                message.len(),
            )
        },
        "invalid participant_id",
    );
}

// -------------------- NULL and malformed arguments --------------------

#[test]
fn null_state_is_rejected_everywhere() {
    let msgs = cstr("[]");
    let (dkg, signing) = (ptr::null_mut(), ptr::null_mut());
    // The error is cleared when read, so check each call immediately.
    let check = |name: &str, out: *mut c_char| {
        assert!(out.is_null(), "{name} accepted a NULL state");
        assert_eq!(last_error(), "NULL state", "{name}");
    };
    unsafe {
        check("dkg_generate_msg1", frost_dkg_generate_msg1(dkg));
        check("dkg_handle_msg1", frost_dkg_handle_msg1(dkg, msgs.as_ptr()));
        check("dkg_handle_msg2", frost_dkg_handle_msg2(dkg, msgs.as_ptr()));
        check("dkg_finalize", frost_dkg_finalize(dkg));
        check("signing_msg1", frost_signing_generate_msg1(signing));
        check(
            "signing_handle_msg1",
            frost_signing_handle_msg1(signing, msgs.as_ptr()),
        );
    }
}

#[test]
fn null_and_malformed_payloads_are_rejected() {
    let parties = dkg_parties(2, 2);
    dkg_round1(&parties);
    let bad = cstr("{not json");
    unsafe {
        expect_err(
            frost_dkg_handle_msg1(parties[0].ptr, ptr::null()),
            "NULL msg1 payload",
        );
        // The failed call consumed the round 1 secret.
        expect_err(
            frost_dkg_handle_msg1(parties[0].ptr, bad.as_ptr()),
            "part1 not run",
        );
        expect_err(
            frost_dkg_handle_msg1(parties[1].ptr, bad.as_ptr()),
            "parse msgs",
        );
        expect_err(
            frost_combine_signatures(ptr::null(), bad.as_ptr()),
            "null",
        );
        expect_err(
            frost_combine_signatures(bad.as_ptr(), bad.as_ptr()),
            "parse first partial",
        );
        expect_err(
            frost_create_partial_signature(ptr::null(), ptr::null()),
            "null",
        );
        expect_err(
            frost_derive_public_key(ptr::null(), ptr::null()),
            "null keyshare",
        );
        expect_err(
            frost_derive_keyshare(bad.as_ptr(), ptr::null()),
            "parse keyshare",
        );
    }
}

// -------------------- DKG misuse --------------------

#[test]
fn dkg_rounds_must_run_in_order() {
    let parties = dkg_parties(2, 2);
    let empty = cstr("[]");
    unsafe {
        expect_err(
            frost_dkg_handle_msg1(parties[0].ptr, empty.as_ptr()),
            "part1 not run",
        );
        expect_err(
            frost_dkg_handle_msg2(parties[0].ptr, empty.as_ptr()),
            "part2 not run",
        );
        expect_err(frost_dkg_finalize(parties[0].ptr), "keyshare not ready");
    }
}

#[test]
fn dkg_round1_rejects_bad_sender_sets() {
    let cases: [(&str, Tamper); 5] = [
        ("unexpected number", |m| vec![m[1].clone()]),
        ("invalid sender", |m| vec![m[0].clone(), m[1].clone()]),
        ("duplicate round1 sender", |m| {
            vec![m[1].clone(), m[1].clone()]
        }),
        ("invalid sender", |m| {
            vec![m[1].clone(), with_field(&m[2], "from", 0)]
        }),
        ("invalid sender", |m| {
            vec![m[1].clone(), with_field(&m[2], "from", 9)]
        }),
    ];
    for (needle, build) in cases {
        let parties = dkg_parties(3, 2);
        let msg1 = dkg_round1(&parties);
        let input = to_c(&build(&msg1));
        expect_err(
            unsafe { frost_dkg_handle_msg1(parties[0].ptr, input.as_ptr()) },
            needle,
        );
    }
}

#[test]
fn dkg_round2_rejects_misrouted_packets() {
    let parties = dkg_parties(3, 2);
    let msg1 = dkg_round1(&parties);
    let msg2 = dkg_round2(&parties, &msg1);

    // Party 1 is handed the packets addressed to party 2.
    let wrong = to_c(&addressed_to(&msg2, 2));
    expect_err(
        unsafe { frost_dkg_handle_msg2(parties[0].ptr, wrong.as_ptr()) },
        "invalid route",
    );
}

#[test]
fn dkg_round2_rejects_bad_sender_sets() {
    let cases: [(&str, Tamper); 3] = [
        ("unexpected number of round2 packages", |m| {
            vec![m[0].clone()]
        }),
        ("duplicate round2 sender", |m| {
            vec![m[0].clone(), m[0].clone()]
        }),
        ("invalid route", |m| {
            vec![m[0].clone(), with_field(&m[1], "from", 1)]
        }),
    ];
    for (needle, build) in cases {
        let parties = dkg_parties(3, 2);
        let msg1 = dkg_round1(&parties);
        let msg2 = dkg_round2(&parties, &msg1);
        let input = to_c(&build(&addressed_to(&msg2, 1)));
        expect_err(
            unsafe { frost_dkg_handle_msg2(parties[0].ptr, input.as_ptr()) },
            needle,
        );
    }
}

#[test]
fn dkg_round2_rejects_swapped_packages() {
    let parties = dkg_parties(3, 2);
    let msg1 = dkg_round1(&parties);
    let msg2 = dkg_round2(&parties, &msg1);
    let mut mine = addressed_to(&msg2, 1);
    // Valid routing metadata, but the secret shares belong to the other
    // sender: share verification must fail.
    let first = mine[0]["package"].clone();
    mine[0]["package"] = mine[1]["package"].clone();
    mine[1]["package"] = first;
    expect_err(
        unsafe {
            frost_dkg_handle_msg2(parties[0].ptr, to_c(&mine).as_ptr())
        },
        "dkg part3 error",
    );
}

// -------------------- Signing misuse --------------------

#[test]
fn signing_commitments_are_generated_once() {
    let (signers, _) = signing_round1(b"twice");
    expect_err(
        unsafe { frost_signing_generate_msg1(signers[0].ptr) },
        "already generated",
    );
}

#[test]
fn signing_nonces_are_single_use() {
    let (signers, commits) = signing_round1(b"nonce reuse");
    let others = to_c(&excluding(&commits, signers[0].id));
    unsafe {
        ok(frost_signing_handle_msg1(signers[0].ptr, others.as_ptr()));
        expect_err(
            frost_signing_handle_msg1(signers[0].ptr, others.as_ptr()),
            "already used",
        );
    }
}

#[test]
fn failed_signing_attempt_still_burns_nonces() {
    let (signers, commits) = signing_round1(b"burn");
    let bad = cstr("{not json");
    let others = to_c(&excluding(&commits, signers[0].id));
    unsafe {
        expect_err(
            frost_signing_handle_msg1(signers[0].ptr, bad.as_ptr()),
            "parse msg1 commitments",
        );
        expect_err(
            frost_signing_handle_msg1(signers[0].ptr, others.as_ptr()),
            "already used",
        );
    }
}

#[test]
fn signing_requires_threshold_commitments() {
    let (signers, _) = signing_round1(b"alone");
    let none = cstr("[]");
    expect_err(
        unsafe { frost_signing_handle_msg1(signers[0].ptr, none.as_ptr()) },
        "signing error",
    );
}

#[test]
fn signing_rejects_commitment_spoofing_own_id() {
    let (signers, commits) = signing_round1(b"spoof");
    // A peer's commitments relabelled as party 1's own.
    let spoofed = to_c(&[with_field(&commits[1], "from", signers[0].id)]);
    expect_err(
        unsafe {
            frost_signing_handle_msg1(signers[0].ptr, spoofed.as_ptr())
        },
        "signing error",
    );
}

#[test]
fn combine_rejects_bad_shares() {
    let keyshares = keyshares_2_of_3();
    let message = b"combine";
    let bundles = share_bundles(&[&keyshares[0], &keyshares[1]], message);

    // Missing the peer's share.
    expect_err(combine(&bundles[0], &[]), "aggregate error");

    // Peer bundle carrying our share: cheater detection must trip.
    let mut forged = bundles[1].clone();
    forged["signature_share"] = bundles[0]["signature_share"].clone();
    expect_err(combine(&bundles[0], &[forged]), "aggregate error");

    // Invalid own participant id (identifier zero).
    let zero = with_field(&bundles[0], "participant_id", 0);
    expect_err(combine(&zero, &bundles[1..]), "invalid participant_id");

    let sig = ok(combine(&bundles[0], &bundles[1..]));
    assert!(verify(&public_key_hex(&keyshares[0]), message, &sig));
}

#[test]
fn bundles_for_different_messages_do_not_combine() {
    let keyshares = keyshares_2_of_3();
    let a = share_bundles(&[&keyshares[0], &keyshares[1]], b"message a");
    let b = share_bundles(&[&keyshares[0], &keyshares[1]], b"message b");
    expect_err(combine(&a[0], &b[1..]), "aggregate error");
}

// -------------------- Verification --------------------

#[test]
fn verify_rejects_malformed_inputs() {
    let keyshares = keyshares_2_of_3();
    let pubkey = public_key_hex(&keyshares[0]);
    let message = b"verify";
    let sig = sign(&[&keyshares[1], &keyshares[2]], message);

    assert_eq!(ffi_verify(&pubkey, message, &sig), Some(true));
    // Flip one bit of S.
    let mut tampered = hex::decode(&sig).unwrap();
    tampered[40] ^= 1;
    let tampered = hex::encode(tampered);
    assert_ne!(ffi_verify(&pubkey, message, &tampered), Some(true));

    let cases = [
        ("zz", sig.as_str(), "decode pubkey"),
        (pubkey.as_str(), "zz", "decode signature"),
        (pubkey.as_str(), "00", "signature parse"),
        ("00", sig.as_str(), "pubkey parse"),
        (
            r#"{"derived_public_key": 5}"#,
            sig.as_str(),
            "invalid public key",
        ),
    ];
    for (key, signature, needle) in cases {
        assert_eq!(ffi_verify(key, message, signature), None, "{needle}");
        assert!(last_error().contains(needle), "{needle}");
    }

    assert_eq!(ffi_verify(&pubkey, b"", &sig), None);
    assert!(last_error().contains("message len 0"));

    let (k, s) = (cstr(&pubkey), cstr(&sig));
    expect_err(
        unsafe {
            frost_verify_signature(k.as_ptr(), ptr::null(), 1, s.as_ptr())
        },
        "null params",
    );
}
