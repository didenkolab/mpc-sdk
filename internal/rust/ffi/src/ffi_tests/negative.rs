//! Failure handling of the DKLs23 C ABI: invalid arguments, malformed or
//! misrouted messages, and single-use presignatures. Every failure must
//! return NULL with a descriptive `dkls23_get_last_error`, never abort.

use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;
use std::sync::OnceLock;

use super::common::last_error;
use super::common::*;
use crate::*;
use serde_json::{json, Value};

fn keyshares_2_of_2() -> &'static [String] {
    static KEYSHARES: OnceLock<Vec<String>> = OnceLock::new();
    KEYSHARES.get_or_init(|| run_dkg(&dkg_parties(2, 2)))
}

fn keyshare_refs() -> Vec<&'static str> {
    keyshares_2_of_2().iter().map(String::as_str).collect()
}

/// Signing states for both parties after round 1, plus the round 1
/// messages.
fn signing_round1() -> (Vec<Dsg>, Vec<Value>) {
    let states: Vec<Dsg> =
        keyshare_refs().iter().map(|ks| dsg_init(ks, "m")).collect();
    let msg1 = states
        .iter()
        .map(|s| json(&ok(unsafe { dkls23_dsg_generate_msg1(s.0) })))
        .collect();
    (states, msg1)
}

/// Run signing rounds 1 and 2 and return the round 2 output.
fn signing_round2() -> (Vec<Dsg>, Vec<Value>) {
    let (states, msg1) = signing_round1();
    let mut msg2 = Vec::new();
    for (i, s) in states.iter().enumerate() {
        let others = to_c(&excluding(&msg1, i as u64));
        msg2.extend(array(&ok(unsafe {
            dkls23_dsg_handle_msg1(s.0, others.as_ptr())
        })));
    }
    (states, msg2)
}

fn with_field(msg: &Value, field: &str, value: u64) -> Value {
    let mut msg = msg.clone();
    msg[field] = json!(value);
    msg
}

// -------------------- Error reporting --------------------

#[test]
fn free_functions_accept_null() {
    unsafe {
        dkls23_free_string(ptr::null_mut());
        dkls23_dkg_free_state(ptr::null_mut());
        dkls23_dsg_free_state(ptr::null_mut());
    }
}

#[test]
fn last_error_is_thread_local() {
    expect_err(unsafe { dkls23_dkg_generate_msg1(ptr::null_mut()) }, "NULL");
    let other = std::thread::spawn(|| take(dkls23_get_last_error()))
        .join()
        .unwrap();
    assert_eq!(other, None);
}

// -------------------- Invalid parameters --------------------

#[test]
fn dkg_init_rejects_invalid_parameters() {
    assert!(dkls23_dkg_init(2, 2, 2).is_null());
    assert!(last_error().contains("party_id out of bounds"));
    assert!(dkls23_dkg_init(0, 0, 2).is_null());
    assert!(dkls23_dkg_init(0, 3, 0).is_null());
    assert!(last_error().contains("invalid threshold"));
    assert!(dkls23_dkg_init(0, 3, 256).is_null());
}

#[test]
fn dkg_init_with_ranks_rejects_invalid_parameters() {
    let ranks = [0u8, 1, 0];
    unsafe {
        assert!(dkls23_dkg_init_with_ranks(0, ptr::null(), 3, 2).is_null());
        assert!(last_error().contains("NULL ranks pointer"));

        assert!(dkls23_dkg_init_with_ranks(3, ranks.as_ptr(), 3, 2).is_null());
        assert!(last_error().contains("party_id out of bounds"));

        assert!(dkls23_dkg_init_with_ranks(0, ranks.as_ptr(), 3, 1).is_null());
        assert!(last_error().contains("max rank must be less than threshold"));

        assert!(dkls23_dkg_init_with_ranks(0, ranks.as_ptr(), 0, 2).is_null());
    }
}

// -------------------- NULL and malformed arguments --------------------

#[test]
fn null_state_is_rejected_everywhere() {
    let msgs = cstr("[]");
    let null_dkg = ptr::null_mut();
    let null_dsg = ptr::null_mut();
    let calls: [(&str, *mut c_char); 10] = unsafe {
        [
            ("dkg_generate_msg1", dkls23_dkg_generate_msg1(null_dkg)),
            (
                "dkg_handle_msg1",
                dkls23_dkg_handle_msg1(null_dkg, msgs.as_ptr()),
            ),
            (
                "dkg_handle_msg2",
                dkls23_dkg_handle_msg2(null_dkg, msgs.as_ptr()),
            ),
            (
                "dkg_commitment_2",
                dkls23_dkg_calculate_commitment_2(null_dkg),
            ),
            (
                "dkg_handle_msg3",
                dkls23_dkg_handle_msg3(
                    null_dkg,
                    msgs.as_ptr(),
                    msgs.as_ptr(),
                ),
            ),
            (
                "dkg_handle_msg4",
                dkls23_dkg_handle_msg4(null_dkg, msgs.as_ptr()),
            ),
            ("dsg_generate_msg1", dkls23_dsg_generate_msg1(null_dsg)),
            (
                "dsg_handle_msg1",
                dkls23_dsg_handle_msg1(null_dsg, msgs.as_ptr()),
            ),
            (
                "dsg_handle_msg2",
                dkls23_dsg_handle_msg2(null_dsg, msgs.as_ptr()),
            ),
            (
                "dsg_handle_msg3",
                dkls23_dsg_handle_msg3(null_dsg, msgs.as_ptr()),
            ),
        ]
    };
    for (name, out) in calls {
        assert!(out.is_null(), "{name} accepted a NULL state");
        assert_eq!(last_error(), "NULL state pointer", "{name}");
    }
}

#[test]
fn null_message_payloads_are_rejected() {
    let parties = dkg_parties(2, 2);
    let p = parties[0].0;
    let empty = cstr("[]");
    unsafe {
        expect_err(dkls23_dkg_handle_msg1(p, ptr::null()), "NULL msg1");
        expect_err(dkls23_dkg_handle_msg2(p, ptr::null()), "NULL msg2");
        expect_err(
            dkls23_dkg_handle_msg3(p, empty.as_ptr(), ptr::null()),
            "NULL commitments",
        );
        expect_err(dkls23_dkg_handle_msg4(p, ptr::null()), "NULL msg4");
        expect_err(
            dkls23_combine_signatures(ptr::null(), empty.as_ptr()),
            "NULL partial signature",
        );
        expect_err(dkls23_dsg_init(ptr::null(), empty.as_ptr()), "NULL");
        expect_err(
            dkls23_derive_public_key(ptr::null(), empty.as_ptr()),
            "Null pointer provided",
        );
        expect_err(
            dkls23_derive_keyshare(empty.as_ptr(), ptr::null()),
            "Null pointer provided",
        );
    }
}

#[test]
fn malformed_json_is_rejected() {
    let parties = dkg_parties(2, 2);
    let bad = cstr("{not json");
    let wrong_shape = cstr(r#"[{"from_id": 1}]"#);
    unsafe {
        expect_err(
            dkls23_dkg_handle_msg1(parties[0].0, bad.as_ptr()),
            "Failed to parse msg1 JSON",
        );
        expect_err(
            dkls23_dkg_handle_msg1(parties[1].0, wrong_shape.as_ptr()),
            "Failed to parse msg1 JSON",
        );
        let path = cstr("m");
        expect_err(
            dkls23_dsg_init(bad.as_ptr(), path.as_ptr()),
            "Failed to parse keyshare JSON",
        );
        expect_err(
            dkls23_derive_public_key(bad.as_ptr(), path.as_ptr()),
            "Failed to parse keyshare",
        );
        expect_err(
            dkls23_combine_signatures(bad.as_ptr(), bad.as_ptr()),
            "Failed to parse partial signature JSON",
        );
    }
}

#[test]
fn invalid_utf8_is_rejected() {
    let parties = dkg_parties(2, 2);
    let invalid = CString::new(vec![b'[', 0xff, b']']).unwrap();
    expect_err(
        unsafe { dkls23_dkg_handle_msg1(parties[0].0, invalid.as_ptr()) },
        "Invalid UTF-8 in msg1",
    );
}

#[test]
fn invalid_derivation_paths_are_rejected() {
    let ks = cstr(&keyshares_2_of_2()[0]);
    for path in ["not/a/path", "m/x"] {
        let path = cstr(path);
        unsafe {
            expect_err(
                dkls23_derive_public_key(ks.as_ptr(), path.as_ptr()),
                "Invalid derivation path",
            );
            expect_err(
                dkls23_dsg_init(ks.as_ptr(), path.as_ptr()),
                "Failed to parse derivation path",
            );
        }
    }
    // Hardened steps need the private key and cannot be derived publicly.
    let hardened = cstr("m/44'/60'");
    expect_err(
        unsafe { dkls23_derive_public_key(ks.as_ptr(), hardened.as_ptr()) },
        "Derivation failed",
    );
}

// -------------------- Protocol misuse --------------------

#[test]
fn dkg_rejects_wrong_number_of_messages() {
    let parties = dkg_parties(3, 2);
    let msg1 = dkg_round1(&parties);
    let only_one = to_c(&msg1[1..2]);
    expect_err(
        unsafe { dkls23_dkg_handle_msg1(parties[0].0, only_one.as_ptr()) },
        "MissingMessage",
    );
}

#[test]
fn dkg_rejects_misrouted_round2_messages() {
    let parties = dkg_parties(3, 2);
    let msg1 = dkg_round1(&parties);
    let msg2 = dkg_round2(&parties, &msg1);
    // Hand party 0 the messages addressed to party 1.
    let wrong = to_c(&select(&msg2, "to_id", 1));
    expect_err(
        unsafe { dkls23_dkg_handle_msg2(parties[0].0, wrong.as_ptr()) },
        "InvalidMessage",
    );
}

#[test]
fn dkg_rejects_unknown_round1_sender() {
    let parties = dkg_parties(3, 2);
    let msg1 = dkg_round1(&parties);
    let forged = to_c(&[msg1[1].clone(), with_field(&msg1[2], "from_id", 9)]);
    expect_err(
        unsafe { dkls23_dkg_handle_msg1(parties[0].0, forged.as_ptr()) },
        "msg1",
    );
}

#[test]
fn dkg_rejects_unknown_round4_sender() {
    let parties = dkg_parties(2, 2);
    let msg1 = dkg_round1(&parties);
    let msg2 = dkg_round2(&parties, &msg1);
    let msg4 = dkg_round4(&parties, &msg2);
    for forged in [
        with_field(&msg4[1], "from_id", 9),
        // Party 0's own broadcast echoed back.
        msg4[0].clone(),
    ] {
        let forged = to_c(&[forged]);
        expect_err(
            unsafe { dkls23_dkg_handle_msg4(parties[0].0, forged.as_ptr()) },
            "msg4",
        );
    }
}

#[test]
fn dkg_rejects_tampered_commitments() {
    let parties = dkg_parties(2, 2);
    let msg1 = dkg_round1(&parties);
    let msg2 = dkg_round2(&parties, &msg1);

    let mut msg3 = Vec::new();
    for (i, p) in parties.iter().enumerate() {
        let mine = to_c(&select(&msg2, "to_id", i as u64));
        msg3.extend(array(&ok(unsafe {
            dkls23_dkg_handle_msg2(p.0, mine.as_ptr())
        })));
    }
    let real: Vec<String> = parties
        .iter()
        .map(|p| ok(unsafe { dkls23_dkg_calculate_commitment_2(p.0) }))
        .collect();
    let mine = to_c(&select(&msg3, "to_id", 0));

    // Party 1's commitment replaced: verification must fail.
    let forged = to_c(&[json!(real[0]), json!("00".repeat(32))]);
    expect_err(
        unsafe {
            dkls23_dkg_handle_msg3(
                parties[0].0,
                mine.as_ptr(),
                forged.as_ptr(),
            )
        },
        "InvalidCommitmentHash",
    );
}

#[test]
fn dkg_rejects_unknown_round3_sender() {
    let parties = dkg_parties(2, 2);
    let msg1 = dkg_round1(&parties);
    let msg2 = dkg_round2(&parties, &msg1);
    let mine = to_c(&select(&msg2, "to_id", 0));
    let msg3 = array(&ok(unsafe {
        dkls23_dkg_handle_msg2(parties[0].0, mine.as_ptr())
    }));
    let _ = array(&ok(unsafe {
        let theirs = to_c(&select(&msg2, "to_id", 1));
        dkls23_dkg_handle_msg2(parties[1].0, theirs.as_ptr())
    }));
    // Party 0's own round 3 message replayed back to it.
    let replayed = to_c(&[with_field(&msg3[0], "to_id", 0)]);
    let commitments = to_c(&[json!("00".repeat(32)), json!("00".repeat(32))]);
    expect_err(
        unsafe {
            dkls23_dkg_handle_msg3(
                parties[0].0,
                replayed.as_ptr(),
                commitments.as_ptr(),
            )
        },
        "msg3",
    );
}

#[test]
fn dsg_rejects_out_of_range_sender() {
    let (states, msg1) = signing_round1();
    let forged = to_c(&[with_field(&msg1[1], "from_id", 200)]);
    expect_err(
        unsafe { dkls23_dsg_handle_msg1(states[0].0, forged.as_ptr()) },
        "sender",
    );
}

#[test]
fn dsg_rejects_missing_messages() {
    let (states, _) = signing_round1();
    let none = cstr("[]");
    expect_err(
        unsafe { dkls23_dsg_handle_msg1(states[0].0, none.as_ptr()) },
        "expected 1 peer messages (threshold 2), got 0",
    );
}

#[test]
fn dsg_rejects_misrouted_round2_messages() {
    let (states, msg2) = signing_round2();
    // Party 0 receives the message it sent to party 1.
    let own = to_c(&select(&msg2, "to_id", 1));
    expect_err(
        unsafe { dkls23_dsg_handle_msg2(states[0].0, own.as_ptr()) },
        "msg2",
    );
}

#[test]
fn dsg_rejects_misrouted_round3_messages() {
    let (states, msg2) = signing_round2();
    let mut msg3 = Vec::new();
    for (i, s) in states.iter().enumerate() {
        let mine = to_c(&select(&msg2, "to_id", i as u64));
        msg3.extend(array(&ok(unsafe {
            dkls23_dsg_handle_msg2(s.0, mine.as_ptr())
        })));
    }
    let own = to_c(&select(&msg3, "to_id", 1));
    expect_err(
        unsafe { dkls23_dsg_handle_msg3(states[0].0, own.as_ptr()) },
        "msg3",
    );
}

// -------------------- Presignature handles --------------------

#[test]
fn presignature_handle_is_single_use() {
    let hash = sha256(b"single use");
    let presigs = presign(&keyshare_refs(), "m");
    let first = partial(&presigs[0].1, &hash);
    assert!(first["msg4"].is_object());

    let handle = cstr(&presigs[0].1);
    expect_err(
        unsafe {
            dkls23_create_partial_signature(handle.as_ptr(), hash.as_ptr())
        },
        "already consumed",
    );
    partial(&presigs[1].1, &hash);
}

#[test]
fn failed_partial_signature_still_burns_handle() {
    let hash = sha256(b"burn");
    let presigs = presign(&keyshare_refs(), "m");
    let handle = cstr(&presigs[0].1);
    unsafe {
        expect_err(
            dkls23_create_partial_signature(handle.as_ptr(), ptr::null()),
            "NULL message hash",
        );
        expect_err(
            dkls23_create_partial_signature(handle.as_ptr(), hash.as_ptr()),
            "already consumed",
        );
    }
    partial(&presigs[1].1, &hash);
}

#[test]
fn malformed_presignature_handles_are_rejected() {
    let hash = [0u8; 32];
    let cases = [
        ("{}", "missing presignature_handle"),
        (r#"{"presignature_handle":"deadbeef"}"#, "unknown"),
        ("not json", "failed to parse presignature handle"),
    ];
    for (input, needle) in cases {
        let handle = cstr(input);
        expect_err(
            unsafe {
                dkls23_create_partial_signature(
                    handle.as_ptr(),
                    hash.as_ptr(),
                )
            },
            needle,
        );
    }
    expect_err(
        unsafe {
            dkls23_create_partial_signature(ptr::null(), hash.as_ptr())
        },
        "NULL presignature handle",
    );
}

#[test]
fn combine_rejects_inconsistent_shares() {
    let hash = sha256(b"combine");
    let presigs = presign(&keyshare_refs(), "m");
    let p0 = partial(&presigs[0].1, &hash);
    let p1 = partial(&presigs[1].1, &hash);

    // Missing the peer's share.
    expect_err(combine(&p0, &[]), "Failed to combine signatures");

    // Peer share for a different message.
    let mut wrong = p1.clone();
    wrong["msg4"]["s_0"] = p0["msg4"]["s_0"].clone();
    expect_err(combine(&p0, &[wrong]), "Failed to combine signatures");

    // The genuine pair still combines.
    let sig = ok(combine(&p0, &[p1]));
    let pubkey = derive_public_key(&keyshares_2_of_2()[0], "m");
    assert!(verify(&pubkey, &hash, &sig));
}

// -------------------- Signer set --------------------

/// Run signing round 1 for `signers` and return each signer's round 1
/// result (`Err` holds the last error).
fn round1_results(
    keyshares: &[String],
    signers: &[usize],
) -> Vec<Result<String, String>> {
    let states: Vec<Dsg> = signers
        .iter()
        .map(|&i| dsg_init(&keyshares[i], "m"))
        .collect();
    let msg1: Vec<Value> = states
        .iter()
        .map(|s| json(&ok(unsafe { dkls23_dsg_generate_msg1(s.0) })))
        .collect();
    states
        .iter()
        .zip(signers)
        .map(|(s, &me)| {
            let others = to_c(&excluding(&msg1, me as u64));
            take(unsafe { dkls23_dsg_handle_msg1(s.0, others.as_ptr()) })
                .ok_or_else(last_error)
        })
        .collect()
}

#[test]
fn signing_requires_exactly_threshold_signers() {
    let keyshares = run_dkg(&dkg_parties(3, 2));
    for result in round1_results(&keyshares, &[0, 1, 2]) {
        let err = result.unwrap_err();
        assert!(
            err.contains("expected 1 peer messages (threshold 2), got 2"),
            "{err}"
        );
    }
}

#[test]
fn ranked_signing_rejects_non_poised_signer_set() {
    // Ranks [0, 1, 1], threshold 2: parties 1 and 2 both hold rank 1, so
    // the sorted ranks [1, 1] violate rank[i] <= i.
    let keyshares = run_dkg(&ranked_parties(&[0, 1, 1], 2));
    for result in round1_results(&keyshares, &[1, 2]) {
        let err = result.unwrap_err();
        assert!(err.contains("signer ranks [1, 1]"), "{err}");
    }

    // A mixed set including the rank 0 party is poised and signs.
    let pubkey = derive_public_key(&keyshares[0], "m");
    let hash = sha256(b"poised ranked set");
    for pair in [[0, 1], [0, 2]] {
        let signers: Vec<&str> =
            pair.iter().map(|&i| keyshares[i].as_str()).collect();
        let sig = sign(&signers, "m", &hash);
        assert!(verify(&pubkey, &hash, &sig), "{pair:?}");
    }
}
