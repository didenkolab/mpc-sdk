//! End-to-end FROST DKG and signing through the C ABI, with signatures
//! checked both by `frost_verify_signature` and by the `frost-ed25519`
//! verifier directly.

use std::ptr;

use super::common::*;
use crate::*;

fn refs<'a>(keyshares: &'a [String], ids: &[usize]) -> Vec<&'a str> {
    ids.iter().map(|&i| keyshares[i].as_str()).collect()
}

#[test]
fn dkg_2_of_2_then_sign_verifies() {
    let keyshares = run_dkg(&dkg_parties(2, 2));
    let pubkey = public_key_hex(&keyshares[0]);
    assert_eq!(pubkey, public_key_hex(&keyshares[1]));
    assert_eq!(pubkey.len(), 64, "32-byte Ed25519 key");

    // FROST signs the raw message, so any length works.
    let message = b"send 1.5 SOL to the treasury";
    let sig = sign(&refs(&keyshares, &[0, 1]), message);
    assert!(verify(&pubkey, message, &sig));
    assert!(!verify(&pubkey, b"send 15 SOL to the treasury", &sig));
    assert_eq!(ffi_verify(&pubkey, message, &sig), Some(true));
    assert_eq!(ffi_verify(&pubkey, b"other", &sig), Some(false));
}

#[test]
fn dkg_2_of_3_every_pair_can_sign() {
    let keyshares = run_dkg(&dkg_parties(3, 2));
    let pubkey = public_key_hex(&keyshares[0]);
    for ks in &keyshares[1..] {
        assert_eq!(public_key_hex(ks), pubkey);
    }

    for pair in [[0, 1], [1, 2], [0, 2]] {
        let message = format!("pair {pair:?}");
        let sig = sign(&refs(&keyshares, &pair), message.as_bytes());
        assert!(verify(&pubkey, message.as_bytes(), &sig), "{pair:?}");
    }

    // More signers than the threshold also works.
    let sig = sign(&refs(&keyshares, &[0, 1, 2]), b"all three");
    assert!(verify(&pubkey, b"all three", &sig));
}

#[test]
fn dkg_messages_are_addressed_and_keyshares_identify_parties() {
    let parties = dkg_parties(3, 2);
    let msg1 = dkg_round1(&parties);
    for (p, m) in parties.iter().zip(&msg1) {
        assert_eq!(field(m, "from"), p.id);
    }

    let msg2 = dkg_round2(&parties, &msg1);
    assert_eq!(msg2.len(), 3 * 2, "one packet per ordered pair");
    for m in &msg2 {
        // to_id is zero-based, from is one-based.
        assert_ne!(field(m, "to_id") + 1, field(m, "from"));
        assert!(field(m, "to_id") < 3);
    }

    for p in &parties {
        let mine = to_c(&addressed_to(&msg2, p.id));
        let keyshare =
            ok(unsafe { frost_dkg_handle_msg2(p.ptr, mine.as_ptr()) });
        assert_eq!(field(&json(&keyshare), "participant_id"), p.id);
        // finalize returns the same keyshare again.
        assert_eq!(ok(unsafe { frost_dkg_finalize(p.ptr) }), keyshare);
    }
}

#[test]
fn verify_accepts_hex_or_json_public_key() {
    let keyshares = run_dkg(&dkg_parties(2, 2));
    let message = b"key formats";
    let sig = sign(&refs(&keyshares, &[0, 1]), message);
    assert_eq!(
        ffi_verify(&public_key_json(&keyshares[0]), message, &sig),
        Some(true)
    );
    assert_eq!(
        ffi_verify(&public_key_hex(&keyshares[0]), message, &sig),
        Some(true)
    );
}

#[test]
fn derive_keyshare_is_identity_and_still_signs() {
    // SLIP-10 derivation is not implemented: only the root path is accepted.
    let keyshares = run_dkg(&dkg_parties(2, 2));
    let child = cstr("m/44'/501'/0'");
    let ks0 = cstr(&keyshares[0]);
    unsafe {
        assert!(frost_derive_keyshare(ks0.as_ptr(), child.as_ptr()).is_null());
        assert!(
            frost_derive_public_key(ks0.as_ptr(), child.as_ptr()).is_null()
        );
    }
    assert!(last_error().contains("not supported"), "{}", last_error());
    let path = cstr("m");
    let derived: Vec<String> = keyshares
        .iter()
        .map(|ks| {
            let ks = cstr(ks);
            ok(unsafe { frost_derive_keyshare(ks.as_ptr(), path.as_ptr()) })
        })
        .collect();
    assert_eq!(json(&derived[0]), json(&keyshares[0]));

    let ks = cstr(&keyshares[0]);
    let with_null_path =
        ok(unsafe { frost_derive_public_key(ks.as_ptr(), ptr::null()) });
    assert_eq!(with_null_path, public_key_json(&keyshares[0]));

    let sig = sign(&refs(&derived, &[0, 1]), b"derived");
    assert!(verify(&public_key_hex(&keyshares[0]), b"derived", &sig));
}

#[test]
fn compatibility_shims_behave_as_documented() {
    let keyshares = run_dkg(&dkg_parties(2, 2));
    let s = signer(&keyshares[0], b"shim");
    let empty = cstr("[]");
    assert_eq!(ok(frost_signing_generate_msg2(s.ptr)), "{}");
    assert_eq!(ok(frost_signing_handle_msg2(s.ptr, empty.as_ptr())), "{}");

    let bundle = cstr(r#"{"any":"json"}"#);
    let copy = ok(unsafe {
        frost_create_partial_signature(bundle.as_ptr(), ptr::null())
    });
    assert_eq!(copy, r#"{"any":"json"}"#);
}

#[test]
fn success_clears_previous_error() {
    assert!(frost_dkg_init(0, 2, 2).is_null());
    let keyshares = run_dkg(&dkg_parties(2, 2));
    public_key_json(&keyshares[0]);
    assert_eq!(take(frost_get_last_error()), None);
}
