//! Helpers that drive the FROST C ABI the way a foreign caller would:
//! NUL-terminated JSON in, owned C strings out, freed with
//! `frost_free_string`.

#![allow(dead_code)]

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use crate::*;
use frost_ed25519::{Signature, VerifyingKey};
use serde_json::Value;

pub fn cstr(s: &str) -> CString {
    CString::new(s).unwrap()
}

/// Copy a returned string and free it. `None` for NULL.
pub fn take(ptr: *mut c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let s = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap().to_owned();
    unsafe { frost_free_string(ptr) };
    Some(s)
}

/// Read (and clear) the last error.
pub fn last_error() -> String {
    take(frost_get_last_error()).expect("last error should be set")
}

/// Unwrap a successful call, surfacing the FFI error message otherwise.
pub fn ok(ptr: *mut c_char) -> String {
    take(ptr).unwrap_or_else(|| panic!("FFI call failed: {}", last_error()))
}

/// Assert that a call returned NULL and that the error mentions `needle`.
pub fn expect_err<T>(ptr: *mut T, needle: &str) {
    assert!(ptr.is_null(), "expected failure containing {needle:?}");
    let err = last_error();
    assert!(err.contains(needle), "error {err:?} lacks {needle:?}");
}

pub fn json(s: &str) -> Value {
    serde_json::from_str(s).unwrap()
}

pub fn array(s: &str) -> Vec<Value> {
    match json(s) {
        Value::Array(items) => items,
        other => panic!("expected JSON array, got {other}"),
    }
}

pub fn field(msg: &Value, name: &str) -> u64 {
    msg[name].as_u64().unwrap()
}

/// Messages not sent by `party` (FROST round 1 uses `from`).
pub fn excluding(msgs: &[Value], party: u64) -> Vec<Value> {
    msgs.iter()
        .filter(|m| field(m, "from") != party)
        .cloned()
        .collect()
}

/// Round 2 messages for one-based `party`; `to_id` is zero-based.
pub fn addressed_to(msgs: &[Value], party: u64) -> Vec<Value> {
    msgs.iter()
        .filter(|m| field(m, "to_id") == party - 1)
        .cloned()
        .collect()
}

pub fn to_c(v: &[Value]) -> CString {
    cstr(&serde_json::to_string(v).unwrap())
}

/// One party's DKG state, freed on drop.
pub struct Dkg {
    pub id: u64,
    pub ptr: *mut DkgState,
}

impl Drop for Dkg {
    fn drop(&mut self) {
        unsafe { frost_dkg_free_state(self.ptr) };
    }
}

/// Parties with one-based ids `1..=n`.
pub fn dkg_parties(n: u16, t: u16) -> Vec<Dkg> {
    (1..=n)
        .map(|id| {
            let ptr = frost_dkg_init(id, n, t);
            assert!(!ptr.is_null(), "{}", last_error());
            Dkg { id: id.into(), ptr }
        })
        .collect()
}

pub fn dkg_round1(parties: &[Dkg]) -> Vec<Value> {
    parties
        .iter()
        .map(|p| json(&ok(unsafe { frost_dkg_generate_msg1(p.ptr) })))
        .collect()
}

pub fn dkg_round2(parties: &[Dkg], msg1: &[Value]) -> Vec<Value> {
    let mut msg2 = Vec::new();
    for p in parties {
        let others = to_c(&excluding(msg1, p.id));
        msg2.extend(array(&ok(unsafe {
            frost_dkg_handle_msg1(p.ptr, others.as_ptr())
        })));
    }
    msg2
}

/// Run a complete DKG through the C ABI and return each party's keyshare
/// JSON, ordered by party id.
pub fn run_dkg(parties: &[Dkg]) -> Vec<String> {
    let msg1 = dkg_round1(parties);
    let msg2 = dkg_round2(parties, &msg1);
    parties
        .iter()
        .map(|p| {
            let mine = to_c(&addressed_to(&msg2, p.id));
            ok(unsafe { frost_dkg_handle_msg2(p.ptr, mine.as_ptr()) })
        })
        .collect()
}

/// One party's signing state, freed on drop.
pub struct Signer {
    pub id: u64,
    pub ptr: *mut SigningState,
}

impl Drop for Signer {
    fn drop(&mut self) {
        unsafe { frost_signing_free_state(self.ptr) };
    }
}

pub fn signer(keyshare: &str, message: &[u8]) -> Signer {
    let ks = cstr(keyshare);
    let ptr = unsafe {
        frost_signing_init(ks.as_ptr(), message.as_ptr(), message.len())
    };
    assert!(!ptr.is_null(), "{}", last_error());
    Signer {
        id: field(&json(keyshare), "participant_id"),
        ptr,
    }
}

pub fn commitments(signers: &[Signer]) -> Vec<Value> {
    signers
        .iter()
        .map(|s| json(&ok(unsafe { frost_signing_generate_msg1(s.ptr) })))
        .collect()
}

/// Run both signing rounds and return every signer's share bundle.
pub fn share_bundles(keyshares: &[&str], message: &[u8]) -> Vec<Value> {
    let signers: Vec<Signer> =
        keyshares.iter().map(|ks| signer(ks, message)).collect();
    let commits = commitments(&signers);
    signers
        .iter()
        .map(|s| {
            let others = to_c(&excluding(&commits, s.id));
            json(&ok(unsafe {
                frost_signing_handle_msg1(s.ptr, others.as_ptr())
            }))
        })
        .collect()
}

pub fn combine(own: &Value, others: &[Value]) -> *mut c_char {
    let own = cstr(&own.to_string());
    let others = to_c(others);
    unsafe { frost_combine_signatures(own.as_ptr(), others.as_ptr()) }
}

/// Full signing session. Every signer aggregates independently; all must
/// produce the same hex signature, which is returned.
pub fn sign(keyshares: &[&str], message: &[u8]) -> String {
    let bundles = share_bundles(keyshares, message);
    let sigs: Vec<String> = (0..bundles.len())
        .map(|i| {
            let others: Vec<Value> = bundles
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, b)| b.clone())
                .collect();
            ok(combine(&bundles[i], &others))
        })
        .collect();
    assert!(sigs.windows(2).all(|w| w[0] == w[1]), "{sigs:?}");
    sigs.into_iter().next().unwrap()
}

/// `{"derived_public_key": "<hex>"}` from the FFI.
pub fn public_key_json(keyshare: &str) -> String {
    let (ks, path) = (cstr(keyshare), cstr("m"));
    ok(unsafe { frost_derive_public_key(ks.as_ptr(), path.as_ptr()) })
}

pub fn public_key_hex(keyshare: &str) -> String {
    json(&public_key_json(keyshare))["derived_public_key"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// Verify with the `frost-ed25519` verifier, outside the FFI.
pub fn verify(pubkey_hex: &str, message: &[u8], sig_hex: &str) -> bool {
    let vk =
        VerifyingKey::deserialize(&hex::decode(pubkey_hex).unwrap()).unwrap();
    let sig_bytes = hex::decode(sig_hex).unwrap();
    assert_eq!(sig_bytes.len(), 64, "Ed25519 signatures are 64 bytes");
    let sig = Signature::deserialize(&sig_bytes).unwrap();
    vk.verify(message, &sig).is_ok()
}

/// Verify through `frost_verify_signature`; `None` if the call failed.
pub fn ffi_verify(
    pubkey: &str,
    message: &[u8],
    sig_hex: &str,
) -> Option<bool> {
    let (pubkey, sig) = (cstr(pubkey), cstr(sig_hex));
    take(unsafe {
        frost_verify_signature(
            pubkey.as_ptr(),
            message.as_ptr(),
            message.len(),
            sig.as_ptr(),
        )
    })
    .map(|out| match out.as_str() {
        "true" => true,
        "false" => false,
        other => panic!("unexpected verify output {other:?}"),
    })
}
