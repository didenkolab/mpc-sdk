//! Helpers that drive the DKLs23 C ABI the way a foreign caller would:
//! NUL-terminated JSON in, owned C strings out, freed with
//! `dkls23_free_string`.

#![allow(dead_code)]

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use crate::*;
use dkls23_ll::dkg::State as DkgState;
use dkls23_ll::dsg::State as DsgState;
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};
use k256::sha2::{Digest, Sha256};
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
    unsafe { dkls23_free_string(ptr) };
    Some(s)
}

pub fn last_error() -> String {
    take(dkls23_get_last_error()).expect("last error should be set")
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

pub fn id(msg: &Value, field: &str) -> u64 {
    msg[field].as_u64().unwrap()
}

pub fn select(msgs: &[Value], field: &str, party: u64) -> Vec<Value> {
    msgs.iter()
        .filter(|m| id(m, field) == party)
        .cloned()
        .collect()
}

pub fn excluding(msgs: &[Value], party: u64) -> Vec<Value> {
    msgs.iter()
        .filter(|m| id(m, "from_id") != party)
        .cloned()
        .collect()
}

pub fn to_c(v: &[Value]) -> CString {
    cstr(&serde_json::to_string(v).unwrap())
}

pub fn sha256(msg: &[u8]) -> [u8; 32] {
    Sha256::digest(msg).into()
}

/// One party's DKG state, freed on drop.
pub struct Dkg(pub *mut DkgState);

impl Drop for Dkg {
    fn drop(&mut self) {
        unsafe { dkls23_dkg_free_state(self.0) };
    }
}

pub fn dkg_parties(n: usize, t: usize) -> Vec<Dkg> {
    (0..n as u8)
        .map(|i| {
            let state = dkls23_dkg_init(i, n, t);
            assert!(!state.is_null(), "{}", last_error());
            Dkg(state)
        })
        .collect()
}

pub fn ranked_parties(ranks: &[u8], t: usize) -> Vec<Dkg> {
    (0..ranks.len() as u8)
        .map(|i| {
            let state = unsafe {
                dkls23_dkg_init_with_ranks(i, ranks.as_ptr(), ranks.len(), t)
            };
            assert!(!state.is_null(), "{}", last_error());
            Dkg(state)
        })
        .collect()
}

pub fn dkg_round1(parties: &[Dkg]) -> Vec<Value> {
    parties
        .iter()
        .map(|p| json(&ok(unsafe { dkls23_dkg_generate_msg1(p.0) })))
        .collect()
}

pub fn dkg_round2(parties: &[Dkg], msg1: &[Value]) -> Vec<Value> {
    let mut msg2 = Vec::new();
    for (i, p) in parties.iter().enumerate() {
        let others = to_c(&excluding(msg1, i as u64));
        let out = ok(unsafe { dkls23_dkg_handle_msg1(p.0, others.as_ptr()) });
        msg2.extend(array(&out));
    }
    msg2
}

/// Run a complete DKG through the C ABI and return each party's keyshare
/// JSON, ordered by party id.
pub fn run_dkg(parties: &[Dkg]) -> Vec<String> {
    let msg1 = dkg_round1(parties);
    let msg2 = dkg_round2(parties, &msg1);
    let msg4 = dkg_round4(parties, &msg2);
    parties
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let others = to_c(&excluding(&msg4, i as u64));
            ok(unsafe { dkls23_dkg_handle_msg4(p.0, others.as_ptr()) })
        })
        .collect()
}

/// Run the point-to-point rounds and return every party's round 4
/// broadcast.
pub fn dkg_round4(parties: &[Dkg], msg2: &[Value]) -> Vec<Value> {
    let mut msg3 = Vec::new();
    for (i, p) in parties.iter().enumerate() {
        let mine = to_c(&select(msg2, "to_id", i as u64));
        let out = ok(unsafe { dkls23_dkg_handle_msg2(p.0, mine.as_ptr()) });
        msg3.extend(array(&out));
    }

    let commitments: Vec<Value> = parties
        .iter()
        .map(|p| {
            Value::String(ok(unsafe {
                dkls23_dkg_calculate_commitment_2(p.0)
            }))
        })
        .collect();
    let commitments = to_c(&commitments);

    let mut msg4 = Vec::new();
    for (i, p) in parties.iter().enumerate() {
        let mine = to_c(&select(&msg3, "to_id", i as u64));
        let out = ok(unsafe {
            dkls23_dkg_handle_msg3(p.0, mine.as_ptr(), commitments.as_ptr())
        });
        msg4.push(json(&out));
    }
    msg4
}

/// One party's signing state, freed on drop.
pub struct Dsg(pub *mut DsgState);

impl Drop for Dsg {
    fn drop(&mut self) {
        unsafe { dkls23_dsg_free_state(self.0) };
    }
}

pub fn dsg_init(keyshare: &str, path: &str) -> Dsg {
    let (ks, path) = (cstr(keyshare), cstr(path));
    let state = unsafe { dkls23_dsg_init(ks.as_ptr(), path.as_ptr()) };
    assert!(!state.is_null(), "{}", last_error());
    Dsg(state)
}

pub fn party_id(keyshare: &str) -> u64 {
    id(&json(keyshare), "party_id")
}

/// Run signing rounds 1-3 and return `(party_id, presignature handle)`
/// for every signer.
pub fn presign(keyshares: &[&str], path: &str) -> Vec<(u64, String)> {
    let ids: Vec<u64> = keyshares.iter().map(|ks| party_id(ks)).collect();
    let states: Vec<Dsg> =
        keyshares.iter().map(|ks| dsg_init(ks, path)).collect();

    let msg1: Vec<Value> = states
        .iter()
        .map(|s| json(&ok(unsafe { dkls23_dsg_generate_msg1(s.0) })))
        .collect();

    let mut msg2 = Vec::new();
    for (s, &me) in states.iter().zip(&ids) {
        let others = to_c(&excluding(&msg1, me));
        let out = ok(unsafe { dkls23_dsg_handle_msg1(s.0, others.as_ptr()) });
        msg2.extend(array(&out));
    }

    let mut msg3 = Vec::new();
    for (s, &me) in states.iter().zip(&ids) {
        let mine = to_c(&select(&msg2, "to_id", me));
        let out = ok(unsafe { dkls23_dsg_handle_msg2(s.0, mine.as_ptr()) });
        msg3.extend(array(&out));
    }

    states
        .iter()
        .zip(&ids)
        .map(|(s, &me)| {
            let mine = to_c(&select(&msg3, "to_id", me));
            let handle =
                ok(unsafe { dkls23_dsg_handle_msg3(s.0, mine.as_ptr()) });
            (me, handle)
        })
        .collect()
}

/// `{"partial": ..., "msg4": ...}` for one presignature handle.
pub fn partial(handle: &str, hash: &[u8; 32]) -> Value {
    let handle = cstr(handle);
    json(&ok(unsafe {
        dkls23_create_partial_signature(handle.as_ptr(), hash.as_ptr())
    }))
}

pub fn combine(own: &Value, others: &[Value]) -> *mut c_char {
    let partial = cstr(&own["partial"].to_string());
    let msg4: Vec<Value> = others.iter().map(|o| o["msg4"].clone()).collect();
    let msg4 = to_c(&msg4);
    unsafe { dkls23_combine_signatures(partial.as_ptr(), msg4.as_ptr()) }
}

/// Full signing session. Every signer combines independently; all must
/// produce the same `r || s` hex signature, which is returned.
pub fn sign(keyshares: &[&str], path: &str, hash: &[u8; 32]) -> String {
    let partials: Vec<Value> = presign(keyshares, path)
        .iter()
        .map(|(_, handle)| partial(handle, hash))
        .collect();

    let sigs: Vec<String> = (0..partials.len())
        .map(|i| {
            let others: Vec<Value> = partials
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, p)| p.clone())
                .collect();
            ok(combine(&partials[i], &others))
        })
        .collect();
    assert!(sigs.windows(2).all(|w| w[0] == w[1]), "{sigs:?}");
    sigs.into_iter().next().unwrap()
}

/// Compressed SEC1 public key hex for `path`, via the FFI.
pub fn derive_public_key(keyshare: &str, path: &str) -> String {
    let (ks, path) = (cstr(keyshare), cstr(path));
    let out =
        ok(unsafe { dkls23_derive_public_key(ks.as_ptr(), path.as_ptr()) });
    json(&out)["derived_public_key"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// Verify an `r || s` hex signature over a prehashed message with the
/// independent RustCrypto ECDSA implementation.
pub fn verify(pubkey_hex: &str, hash: &[u8; 32], sig_hex: &str) -> bool {
    let vk = VerifyingKey::from_sec1_bytes(&hex::decode(pubkey_hex).unwrap())
        .unwrap();
    let sig_bytes = hex::decode(sig_hex).unwrap();
    assert_eq!(sig_bytes.len(), 64, "signature must be r || s");
    let sig = Signature::from_slice(&sig_bytes).unwrap();
    vk.verify_prehash(hash, &sig).is_ok()
}
