//! Honest FROST protocol transcript, built once per fuzzing process.
//!
//! A 2-of-3 DKG and a 2-party signing session (participants 1 and 2) are
//! run through the C ABI. FROST states are not serializable, so targets
//! rebuild participant 1's state per iteration; this is cheap, and the
//! peers' honest messages stay valid because they do not depend on
//! participant 1's own secrets.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::OnceLock;

use serde_json::Value;

use crate::frost::*;

pub const N: u16 = 3;
pub const T: u16 = 2;
pub const MESSAGE: &[u8] = b"fuzz message for frost signing";

pub struct Frost {
    /// Round 1 messages of participants 2 and 3.
    pub dkg_msg1_others: Value,
    /// Round 2 messages addressed to participant 1.
    pub dkg_msg2_to_me: Value,
    pub keyshares: Vec<Value>,
    /// Participant 2's signing commitments.
    pub commitments_others: Value,
    /// Share bundles of participant 1 and the list holding participant 2's.
    pub bundle: Value,
    pub bundles_others: Value,
    pub public_key: Value,
    pub signature: String,
}

pub fn take(ptr: *mut c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let s = unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .expect("FFI output must be UTF-8")
        .to_owned();
    unsafe { frost_free_string(ptr) };
    Some(s)
}

pub fn ok(ptr: *mut c_char) -> Value {
    match take(ptr) {
        Some(s) => {
            serde_json::from_str(&s).unwrap_or_else(|_| Value::String(s))
        }
        None => {
            panic!("honest call failed: {:?}", take(frost_get_last_error()))
        }
    }
}

pub fn c(v: &Value) -> CString {
    CString::new(v.to_string()).unwrap()
}

fn list(items: impl IntoIterator<Item = Value>) -> Value {
    Value::Array(items.into_iter().collect())
}

fn field(v: &Value, name: &str) -> u64 {
    v[name].as_u64().unwrap()
}

fn items(v: Value) -> Vec<Value> {
    match v {
        Value::Array(a) => a,
        other => vec![other],
    }
}

/// Participant 1 after DKG round 1, ready for `frost_dkg_handle_msg1`.
pub fn dkg_party1() -> *mut DkgState {
    let st = frost_dkg_init(1, N, T);
    ok(unsafe { frost_dkg_generate_msg1(st) });
    st
}

/// Participant 1 after DKG round 2, ready for `frost_dkg_handle_msg2`.
pub fn dkg_party1_round2(f: &Frost) -> *mut DkgState {
    let st = dkg_party1();
    ok(unsafe { frost_dkg_handle_msg1(st, c(&f.dkg_msg1_others).as_ptr()) });
    st
}

/// Participant 1's signing state after round 1, ready for
/// `frost_signing_handle_msg1`.
pub fn signer1(f: &Frost) -> *mut SigningState {
    let st = unsafe {
        frost_signing_init(
            c(&f.keyshares[0]).as_ptr(),
            MESSAGE.as_ptr(),
            MESSAGE.len(),
        )
    };
    ok(unsafe { frost_signing_generate_msg1(st) });
    st
}

pub fn frost() -> &'static Frost {
    static FIXTURE: OnceLock<Frost> = OnceLock::new();
    FIXTURE.get_or_init(build)
}

fn build() -> Frost {
    let parties: Vec<*mut DkgState> =
        (1..=N).map(|id| frost_dkg_init(id, N, T)).collect();
    let msg1: Vec<Value> = parties
        .iter()
        .map(|&p| ok(unsafe { frost_dkg_generate_msg1(p) }))
        .collect();
    let others = |msgs: &[Value], me: u64| {
        list(msgs.iter().filter(|m| field(m, "from") != me).cloned())
    };
    let mut msg2 = Vec::new();
    for (i, &p) in parties.iter().enumerate() {
        let input = others(&msg1, i as u64 + 1);
        msg2.extend(items(ok(unsafe {
            frost_dkg_handle_msg1(p, c(&input).as_ptr())
        })));
    }
    let to_me = |me: u64| {
        list(msg2.iter().filter(|m| field(m, "to_id") == me - 1).cloned())
    };
    let keyshares: Vec<Value> = parties
        .iter()
        .enumerate()
        .map(|(i, &p)| {
            let input = to_me(i as u64 + 1);
            let ks =
                ok(unsafe { frost_dkg_handle_msg2(p, c(&input).as_ptr()) });
            unsafe { frost_dkg_free_state(p) };
            ks
        })
        .collect();

    let signers: Vec<*mut SigningState> = keyshares[..usize::from(T)]
        .iter()
        .map(|ks| unsafe {
            frost_signing_init(
                c(ks).as_ptr(),
                MESSAGE.as_ptr(),
                MESSAGE.len(),
            )
        })
        .collect();
    let commits: Vec<Value> = signers
        .iter()
        .map(|&s| ok(unsafe { frost_signing_generate_msg1(s) }))
        .collect();
    let bundles: Vec<Value> = signers
        .iter()
        .enumerate()
        .map(|(i, &s)| {
            let input = others(&commits, i as u64 + 1);
            let b = ok(unsafe {
                frost_signing_handle_msg1(s, c(&input).as_ptr())
            });
            unsafe { frost_signing_free_state(s) };
            b
        })
        .collect();
    let bundles_others = list(bundles[1..].iter().cloned());
    let signature = ok(unsafe {
        frost_combine_signatures(
            c(&bundles[0]).as_ptr(),
            c(&bundles_others).as_ptr(),
        )
    });
    let path = CString::new("m").unwrap();
    let public_key = ok(unsafe {
        frost_derive_public_key(c(&keyshares[0]).as_ptr(), path.as_ptr())
    });

    let fixture = Frost {
        dkg_msg1_others: others(&msg1, 1),
        dkg_msg2_to_me: to_me(1),
        commitments_others: others(&commits, 1),
        bundle: bundles[0].clone(),
        bundles_others,
        public_key,
        signature: signature.as_str().unwrap().to_owned(),
        keyshares,
    };
    // Rebuilt participant states must accept the honest messages.
    let st = dkg_party1_round2(&fixture);
    ok(unsafe {
        frost_dkg_handle_msg2(st, c(&fixture.dkg_msg2_to_me).as_ptr())
    });
    unsafe { frost_dkg_free_state(st) };
    let st = signer1(&fixture);
    ok(unsafe {
        frost_signing_handle_msg1(st, c(&fixture.commitments_others).as_ptr())
    });
    unsafe { frost_signing_free_state(st) };
    fixture
}
