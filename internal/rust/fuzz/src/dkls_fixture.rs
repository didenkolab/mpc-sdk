//! Honest DKLs23 protocol transcript, built once per fuzzing process.
//!
//! A 2-of-3 DKG and a 2-party signing session (parties 0 and 1) are run
//! through the C ABI. Before each message-handling call, party 0's state is
//! snapshotted with bincode so that every fuzz iteration starts from a fresh
//! copy of the exact state the real call would see.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::OnceLock;

use dkls23_ll::dkg::State as DkgState;
use dkls23_ll::dsg::State as DsgState;
use serde_json::Value;

use crate::dkls23::*;

pub const N: usize = 3;
pub const T: usize = 2;
// Public (non-hardened) BIP32 derivation only.
pub const PATH: &str = "m/44/60/0/0/7";
pub const HASH: [u8; 32] = [0x5a; 32];

pub struct Dkls {
    /// Party 0 DKG state before `dkg_handle_msg{1..4}`.
    pub dkg_state: [Vec<u8>; 4],
    /// Honest input of `dkg_handle_msg{1..4}` for party 0.
    pub dkg_input: [Value; 4],
    /// Honest `commitments_json` for `dkg_handle_msg3`.
    pub commitments: Value,
    pub keyshares: Vec<Value>,
    /// Party 0 signing state before `dsg_handle_msg{1..3}`.
    pub dsg_state: [Vec<u8>; 3],
    /// Honest input of `dsg_handle_msg{1..3}` for party 0.
    pub dsg_input: [Value; 3],
    /// Party 0's `partial` and the other signer's `msg4` list.
    pub partial: Value,
    pub msg4_others: Value,
}

pub fn take(ptr: *mut c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let s = unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .expect("FFI output must be UTF-8")
        .to_owned();
    unsafe { dkls23_free_string(ptr) };
    Some(s)
}

fn ok(ptr: *mut c_char) -> Value {
    match take(ptr) {
        Some(s) => {
            serde_json::from_str(&s).unwrap_or_else(|_| Value::String(s))
        }
        None => {
            panic!("honest call failed: {:?}", take(dkls23_get_last_error()))
        }
    }
}

fn c(v: &Value) -> CString {
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

fn from_others(msgs: &[Value], me: u64) -> Value {
    list(msgs.iter().filter(|m| field(m, "from_id") != me).cloned())
}

fn to_me(msgs: &[Value], me: u64) -> Value {
    list(msgs.iter().filter(|m| field(m, "to_id") == me).cloned())
}

fn snap<T: serde::Serialize>(state: *mut T) -> Vec<u8> {
    bincode::serialize(unsafe { &*state }).unwrap()
}

/// Fresh heap copy of a snapshotted DKG state; free with
/// `dkls23_dkg_free_state`.
pub fn dkg_state(snapshot: &[u8]) -> *mut DkgState {
    let state: DkgState = bincode::deserialize(snapshot).unwrap();
    Box::into_raw(Box::new(state))
}

/// Fresh heap copy of a snapshotted signing state; free with
/// `dkls23_dsg_free_state`.
pub fn dsg_state(snapshot: &[u8]) -> *mut DsgState {
    let state: DsgState = bincode::deserialize(snapshot).unwrap();
    Box::into_raw(Box::new(state))
}

pub fn dkls() -> &'static Dkls {
    static FIXTURE: OnceLock<Dkls> = OnceLock::new();
    FIXTURE.get_or_init(build)
}

fn build() -> Dkls {
    let parties: Vec<*mut DkgState> =
        (0..N as u8).map(|i| dkls23_dkg_init(i, N, T)).collect();
    let msg1: Vec<Value> = parties
        .iter()
        .map(|&p| ok(unsafe { dkls23_dkg_generate_msg1(p) }))
        .collect();

    let mut dkg_state: Vec<Vec<u8>> = Vec::new();
    let mut dkg_input: Vec<Value> = Vec::new();

    let mut msg2 = Vec::new();
    for (i, &p) in parties.iter().enumerate() {
        let input = from_others(&msg1, i as u64);
        if i == 0 {
            dkg_state.push(snap(p));
            dkg_input.push(input.clone());
        }
        msg2.extend(items(ok(unsafe {
            dkls23_dkg_handle_msg1(p, c(&input).as_ptr())
        })));
    }

    let mut msg3 = Vec::new();
    for (i, &p) in parties.iter().enumerate() {
        let input = to_me(&msg2, i as u64);
        if i == 0 {
            dkg_state.push(snap(p));
            dkg_input.push(input.clone());
        }
        msg3.extend(items(ok(unsafe {
            dkls23_dkg_handle_msg2(p, c(&input).as_ptr())
        })));
    }

    let commitments = list(
        parties
            .iter()
            .map(|&p| ok(unsafe { dkls23_dkg_calculate_commitment_2(p) })),
    );
    let mut msg4 = Vec::new();
    for (i, &p) in parties.iter().enumerate() {
        let input = to_me(&msg3, i as u64);
        if i == 0 {
            dkg_state.push(snap(p));
            dkg_input.push(input.clone());
        }
        msg4.push(ok(unsafe {
            dkls23_dkg_handle_msg3(
                p,
                c(&input).as_ptr(),
                c(&commitments).as_ptr(),
            )
        }));
    }

    let mut keyshares = Vec::new();
    for (i, &p) in parties.iter().enumerate() {
        let input = from_others(&msg4, i as u64);
        if i == 0 {
            dkg_state.push(snap(p));
            dkg_input.push(input.clone());
        }
        keyshares.push(ok(unsafe {
            dkls23_dkg_handle_msg4(p, c(&input).as_ptr())
        }));
        unsafe { dkls23_dkg_free_state(p) };
    }

    // Signing with parties 0 and 1.
    let path = CString::new(PATH).unwrap();
    let signers: Vec<*mut DsgState> = keyshares[..T]
        .iter()
        .map(|ks| unsafe { dkls23_dsg_init(c(ks).as_ptr(), path.as_ptr()) })
        .collect();
    assert!(signers.iter().all(|s| !s.is_null()));
    let smsg1: Vec<Value> = signers
        .iter()
        .map(|&s| ok(unsafe { dkls23_dsg_generate_msg1(s) }))
        .collect();

    let mut dsg_state: Vec<Vec<u8>> = Vec::new();
    let mut dsg_input: Vec<Value> = Vec::new();
    let mut smsg2 = Vec::new();
    for (i, &s) in signers.iter().enumerate() {
        let input = from_others(&smsg1, i as u64);
        if i == 0 {
            dsg_state.push(snap(s));
            dsg_input.push(input.clone());
        }
        smsg2.extend(items(ok(unsafe {
            dkls23_dsg_handle_msg1(s, c(&input).as_ptr())
        })));
    }
    let mut smsg3 = Vec::new();
    for (i, &s) in signers.iter().enumerate() {
        let input = to_me(&smsg2, i as u64);
        if i == 0 {
            dsg_state.push(snap(s));
            dsg_input.push(input.clone());
        }
        smsg3.extend(items(ok(unsafe {
            dkls23_dsg_handle_msg2(s, c(&input).as_ptr())
        })));
    }
    let mut partials = Vec::new();
    for (i, &s) in signers.iter().enumerate() {
        let input = to_me(&smsg3, i as u64);
        if i == 0 {
            dsg_state.push(snap(s));
            dsg_input.push(input.clone());
        }
        let handle =
            ok(unsafe { dkls23_dsg_handle_msg3(s, c(&input).as_ptr()) });
        partials.push(ok(unsafe {
            dkls23_create_partial_signature(
                c(&handle).as_ptr(),
                HASH.as_ptr(),
            )
        }));
        unsafe { dkls23_dsg_free_state(s) };
    }

    let partial = partials[0]["partial"].clone();
    let msg4_others = list(partials[1..].iter().map(|p| p["msg4"].clone()));
    // The honest transcript must combine, or the fuzz targets would only
    // exercise error paths.
    let sig = take(unsafe {
        dkls23_combine_signatures(
            c(&partial).as_ptr(),
            c(&msg4_others).as_ptr(),
        )
    });
    assert!(sig.is_some(), "honest signature did not combine");

    let fixture = Dkls {
        dkg_state: dkg_state.try_into().unwrap(),
        dkg_input: dkg_input.try_into().unwrap(),
        commitments,
        keyshares,
        dsg_state: dsg_state.try_into().unwrap(),
        dsg_input: dsg_input.try_into().unwrap(),
        partial,
        msg4_others,
    };
    fixture.self_check();
    fixture
}

impl Dkls {
    /// Restored snapshots must accept the honest input again.
    fn self_check(&self) {
        let st = dkg_state(&self.dkg_state[0]);
        ok(unsafe {
            dkls23_dkg_handle_msg1(st, c(&self.dkg_input[0]).as_ptr())
        });
        unsafe { dkls23_dkg_free_state(st) };
        let st = dkg_state(&self.dkg_state[3]);
        ok(unsafe {
            dkls23_dkg_handle_msg4(st, c(&self.dkg_input[3]).as_ptr())
        });
        unsafe { dkls23_dkg_free_state(st) };
        let st = dsg_state(&self.dsg_state[2]);
        ok(unsafe {
            dkls23_dsg_handle_msg3(st, c(&self.dsg_input[2]).as_ptr())
        });
        unsafe { dkls23_dsg_free_state(st) };
    }
}
