//! Fuzz target bodies. Each `fuzz_targets/<name>.rs` calls the function of
//! the same name here, so crashes can also be replayed from ordinary code.
//!
//! Besides "no panic", every target checks that a NULL result comes with a
//! last-error message.

use std::ffi::CString;
use std::os::raw::c_char;
use std::sync::OnceLock;

use serde_json::Value;

use crate::dkls23::*;
use crate::dkls_fixture::{self as dk, dkls};
use crate::frost::*;
use crate::frost_fixture::{self as fr, frost};
use crate::input::{args, Arg};

/// Honest arguments built once per call site (rendering a DKLs23 keyshare
/// costs milliseconds).
macro_rules! honest {
    ($($arg:expr),+ $(,)?) => {{
        static ARGS: OnceLock<Vec<Arg>> = OnceLock::new();
        ARGS.get_or_init(|| vec![$($arg),+]).as_slice()
    }};
}

// -------------------- DKLs23 --------------------

fn dkls_out(ptr: *mut c_char) -> Option<String> {
    let out = dk::take(ptr);
    if out.is_none() {
        assert!(
            dk::take(dkls23_get_last_error()).is_some(),
            "NULL result without last error"
        );
    }
    out
}

fn c(v: &Value) -> CString {
    CString::new(v.to_string()).unwrap()
}

pub fn dkls_dkg_msg1(data: &[u8]) {
    let f = dkls();
    let a = args(data, honest![Arg::json(f.dkg_input[0].clone())]);
    let st = dk::dkg_state(&f.dkg_state[0]);
    dkls_out(unsafe { dkls23_dkg_handle_msg1(st, a[0].as_ptr()) });
    unsafe { dkls23_dkg_free_state(st) };
}

pub fn dkls_dkg_msg2(data: &[u8]) {
    let f = dkls();
    let a = args(data, honest![Arg::json(f.dkg_input[1].clone())]);
    let st = dk::dkg_state(&f.dkg_state[1]);
    dkls_out(unsafe { dkls23_dkg_handle_msg2(st, a[0].as_ptr()) });
    unsafe { dkls23_dkg_free_state(st) };
}

pub fn dkls_dkg_msg3(data: &[u8]) {
    let f = dkls();
    let a = args(
        data,
        honest![
            Arg::json(f.dkg_input[2].clone()),
            Arg::json(f.commitments.clone()),
        ],
    );
    let st = dk::dkg_state(&f.dkg_state[2]);
    dkls_out(unsafe {
        dkls23_dkg_handle_msg3(st, a[0].as_ptr(), a[1].as_ptr())
    });
    unsafe { dkls23_dkg_free_state(st) };
}

pub fn dkls_dkg_msg4(data: &[u8]) {
    let f = dkls();
    let a = args(data, honest![Arg::json(f.dkg_input[3].clone())]);
    let st = dk::dkg_state(&f.dkg_state[3]);
    dkls_out(unsafe { dkls23_dkg_handle_msg4(st, a[0].as_ptr()) });
    unsafe { dkls23_dkg_free_state(st) };
}

/// Fuzzed keyshare and derivation path; a state that initializes is then
/// driven through the signing rounds with the honest peer messages so a
/// corrupted keyshare reaches the protocol code too.
pub fn dkls_dsg_init(data: &[u8]) {
    let f = dkls();
    let a = args(
        data,
        honest![Arg::json(f.keyshares[0].clone()), Arg::text(dk::PATH),],
    );
    let st = unsafe { dkls23_dsg_init(a[0].as_ptr(), a[1].as_ptr()) };
    if st.is_null() {
        dkls_out(std::ptr::null_mut());
        return;
    }
    dkls_out(unsafe { dkls23_dsg_generate_msg1(st) });
    if dkls_out(unsafe {
        dkls23_dsg_handle_msg1(st, c(&f.dsg_input[0]).as_ptr())
    })
    .is_some()
    {
        dkls_out(unsafe {
            dkls23_dsg_handle_msg2(st, c(&f.dsg_input[1]).as_ptr())
        });
        dkls_out(unsafe {
            dkls23_dsg_handle_msg3(st, c(&f.dsg_input[2]).as_ptr())
        });
    }
    unsafe { dkls23_dsg_free_state(st) };
}

pub fn dkls_dsg_msg1(data: &[u8]) {
    let f = dkls();
    let a = args(data, honest![Arg::json(f.dsg_input[0].clone())]);
    let st = dk::dsg_state(&f.dsg_state[0]);
    dkls_out(unsafe { dkls23_dsg_handle_msg1(st, a[0].as_ptr()) });
    unsafe { dkls23_dsg_free_state(st) };
}

pub fn dkls_dsg_msg2(data: &[u8]) {
    let f = dkls();
    let a = args(data, honest![Arg::json(f.dsg_input[1].clone())]);
    let st = dk::dsg_state(&f.dsg_state[1]);
    dkls_out(unsafe { dkls23_dsg_handle_msg2(st, a[0].as_ptr()) });
    unsafe { dkls23_dsg_free_state(st) };
}

pub fn dkls_dsg_msg3(data: &[u8]) {
    let f = dkls();
    let a = args(data, honest![Arg::json(f.dsg_input[2].clone())]);
    let st = dk::dsg_state(&f.dsg_state[2]);
    dkls_out(unsafe { dkls23_dsg_handle_msg3(st, a[0].as_ptr()) });
    unsafe { dkls23_dsg_free_state(st) };
}

/// Fuzzed presignature handle JSON against a registry holding one live
/// presignature from an honest round 3.
pub fn dkls_partial_sig(data: &[u8]) {
    let f = dkls();
    let st = dk::dsg_state(&f.dsg_state[2]);
    let handle = dkls_out(unsafe {
        dkls23_dsg_handle_msg3(st, c(&f.dsg_input[2]).as_ptr())
    })
    .expect("honest round 3");
    unsafe { dkls23_dsg_free_state(st) };
    let handle: Value = serde_json::from_str(&handle).unwrap();
    let a = args(data, &[Arg::json(handle.clone())]);
    dkls_out(unsafe {
        dkls23_create_partial_signature(a[0].as_ptr(), dk::HASH.as_ptr())
    });
    // Burn the honest handle so the registry does not grow.
    dkls_out(unsafe {
        dkls23_create_partial_signature(
            c(&handle).as_ptr(),
            dk::HASH.as_ptr(),
        )
    });
}

pub fn dkls_combine(data: &[u8]) {
    let f = dkls();
    let a = args(
        data,
        honest![
            Arg::json(f.partial.clone()),
            Arg::json(f.msg4_others.clone()),
        ],
    );
    dkls_out(unsafe {
        dkls23_combine_signatures(a[0].as_ptr(), a[1].as_ptr())
    });
}

pub fn dkls_derive(data: &[u8]) {
    let f = dkls();
    let a = args(
        data,
        honest![Arg::json(f.keyshares[0].clone()), Arg::text(dk::PATH),],
    );
    dkls_out(unsafe {
        dkls23_derive_public_key(a[0].as_ptr(), a[1].as_ptr())
    });
    dkls_out(unsafe { dkls23_derive_keyshare(a[0].as_ptr(), a[1].as_ptr()) });
}

// -------------------- FROST --------------------

fn frost_out(ptr: *mut c_char) -> Option<String> {
    let out = fr::take(ptr);
    if out.is_none() {
        assert!(
            fr::take(frost_get_last_error()).is_some(),
            "NULL result without last error"
        );
    }
    out
}

pub fn frost_dkg_msg1(data: &[u8]) {
    let f = frost();
    let a = args(data, honest![Arg::json(f.dkg_msg1_others.clone())]);
    let st = fr::dkg_party1();
    frost_out(unsafe { frost_dkg_handle_msg1(st, a[0].as_ptr()) });
    unsafe { frost_dkg_free_state(st) };
}

pub fn frost_dkg_msg2(data: &[u8]) {
    let f = frost();
    let a = args(data, honest![Arg::json(f.dkg_msg2_to_me.clone())]);
    let st = fr::dkg_party1_round2(f);
    frost_out(unsafe { frost_dkg_handle_msg2(st, a[0].as_ptr()) });
    unsafe { frost_dkg_free_state(st) };
}

/// Sign with the resulting share bundle and aggregate it with the honest
/// bundle of the other signer.
fn frost_sign_and_combine(st: *mut SigningState, commitments: &CString) {
    let f = frost();
    if let Some(bundle) = frost_out(unsafe {
        frost_signing_handle_msg1(st, commitments.as_ptr())
    }) {
        let bundle = CString::new(bundle).unwrap();
        frost_out(unsafe {
            frost_combine_signatures(
                bundle.as_ptr(),
                c(&f.bundles_others).as_ptr(),
            )
        });
    }
}

pub fn frost_signing_init(data: &[u8]) {
    let f = frost();
    let a = args(data, honest![Arg::json(f.keyshares[0].clone())]);
    let st = unsafe {
        crate::frost::frost_signing_init(
            a[0].as_ptr(),
            fr::MESSAGE.as_ptr(),
            fr::MESSAGE.len(),
        )
    };
    if st.is_null() {
        frost_out(std::ptr::null_mut());
        return;
    }
    if frost_out(unsafe { frost_signing_generate_msg1(st) }).is_some() {
        frost_sign_and_combine(st, &c(&f.commitments_others));
    }
    unsafe { frost_signing_free_state(st) };
}

pub fn frost_signing_msg1(data: &[u8]) {
    let f = frost();
    let a = args(data, honest![Arg::json(f.commitments_others.clone())]);
    let st = fr::signer1(f);
    frost_sign_and_combine(st, &a[0]);
    unsafe { frost_signing_free_state(st) };
}

pub fn frost_combine(data: &[u8]) {
    let f = frost();
    let a = args(
        data,
        honest![
            Arg::json(f.bundle.clone()),
            Arg::json(f.bundles_others.clone()),
        ],
    );
    frost_out(unsafe {
        frost_combine_signatures(a[0].as_ptr(), a[1].as_ptr())
    });
}

pub fn frost_verify(data: &[u8]) {
    let f = frost();
    let a = args(
        data,
        honest![Arg::json(f.public_key.clone()), Arg::text(&f.signature),],
    );
    frost_out(unsafe {
        frost_verify_signature(
            a[0].as_ptr(),
            fr::MESSAGE.as_ptr(),
            fr::MESSAGE.len(),
            a[1].as_ptr(),
        )
    });
}

pub fn frost_derive(data: &[u8]) {
    let f = frost();
    let a = args(data, honest![Arg::json(f.keyshares[0].clone())]);
    let path = CString::new("m").unwrap();
    frost_out(unsafe {
        frost_derive_public_key(a[0].as_ptr(), path.as_ptr())
    });
    frost_out(unsafe { frost_derive_keyshare(a[0].as_ptr(), path.as_ptr()) });
}
