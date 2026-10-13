//! C ABI for FROST threshold Ed25519 signatures, built on the Zcash
//! Foundation `frost-ed25519` crate. Supports DKG and two-round threshold
//! signing.
//!
//! # Conventions
//!
//! * Party ids are one-based FROST identifiers, except `to_id` in DKG
//!   round 2 messages, which is zero-based to match the mobile transports.
//! * Every function returning `*mut c_char` hands ownership of a
//!   NUL-terminated string to the caller, who must release it with
//!   [`frost_free_string`]. NULL signals failure; the reason is available
//!   once from [`frost_get_last_error`] (stored per thread, cleared on
//!   success and when read).
//!
//! # Safety
//!
//! Every pointer argument must be NULL or valid for the documented access:
//! strings must be NUL-terminated, state pointers must come from the
//! matching `*_init` function and must not be used after being freed or
//! from several threads at once, and byte buffers must be readable for the
//! stated length.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use frost::{
    keys::{self, dkg},
    round1, round2, Identifier, SigningPackage,
};
use frost_ed25519 as frost;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use serde_json::Value;

// -------------------- Error handling --------------------

thread_local! {
    static LAST_ERROR: RefCell<Option<String>> = const { RefCell::new(None) };
}

fn set_last_error(err: impl std::fmt::Display) {
    // Interior NULs would make the message unrepresentable as a C string.
    let err = err.to_string().replace('\0', "");
    LAST_ERROR.with(|e| *e.borrow_mut() = Some(err));
}

fn clear_last_error() {
    LAST_ERROR.with(|e| *e.borrow_mut() = None);
}

fn take_last_error() -> Option<String> {
    LAST_ERROR.with(|e| e.borrow_mut().take())
}

fn invalid_arg(msg: &str) -> *mut c_char {
    set_last_error(msg);
    std::ptr::null_mut()
}

/// serde_json errors quote offending string values, which may be key
/// material; keep the error shape but drop the quoted contents.
fn redact(e: &serde_json::Error) -> String {
    let msg = e.to_string();
    let mut out = String::with_capacity(msg.len());
    let mut in_quote = false;
    for c in msg.chars() {
        if c == '"' {
            out.push_str(if in_quote { "\"" } else { "\"…" });
            in_quote = !in_quote;
        } else if !in_quote {
            out.push(c);
        }
    }
    out
}

/// Ed25519 child key derivation (SLIP-10) is not implemented, so only the
/// root path is accepted; anything else would silently return the root key.
unsafe fn check_root_path(path: *const c_char) -> Result<(), String> {
    if path.is_null() {
        return Ok(());
    }
    match CStr::from_ptr(path).to_str() {
        Ok("m") | Ok("") => Ok(()),
        _ => Err("Ed25519 child key derivation is not supported; only the \
                  root path \"m\" is accepted"
            .to_string()),
    }
}

fn null_with_err<T>(msg: &str) -> *mut T {
    set_last_error(msg);
    std::ptr::null_mut()
}

fn cstring_or_null(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(c) => {
            clear_last_error();
            c.into_raw()
        }
        Err(e) => invalid_arg(&format!("Failed to create C string: {e}")),
    }
}

// -------------------- Wire formats --------------------

#[derive(Serialize, Deserialize, Clone)]
struct Round1Msg {
    from: u16,
    package: dkg::round1::Package,
}

#[derive(Serialize, Deserialize, Clone)]
struct Round2Msg {
    from: u16,
    to_id: u16,
    package: dkg::round2::Package,
}

#[derive(Serialize, Deserialize, Clone)]
struct Keyshare {
    participant_id: u16,
    key_package: keys::KeyPackage,
    pubkey_package: keys::PublicKeyPackage,
}

#[derive(Serialize, Deserialize, Clone)]
struct SignatureShareBundle {
    participant_id: u16,
    signature_share: round2::SignatureShare,
    signing_package: SigningPackage,
    pubkey_package: keys::PublicKeyPackage,
}

fn id_from_u16(id: u16) -> Result<Identifier, frost::Error> {
    Identifier::try_from(id)
}

/// Accept list items either as JSON objects or as JSON-encoded strings.
fn parse_json_value<T: for<'a> Deserialize<'a>>(
    val: &Value,
) -> Result<T, serde_json::Error> {
    if let Some(s) = val.as_str() {
        serde_json::from_str(s)
    } else {
        serde_json::from_value(val.clone())
    }
}

// -------------------- DKG state --------------------

/// Opaque DKG state handed to C callers.
pub struct DkgState {
    id: Identifier,
    id_raw: u16,
    max_signers: u16,
    min_signers: u16,
    round1_secret: Option<dkg::round1::SecretPackage>,
    round1_pkgs: Option<BTreeMap<Identifier, dkg::round1::Package>>,
    round2_secret: Option<dkg::round2::SecretPackage>,
    keyshare: Option<Keyshare>,
}

// -------------------- Signing state --------------------

/// Opaque signing state handed to C callers.
pub struct SigningState {
    id: Identifier,
    id_raw: u16,
    key_package: keys::KeyPackage,
    pubkey_package: keys::PublicKeyPackage,
    message: Vec<u8>,
    nonces: Option<round1::SigningNonces>,
    commitments: Option<round1::SigningCommitments>,
}

fn take_signing_material(
    nonces: &mut Option<round1::SigningNonces>,
    commitments: &mut Option<round1::SigningCommitments>,
) -> Result<(round1::SigningNonces, round1::SigningCommitments), &'static str>
{
    let nonces = nonces
        .take()
        .ok_or("signing nonces already used or not generated")?;
    let commitments = commitments.take().ok_or("missing commitments")?;
    Ok((nonces, commitments))
}

// -------------------- FFI: Error handling --------------------

/// Return and clear the last error message of the calling thread, or NULL.
#[no_mangle]
pub extern "C" fn frost_get_last_error() -> *mut c_char {
    match take_last_error() {
        Some(err) => {
            CString::new(err).map_or(std::ptr::null_mut(), |c| c.into_raw())
        }
        None => std::ptr::null_mut(),
    }
}

/// Free a string returned by this library.
///
/// # Safety
///
/// `s` must be NULL or a string returned by this library that has not
/// been freed yet.
#[no_mangle]
pub unsafe extern "C" fn frost_free_string(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

// -------------------- FFI: DKG --------------------

/// Create a DKG state for `party_id` (1..=participants) in a
/// `threshold`-of-`participants` scheme.
#[no_mangle]
pub extern "C" fn frost_dkg_init(
    party_id: u16,
    participants: u16,
    threshold: u16,
) -> *mut DkgState {
    clear_last_error();
    if party_id == 0
        || party_id > participants
        || participants < 2
        || threshold < 2
        || threshold > participants
    {
        return null_with_err("invalid party_id/participants/threshold");
    }
    let id = match id_from_u16(party_id) {
        Ok(i) => i,
        Err(e) => return null_with_err(&format!("invalid identifier: {e}")),
    };
    let state = DkgState {
        id,
        id_raw: party_id,
        max_signers: participants,
        min_signers: threshold,
        round1_secret: None,
        round1_pkgs: None,
        round2_secret: None,
        keyshare: None,
    };
    Box::into_raw(Box::new(state))
}

/// DKG round 1: return this party's broadcast package.
///
/// # Safety
///
/// See the crate-level safety contract.
#[no_mangle]
pub unsafe extern "C" fn frost_dkg_generate_msg1(
    state: *mut DkgState,
) -> *mut c_char {
    let Some(st) = state.as_mut() else {
        return invalid_arg("NULL state");
    };
    let mut rng = thread_rng();
    match dkg::part1(st.id, st.max_signers, st.min_signers, &mut rng) {
        Ok((secret, pkg)) => {
            st.round1_secret = Some(secret);
            let msg = Round1Msg {
                from: st.id_raw,
                package: pkg,
            };
            match serde_json::to_string(&msg) {
                Ok(s) => cstring_or_null(s),
                Err(e) => invalid_arg(&format!("serialize msg1: {e}")),
            }
        }
        Err(e) => invalid_arg(&format!("dkg part1 error: {e}")),
    }
}

/// DKG round 2: consume the other parties' round 1 packages and return
/// one addressed round 2 message per recipient.
///
/// # Safety
///
/// See the crate-level safety contract.
#[no_mangle]
pub unsafe extern "C" fn frost_dkg_handle_msg1(
    state: *mut DkgState,
    msgs_json: *const c_char,
) -> *mut c_char {
    let Some(st) = state.as_mut() else {
        return invalid_arg("NULL state");
    };
    let secret = match st.round1_secret.take() {
        Some(s) => s,
        None => return invalid_arg("part1 not run"),
    };
    if msgs_json.is_null() {
        return invalid_arg("NULL msg1 payload");
    }
    let msgs_str = CStr::from_ptr(msgs_json).to_string_lossy();
    let values: Vec<Value> = match serde_json::from_str(&msgs_str) {
        Ok(v) => v,
        Err(e) => return invalid_arg(&format!("parse msgs: {}", redact(&e))),
    };
    if values.len() != usize::from(st.max_signers - 1) {
        return invalid_arg("unexpected number of round1 packages");
    }
    let mut round1_packages: BTreeMap<Identifier, dkg::round1::Package> =
        BTreeMap::new();
    let mut raw_ids: BTreeMap<Identifier, u16> = BTreeMap::new();
    for v in values {
        match parse_json_value::<Round1Msg>(&v) {
            Ok(m) => {
                if m.from == st.id_raw
                    || m.from == 0
                    || m.from > st.max_signers
                {
                    return invalid_arg("round1 package has invalid sender");
                }
                if let Ok(id) = id_from_u16(m.from) {
                    if round1_packages.contains_key(&id) {
                        return invalid_arg("duplicate round1 sender");
                    }
                    raw_ids.insert(id, m.from);
                    round1_packages.insert(id, m.package);
                } else {
                    return invalid_arg(
                        "round1 package has invalid identifier",
                    );
                }
            }
            Err(e) => {
                return invalid_arg(&format!(
                    "parse msg1 item: {}",
                    redact(&e)
                ))
            }
        }
    }
    match dkg::part2(secret, &round1_packages) {
        Ok((secret2, pkgs)) => {
            st.round1_pkgs = Some(round1_packages);
            st.round2_secret = Some(secret2);
            // Round 2 packages contain secret shares. Return one explicitly
            // addressed packet per recipient so callers cannot broadcast the
            // complete package map by accident.
            let mut out = Vec::with_capacity(pkgs.len());
            for (to_id, pkg) in pkgs {
                let Some(to_id_raw) = raw_ids.get(&to_id).copied() else {
                    return invalid_arg(
                        "round2 package has unknown recipient",
                    );
                };
                out.push(Round2Msg {
                    from: st.id_raw,
                    // Mobile transports use zero-based party IDs while FROST
                    // identifiers are non-zero and therefore one-based.
                    to_id: to_id_raw - 1,
                    package: pkg,
                });
            }
            match serde_json::to_string(&out) {
                Ok(s) => cstring_or_null(s),
                Err(e) => invalid_arg(&format!("serialize msg2: {e}")),
            }
        }
        Err(e) => invalid_arg(&format!("dkg part2 error: {e}")),
    }
}

/// DKG round 3: consume the round 2 messages addressed to this party and
/// return the keyshare JSON.
///
/// # Safety
///
/// See the crate-level safety contract.
#[no_mangle]
pub unsafe extern "C" fn frost_dkg_handle_msg2(
    state: *mut DkgState,
    msgs_json: *const c_char,
) -> *mut c_char {
    let Some(st) = state.as_mut() else {
        return invalid_arg("NULL state");
    };
    let secret2 = match st.round2_secret.take() {
        Some(s) => s,
        None => return invalid_arg("part2 not run"),
    };
    let round1_pkgs = match st.round1_pkgs.take() {
        Some(r) => r,
        None => return invalid_arg("missing round1 packages"),
    };

    if msgs_json.is_null() {
        return invalid_arg("NULL msg2 payload");
    }
    let msgs_str = CStr::from_ptr(msgs_json).to_string_lossy();
    let values: Vec<Value> = match serde_json::from_str(&msgs_str) {
        Ok(v) => v,
        Err(e) => {
            return invalid_arg(&format!("parse msgs2: {}", redact(&e)))
        }
    };
    if values.len() != usize::from(st.max_signers - 1) {
        return invalid_arg("unexpected number of round2 packages");
    }
    let mut round2_pkgs: BTreeMap<Identifier, dkg::round2::Package> =
        BTreeMap::new();
    for v in values {
        let m: Round2Msg = match parse_json_value(&v) {
            Ok(m) => m,
            Err(e) => {
                return invalid_arg(&format!(
                    "parse msg2 item: {}",
                    redact(&e)
                ))
            }
        };
        if m.to_id >= st.max_signers
            || m.to_id + 1 != st.id_raw
            || m.from == st.id_raw
            || m.from == 0
            || m.from > st.max_signers
        {
            return invalid_arg("round2 package has invalid route");
        }
        let sender = match id_from_u16(m.from) {
            Ok(sender) => sender,
            Err(e) => {
                return invalid_arg(&format!("invalid round2 sender: {e}"))
            }
        };
        if round2_pkgs.insert(sender, m.package).is_some() {
            return invalid_arg("duplicate round2 sender");
        }
    }

    match dkg::part3(&secret2, &round1_pkgs, &round2_pkgs) {
        Ok((key_package, pubkey_package)) => {
            let ks = Keyshare {
                participant_id: st.id_raw,
                key_package,
                pubkey_package,
            };
            let json = serde_json::to_string(&ks);
            st.keyshare = Some(ks);
            match json {
                Ok(s) => cstring_or_null(s),
                Err(e) => invalid_arg(&format!("serialize keyshare: {e}")),
            }
        }
        Err(e) => invalid_arg(&format!("dkg part3 error: {e}")),
    }
}

/// Return the keyshare produced by [`frost_dkg_handle_msg2`] again.
///
/// # Safety
///
/// See the crate-level safety contract.
#[no_mangle]
pub unsafe extern "C" fn frost_dkg_finalize(
    state: *mut DkgState,
) -> *mut c_char {
    let Some(st) = state.as_mut() else {
        return invalid_arg("NULL state");
    };
    if let Some(ks) = st.keyshare.as_ref() {
        match serde_json::to_string(ks) {
            Ok(s) => cstring_or_null(s),
            Err(e) => invalid_arg(&format!("serialize keyshare: {e}")),
        }
    } else {
        invalid_arg("keyshare not ready")
    }
}

/// Free a DKG state.
///
/// # Safety
///
/// `state` must be NULL or a live pointer from [`frost_dkg_init`].
#[no_mangle]
pub unsafe extern "C" fn frost_dkg_free_state(state: *mut DkgState) {
    if !state.is_null() {
        drop(Box::from_raw(state));
    }
}

// -------------------- FFI: Signing --------------------

/// Create a signing state for `keyshare_json` over the raw message bytes
/// (`message_hash` is signed as-is, not hashed again by the caller).
///
/// # Safety
///
/// `message_hash` must be NULL or readable for `message_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn frost_signing_init(
    keyshare_json: *const c_char,
    message_hash: *const u8,
    message_len: usize,
) -> *mut SigningState {
    clear_last_error();
    if keyshare_json.is_null() || message_hash.is_null() {
        return null_with_err("null params");
    }
    let ks_str = CStr::from_ptr(keyshare_json).to_string_lossy();
    let ks: Keyshare = match serde_json::from_str(&ks_str) {
        Ok(k) => k,
        Err(e) => {
            return null_with_err(&format!("parse keyshare: {}", redact(&e)))
        }
    };
    let id = match id_from_u16(ks.participant_id) {
        Ok(i) => i,
        Err(e) => {
            return null_with_err(&format!("invalid participant_id: {e}"))
        }
    };
    let msg = std::slice::from_raw_parts(message_hash, message_len).to_vec();
    let state = SigningState {
        id,
        id_raw: ks.participant_id,
        key_package: ks.key_package,
        pubkey_package: ks.pubkey_package,
        message: msg,
        nonces: None,
        commitments: None,
    };
    Box::into_raw(Box::new(state))
}

/// Signing round 1: generate nonces and return this party's commitments.
///
/// # Safety
///
/// See the crate-level safety contract.
#[no_mangle]
pub unsafe extern "C" fn frost_signing_generate_msg1(
    state: *mut SigningState,
) -> *mut c_char {
    let Some(st) = state.as_mut() else {
        return invalid_arg("NULL state");
    };
    if st.nonces.is_some() || st.commitments.is_some() {
        return invalid_arg("signing commitments already generated");
    }
    let mut rng = thread_rng();
    let (nonces, commitments) =
        round1::commit(st.key_package.signing_share(), &mut rng);
    st.nonces = Some(nonces);
    st.commitments = Some(commitments);
    #[derive(Serialize)]
    struct CommitOut {
        from: u16,
        commitments: round1::SigningCommitments,
    }
    match serde_json::to_string(&CommitOut {
        from: st.id_raw,
        commitments,
    }) {
        Ok(s) => cstring_or_null(s),
        Err(e) => invalid_arg(&format!("serialize commitments: {e}")),
    }
}

/// Signing round 2: consume the other signers' commitments and return
/// this party's signature share bundle.
///
/// # Safety
///
/// See the crate-level safety contract.
#[no_mangle]
pub unsafe extern "C" fn frost_signing_handle_msg1(
    state: *mut SigningState,
    msgs_json: *const c_char,
) -> *mut c_char {
    let Some(st) = state.as_mut() else {
        return invalid_arg("NULL state");
    };
    // Burn both nonces and commitments before parsing any peer-controlled
    // input. A failed or aborted attempt must never make them reusable.
    let (nonces, commitments_self) =
        match take_signing_material(&mut st.nonces, &mut st.commitments) {
            Ok(material) => material,
            Err(e) => return invalid_arg(e),
        };
    if msgs_json.is_null() {
        return invalid_arg("NULL signing commitments payload");
    }
    let msgs_str = CStr::from_ptr(msgs_json).to_string_lossy();
    let values: Vec<Value> = match serde_json::from_str(&msgs_str) {
        Ok(v) => v,
        Err(e) => {
            return invalid_arg(&format!(
                "parse msg1 commitments: {}",
                redact(&e)
            ))
        }
    };
    #[derive(Deserialize)]
    struct CommitIn {
        from: u16,
        commitments: round1::SigningCommitments,
    }
    let mut commitments_map: BTreeMap<
        Identifier,
        round1::SigningCommitments,
    > = BTreeMap::new();
    commitments_map.insert(st.id, commitments_self);
    for v in values {
        let cm: CommitIn = match parse_json_value(&v) {
            Ok(c) => c,
            Err(e) => {
                return invalid_arg(&format!(
                    "parse commitment item: {}",
                    redact(&e)
                ))
            }
        };
        if let Ok(pid) = id_from_u16(cm.from) {
            commitments_map.insert(pid, cm.commitments);
        }
    }
    let signing_package = SigningPackage::new(commitments_map, &st.message);
    let sig_share =
        match round2::sign(&signing_package, &nonces, &st.key_package) {
            Ok(s) => s,
            Err(e) => return invalid_arg(&format!("signing error: {e}")),
        };
    let bundle = SignatureShareBundle {
        participant_id: st.id_raw,
        signature_share: sig_share,
        signing_package,
        pubkey_package: st.pubkey_package.clone(),
    };
    match serde_json::to_string(&bundle) {
        Ok(s) => cstring_or_null(s),
        Err(e) => invalid_arg(&format!("serialize signature share: {e}")),
    }
}

/// No-op kept for API symmetry with DKLs23: FROST signing has only two
/// rounds. Always returns `"{}"`.
#[no_mangle]
pub extern "C" fn frost_signing_generate_msg2(
    _state: *mut SigningState,
) -> *mut c_char {
    cstring_or_null("{}".to_string())
}

/// No-op kept for API symmetry with DKLs23. Always returns `"{}"`.
#[no_mangle]
pub extern "C" fn frost_signing_handle_msg2(
    _state: *mut SigningState,
    _msgs_json: *const c_char,
) -> *mut c_char {
    cstring_or_null("{}".to_string())
}

/// Free a signing state.
///
/// # Safety
///
/// `state` must be NULL or a live pointer from [`frost_signing_init`].
#[no_mangle]
pub unsafe extern "C" fn frost_signing_free_state(state: *mut SigningState) {
    if !state.is_null() {
        drop(Box::from_raw(state));
    }
}

// -------------------- FFI: Signatures --------------------

/// Return a copy of `presig_json`, which already holds the signature share
/// and signing package. Kept for API symmetry with DKLs23.
///
/// # Safety
///
/// See the crate-level safety contract.
#[no_mangle]
pub unsafe extern "C" fn frost_create_partial_signature(
    presig_json: *const c_char,
    _message_hash: *const u8,
) -> *mut c_char {
    if presig_json.is_null() {
        return invalid_arg("null presig_json");
    }
    let s = CStr::from_ptr(presig_json).to_string_lossy().to_string();
    cstring_or_null(s)
}

/// Aggregate this party's share bundle with the other signers' bundles and
/// return the 64-byte Ed25519 signature as hex.
///
/// # Safety
///
/// See the crate-level safety contract.
#[no_mangle]
pub unsafe extern "C" fn frost_combine_signatures(
    partial_sig_json: *const c_char,
    msg_list_json: *const c_char,
) -> *mut c_char {
    if partial_sig_json.is_null() || msg_list_json.is_null() {
        return invalid_arg("null params");
    }
    let first_str = CStr::from_ptr(partial_sig_json).to_string_lossy();
    let msg_list_str = CStr::from_ptr(msg_list_json).to_string_lossy();

    let first: SignatureShareBundle = match serde_json::from_str(&first_str) {
        Ok(v) => v,
        Err(e) => {
            return invalid_arg(&format!(
                "parse first partial: {}",
                redact(&e)
            ))
        }
    };
    let vals: Vec<Value> = match serde_json::from_str(&msg_list_str) {
        Ok(v) => v,
        Err(e) => {
            return invalid_arg(&format!("parse msg list: {}", redact(&e)))
        }
    };

    let first_id = match id_from_u16(first.participant_id) {
        Ok(id) => id,
        Err(e) => {
            return invalid_arg(&format!("invalid participant_id: {e}"))
        }
    };
    let mut shares: BTreeMap<Identifier, round2::SignatureShare> =
        BTreeMap::new();
    shares.insert(first_id, first.signature_share);

    for v in vals {
        let bundle: SignatureShareBundle = match parse_json_value(&v) {
            Ok(b) => b,
            Err(e) => {
                return invalid_arg(&format!(
                    "parse partial item: {}",
                    redact(&e)
                ))
            }
        };
        if let Ok(pid) = id_from_u16(bundle.participant_id) {
            shares.insert(pid, bundle.signature_share);
        }
    }

    match frost::aggregate(
        &first.signing_package,
        &shares,
        &first.pubkey_package,
    ) {
        Ok(sig) => match sig.serialize() {
            Ok(bytes) => cstring_or_null(hex::encode(bytes)),
            Err(e) => invalid_arg(&format!("signature serialize: {e}")),
        },
        Err(e) => invalid_arg(&format!("aggregate error: {e}")),
    }
}

// -------------------- FFI: Utility --------------------

/// Return `{"derived_public_key": "<hex>"}` with the group verifying key.
///
/// Ed25519 derivation (SLIP-10) is not implemented: `derivation_path` must be
/// NULL, empty or "m"; any other path is rejected.
///
/// # Safety
///
/// See the crate-level safety contract.
#[no_mangle]
pub unsafe extern "C" fn frost_derive_public_key(
    keyshare_json: *const c_char,
    derivation_path: *const c_char,
) -> *mut c_char {
    if keyshare_json.is_null() {
        return invalid_arg("null keyshare");
    }
    if let Err(e) = check_root_path(derivation_path) {
        return invalid_arg(&e);
    }
    let ks_str = CStr::from_ptr(keyshare_json).to_string_lossy();
    let ks: Keyshare = match serde_json::from_str(&ks_str) {
        Ok(k) => k,
        Err(e) => {
            return invalid_arg(&format!("parse keyshare: {}", redact(&e)))
        }
    };

    let pubkey = ks.pubkey_package.verifying_key();
    match pubkey.serialize() {
        Ok(bytes) => {
            let resp = serde_json::json!({
                "derived_public_key": hex::encode(bytes)
            });
            cstring_or_null(resp.to_string())
        }
        Err(e) => invalid_arg(&format!("pubkey serialize: {e}")),
    }
}

/// Return the keyshare unchanged (re-serialized).
///
/// Ed25519 derivation (SLIP-10) is not implemented: `derivation_path` must be
/// NULL, empty or "m"; any other path is rejected.
///
/// # Safety
///
/// See the crate-level safety contract.
#[no_mangle]
pub unsafe extern "C" fn frost_derive_keyshare(
    keyshare_json: *const c_char,
    derivation_path: *const c_char,
) -> *mut c_char {
    if keyshare_json.is_null() {
        return invalid_arg("null keyshare");
    }
    if let Err(e) = check_root_path(derivation_path) {
        return invalid_arg(&e);
    }
    let ks_str = CStr::from_ptr(keyshare_json).to_string_lossy();
    let ks: Keyshare = match serde_json::from_str(&ks_str) {
        Ok(k) => k,
        Err(e) => {
            return invalid_arg(&format!("parse keyshare: {}", redact(&e)))
        }
    };
    match serde_json::to_string(&ks) {
        Ok(json) => cstring_or_null(json),
        Err(e) => invalid_arg(&format!("serialize keyshare: {e}")),
    }
}

/// Verify an Ed25519 signature. Returns `"true"` or `"false"`, or NULL if
/// an argument is malformed.
///
/// `public_key_json` is either a hex key or the JSON returned by
/// [`frost_derive_public_key`].
///
/// # Safety
///
/// `message` must be NULL or readable for `message_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn frost_verify_signature(
    public_key_json: *const c_char,
    message: *const u8,
    message_len: usize,
    signature_hex: *const c_char,
) -> *mut c_char {
    if public_key_json.is_null()
        || message.is_null()
        || signature_hex.is_null()
    {
        return invalid_arg("null params");
    }
    let pub_str = CStr::from_ptr(public_key_json).to_string_lossy();
    let sig_str = CStr::from_ptr(signature_hex).to_string_lossy();
    let derived_hex = if pub_str.contains("derived_public_key") {
        match serde_json::from_str::<Value>(&pub_str).ok().and_then(|v| {
            v.get("derived_public_key")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string())
        }) {
            Some(h) => h,
            None => return invalid_arg("invalid public key json"),
        }
    } else {
        pub_str.to_string()
    };
    let pub_bytes = match hex::decode(derived_hex) {
        Ok(b) => b,
        Err(e) => return invalid_arg(&format!("decode pubkey: {e}")),
    };
    let sig_bytes = match hex::decode(&*sig_str) {
        Ok(b) => b,
        Err(e) => return invalid_arg(&format!("decode signature: {e}")),
    };
    if message_len == 0 {
        return invalid_arg("message len 0");
    }
    let msg = std::slice::from_raw_parts(message, message_len);
    let vk = match frost::VerifyingKey::deserialize(&pub_bytes) {
        Ok(v) => v,
        Err(e) => return invalid_arg(&format!("pubkey parse: {e}")),
    };
    let sig = match frost::Signature::deserialize(&sig_bytes) {
        Ok(s) => s,
        Err(e) => return invalid_arg(&format!("signature parse: {e}")),
    };
    let ok = vk.verify(msg, &sig).is_ok();
    cstring_or_null(if ok { "true" } else { "false" }.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use frost::keys::IdentifierList;

    #[test]
    fn signing_material_is_single_use() {
        let mut rng = thread_rng();
        let (shares, _) = keys::generate_with_dealer(
            2,
            2,
            IdentifierList::Default,
            &mut rng,
        )
        .unwrap();
        let identifier = id_from_u16(1).unwrap();
        let secret_share = shares.get(&identifier).unwrap().clone();
        let key_package = keys::KeyPackage::try_from(secret_share).unwrap();
        let (nonces, commitments) =
            round1::commit(key_package.signing_share(), &mut rng);
        let mut nonces = Some(nonces);
        let mut commitments = Some(commitments);

        assert!(take_signing_material(&mut nonces, &mut commitments).is_ok());
        assert!(take_signing_material(&mut nonces, &mut commitments).is_err());
    }

    #[test]
    fn signing_material_requires_commitments() {
        let mut nonces = None;
        let mut commitments = None;
        let err =
            take_signing_material(&mut nonces, &mut commitments).unwrap_err();
        assert!(err.contains("not generated"), "{err}");
    }

    #[test]
    fn parse_json_value_accepts_object_or_string() {
        #[derive(Deserialize)]
        struct Item {
            from: u16,
        }
        let object: Item =
            parse_json_value(&serde_json::json!({ "from": 3 })).unwrap();
        let string: Item =
            parse_json_value(&Value::String(r#"{"from":4}"#.into())).unwrap();
        assert_eq!((object.from, string.from), (3, 4));
    }

    #[test]
    fn zero_is_not_a_valid_identifier() {
        assert!(id_from_u16(0).is_err());
        assert!(id_from_u16(1).is_ok());
    }

    #[test]
    fn last_error_is_taken_once_and_strips_nul() {
        set_last_error("bad\0input");
        assert_eq!(take_last_error().as_deref(), Some("badinput"));
        assert_eq!(take_last_error(), None);
    }
}

#[cfg(test)]
mod ffi_tests;
