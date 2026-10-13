// Copyright (c) Vadym Didenko
// SPDX-License-Identifier: Apache-2.0

//! C ABI for DKLs23 threshold ECDSA (secp256k1).
//!
//! # Conventions
//!
//! * Party ids are zero-based. Protocol messages are JSON and carry
//!   `from_id` (and `to_id` for point-to-point messages).
//! * Every function returning `*mut c_char` hands ownership of a
//!   NUL-terminated string to the caller, who must release it with
//!   [`dkls23_free_string`]. NULL signals failure; the reason is available
//!   from [`dkls23_get_last_error`] (stored per thread).
//! * State handles returned by the `*_init` functions must be released with
//!   the matching `*_free_state` function.
//!
//! # Safety
//!
//! Every pointer argument must be NULL or valid for the documented access:
//! strings must be NUL-terminated, state pointers must come from the
//! matching `*_init` function and must not be used after being freed or
//! from several threads at once, and byte buffers must be readable for the
//! stated length.

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;
use std::str::FromStr;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use derivation_path::DerivationPath;
use dkls23_ll::dkg::{
    KeygenMsg1, KeygenMsg2, KeygenMsg3, KeygenMsg4, Keyshare, Party,
    State as DkgState,
};
use dkls23_ll::dsg::{
    combine_signatures, create_partial_signature, derive_with_offset,
    PartialSignature, PreSignature, SignMsg1, SignMsg2, SignMsg3, SignMsg4,
    State as DsgState,
};
use k256::elliptic_curve::group::prime::PrimeCurveAffine;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::ProjectivePoint;
use rand::{thread_rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sl_mpc_mate::bip32::{derive_child_pubkey, BIP32Error};

// -------------------- Error handling --------------------

thread_local! {
    static LAST_ERROR: RefCell<Option<String>> = const { RefCell::new(None) };
}

fn last_error() -> Option<String> {
    LAST_ERROR.with(|e| e.borrow().clone())
}

fn set_last_error(err: impl Into<String>) {
    // Interior NULs would make the message unrepresentable as a C string.
    let err = err.into().replace('\0', "");
    LAST_ERROR.with(|e| *e.borrow_mut() = Some(err));
}

/// Record `err` as the last error and return NULL.
fn fail<T>(err: impl Into<String>) -> *mut T {
    set_last_error(err);
    ptr::null_mut()
}

fn into_c_string(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(c) => c.into_raw(),
        Err(e) => fail(format!("Failed to create C string: {e}")),
    }
}

/// Run an FFI body that produces a string, converting errors into NULL.
fn ffi_string(body: impl FnOnce() -> Result<String, String>) -> *mut c_char {
    match body() {
        Ok(s) => into_c_string(s),
        Err(e) => fail(e),
    }
}

/// Run an FFI body that produces a state object, boxing it for the caller.
fn ffi_state<T>(body: impl FnOnce() -> Result<T, String>) -> *mut T {
    match body() {
        Ok(state) => Box::into_raw(Box::new(state)),
        Err(e) => fail(e),
    }
}

fn ser_err(what: &str) -> impl FnOnce(serde_json::Error) -> String + '_ {
    move |e| format!("Failed to serialize {what}: {e}")
}

fn parse_err(what: &str) -> impl FnOnce(serde_json::Error) -> String + '_ {
    move |e| {
        format!(
            "Failed to parse {what} JSON: {}",
            redact_quoted(&e.to_string())
        )
    }
}

/// serde_json errors quote offending string values, which may be key
/// material; keep the error shape but drop the quoted contents.
fn redact_quoted(msg: &str) -> String {
    let mut out = String::with_capacity(msg.len());
    let mut in_quote = false;
    for c in msg.chars() {
        if c == '"' {
            if !in_quote {
                out.push_str("\"…");
            }
            in_quote = !in_quote;
            if !in_quote {
                out.push('"');
            }
        } else if !in_quote {
            out.push(c);
        }
    }
    out
}

unsafe fn str_arg<'a>(
    ptr: *const c_char,
    what: &str,
) -> Result<&'a str, String> {
    if ptr.is_null() {
        return Err(format!("NULL {what} pointer"));
    }
    CStr::from_ptr(ptr)
        .to_str()
        .map_err(|e| format!("Invalid UTF-8 in {what}: {e}"))
}

unsafe fn state_mut<'a, T>(state: *mut T) -> Result<&'a mut T, String> {
    state
        .as_mut()
        .ok_or_else(|| "NULL state pointer".to_string())
}

// -------------------- Round tracking --------------------

// Each protocol round must run exactly once per state: re-running a round
// re-uses its secret randomness against attacker-chosen messages, and a
// round that failed inside the protocol code may leave the state half
// updated. States created by the init functions are tracked by address;
// a failure inside the protocol code poisons the state for good. Failures
// before the protocol code runs (bad JSON, wrong senders) leave it usable.

#[derive(Clone, Copy)]
enum Progress {
    Next(u8),
    Poisoned,
}

static PROGRESS: OnceLock<Mutex<HashMap<usize, Progress>>> = OnceLock::new();

fn with_progress<R>(f: impl FnOnce(&mut HashMap<usize, Progress>) -> R) -> R {
    let mut map = PROGRESS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    f(&mut map)
}

fn track<T>(state: *mut T) -> *mut T {
    if !state.is_null() {
        with_progress(|m| m.insert(state as usize, Progress::Next(1)));
    }
    state
}

fn untrack<T>(state: *mut T) {
    with_progress(|m| m.remove(&(state as usize)));
}

/// Fail unless `round` is the next round of `state`.
fn check_round<T>(
    state: *mut T,
    round: u8,
    what: &str,
) -> Result<(), String> {
    match with_progress(|m| m.get(&(state as usize)).copied()) {
        None => Ok(()),
        Some(Progress::Next(next)) if next == round => Ok(()),
        Some(Progress::Poisoned) => Err(format!(
            "Failed to handle {what}: state is unusable after an earlier \
             protocol error; start a new session"
        )),
        Some(Progress::Next(next)) => Err(format!(
            "Failed to handle {what}: out of order (expected round {next})"
        )),
    }
}

/// Record the outcome of the protocol step for `round`.
fn finish_round<T, R, E: std::fmt::Debug>(
    state: *mut T,
    round: u8,
    what: &str,
    result: Result<R, E>,
) -> Result<R, String> {
    with_progress(|m| {
        if let Some(p) = m.get_mut(&(state as usize)) {
            *p = match result {
                Ok(_) => Progress::Next(round + 1),
                Err(_) => Progress::Poisoned,
            };
        }
    });
    result.map_err(|e| format!("Failed to handle {what}: {e:?}"))
}

// -------------------- Sender validation --------------------

// The protocol code looks per-party data up by `from_id` and panics when a
// lookup misses. Across the C ABI a panic aborts the host process, so
// every peer message is checked against the expected sender set first.

/// Fail unless every sender is in `expected` and appears at most once.
fn check_senders(
    round: &str,
    expected: impl IntoIterator<Item = u8>,
    senders: impl IntoIterator<Item = u8>,
) -> Result<(), String> {
    let expected: BTreeSet<u8> = expected.into_iter().collect();
    let mut seen = BTreeSet::new();
    for from in senders {
        if !expected.contains(&from) || !seen.insert(from) {
            return Err(format!(
                "Failed to handle {round}: unexpected sender {from}"
            ));
        }
    }
    Ok(())
}

fn dkg_party_id(state: &DkgState) -> u8 {
    state.generate_msg1().from_id
}

/// Parties other than `me` among `0..n`.
fn peers_of(me: u8, n: usize) -> impl Iterator<Item = u8> {
    (0..=u8::MAX).take(n).filter(move |&p| p != me)
}

/// DKG peers once round 1 has been processed (`sid_i_list` then holds
/// every party).
fn dkg_peers(state: &DkgState) -> impl Iterator<Item = u8> + '_ {
    let me = dkg_party_id(state);
    state
        .sid_i_list
        .iter()
        .map(|(p, _)| *p)
        .filter(move |&p| p != me)
}

/// Signers other than this party once signing round 1 has been processed.
fn dsg_peers(state: &DsgState) -> impl Iterator<Item = u8> + '_ {
    let me = state.keyshare.party_id;
    state
        .sid_list
        .iter()
        .map(|(p, _)| *p)
        .filter(move |&p| p != me)
}

/// Validate the signer set once every peer's round 1 message is known.
///
/// The protocol needs exactly `threshold` signers; with any other count it
/// only fails at `combine_signatures` with an opaque curve error. For
/// ranked keys the set must also be poised for Birkhoff interpolation
/// (ranks sorted ascending satisfy `rank[i] <= i`); otherwise the
/// interpolation matrix is singular and the protocol code panics.
fn check_signer_set(
    keyshare: &Keyshare,
    peers: Vec<u8>,
) -> Result<(), String> {
    let expected = usize::from(keyshare.threshold).saturating_sub(1);
    if peers.len() != expected {
        return Err(format!(
            "Failed to handle msg1: expected {expected} peer messages \
             (threshold {}), got {}",
            keyshare.threshold,
            peers.len()
        ));
    }
    let mut ranks = peers
        .iter()
        .chain([&keyshare.party_id])
        .map(|&p| keyshare.rank_list.get(usize::from(p)).copied())
        .collect::<Option<Vec<u8>>>()
        .ok_or("Failed to handle msg1: party id outside the rank list")?;
    ranks.sort_unstable();
    if ranks.iter().enumerate().any(|(i, &r)| usize::from(r) > i) {
        return Err(format!(
            "Failed to handle msg1: signer ranks {ranks:?} cannot \
             reconstruct the key (need sorted rank[i] <= i)"
        ));
    }
    Ok(())
}

/// Validate the shape of a keyshare before signing with it.
///
/// The signing code indexes the per-party lists by party id without bounds
/// checks, inverts the threshold, and inverts a Birkhoff matrix that is
/// singular when evaluation points repeat. Several of these lists are
/// private to `dkls23_ll`, so they are checked on the JSON form.
fn check_keyshare(
    keyshare: &Keyshare,
    json: &serde_json::Value,
) -> Result<(), String> {
    let n = keyshare.rank_list.len();
    let me = usize::from(keyshare.party_id);
    if keyshare.threshold == 0 || me >= n {
        return Err("Invalid keyshare: threshold or party_id out of range"
            .to_string());
    }
    let lists =
        |field: &str| json.get(field).and_then(serde_json::Value::as_array);
    for (field, expected) in [
        ("x_i_list", n),
        ("seed_ot_receivers", n - 1),
        ("seed_ot_senders", n - 1),
        ("rec_seed_list", me),
        ("sent_seed_list", n - 1 - me),
    ] {
        if lists(field).map(Vec::len) != Some(expected) {
            return Err(format!(
                "Invalid keyshare: {field} must have {expected} entries"
            ));
        }
    }
    let points = lists("x_i_list").map_or(&[][..], Vec::as_slice);
    let same = |a: &serde_json::Value, b: &serde_json::Value| match (
        a.as_str(),
        b.as_str(),
    ) {
        (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
        _ => a == b,
    };
    if points
        .iter()
        .enumerate()
        .any(|(i, a)| points[..i].iter().any(|b| same(a, b)))
    {
        return Err(
            "Invalid keyshare: duplicate x_i_list entries".to_string()
        );
    }
    Ok(())
}

// -------------------- Randomness --------------------

/// ChaCha20 RNG seeded from OS entropy (falling back to `thread_rng`).
///
/// `context` and the current time are mixed into the seed so that parties
/// running on the same host never share a stream, even if the entropy
/// source is degraded.
fn entropy_rng(context: &[u8]) -> ChaCha20Rng {
    let mut seed = [0u8; 32];
    if getrandom::getrandom(&mut seed).is_err() {
        thread_rng().fill_bytes(&mut seed);
    }
    for (s, c) in seed.iter_mut().zip(context) {
        *s ^= c;
    }
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .to_le_bytes();
    for (s, t) in seed[16..].iter_mut().zip(nanos) {
        *s ^= t;
    }
    ChaCha20Rng::from_seed(seed)
}

// -------------------- Presignature registry --------------------

// Presignatures never cross the FFI boundary. Callers receive an opaque,
// single-use handle so nonce material cannot be replayed or persisted.

const PRESIGNATURE_TTL: Duration = Duration::from_secs(15 * 60);

struct StoredPreSignature {
    value: PreSignature,
    created_at: Instant,
}

type PreSignatureMap = HashMap<String, StoredPreSignature>;

static PRESIGNATURES: OnceLock<Mutex<PreSignatureMap>> = OnceLock::new();

fn presignature_registry() -> &'static Mutex<PreSignatureMap> {
    PRESIGNATURES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn purge_expired_presignatures(entries: &mut PreSignatureMap) {
    let now = Instant::now();
    entries.retain(|_, entry| {
        now.saturating_duration_since(entry.created_at) < PRESIGNATURE_TTL
    });
}

fn store_presignature(presignature: PreSignature) -> Result<String, String> {
    let mut token_bytes = [0u8; 32];
    getrandom::getrandom(&mut token_bytes).map_err(|e| {
        format!("failed to generate presignature handle: {e}")
    })?;
    let token = hex::encode(token_bytes);

    let mut entries = presignature_registry()
        .lock()
        .map_err(|_| "presignature registry unavailable".to_string())?;
    purge_expired_presignatures(&mut entries);
    if entries.contains_key(&token) {
        return Err("presignature handle collision".to_string());
    }
    entries.insert(
        token.clone(),
        StoredPreSignature {
            value: presignature,
            created_at: Instant::now(),
        },
    );

    Ok(serde_json::json!({ "presignature_handle": token }).to_string())
}

fn take_presignature(handle_json: &str) -> Result<PreSignature, String> {
    let value: serde_json::Value = serde_json::from_str(handle_json)
        .map_err(|e| format!("failed to parse presignature handle: {e}"))?;
    let handle = value
        .get("presignature_handle")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "missing presignature_handle".to_string())?;

    let mut entries = presignature_registry()
        .lock()
        .map_err(|_| "presignature registry unavailable".to_string())?;
    purge_expired_presignatures(&mut entries);
    entries
        .remove(handle)
        .map(|entry| entry.value)
        .ok_or_else(|| {
            "presignature is unknown, expired, or already consumed"
                .to_string()
        })
}

// -------------------- FFI: Error handling --------------------

/// Get the last error message
#[no_mangle]
pub extern "C" fn dkls23_get_last_error() -> *mut c_char {
    match last_error() {
        Some(err) => into_c_string(err),
        None => ptr::null_mut(),
    }
}

/// Free a C string allocated by Rust
///
/// # Safety
///
/// `s` must be NULL or a string returned by this library that has not
/// been freed yet.
#[no_mangle]
pub unsafe extern "C" fn dkls23_free_string(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

/// Require 1 <= t <= n <= 255. t = 1 is allowed on purpose: it is a valid
/// 1-of-n wallet in which every party can sign alone (used for "any device
/// can sign" setups); it gives each party full signing power, so only use it
/// when that is the intent.
fn check_threshold(threshold: usize, n_parties: usize) -> Result<(), String> {
    if threshold < 1 || threshold > n_parties || n_parties > u8::MAX as usize
    {
        return Err(format!(
            "invalid threshold {threshold} for {n_parties} parties (need 1 <= t <= n <= 255)"
        ));
    }
    Ok(())
}

// -------------------- FFI: DKG --------------------

/// Initialize DKG state
/// Returns opaque pointer to state or NULL on error
#[no_mangle]
pub extern "C" fn dkls23_dkg_init(
    party_id: u8,
    n_parties: usize,
    threshold: usize,
) -> *mut DkgState {
    track(ffi_state(|| {
        if party_id as usize >= n_parties {
            return Err("party_id out of bounds".to_string());
        }
        check_threshold(threshold, n_parties)?;
        let party = Party::new(n_parties, threshold, party_id as usize);
        let mut rng =
            entropy_rng(&[party_id, n_parties as u8, threshold as u8]);
        Ok(DkgState::new(party, &mut rng))
    }))
}

/// Initialize DKG state with custom ranks
/// ranks_ptr: pointer to array of ranks
/// ranks_len: length of ranks array
/// Returns opaque pointer to state or NULL on error
///
/// # Safety
///
/// `ranks_ptr` must be NULL or readable for `ranks_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn dkls23_dkg_init_with_ranks(
    party_id: u8,
    ranks_ptr: *const u8,
    ranks_len: usize,
    threshold: usize,
) -> *mut DkgState {
    track(ffi_state(|| {
        if ranks_ptr.is_null() {
            return Err("NULL ranks pointer".to_string());
        }
        let ranks = std::slice::from_raw_parts(ranks_ptr, ranks_len).to_vec();
        if party_id as usize >= ranks.len() {
            return Err("party_id out of bounds".to_string());
        }
        check_threshold(threshold, ranks.len())?;
        if let Some(max_rank) = ranks.iter().copied().max() {
            if max_rank as usize >= threshold {
                return Err(
                    "max rank must be less than threshold".to_string()
                );
            }
        }
        // The key is only usable if some t parties can reconstruct it; the
        // t lowest ranks are the best candidates. Without this check the
        // last DKG round hits a singular Birkhoff matrix and panics.
        let mut lowest = ranks.clone();
        lowest.sort_unstable();
        if lowest
            .iter()
            .take(threshold)
            .enumerate()
            .any(|(i, &r)| r as usize > i)
        {
            return Err(format!(
                "ranks {ranks:?} with threshold {threshold} admit no signer \
                 set that can reconstruct the key"
            ));
        }
        let party =
            Party::new_with_ranks(ranks, threshold, party_id as usize);
        let mut rng =
            entropy_rng(&[party_id, ranks_len as u8, threshold as u8]);
        Ok(DkgState::new(party, &mut rng))
    }))
}

/// Generate DKG message 1
///
/// # Safety
///
/// See the crate-level safety contract.
#[no_mangle]
pub unsafe extern "C" fn dkls23_dkg_generate_msg1(
    state: *mut DkgState,
) -> *mut c_char {
    ffi_string(|| {
        serde_json::to_string(&state_mut(state)?.generate_msg1())
            .map_err(ser_err("msg1"))
    })
}

/// Handle DKG message 1 and generate message 2
///
/// # Safety
///
/// See the crate-level safety contract.
#[no_mangle]
pub unsafe extern "C" fn dkls23_dkg_handle_msg1(
    state: *mut DkgState,
    msgs_json: *const c_char,
) -> *mut c_char {
    ffi_string(|| {
        let raw = state;
        let state = state_mut(state)?;
        let msgs: Vec<KeygenMsg1> =
            serde_json::from_str(str_arg(msgs_json, "msg1")?)
                .map_err(parse_err("msg1"))?;
        // A complete round has one message from each of the n - 1 peers.
        check_senders(
            "msg1",
            peers_of(dkg_party_id(state), msgs.len() + 1),
            msgs.iter().map(|m| m.from_id),
        )?;
        check_round(raw, 1, "msg1")?;
        let msg2 = finish_round(
            raw,
            1,
            "msg1",
            state.handle_msg1(&mut entropy_rng(&[]), msgs),
        )?;
        serde_json::to_string(&msg2).map_err(ser_err("msg2"))
    })
}

/// Handle DKG message 2 and generate message 3
///
/// # Safety
///
/// See the crate-level safety contract.
#[no_mangle]
pub unsafe extern "C" fn dkls23_dkg_handle_msg2(
    state: *mut DkgState,
    msgs_json: *const c_char,
) -> *mut c_char {
    ffi_string(|| {
        let raw = state;
        let state = state_mut(state)?;
        let msgs: Vec<KeygenMsg2> =
            serde_json::from_str(str_arg(msgs_json, "msg2")?)
                .map_err(parse_err("msg2"))?;
        check_round(raw, 2, "msg2")?;
        let msg3 = finish_round(
            raw,
            2,
            "msg2",
            state.handle_msg2(&mut entropy_rng(&[]), msgs),
        )?;
        serde_json::to_string(&msg3).map_err(ser_err("msg3"))
    })
}

/// Calculate commitment 2 for DKG round 3
///
/// # Safety
///
/// See the crate-level safety contract.
#[no_mangle]
pub unsafe extern "C" fn dkls23_dkg_calculate_commitment_2(
    state: *mut DkgState,
) -> *mut c_char {
    ffi_string(|| Ok(hex::encode(state_mut(state)?.calculate_commitment_2())))
}

/// Handle DKG message 3 and generate message 4
///
/// # Safety
///
/// See the crate-level safety contract.
#[no_mangle]
pub unsafe extern "C" fn dkls23_dkg_handle_msg3(
    state: *mut DkgState,
    msgs_json: *const c_char,
    commitments_json: *const c_char,
) -> *mut c_char {
    ffi_string(|| {
        let raw = state;
        let state = state_mut(state)?;
        let msgs: Vec<KeygenMsg3> =
            serde_json::from_str(str_arg(msgs_json, "msg3")?)
                .map_err(parse_err("msg3"))?;
        check_senders(
            "msg3",
            dkg_peers(state),
            msgs.iter().map(|m| m.from_id),
        )?;
        let commitments_hex: Vec<String> =
            serde_json::from_str(str_arg(commitments_json, "commitments")?)
                .map_err(parse_err("commitments"))?;
        // Entries that are not 32-byte hex are dropped. The list is indexed
        // by party id, so a dropped entry makes verification fail.
        let commitments: Vec<[u8; 32]> = commitments_hex
            .iter()
            .filter_map(|h| hex::decode(h).ok()?.try_into().ok())
            .collect();
        check_round(raw, 3, "msg3")?;
        let msg4 = finish_round(
            raw,
            3,
            "msg3",
            state.handle_msg3(&mut entropy_rng(&[]), msgs, &commitments),
        )?;
        serde_json::to_string(&msg4).map_err(ser_err("msg4"))
    })
}

/// Handle DKG message 4 and finalize keyshare
///
/// # Safety
///
/// See the crate-level safety contract.
#[no_mangle]
pub unsafe extern "C" fn dkls23_dkg_handle_msg4(
    state: *mut DkgState,
    msgs_json: *const c_char,
) -> *mut c_char {
    ffi_string(|| {
        let raw = state;
        let state = state_mut(state)?;
        let msgs: Vec<KeygenMsg4> =
            serde_json::from_str(str_arg(msgs_json, "msg4")?)
                .map_err(parse_err("msg4"))?;
        check_senders(
            "msg4",
            dkg_peers(state),
            msgs.iter().map(|m| m.from_id),
        )?;
        check_round(raw, 4, "msg4")?;
        let keyshare = finish_round(raw, 4, "msg4", state.handle_msg4(msgs))?;
        serde_json::to_string(&keyshare).map_err(ser_err("keyshare"))
    })
}

/// Free DKG state
///
/// # Safety
///
/// `state` must be NULL or a live pointer from a DKG init function.
#[no_mangle]
pub unsafe extern "C" fn dkls23_dkg_free_state(state: *mut DkgState) {
    if !state.is_null() {
        untrack(state);
        drop(Box::from_raw(state));
    }
}

// -------------------- FFI: Signing --------------------

/// Initialize DSG state from keyshare
///
/// # Safety
///
/// See the crate-level safety contract.
#[no_mangle]
pub unsafe extern "C" fn dkls23_dsg_init(
    keyshare_json: *const c_char,
    derivation_path: *const c_char,
) -> *mut DsgState {
    track(ffi_state(|| {
        let keyshare_str = str_arg(keyshare_json, "keyshare")?;
        let keyshare: Keyshare = serde_json::from_str(keyshare_str)
            .map_err(parse_err("keyshare"))?;
        check_keyshare(
            &keyshare,
            &serde_json::from_str(keyshare_str)
                .map_err(parse_err("keyshare"))?,
        )?;
        let path = DerivationPath::from_str(str_arg(
            derivation_path,
            "derivation path",
        )?)
        .map_err(|e| format!("Failed to parse derivation path: {e}"))?;
        DsgState::new(&mut thread_rng(), keyshare, &path)
            .map_err(|e| format!("Failed to create DSG state: {e:?}"))
    }))
}

/// Generate signing message 1
///
/// # Safety
///
/// See the crate-level safety contract.
#[no_mangle]
pub unsafe extern "C" fn dkls23_dsg_generate_msg1(
    state: *mut DsgState,
) -> *mut c_char {
    ffi_string(|| {
        serde_json::to_string(&state_mut(state)?.generate_msg1())
            .map_err(ser_err("msg1"))
    })
}

/// Handle signing message 1 and generate message 2
///
/// # Safety
///
/// See the crate-level safety contract.
#[no_mangle]
pub unsafe extern "C" fn dkls23_dsg_handle_msg1(
    state: *mut DsgState,
    msgs_json: *const c_char,
) -> *mut c_char {
    ffi_string(|| {
        let raw = state;
        let state = state_mut(state)?;
        let msgs: Vec<SignMsg1> =
            serde_json::from_str(str_arg(msgs_json, "msg1")?)
                .map_err(parse_err("msg1"))?;
        check_senders(
            "msg1",
            peers_of(state.keyshare.party_id, state.keyshare.rank_list.len()),
            msgs.iter().map(|m| m.from_id),
        )?;
        check_signer_set(
            &state.keyshare,
            msgs.iter().map(|m| m.from_id).collect(),
        )?;
        check_round(raw, 1, "msg1")?;
        let msg2 = finish_round(
            raw,
            1,
            "msg1",
            state.handle_msg1(&mut thread_rng(), msgs),
        )?;
        serde_json::to_string(&msg2).map_err(ser_err("msg2"))
    })
}

/// Handle signing message 2 and generate message 3
///
/// # Safety
///
/// See the crate-level safety contract.
#[no_mangle]
pub unsafe extern "C" fn dkls23_dsg_handle_msg2(
    state: *mut DsgState,
    msgs_json: *const c_char,
) -> *mut c_char {
    ffi_string(|| {
        let raw = state;
        let state = state_mut(state)?;
        let msgs: Vec<SignMsg2> =
            serde_json::from_str(str_arg(msgs_json, "msg2")?)
                .map_err(parse_err("msg2"))?;
        check_senders(
            "msg2",
            dsg_peers(state),
            msgs.iter().map(|m| m.from_id),
        )?;
        check_round(raw, 2, "msg2")?;
        let msg3 = finish_round(
            raw,
            2,
            "msg2",
            state.handle_msg2(&mut thread_rng(), msgs),
        )?;
        serde_json::to_string(&msg3).map_err(ser_err("msg3"))
    })
}

/// Handle signing message 3 and generate presignature
///
/// # Safety
///
/// See the crate-level safety contract.
#[no_mangle]
pub unsafe extern "C" fn dkls23_dsg_handle_msg3(
    state: *mut DsgState,
    msgs_json: *const c_char,
) -> *mut c_char {
    ffi_string(|| {
        let raw = state;
        let state = state_mut(state)?;
        let msgs: Vec<SignMsg3> =
            serde_json::from_str(str_arg(msgs_json, "msg3")?)
                .map_err(parse_err("msg3"))?;
        check_senders(
            "msg3",
            dsg_peers(state),
            msgs.iter().map(|m| m.from_id),
        )?;
        check_round(raw, 3, "msg3")?;
        let presig = finish_round(raw, 3, "msg3", state.handle_msg3(msgs))?;
        store_presignature(presig)
            .map_err(|e| format!("Failed to store presignature: {e}"))
    })
}

/// Create partial signature from presignature and message hash
/// Returns JSON with both partial signature and msg4
///
/// # Safety
///
/// `message_hash` must be NULL or readable for 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn dkls23_create_partial_signature(
    presig_json: *const c_char,
    message_hash: *const u8,
) -> *mut c_char {
    ffi_string(|| {
        if presig_json.is_null() {
            return Err("NULL presignature handle".to_string());
        }
        let handle = CStr::from_ptr(presig_json)
            .to_str()
            .map_err(|e| format!("Invalid presignature handle UTF-8: {e}"))?;
        // Remove the value atomically before validating or signing. Any
        // attempt, including one that later fails, permanently burns the
        // nonce material.
        let presig = take_presignature(handle)?;
        if message_hash.is_null() {
            return Err("NULL message hash".to_string());
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(std::slice::from_raw_parts(message_hash, 32));

        let (partial, msg4) = create_partial_signature(presig, hash);
        serde_json::to_string(
            &serde_json::json!({ "partial": partial, "msg4": msg4 }),
        )
        .map_err(ser_err("response"))
    })
}

/// Combine partial signatures into final signature
///
/// # Safety
///
/// See the crate-level safety contract.
#[no_mangle]
pub unsafe extern "C" fn dkls23_combine_signatures(
    partial_sig_json: *const c_char,
    sign_msg4_json: *const c_char,
) -> *mut c_char {
    ffi_string(|| {
        let partial: PartialSignature = serde_json::from_str(str_arg(
            partial_sig_json,
            "partial signature",
        )?)
        .map_err(parse_err("partial signature"))?;
        let msgs: Vec<SignMsg4> =
            serde_json::from_str(str_arg(sign_msg4_json, "SignMsg4")?)
                .map_err(parse_err("SignMsg4"))?;
        let sig = combine_signatures(partial, msgs)
            .map_err(|e| format!("Failed to combine signatures: {e:?}"))?;
        Ok(hex::encode(sig.to_vec()))
    })
}

/// Free DSG state
///
/// # Safety
///
/// `state` must be NULL or a live pointer from [`dkls23_dsg_init`].
#[no_mangle]
pub unsafe extern "C" fn dkls23_dsg_free_state(state: *mut DsgState) {
    if !state.is_null() {
        untrack(state);
        drop(Box::from_raw(state));
    }
}

// -------------------- FFI: BIP32 derivation --------------------

/// Parse the `(keyshare, path)` argument pair shared by the derivation
/// functions.
unsafe fn derivation_args(
    keyshare_json: *const c_char,
    derivation_path: *const c_char,
) -> Result<(Keyshare, DerivationPath), String> {
    if keyshare_json.is_null() || derivation_path.is_null() {
        return Err("Null pointer provided".to_string());
    }
    let keyshare_str = str_arg(keyshare_json, "keyshare")?;
    let path_str = str_arg(derivation_path, "derivation path")?;
    let keyshare: Keyshare = serde_json::from_str(keyshare_str)
        .map_err(|e| format!("Failed to parse keyshare: {e}"))?;
    let path = DerivationPath::from_str(path_str)
        .map_err(|e| format!("Invalid derivation path: {e}"))?;
    Ok((keyshare, path))
}

/// Derive child public key from keyshare using BIP32 derivation path
/// Returns JSON string with derived_public_key (hex) or NULL on error
///
/// Example input:
/// keyshare_json: "{\"party_id\":0,\"public_key\":\"...\",\"root_chain_code\":...}"
/// derivation_path: "m/0/1" or "m/44'/0'/0'/0/0"
///
/// Example output:
/// "{\"derived_public_key\":\"0367891011fef...\"}"
///
/// # Safety
///
/// See the crate-level safety contract.
#[no_mangle]
pub unsafe extern "C" fn dkls23_derive_public_key(
    keyshare_json: *const c_char,
    derivation_path: *const c_char,
) -> *mut c_char {
    ffi_string(|| {
        let (keyshare, path) =
            derivation_args(keyshare_json, derivation_path)?;
        let (_, derived_pubkey) = derive_with_offset(
            &keyshare.public_key.to_curve(),
            &keyshare.root_chain_code,
            &path,
        )
        .map_err(|e| format!("Derivation failed: {e}"))?;

        let compressed = derived_pubkey.to_affine().to_encoded_point(true);
        Ok(serde_json::json!({
            "derived_public_key": hex::encode(compressed.as_bytes())
        })
        .to_string())
    })
}

/// Derive child keyshare from parent keyshare using BIP32 derivation path
/// Returns JSON string with fully derived keyshare or NULL on error
///
/// Example input:
/// keyshare_json: "{\"party_id\":0,\"public_key\":\"...\",\"root_chain_code\":...}"
/// derivation_path: "m/0/1" or "m/44'/0'/0'/0/0"
///
/// Example output:
/// "{\"party_id\":0,\"public_key\":\"...\",\"secret_share\":\"...\",\"root_chain_code\":\"...\"}"
///
/// # Safety
///
/// See the crate-level safety contract.
#[no_mangle]
pub unsafe extern "C" fn dkls23_derive_keyshare(
    keyshare_json: *const c_char,
    derivation_path: *const c_char,
) -> *mut c_char {
    ffi_string(|| {
        let (mut keyshare, path) =
            derivation_args(keyshare_json, derivation_path)?;
        let parent_pubkey = keyshare.public_key.to_curve();
        let parent_chain_code = keyshare.root_chain_code;

        let (secret_offset, derived_pubkey) =
            derive_with_offset(&parent_pubkey, &parent_chain_code, &path)
                .map_err(|e| format!("Derivation failed: {e}"))?;

        // Shift the secret share by the additive offset and move the public
        // key and chain code to the child so further derivations stay
        // consistent. Only rank-0 shares move: a rank-r share is the r-th
        // derivative of the sharing polynomial, and a constant offset of the
        // secret leaves derivatives unchanged.
        let rank = keyshare
            .rank_list
            .get(keyshare.party_id as usize)
            .copied()
            .ok_or("keyshare party_id is out of range")?;
        if rank == 0 {
            keyshare.apply_secret_offset(secret_offset);
        }
        keyshare.public_key = derived_pubkey.to_affine();
        keyshare.root_chain_code =
            derive_chain_code(&parent_pubkey, &parent_chain_code, &path)
                .map_err(|e| format!("Failed to derive chain code: {e}"))?;

        serde_json::to_string(&keyshare).map_err(ser_err("derived keyshare"))
    })
}

/// Final chain code for `chain_path` (mirrors the `derive_with_offset` loop).
fn derive_chain_code(
    public_key: &ProjectivePoint,
    root_chain_code: &[u8; 32],
    chain_path: &DerivationPath,
) -> Result<[u8; 32], BIP32Error> {
    let mut pubkey = *public_key;
    let mut chain_code = *root_chain_code;

    for child_num in chain_path {
        let (_, child_pubkey, child_chain_code) =
            derive_child_pubkey(&pubkey, chain_code, child_num)?;
        pubkey = child_pubkey;
        chain_code = child_chain_code;
    }

    Ok(chain_code)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_presignature() -> PreSignature {
        PreSignature {
            from_id: 1,
            final_session_id: [7u8; 32],
            public_key: k256::AffinePoint::IDENTITY,
            s_0: k256::Scalar::ONE,
            s_1: k256::Scalar::ONE,
            r: k256::AffinePoint::IDENTITY,
            phi_i: k256::Scalar::ONE,
        }
    }

    #[test]
    fn presignature_handle_is_single_use() {
        let handle = store_presignature(test_presignature()).unwrap();
        assert!(take_presignature(&handle).is_ok());
        assert!(take_presignature(&handle).is_err());
    }

    #[test]
    fn raw_presignature_json_is_rejected() {
        let raw = serde_json::to_string(&test_presignature()).unwrap();
        assert!(take_presignature(&raw).is_err());
    }

    #[test]
    fn unknown_presignature_handle_is_rejected() {
        let result = take_presignature(r#"{"presignature_handle":"00"}"#);
        let err = result.err().expect("unknown handle must be rejected");
        assert!(err.contains("unknown"), "{err}");
    }

    #[test]
    fn expired_presignatures_are_purged() {
        let mut entries = PreSignatureMap::new();
        let fresh = Instant::now();
        let Some(stale) = fresh.checked_sub(PRESIGNATURE_TTL) else {
            return; // Monotonic clock too close to its origin to test.
        };
        for (key, created_at) in [("fresh", fresh), ("stale", stale)] {
            entries.insert(
                key.to_string(),
                StoredPreSignature {
                    value: test_presignature(),
                    created_at,
                },
            );
        }
        purge_expired_presignatures(&mut entries);
        assert!(entries.contains_key("fresh"));
        assert!(!entries.contains_key("stale"));
    }

    #[test]
    fn last_error_strips_interior_nul() {
        set_last_error("bad\0input");
        assert_eq!(last_error().as_deref(), Some("badinput"));
    }

    #[test]
    fn entropy_rng_streams_differ() {
        let mut a = entropy_rng(&[1, 2, 3]);
        let mut b = entropy_rng(&[1, 2, 3]);
        assert_ne!(a.next_u64(), b.next_u64());
    }

    #[test]
    fn empty_derivation_path_keeps_root_chain_code() {
        let root = [9u8; 32];
        let path = DerivationPath::from_str("m").unwrap();
        let cc = derive_chain_code(&ProjectivePoint::GENERATOR, &root, &path)
            .unwrap();
        assert_eq!(cc, root);
    }
}

#[cfg(test)]
mod ffi_tests;
