//! Ranked (hierarchical) DKLs23 through the C ABI.
//!
//! Ranked keys use Birkhoff interpolation instead of Lagrange: a party of
//! rank `r` holds the `r`-th derivative of the sharing polynomial at its
//! point. A signer set can reconstruct the key iff its ranks, sorted
//! ascending, satisfy `rank[i] <= i` (Tassa's poised condition). These
//! tests enumerate rank vectors and signer subsets and check that every
//! poised set produces a signature that verifies under an independent
//! ECDSA implementation, and every other set is rejected cleanly.
//!
//! DKG dominates the runtime, so keyshares are cached per
//! `(threshold, ranks)` and independent cases run on all cores.

use std::collections::HashMap;
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;

use super::common::last_error;
use super::common::*;
use crate::*;
use serde_json::Value;

// -------------------- Helpers --------------------

/// Ranks sorted ascending satisfy `rank[i] <= i`.
fn poised(ranks: impl IntoIterator<Item = u8>) -> bool {
    let mut ranks: Vec<u8> = ranks.into_iter().collect();
    ranks.sort_unstable();
    ranks.iter().enumerate().all(|(i, &r)| usize::from(r) <= i)
}

/// Some `t`-subset of the parties is poised. With every rank below `t`
/// this is equivalent to the full party set being poised, because the
/// `t` lowest ranks form the prefix of the sorted rank list.
fn reconstructable(ranks: &[u8], t: usize) -> bool {
    let mut sorted = ranks.to_vec();
    sorted.sort_unstable();
    sorted.len() >= t && poised(sorted[..t].iter().copied())
}

/// Every rank vector of length `n` with entries in `0..t`.
fn all_rank_vectors(n: usize, t: usize) -> Vec<Vec<u8>> {
    let mut out = vec![Vec::new()];
    for _ in 0..n {
        out = out
            .into_iter()
            .flat_map(|prefix| {
                (0..t as u8).map(move |r| {
                    let mut v = prefix.clone();
                    v.push(r);
                    v
                })
            })
            .collect();
    }
    out
}

/// Non-decreasing rank vectors (one per multiset of ranks) plus their
/// reversals, so both "low ids hold low ranks" and the opposite
/// assignment are covered.
fn canonical_rank_vectors(n: usize, t: usize) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = all_rank_vectors(n, t)
        .into_iter()
        .filter(|v| v.windows(2).all(|w| w[0] <= w[1]))
        .flat_map(|v| {
            let rev: Vec<u8> = v.iter().rev().copied().collect();
            [v, rev]
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Party ids selected by `mask`.
fn members(mask: u32, n: usize) -> Vec<usize> {
    (0..n).filter(|i| mask & (1 << i) != 0).collect()
}

/// Every subset of `0..n` with exactly `k` members.
fn subsets(n: usize, k: usize) -> impl Iterator<Item = Vec<usize>> {
    (0u32..1 << n)
        .filter(move |m| m.count_ones() as usize == k)
        .map(move |m| members(m, n))
}

/// Map `f` over `items` on every available core, preserving order.
fn par_map<T: Sync, R: Send>(
    items: &[T],
    f: impl Fn(&T) -> R + Sync,
) -> Vec<R> {
    let workers = thread::available_parallelism()
        .map_or(4, |n| n.get())
        .min(items.len().max(1));
    let next = AtomicUsize::new(0);
    let results: Mutex<Vec<Option<R>>> =
        Mutex::new(items.iter().map(|_| None).collect());
    thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some(item) = items.get(i) else { break };
                let r = f(item);
                results.lock().unwrap()[i] = Some(r);
            });
        }
    });
    results
        .into_inner()
        .unwrap()
        .into_iter()
        .map(Option::unwrap)
        .collect()
}

type CacheKey = (usize, Vec<u8>);
type Slot = Arc<OnceLock<Vec<String>>>;

/// Keyshares for `(t, ranks)`, generated once per test binary. Callers
/// must only pass reconstructable rank vectors: DKG aborts the process
/// otherwise (see `bug_unreconstructable_ranks_are_rejected_cleanly`).
fn ranked_keyshares(ranks: &[u8], t: usize) -> Slot {
    assert!(reconstructable(ranks, t), "{ranks:?} t={t} would abort");
    static CACHE: OnceLock<Mutex<HashMap<CacheKey, Slot>>> = OnceLock::new();
    let slot = CACHE
        .get_or_init(Default::default)
        .lock()
        .unwrap()
        .entry((t, ranks.to_vec()))
        .or_default()
        .clone();
    slot.get_or_init(|| run_dkg(&ranked_parties(ranks, t)));
    slot
}

fn refs<'a>(keyshares: &'a [String], ids: &[usize]) -> Vec<&'a str> {
    ids.iter().map(|&i| keyshares[i].as_str()).collect()
}

/// Run signing round 1 for `signers` and feed every signer its peers'
/// messages. Returns each signer's round 1 outcome: the error text, or
/// `None` if it was accepted.
fn round1_errors(signers: &[&str], path: &str) -> Vec<Option<String>> {
    let ids: Vec<u64> = signers.iter().map(|ks| party_id(ks)).collect();
    let states: Vec<Dsg> =
        signers.iter().map(|ks| dsg_init(ks, path)).collect();
    let msg1: Vec<Value> = states
        .iter()
        .map(|s| json(&ok(unsafe { dkls23_dsg_generate_msg1(s.0) })))
        .collect();
    states
        .iter()
        .zip(&ids)
        .map(|(s, &me)| {
            let others = to_c(&excluding(&msg1, me));
            let out = unsafe { dkls23_dsg_handle_msg1(s.0, others.as_ptr()) };
            match take(out) {
                Some(_) => None,
                None => Some(last_error()),
            }
        })
        .collect()
}

/// Every signer must reject the set in round 1 with an error containing
/// all of `needles`.
fn assert_rejected(signers: &[&str], path: &str, needles: &[&str]) {
    for err in round1_errors(signers, path) {
        let err = err.unwrap_or_else(|| {
            panic!("signer set accepted, expected {needles:?}")
        });
        for needle in needles {
            assert!(err.contains(needle), "error {err:?} lacks {needle:?}");
        }
    }
}

fn sorted_ranks(ranks: &[u8], ids: &[usize]) -> Vec<u8> {
    let mut r: Vec<u8> = ids.iter().map(|&i| ranks[i]).collect();
    r.sort_unstable();
    r
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Tally {
    /// Rank vectors whose key was generated and exercised.
    keys: usize,
    /// Rank vectors with no poised `t`-subset (not generated, see bug
    /// test).
    unreconstructable: usize,
    /// `t`-subsets that signed and verified.
    signed: usize,
    /// `t`-subsets rejected for violating the poised condition.
    rejected: usize,
    /// Wrong-size signer sets rejected for their size.
    wrong_size: usize,
}

impl std::ops::Add for Tally {
    type Output = Tally;
    fn add(self, o: Tally) -> Tally {
        Tally {
            keys: self.keys + o.keys,
            unreconstructable: self.unreconstructable + o.unreconstructable,
            signed: self.signed + o.signed,
            rejected: self.rejected + o.rejected,
            wrong_size: self.wrong_size + o.wrong_size,
        }
    }
}

/// Exercise one ranked key: every `t`-subset either signs and verifies
/// against the group key or is rejected by every signer; signer sets of
/// size `t - 1` and `t + 1` are rejected for their size.
fn check_key(ranks: &[u8], t: usize) -> Tally {
    let n = ranks.len();
    if !reconstructable(ranks, t) {
        return Tally {
            unreconstructable: 1,
            ..Tally::default()
        };
    }
    let slot = ranked_keyshares(ranks, t);
    let keyshares = slot.get().unwrap();
    let pubkey = derive_public_key(&keyshares[0], "m");
    for (i, ks) in keyshares.iter().enumerate() {
        assert_eq!(derive_public_key(ks, "m"), pubkey, "party {i}");
        assert_eq!(json(ks)["rank_list"], serde_json::json!(ranks));
    }

    let mut tally = Tally {
        keys: 1,
        ..Tally::default()
    };
    for ids in subsets(n, t) {
        let signers = refs(keyshares, &ids);
        let sorted = sorted_ranks(ranks, &ids);
        if poised(sorted.iter().copied()) {
            let hash = sha256(format!("{ranks:?} t={t} {ids:?}").as_bytes());
            let sig = sign(&signers, "m", &hash);
            assert!(
                verify(&pubkey, &hash, &sig),
                "ranks {ranks:?} t={t} signers {ids:?}: invalid signature"
            );
            tally.signed += 1;
        } else {
            let needle =
                format!("signer ranks {sorted:?} cannot reconstruct");
            assert_rejected(&signers, "m", &[&needle]);
            tally.rejected += 1;
        }
    }

    // Too few (t - 1, possibly a lone signer) and too many (t + 1).
    for k in [t - 1, t + 1] {
        if k == 0 || k > n {
            continue;
        }
        let ids: Vec<usize> = (0..k).collect();
        let needle = format!("expected {} peer messages", t - 1);
        assert_rejected(&refs(keyshares, &ids), "m", &[&needle]);
        tally.wrong_size += 1;
    }
    tally
}

fn check_all(cases: &[(Vec<u8>, usize)]) -> Tally {
    par_map(cases, |(ranks, t)| check_key(ranks, *t))
        .into_iter()
        .fold(Tally::default(), |a, b| a + b)
}

fn cases(
    ns: impl IntoIterator<Item = usize>,
    vectors: fn(usize, usize) -> Vec<Vec<u8>>,
) -> Vec<(Vec<u8>, usize)> {
    ns.into_iter()
        .flat_map(|n| {
            (2..=n).flat_map(move |t| {
                vectors(n, t).into_iter().map(move |r| (r, t))
            })
        })
        .collect()
}

/// DKG that tolerates failures: `Err((round, party, error))` from the
/// first failing call, `Ok(keyshares)` otherwise.
fn try_run_dkg(parties: &[Dkg]) -> Result<Vec<String>, String> {
    fn step(
        round: &str,
        party: usize,
        out: *mut std::os::raw::c_char,
    ) -> Result<String, String> {
        take(out).ok_or_else(|| format!("{round} p{party}: {}", last_error()))
    }
    let msg1: Vec<Value> = parties
        .iter()
        .enumerate()
        .map(|(i, p)| {
            step("msg1", i, unsafe { dkls23_dkg_generate_msg1(p.0) })
                .map(|s| json(&s))
        })
        .collect::<Result<_, _>>()?;
    let mut msg2 = Vec::new();
    for (i, p) in parties.iter().enumerate() {
        let others = to_c(&excluding(&msg1, i as u64));
        let out = unsafe { dkls23_dkg_handle_msg1(p.0, others.as_ptr()) };
        msg2.extend(array(&step("handle_msg1", i, out)?));
    }
    let mut msg3 = Vec::new();
    for (i, p) in parties.iter().enumerate() {
        let mine = to_c(&select(&msg2, "to_id", i as u64));
        let out = unsafe { dkls23_dkg_handle_msg2(p.0, mine.as_ptr()) };
        msg3.extend(array(&step("handle_msg2", i, out)?));
    }
    let commitments: Vec<Value> = parties
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let out = unsafe { dkls23_dkg_calculate_commitment_2(p.0) };
            step("commitment_2", i, out).map(Value::String)
        })
        .collect::<Result<_, _>>()?;
    let commitments = to_c(&commitments);
    let mut msg4 = Vec::new();
    for (i, p) in parties.iter().enumerate() {
        let mine = to_c(&select(&msg3, "to_id", i as u64));
        let out = unsafe {
            dkls23_dkg_handle_msg3(p.0, mine.as_ptr(), commitments.as_ptr())
        };
        msg4.push(json(&step("handle_msg3", i, out)?));
    }
    parties
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let others = to_c(&excluding(&msg4, i as u64));
            let out = unsafe { dkls23_dkg_handle_msg4(p.0, others.as_ptr()) };
            step("handle_msg4", i, out)
        })
        .collect()
}

/// Initialise one party per entry of `configs` (each with its own view of
/// the rank vector).
fn parties_with(configs: &[&[u8]], t: usize) -> Vec<Dkg> {
    configs
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let state = unsafe {
                dkls23_dkg_init_with_ranks(i as u8, r.as_ptr(), r.len(), t)
            };
            assert!(!state.is_null(), "{}", last_error());
            Dkg(state)
        })
        .collect()
}

// -------------------- 1. Enumeration --------------------

/// n in {2, 3}: every rank vector in `0..t`; n = 4: one vector per rank
/// multiset plus its reversal. Every `t`-subset of every key.
#[test]
fn ranked_signing_enumeration() {
    let mut all = cases([2, 3], all_rank_vectors);
    all.extend(cases([4], canonical_rank_vectors));
    let tally = check_all(&all);
    assert_eq!(
        tally,
        Tally {
            keys: 77,
            unreconstructable: 63,
            signed: 154,
            rejected: 23,
            wrong_size: 108,
        },
        "{} rank vectors enumerated",
        all.len()
    );
}

/// Exhaustive version: every rank vector for n = 4 and one per rank
/// multiset (plus reversal) for n = 5. Several minutes of CPU, spread
/// over all cores: `cargo test --release -p dkls23-ffi -- --ignored
/// ranked_signing_exhaustive`.
#[test]
#[ignore = "slow: ~350 extra DKGs; run explicitly with --ignored"]
fn ranked_signing_exhaustive() {
    let mut all = cases([4], all_rank_vectors);
    all.extend(cases([5], canonical_rank_vectors));
    let tally = check_all(&all);
    assert_eq!(
        tally,
        Tally {
            keys: 375,
            unreconstructable: 382,
            signed: 961,
            rejected: 216,
            wrong_size: 542,
        },
        "{} rank vectors enumerated",
        all.len()
    );
}

// -------------------- 2. Rejection at DKG init --------------------

#[test]
fn dkg_init_with_ranks_rejects_out_of_range_parameters() {
    let init = |pid: u8, ranks: &[u8], len: usize, t: usize| unsafe {
        dkls23_dkg_init_with_ranks(pid, ranks.as_ptr(), len, t)
    };
    unsafe {
        expect_err(
            dkls23_dkg_init_with_ranks(0, ptr::null(), 2, 2),
            "NULL ranks pointer",
        );
    }
    // Zero-length rank list: no valid party id.
    expect_err(init(0, &[0, 0], 0, 2), "party_id out of bounds");
    // Threshold 0 can never exceed a rank.
    expect_err(init(0, &[0, 0], 2, 0), "invalid threshold");
    // Threshold beyond the u8 wire format.
    expect_err(init(0, &[0, 0], 2, 256), "invalid threshold");

    for n in 2..=5usize {
        // t = 1 is rejected as an invalid threshold (covered above).
        for t in 2..=n {
            let pid = n as u8;
            expect_err(
                init(pid, &vec![0; n], n, t),
                "party_id out of bounds",
            );
            // A rank of t or more at any position, for every party id.
            for pos in 0..n {
                for bad in [t, t + 1, usize::from(u8::MAX)] {
                    let mut ranks = vec![0u8; n];
                    ranks[pos] = bad as u8;
                    for pid in 0..n as u8 {
                        expect_err(
                            init(pid, &ranks, n, t),
                            "max rank must be less than threshold",
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn threshold_above_party_count_is_rejected_at_init() {
    for (ranks, t) in [(&[0u8, 0][..], 3), (&[0, 1], 3), (&[0, 1, 2], 4)] {
        for party in 0..ranks.len() as u8 {
            expect_err(
                unsafe {
                    dkls23_dkg_init_with_ranks(
                        party,
                        ranks.as_ptr(),
                        ranks.len(),
                        t,
                    )
                },
                "invalid threshold",
            );
        }
    }
}

#[test]
fn parties_with_inconsistent_rank_vectors_fail_cleanly() {
    // Party 0 believes it holds rank 1; the others think rank 0. The
    // rank is bound into the round 1 commitment, so this is detected.
    let configs: [&[u8]; 3] = [&[0, 1, 1], &[0, 0, 1], &[0, 0, 1]];
    let err = try_run_dkg(&parties_with(&configs, 2)).unwrap_err();
    assert!(err.contains("InvalidCommitmentHash"), "{err}");

    // A party that sees a shorter rank list cannot even be addressed.
    let short = [0u8, 1];
    expect_err(
        unsafe { dkls23_dkg_init_with_ranks(2, short.as_ptr(), 2, 2) },
        "party_id out of bounds",
    );
}

/// Unreconstructable rank vectors (no `t`-subset is poised) used to pass
/// init and then abort the process in the last DKG round.
#[test]
fn unreconstructable_ranks_are_rejected_cleanly() {
    // No t-subset of these rank vectors satisfies sorted rank[i] <= i, so
    // the key could never be used; init must refuse instead of letting the
    // last DKG round panic on a singular Birkhoff matrix.
    for (ranks, t) in [
        (vec![1u8, 1, 1], 2usize),
        (vec![1, 1], 2),
        (vec![0, 2, 2, 2], 3),
        (vec![1, 1, 2, 2], 3),
    ] {
        for party in 0..ranks.len() as u8 {
            let state = unsafe {
                dkls23_dkg_init_with_ranks(
                    party,
                    ranks.as_ptr(),
                    ranks.len(),
                    t,
                )
            };
            assert!(state.is_null(), "ranks {ranks:?}, t = {t} accepted");
            assert!(
                last_error().contains("reconstruct"),
                "unexpected error for {ranks:?}: {}",
                last_error()
            );
        }
    }
}

// -------------------- 3. Ranked + BIP32 --------------------

#[test]
fn ranked_signing_on_derived_path() {
    let ranks = [1u8, 0, 2, 1];
    let t = 3;
    let slot = ranked_keyshares(&ranks, t);
    let keyshares = slot.get().unwrap();
    let path = DERIVED_PATH;
    let root = derive_public_key(&keyshares[0], "m");
    let child = derive_public_key(&keyshares[0], path);
    assert_ne!(root, child);
    for ks in &keyshares[1..] {
        assert_eq!(derive_public_key(ks, path), child);
    }

    // Mixed sets: sorted ranks [0, 1, 2] and [0, 1, 1].
    for ids in [[0, 1, 2], [3, 1, 2], [0, 3, 1]] {
        let hash = sha256(format!("derived {ids:?}").as_bytes());
        let sig = sign(&refs(keyshares, &ids), path, &hash);
        assert!(verify(&child, &hash, &sig), "signers {ids:?}");
        assert!(!verify(&root, &hash, &sig), "signers {ids:?}");
    }
    // Sorted ranks [1, 1, 2]: not poised on the derived path either.
    assert_rejected(
        &refs(keyshares, &[0, 2, 3]),
        path,
        &["signer ranks [1, 1, 2] cannot reconstruct"],
    );
}

/// `dkls23_derive_keyshare` for every party of `keyshares`.
fn derive_keyshares(keyshares: &[String], path: &str) -> Vec<String> {
    let path = cstr(path);
    keyshares
        .iter()
        .map(|ks| {
            let ks = cstr(ks);
            ok(unsafe { dkls23_derive_keyshare(ks.as_ptr(), path.as_ptr()) })
        })
        .collect()
}

const DERIVED_PATH: &str = "m/44/60/0/0/7";

/// Ranks `[0, 0, 1]`, threshold 2, and its keyshares derived to
/// `DERIVED_PATH` (the key is shared with the enumeration cache).
fn derived_0_0_1() -> (String, Vec<String>) {
    let slot = ranked_keyshares(&[0, 0, 1], 2);
    let keyshares = slot.get().unwrap();
    let child = derive_public_key(&keyshares[0], DERIVED_PATH);
    (child, derive_keyshares(keyshares, DERIVED_PATH))
}

#[test]
fn derived_ranked_keyshares_keep_ranks_and_child_key() {
    let (child, derived) = derived_0_0_1();
    for ks in &derived {
        assert_eq!(json(ks)["rank_list"], serde_json::json!([0, 0, 1]));
        assert_eq!(derive_public_key(ks, "m"), child);
    }
    // Two rank 0 signers: unaffected by the bug below.
    let hash = sha256(b"derived rank 0 keyshares");
    let sig = sign(&refs(&derived, &[0, 1]), "m", &hash);
    assert!(verify(&child, &hash, &sig));
}

/// `dkls23_derive_keyshare` adds the BIP32 offset to every party's
/// `s_i`. That is right for Lagrange (the coefficients sum to 1) but not
/// for Birkhoff: a rank `r > 0` share is the `r`-th derivative of the
/// sharing polynomial, which a constant shift leaves unchanged. Only the
/// rank 0 coefficients sum to 1, so a signer set containing a rank > 0
/// party reconstructs the wrong secret and every signer aborts in round
/// 3 with "Consistency check 3 failed". Signing the same path from the
/// root keyshares (`dkls23_dsg_init` with the path) works.
#[test]
fn derived_ranked_keyshares_sign_for_child_key() {
    let (child, derived) = derived_0_0_1();
    let hash = sha256(b"derived ranked keyshares");
    let sig = sign(&refs(&derived, &[0, 2]), "m", &hash);
    assert!(verify(&child, &hash, &sig));
}

// -------------------- 4. All-zero ranks == standard --------------------

#[test]
fn all_zero_ranks_behave_like_a_standard_key() {
    let (n, t) = (4, 3);
    let ranked = ranked_keyshares(&[0; 4], t);
    let ranked = ranked.get().unwrap();
    let standard = run_dkg(&dkg_parties(n, t));

    for keyshares in [ranked, &standard] {
        let first = json(&keyshares[0]);
        assert_eq!(first["rank_list"], serde_json::json!([0, 0, 0, 0]));
        assert_eq!(first["threshold"], t);
        assert_eq!(first["total_parties"], n);

        let pubkey = derive_public_key(&keyshares[0], "m");
        for ids in subsets(n, t) {
            let hash = sha256(format!("zero ranks {ids:?}").as_bytes());
            let sig = sign(&refs(keyshares, &ids), "m", &hash);
            assert!(verify(&pubkey, &hash, &sig), "signers {ids:?}");
        }
        for ids in [vec![0, 1], vec![0, 1, 2, 3]] {
            assert_rejected(
                &refs(keyshares, &ids),
                "m",
                &["expected 2 peer messages"],
            );
        }
    }

    // Same keyshare layout field for field.
    let keys = |ks: &str| -> Vec<String> {
        let Value::Object(map) = json(ks) else {
            panic!("keyshare is not an object")
        };
        map.keys().cloned().collect()
    };
    assert_eq!(keys(&ranked[0]), keys(&standard[0]));
}
