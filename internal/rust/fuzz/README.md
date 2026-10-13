# FFI fuzzing

Coverage-guided fuzzing (libFuzzer via `cargo-fuzz`) for the C ABIs in
`../ffi` (DKLs23, `mpc_dkls23_ffi`) and `../frost-ffi` (FROST,
`mpc_frost_ffi`).

Release builds use `panic = "abort"`, so a panic reachable from a peer
message or a stored keyshare kills the host application. Every target feeds
fuzzer-controlled strings to an exported `extern "C"` function and fails on
any panic, or on a NULL result without a last-error message.

## How the FFI code is linked

The FFI crates are `staticlib` + `cdylib` only (an `rlib` crate type would
disable LTO for the shipped libraries). Instead of depending on them, this
crate compiles their `src/lib.rs` files as modules via `#[path]`
(`src/lib.rs`). The code under test is the shipped source, unchanged, and the
FFI crates contain nothing fuzz-specific.

This directory is a separate Cargo workspace, so the normal
`internal/rust` build never needs nightly or libFuzzer. `Cargo.lock` started
as a copy of `../Cargo.lock`; all shared dependencies resolve to the same
versions.

## Targets

Each target builds an honest transcript once per process (DKLs23: 2-of-3 DKG
plus a 2-party signing session; FROST: 2-of-3 DKG plus 2-party signing) and
replays the call under test from a fresh copy of the real party state.
DKLs23 states are snapshotted with bincode. FROST states are rebuilt each
iteration.

| Target | Function(s) under test | Fuzzed arguments |
|---|---|---|
| `dkls_dkg_msg1`..`dkls_dkg_msg4` | `dkls23_dkg_handle_msg{1..4}` | `msgs_json` (msg3: also `commitments_json`) |
| `dkls_dsg_init` | `dkls23_dsg_init`, then signing rounds 1-3 | keyshare JSON, derivation path |
| `dkls_dsg_msg1`..`dkls_dsg_msg3` | `dkls23_dsg_handle_msg{1..3}` | `msgs_json` |
| `dkls_partial_sig` | `dkls23_create_partial_signature` | presignature handle JSON |
| `dkls_combine` | `dkls23_combine_signatures` | partial signature, `SignMsg4` list |
| `dkls_derive` | `dkls23_derive_public_key`, `dkls23_derive_keyshare` | keyshare JSON, derivation path |
| `frost_dkg_msg1`, `frost_dkg_msg2` | `frost_dkg_handle_msg{1,2}` | `msgs_json` |
| `frost_signing_init` | `frost_signing_init`, then signing and aggregation | keyshare JSON |
| `frost_signing_msg1` | `frost_signing_handle_msg1`, then aggregation | commitments JSON |
| `frost_combine` | `frost_combine_signatures` | own bundle, other bundles |
| `frost_verify` | `frost_verify_signature` | public key JSON, signature hex |
| `frost_derive` | `frost_derive_public_key`, `frost_derive_keyshare` | keyshare JSON |

### Input format

The first byte picks the mode (`src/input.rs`):

* `0` raw: the second byte picks an argument. The rest of the input replaces
  it verbatim, cut at the first NUL. This covers invalid UTF-8 and broken
  JSON.
* `1` structured: tree mutations driven by `arbitrary` are applied to one
  honest JSON argument (edge-value numbers, spliced subtrees, dropped or
  duplicated items, deleted keys, corrupted hex).
* `2` text: byte-level edits are applied to one honest argument's serialized
  text.

The single-byte inputs `\x01` and `\x02` replay the honest call unchanged.
Keys are random per process, so seed inputs carry no key material. The
`seeds/<target>/` files are those mode bytes plus a few raw edge cases.

## Running

```sh
rustup toolchain install nightly --profile minimal
cargo +nightly install cargo-fuzz --locked

cd internal/rust/fuzz
cargo +nightly fuzz list
# Ship-equivalent semantics (no debug assertions or overflow checks, as in
# the release profile) and no ASan, which is ~5x faster:
cargo +nightly fuzz run -O -s none dkls_dsg_msg1 corpus/dkls_dsg_msg1 seeds/dkls_dsg_msg1 \
    -- -max_total_time=300 -timeout=30
```

`corpus/<target>` collects new inputs (git-ignored, but create it before the
first run). Crashes are written to `artifacts/<target>/`. To reproduce or
minimize one:

```sh
cargo +nightly fuzz run -O -s none <target> artifacts/<target>/crash-...
cargo +nightly fuzz tmin -O -s none <target> artifacts/<target>/crash-...
```

Structured-mode inputs are opaque bytes. To see what they change in the
honest arguments, run (stable toolchain is enough):

```sh
cargo run --release --example explain -- dkls_keyshare artifacts/dkls_dsg_init/crash-...
```

Without `-O`, cargo-fuzz builds with debug assertions and overflow checks.
Those builds also flag `debug_assert!` failures and integer overflows that
wrap silently in the shipped release build. Treat such reports as logic bugs
to triage, not as aborts.

Every crash fixed so far has a regression test in
`../ffi/src/ffi_tests/negative.rs` or `../frost-ffi/src/ffi_tests/negative.rs`,
so the stable `cargo test` run keeps it covered.

## CI smoke run

```sh
cd internal/rust/fuzz
cargo +nightly fuzz build -O -s none
for t in $(cargo +nightly fuzz list); do
  mkdir -p corpus/$t
  cargo +nightly fuzz run -O -s none "$t" corpus/$t seeds/$t -- \
      -max_total_time=30 -timeout=30 || exit 1
done
```
