# FROST golden fixtures

**Throwaway test keys. Never use them with real funds.** Every keyshare here
was generated once by a local test run, its other shares are committed next
to it, so anyone can sign with these keys. They exist only to pin the JSON
format.

These files freeze the wire and storage format of `frost-ffi`: keyshares as
returned by `frost_dkg_handle_msg2`, and one example of every protocol
message. `src/ffi_tests/golden.rs` checks that the current code still parses
them, re-serializes them to the same JSON, reports the same group public key,
and signs with them (signatures checked with `frost-ed25519` directly and
with `frost_verify_signature`).

| File | Content |
| --- | --- |
| `keyshare_2of3_party{1,2,3}.json` | 2-of-3 keyshares (participant ids are one-based) |
| `messages/dkg_msg1.json` | `frost_dkg_generate_msg1` output of party 1 |
| `messages/dkg_msg2.json` | `frost_dkg_handle_msg1` output of party 1 |
| `messages/sign_msg1.json` | `frost_signing_generate_msg1` output of party 1 |
| `messages/signature_share_party{1,2}.json` | `frost_signing_handle_msg1` outputs of one session |
| `expected.json` | group public key, derived public key, signing transcript and its signature |

## Regenerating

Do not regenerate to make a failing test pass: a failure means stored
keyshares or in-flight messages would no longer load. Only after an
intentional, reviewed format change (with a migration path for existing
keyshares):

```sh
cd internal/rust
UPDATE_GOLDEN=1 cargo test --locked --release -p frost-ffi golden
```

The tests never rewrite these files unless `UPDATE_GOLDEN=1` is set.
