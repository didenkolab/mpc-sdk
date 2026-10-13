# DKLs23 golden fixtures

**Throwaway test keys. Never use them with real funds.** Every keyshare here
was generated once by a local test run, its other shares are committed next
to it, so anyone can sign with these keys. They exist only to pin the JSON
format.

These files freeze the wire and storage format of `dkls23-ffi`: keyshares as
returned by `dkls23_dkg_handle_msg4`, and one example of every protocol
message. `src/ffi_tests/golden.rs` checks that the current code still parses
them, re-serializes them to the same JSON, derives the same public keys, and
signs with them (signatures checked with the independent `k256` verifier).

| File | Content |
| --- | --- |
| `keyshare_2of3_party{0,1,2}.json` | 2-of-3 keyshares (ranks `[0,0,0]`) |
| `keyshare_ranked_party{0,1,2}.json` | 2-of-3 ranked keyshares (ranks `[0,1,1]`) |
| `messages/dkg_msg1.json` | `dkls23_dkg_generate_msg1` output of party 0 |
| `messages/dkg_msg2.json` | `dkls23_dkg_handle_msg1` output of party 0 |
| `messages/dkg_msg3.json` | `dkls23_dkg_handle_msg2` output of party 0 |
| `messages/dkg_commitments.json` | commitments array passed to `dkls23_dkg_handle_msg3` |
| `messages/dkg_msg4.json` | `dkls23_dkg_handle_msg3` output of party 0 |
| `messages/sign_msg{1,2,3}.json` | signing round outputs of party 0 |
| `messages/partial_signature_party{0,1}.json` | `dkls23_create_partial_signature` outputs of one session |
| `expected.json` | public keys, derived public key, signing transcript and its signature |

## Regenerating

Do not regenerate to make a failing test pass: a failure means stored
keyshares or in-flight messages would no longer load. Only after an
intentional, reviewed format change (with a migration path for existing
keyshares):

```sh
cd internal/rust
UPDATE_GOLDEN=1 cargo test --locked --release -p dkls23-ffi golden
```

The tests never rewrite these files unless `UPDATE_GOLDEN=1` is set.
