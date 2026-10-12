# pkg/frost

Go bindings for threshold Ed25519 signatures using
[FROST](https://eprint.iacr.org/2020/852) (RFC 9591). The cryptography is the
Zcash Foundation [`frost-ed25519`](https://crates.io/crates/frost-ed25519)
crate, exposed through the `mpc_frost_ffi` C ABI in
`internal/rust/frost-ffi`. Signatures are standard Ed25519 and verify with
`crypto/ed25519`.

Used for Solana and NEAR. The API mirrors `pkg/dkls23` so callers can switch
protocols with minimal changes.

## Layers

```
pkg/frost (Go, cgo)
    -> internal/rust/frost-ffi (C ABI, JSON wire format)
        -> frost-ed25519 (Zcash Foundation)
```

## Protocol

Party IDs are one-based (`1..n`). Every party runs the same steps; messages
are exchanged by the caller's transport.

**DKG (t-of-n)**

1. `GenerateMsg1` - broadcast commitments.
2. `HandleMsg1(msgs)` - takes the `n-1` round 1 messages of the other parties
   and returns a JSON array of point-to-point packets. Each packet carries a
   secret share and a zero-based `to_id`; deliver it only to that recipient.
3. `HandleMsg2(msgs)` - takes the `n-1` packets addressed to this party and
   returns the keyshare JSON. `Round2MessagesFor(partyID, outputs...)` selects
   those packets from the round 2 outputs.

**Signing (any t parties)**

1. `GenerateMsg1` - broadcast nonce commitments.
2. `HandleMsg1(msgs)` - takes the other signers' commitments and returns this
   signer's signature share.
3. `CombineSignatures(share, otherShares)` - returns the 64-byte Ed25519
   signature as hex.

Nonces are single-use: a signing state cannot run `HandleMsg1` twice, even
after a failure.

## Example

```go
// DKG: 2-of-3, shown in one process for brevity.
parties := make([]*frost.DKGState, 3)
for i := range parties {
	parties[i], _ = frost.NewDKGState(uint8(i+1), 3, 2)
	defer parties[i].Free()
}
// ... exchange GenerateMsg1 / HandleMsg1 outputs ...
in, _ := frost.Round2MessagesFor(1, round2Outputs...)
keyshare1, _ := parties[0].HandleMsg2(in)

// Signing with parties 1 and 2.
s1, _ := frost.NewSigningStateForMessage(keyshare1, message)
defer s1.Free()
// ... exchange GenerateMsg1 outputs, call HandleMsg1, then:
sigHex, _ := frost.CombineSignatures(share1, []interface{}{share2})
```

See `frost_test.go` for a complete, runnable flow.

## Notes

- `NewSigningState` signs a 32-byte digest; `NewSigningStateForMessage` signs
  arbitrary bytes. Use the latter when the target chain expects Ed25519 over
  the raw message (for example Solana).
- `DerivePublicKey` and `DeriveKeyshare` accept a derivation path but the FFI
  does not implement hierarchical derivation yet; they return the group key
  and the unchanged keyshare.
- `CreatePartialSignature`, `SigningState.GenerateMsg2` and
  `SigningState.HandleMsg2` exist for DKLs23 API parity and are no-ops.
- State objects own native memory: call `Free` when done. They are not safe
  for concurrent use.
