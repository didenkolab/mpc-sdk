# threshold

High-level Go API for threshold signatures. One interface covers two protocols:

| Algorithm | Protocol | Curve | Typical chains |
|-----------|----------|-------|----------------|
| `ECDSASecp256k1` | DKLs23 | secp256k1 | Bitcoin, Ethereum and EVM chains, Tron |
| `Ed25519FROST` | FROST | Ed25519 | Solana, NEAR |

The cryptography runs in the Rust libraries under `internal/rust`, linked
through `pkg/dkls23` and `pkg/frost`.

```
pkg/threshold   WalletManager, DKGSession, MessageTransport
      |
pkg/dkls23  pkg/frost      typed cgo bindings
      |
internal/rust              DKLs23 and FROST implementations
```

## Execution modes

- `ExecutionModeProd` (default): this process is one party. Key generation
  talks to the other parties through a `MessageTransport` and returns only the
  local keyshare. Signing a threshold key with several local shares is refused.
- `ExecutionModeInMemoryDemo`: all parties run in this process. Use it for
  tests and demos only; one process holding every share defeats the purpose of
  threshold cryptography.

## Quick start (demo mode)

```go
wm := threshold.NewWalletManagerWithMode(threshold.ECDSASecp256k1, threshold.ExecutionModeInMemoryDemo)

// 3 parties, any 2 can sign.
wallet, err := wm.CreateCompleteWallet(3, 2, 0)
if err != nil {
    log.Fatal(err)
}
fmt.Println(wallet.MainAddress.Address) // bc1q...

msg := []byte("hello")
sig, err := wallet.SignWithWallet(msg, []int{0, 2}, wm)
if err != nil {
    log.Fatal(err)
}
valid, _ := wm.VerifySignature(msg, sig)
```

`SignMessage` signs `SHA-256(message)`. `SignTransaction` signs a 32-byte
transaction digest (a BIP-143 sighash, an EIP-155 signing hash, a Tron txID)
as-is, so the signature is valid on chain; verify it with
`VerifyTransactionSignature`.

ECDSA signatures are 64 bytes `r || s` with low `s`, also exposed as hex in
`Signature.R` and `Signature.S`. Ed25519 signatures are standard 64-byte
signatures.

DKLs23 signs with exactly `Threshold` parties; if more signer indices are
given, the first `Threshold` take part.

## Distributed key generation

Each party creates a `DKGSession` with the same participant list and session ID
and calls `ExecuteDKG`. Party IDs are `0..n-1`.

```go
session, err := threshold.NewDKGSession(myID, []uint8{0, 1, 2}, 2, threshold.ECDSASecp256k1)
if err != nil {
    log.Fatal(err)
}
defer session.Free()
session.SetSessionID(sharedSessionID)
session.SetTransport(transport)

keyshare, err := session.ExecuteDKG()
```

`NewDKGSessionWithRanks` creates a hierarchical (ranked) DKLs23 key; see
`docs/ranked-participants.md`.

`WalletManager.GenerateThresholdKeys` does the same through a
`ThresholdConfig` with `SessionID` and `Transport` set.

### Transport contract

```go
type MessageTransport interface {
    SendMessage(sessionID string, round int, toPartyID uint8, message Message) error
    BroadcastMessage(sessionID string, round int, message Message) error
    ReceiveMessages(sessionID string, round int, expectedCount int) ([]Message, error)
    SetTimeout(timeout time.Duration)
}
```

`ReceiveMessages` blocks until at least `expectedCount` messages are stored for
the round and returns them. It may return messages that are not for the
caller, including the caller's own broadcasts: sessions filter by sender and
recipient and ask again with a larger count when messages are missing.
`InMemoryTransport` implements the contract for tests and simulations.

## Key derivation

```go
child, err := wm.DeriveChildKey(keyshare, "m/44'/60'/0'/0/0")
addr, err := wm.GenerateAddress(child, "eth")
```

For DKLs23 the path is absolute from the root key; the child share keeps the
root key data and signs for the child public key. FROST does not support child
derivation yet and returns `ErrDerivationUnsupported` for any path other than
`m`.

## Addresses

| Algorithm | `addressType` | Result |
|-----------|---------------|--------|
| ECDSA | `""`, `bitcoin`, `btc` | Bitcoin P2WPKH (`bc1q...`) |
| ECDSA | `bitcoin-legacy`, `btc-legacy` | Bitcoin P2PKH (`1...`) |
| ECDSA | `ethereum`, `eth`, `bsc`, `polygon` | EIP-55 checksummed address |
| Ed25519 | `""`, `solana` | Base58 public key |
| Ed25519 | `near` | Hex implicit account |

## Security notes

- Every presignature is single-use; the native library enforces this.
- Messages are not encrypted or authenticated by this package. Run the
  transport over an authenticated, encrypted channel.
- Hash or otherwise domain-separate messages before signing; `SignTransaction`
  expects an already computed digest.
- `GetBalance` returns a fixed placeholder in demo mode unless a
  `BalanceProvider` is set.

## Testing

```bash
go test ./pkg/threshold
go test -run Example -v ./pkg/threshold
```

The tests verify every signature with independent implementations
(`github.com/decred/dcrd/dcrec/secp256k1/v4` for ECDSA, `crypto/ed25519` for
Ed25519).
