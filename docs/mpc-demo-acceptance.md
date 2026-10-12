# MPC demo acceptance criteria

Every chain example runs the full path DKG → address → transaction build →
threshold signature → signature attached to the transaction → local
verification, with no stubs or hard-coded keys.

## Requirements

- The key and address come from an MPC DKG run; no pre-generated keys.
- The signature is verified locally with the same hash and algorithm the chain
  uses (Bitcoin sighash, EIP-155 Keccak, `sha256(raw_data)` for Tron,
  `sha256(Borsh tx)` for NEAR, Ed25519 over the serialized message for Solana),
  using an implementation independent of the SDK where possible.
- The signature is embedded in the final raw transaction or JSON and the
  serialization is deterministic.
- Any inconsistency (failed verification, wrong hash, empty key) makes the
  example exit with a non-zero status.
- Reproducible: `go run ./examples/<name>` from the repository root after
  `make build-ffi`; `examples/run-all.sh` runs them all.

Transaction inputs that come from the chain (UTXOs, nonces, recent block
hashes) are placeholders, so the signed transactions are valid against those
inputs but must be rebuilt with live data before broadcasting.

## Status

| Chain | Protocol | Example | Verification |
|-------|----------|---------|--------------|
| Bitcoin | DKLs23, secp256k1 | `bitcoin-mpc` | P2PKH and P2WPKH spends executed by the btcd script engine |
| Litecoin | DKLs23, secp256k1 | `litecoin-mpc` | P2PKH and P2WPKH (BIP143) spends executed by the script engine |
| Ethereum and EVM (BSC, Polygon, Arbitrum, Avalanche C-Chain) | DKLs23, secp256k1 | `ethereum-mpc` | EIP-155 legacy transactions; `types.Sender` recovers the MPC address |
| Tron | DKLs23, secp256k1 | `tron-mpc` | TRX transfer; public key recovered from the 65-byte signature maps to the MPC address |
| Cosmos Hub | DKLs23, secp256k1 | `cosmos-mpc` | `MsgSend` sign document; ECDSA verification of `sha256(sign bytes)` (see note) |
| Solana | FROST, Ed25519 | `solana-frost-mpc` | SOL transfer; `ed25519.Verify` over the serialized message |
| NEAR | FROST, Ed25519 | `near-frost-mpc` | Transfer; `ed25519.Verify` over `sha256(Borsh tx)` |

Note: `pkg/chain/cosmos` encodes the sign document as JSON rather than the
protobuf encoding required by `SIGN_MODE_DIRECT`, so the Cosmos example proves
the key, address and signature format but does not yet produce a transaction a
node would accept.

## Chains reachable with the existing signature schemes

- **ECDSA secp256k1** (DKLs23): Bitcoin and its forks (Litecoin, Dogecoin,
  Bitcoin Cash, Dash, Zcash transparent), Ethereum and EVM chains (BSC,
  Polygon, Arbitrum, Optimism, Base, Avalanche C-Chain, and others), Tron,
  Cosmos SDK chains, XRP Ledger (secp256k1 keys).
- **Ed25519** (FROST): Solana, NEAR, Stellar, Algorand, Aptos, Sui, TON,
  Hedera, Tezos (tz1). Cardano uses extended Ed25519 keys and needs extra work.
- **Not covered**: chains with other schemes, such as Polkadot (sr25519) and
  Monero.

## Building the FFI

- `make build-ffi` builds `mpc_dkls23_ffi` and `mpc_frost_ffi` into
  `internal/rust/target/release`.
- cgo links them with `-lmpc_dkls23_ffi` and `-lmpc_frost_ffi`
  (see `pkg/dkls23` and `pkg/frost`).
- On Linux, export `LD_LIBRARY_PATH=$PWD/internal/rust/target/release` before
  running the examples so the shared libraries are found at run time.
