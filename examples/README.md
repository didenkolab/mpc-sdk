# Examples

Each Go example runs a complete threshold flow in one process: distributed key
generation, address derivation, transaction building, threshold signing and
local verification of the result with an independent implementation (btcd
script engine, btcec ECDSA, go-ethereum sender recovery, `crypto/ed25519`). An example
exits with a non-zero status if any step fails.

| Example | Protocol | Shows |
|---------|----------|-------|
| [basic-dkls23](basic-dkls23) | DKLs23 2-of-2 | every DKG and signing round, step by step |
| [ranked-participants-example](ranked-participants-example) | DKLs23 2-of-3 | standard vs hierarchical (ranked) keys |
| [bitcoin-mpc](bitcoin-mpc) | DKLs23 2-of-2 | P2PKH and P2WPKH spends, script validation |
| [litecoin-mpc](litecoin-mpc) | DKLs23 2-of-2 | P2PKH and P2WPKH spends, script validation |
| [ethereum-mpc](ethereum-mpc) | DKLs23 2-of-2 | EIP-155 ETH and ERC-20 transfers on five EVM chains |
| [tron-mpc](tron-mpc) | DKLs23 2-of-2 | TRX transfer, recoverable signature |
| [cosmos-mpc](cosmos-mpc) | DKLs23 2-of-2 | bank MsgSend sign document |
| [solana-frost-mpc](solana-frost-mpc) | FROST 2-of-3 | SOL transfer |
| [near-frost-mpc](near-frost-mpc) | FROST 2-of-3 | NEAR transfer |

Live networks: [testnet](testnet) threshold-signs real transactions on
Bitcoin testnet4/signet, Sepolia, Solana devnet, Tron Nile and NEAR testnet
with live chain data (dry run unless `-broadcast` is passed; mainnet is refused).

Mobile apps: [ios](ios) (Swift) and [android](android) (Kotlin + JNI).

## Running

```sh
make build-ffi                  # once: builds the Rust FFI libraries
go run ./examples/bitcoin-mpc   # any example, from the repository root
examples/run-all.sh             # every Go example, stops at the first failure
```

On Linux, export `LD_LIBRARY_PATH=$PWD/internal/rust/target/release` before
`go run` so the shared FFI libraries are found at run time (`run-all.sh` does
this for you).

All parties run in the same process and messages are passed in memory by
[`internal/mpcdemo`](internal/mpcdemo), which routes broadcast and
point-to-point messages exactly as a network transport would. The chain
examples use placeholder inputs (UTXOs, nonces, block hashes), so they are valid
against those inputs but not broadcastable; use `testnet` for real chain data.
