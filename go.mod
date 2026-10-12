module github.com/didenkolab/mpc-sdk

go 1.25.0

require (
	github.com/blocto/solana-go-sdk v1.30.0
	github.com/btcsuite/btcd v0.24.2
	github.com/btcsuite/btcd/btcec/v2 v2.2.0
	github.com/btcsuite/btcd/btcutil v1.1.6
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0
	github.com/btcsuite/btcutil v1.0.2
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1
	github.com/ethereum/go-ethereum v1.17.0
	github.com/mr-tron/base58 v1.2.0
	golang.org/x/crypto v0.52.0
)

replace github.com/btcsuite/btcd => github.com/btcsuite/btcd v0.24.2

require (
	filippo.io/edwards25519 v1.1.1 // indirect
	github.com/ProjectZKM/Ziren/crates/go-runtime/zkvm_runtime v0.0.0-20251001021608-1fe7b43fc4d6 // indirect
	github.com/bits-and-blooms/bitset v1.20.0 // indirect
	github.com/btcsuite/btclog v0.0.0-20170628155309-84c8d2346e9f // indirect
	github.com/consensys/gnark-crypto v0.18.1 // indirect
	github.com/crate-crypto/go-eth-kzg v1.4.0 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.0.0 // indirect
	github.com/ethereum/c-kzg-4844/v2 v2.1.5 // indirect
	github.com/holiman/uint256 v1.3.2 // indirect
	github.com/supranational/blst v0.3.16-0.20250831170142-f48500c1fdbe // indirect
	golang.org/x/sync v0.18.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
)
