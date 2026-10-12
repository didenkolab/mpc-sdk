module github.com/didenkolab/mpc-sdk

go 1.25.0

require (
	github.com/blocto/solana-go-sdk v1.30.0
	github.com/btcsuite/btcd v0.24.2
	github.com/btcsuite/btcd/btcec/v2 v2.5.0
	github.com/btcsuite/btcd/btcutil v1.2.0
	github.com/btcsuite/btcd/chaincfg/chainhash v1.2.0
	github.com/btcsuite/btcutil v1.0.2
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0
	github.com/ethereum/go-ethereum v1.17.8
	github.com/mr-tron/base58 v1.3.0
	golang.org/x/crypto v0.55.0
)

replace github.com/btcsuite/btcd => github.com/btcsuite/btcd v0.24.2

require (
	filippo.io/edwards25519 v1.0.0-rc.1 // indirect
	github.com/ProjectZKM/Ziren/crates/go-runtime/zkvm_runtime v0.0.0-20251001021608-1fe7b43fc4d6 // indirect
	github.com/bits-and-blooms/bitset v1.20.0 // indirect
	github.com/btcsuite/btcd/chainhash/v2 v2.0.0 // indirect
	github.com/btcsuite/btclog v0.0.0-20170628155309-84c8d2346e9f // indirect
	github.com/consensys/gnark-crypto v0.18.1 // indirect
	github.com/crate-crypto/go-eth-kzg v1.5.0 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.1.0 // indirect
	github.com/ethereum/c-kzg-4844/v2 v2.1.8 // indirect
	github.com/holiman/uint256 v1.3.2 // indirect
	github.com/kcalvinalvin/anet v0.0.0-20251112173137-d8ddc1f6dbee // indirect
	github.com/supranational/blst v0.3.16 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)
