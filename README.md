<div align="center">

# mpc-sdk

**Threshold signatures (MPC) for wallets — DKLs23 ECDSA + FROST Ed25519**

[![CI](https://github.com/didenkolab/mpc-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/didenkolab/mpc-sdk/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0%20%2B%20SLL%20core-blue)](#licensing--read-first)
[![Go](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go&logoColor=white)](go.mod)
[![Rust](https://img.shields.io/badge/Rust-1.88-000000?logo=rust&logoColor=white)](rust-toolchain.toml)
[![Status](https://img.shields.io/badge/status-experimental%20%C2%B7%20not%20audited-orange)](SECURITY.md)
[![GitHub stars](https://img.shields.io/github/stars/didenkolab/mpc-sdk?style=social)](https://github.com/didenkolab/mpc-sdk/stargazers)

![iOS](https://img.shields.io/badge/iOS-Swift-F05138?logo=swift&logoColor=white)
![Android](https://img.shields.io/badge/Android-Kotlin%20%2B%20JNI-3DDC84?logo=android&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-supported-FCC624?logo=linux&logoColor=black)
![macOS](https://img.shields.io/badge/macOS-supported-000000?logo=apple&logoColor=white)

![Bitcoin](https://img.shields.io/badge/Bitcoin-F7931A?logo=bitcoin&logoColor=white)
![Ethereum](https://img.shields.io/badge/Ethereum%20%26%20EVM-3C3C3D?logo=ethereum&logoColor=white)
![Solana](https://img.shields.io/badge/Solana-9945FF?logo=solana&logoColor=white)
![NEAR](https://img.shields.io/badge/NEAR-000000?logo=near&logoColor=white)
![Tron](https://img.shields.io/badge/Tron-FF060A)
![Litecoin](https://img.shields.io/badge/Litecoin-345D9D?logo=litecoin&logoColor=white)
![Cosmos](https://img.shields.io/badge/Cosmos-2E3148)

</div>

Threshold-signature (MPC) SDK: DKLs23 threshold ECDSA (secp256k1) and FROST
(Ed25519) behind a Rust FFI, with Go bindings, mobile bindings and chain
adapters for Bitcoin, EVM chains, Solana, NEAR, Tron, Litecoin and Cosmos.

Every party runs the cryptography locally; the SDK does not include or require
any particular server. Message transport between parties is up to you.

> **Status: experimental, not audited.** Do not use it to protect real funds
> without an independent security review. See [SECURITY.md](SECURITY.md).

## Licensing — read first

| Part | License |
|------|---------|
| Go packages, chain adapters, FFI wrappers (`internal/rust/ffi`, `internal/rust/frost-ffi`) | [Apache-2.0](LICENSE) |
| DKLs23 core `internal/rust/core` (derived from Silence Laboratories' `silent-shard-dkls23-ll`) | [Silence Laboratories Non-Commercial License](internal/rust/core/LICENSE.md) |

Anything that links the DKLs23 core (ECDSA: `pkg/dkls23`, `pkg/threshold`,
`pkg/sdk`, `pkg/mobile`) is **non-commercial only** unless you obtain a
commercial license from Silence Laboratories. FROST (Ed25519) and the chain
adapters do not link it. Details in [NOTICE](NOTICE).

## Layout

```
internal/rust/core       DKLs23 protocol (SLL)            + MODIFICATIONS.md
internal/rust/ffi        C ABI over the DKLs23 core       -> libmpc_dkls23_ffi
internal/rust/frost-ffi  C ABI over frost-ed25519         -> libmpc_frost_ffi
pkg/dkls23, pkg/frost    cgo bindings
pkg/threshold            high-level wallet / signing API
pkg/sdk                  SDK facade
pkg/mobile               gomobile bindings (Android / iOS)
pkg/chain/*              address derivation and transaction building per chain
examples/                Go demos per chain, start with basic-dkls23 (see examples/README.md)
examples/ios             Swift app: DKLs23 + FROST key generation and signing
examples/android         Kotlin + JNI app: DKLs23 + FROST key generation and signing
tools/mobile             cross-compilation of the FFI for iOS / Android
```

## Requirements

- Go 1.25+ with CGO enabled
- Rust (toolchain pinned in `rust-toolchain.toml`)
- Android NDK / Xcode for mobile builds (see [docs/mobile-build.md](docs/mobile-build.md))

## Build and test

```sh
make build-ffi     # build libmpc_dkls23_ffi + libmpc_frost_ffi
make test          # Rust + Go tests
make lint          # golangci-lint, cargo fmt, cargo clippy
make coverage      # Go coverage report
make mobile-all    # libraries for iOS and Android
```

Go packages that use the FFI need the libraries on the linker path
(`internal/rust/target/release` is used by default via cgo directives; on Linux
also set `LD_LIBRARY_PATH` to it).

## Quick start

```go
import "github.com/didenkolab/mpc-sdk/pkg/threshold"

// A 2-of-3 ECDSA wallet with all parties simulated in one process.
wm := threshold.NewWalletManagerWithMode(threshold.ECDSASecp256k1, threshold.ExecutionModeInMemoryDemo)

wallet, err := wm.CreateCompleteWallet(3, 2, 0)
if err != nil {
    log.Fatal(err)
}

msg := []byte("hello, threshold signatures")
sig, err := wallet.SignWithWallet(msg, []int{0, 2}, wm) // any 2 of the 3 parties
if err != nil {
    log.Fatal(err)
}
valid, _ := wm.VerifySignature(msg, sig)
fmt.Println(wallet.MainAddress.Address, valid) // bc1q... true
```

In production each party runs on its own device and exchanges messages over a
`MessageTransport` you provide; the in-memory mode routes the same messages
locally.

More in [pkg/threshold/README.md](pkg/threshold/README.md) and the runnable demos
([examples/README.md](examples/README.md)):

```sh
go run ./examples/basic-dkls23      # every DKG and signing round, step by step
go run ./examples/bitcoin-mpc       # threshold-signed Bitcoin spend, validated by the btcd script engine
go run ./examples/solana-frost-mpc  # FROST 2-of-3 Solana transfer
examples/run-all.sh                 # all of them
```

Every example verifies its signatures with an independent implementation. Chain
inputs (UTXOs, nonces, block hashes) are placeholders, so the transactions are
not broadcastable as-is; [examples/testnet](examples/testnet) signs real
testnet transactions with live chain data.

**Not yet supported:** Cosmos transactions (`pkg/chain/cosmos` builds a JSON
sign document, not the protobuf `SIGN_MODE_DIRECT` one — address derivation
works), Ed25519 child key derivation for FROST, key refresh and share recovery,
and distributed signing in `pkg/threshold` (key generation is distributed;
signing over a network uses the round functions in `pkg/sdk`).

Mobile: [examples/ios](examples/ios) (Swift) and [examples/android](examples/android) (Kotlin + JNI).

## Security cautions

- Presignatures are single-use handles held in memory by the native library and
  are lost on restart (fail closed); never try to persist them.
- Hash messages with the chain's algorithm before signing; never sign raw client input.
- Authenticate and encrypt protocol messages between parties.
- Encrypt key shares at rest and never export them.
- Verify every signature locally before broadcasting.

## Further docs

- [docs/ranked-participants.md](docs/ranked-participants.md) — hierarchical (ranked) DKG and signing
- [docs/mpc-demo-acceptance.md](docs/mpc-demo-acceptance.md) — per-chain demo status
- [docs/mobile-build.md](docs/mobile-build.md) — iOS / Android builds
- [pkg/frost/README.md](pkg/frost/README.md), [pkg/sdk/README.md](pkg/sdk/README.md)

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md). Report vulnerabilities privately as
described in [SECURITY.md](SECURITY.md). Changes are tracked in
[CHANGELOG.md](CHANGELOG.md).

## Star history

[![Star History Chart](https://api.star-history.com/svg?repos=didenkolab/mpc-sdk&type=Date)](https://star-history.com/#didenkolab/mpc-sdk&Date)
