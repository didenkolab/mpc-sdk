# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-12

First public release.

### Added

- DKLs23 threshold ECDSA (secp256k1) with ranked (hierarchical) participants and BIP32 derivation.
- FROST threshold Ed25519 signing.
- Rust FFI (C ABI), Go bindings, high-level `pkg/threshold` and `pkg/sdk` APIs, gomobile bindings.
- Chain adapters: Bitcoin, Ethereum and EVM chains, Solana, NEAR, Tron, Litecoin, Cosmos.
- iOS (Swift) and Android (Kotlin + JNI) example apps.

### Security

- The Rust FFI validates peer messages (sender ids, JSON, signer sets) before
  they reach the protocol core, so a malicious party cannot crash other parties.
- Presignatures and FROST nonces are single-use, even when a signing attempt fails.

[Unreleased]: https://github.com/didenkolab/mpc-sdk/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/didenkolab/mpc-sdk/releases/tag/v0.1.0
