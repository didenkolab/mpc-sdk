# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.1] - 2026-10-13

### Fixed

- **Tron:** `raw_data.timestamp` is now written as protobuf field 14 (was 13), so
  txIDs and signatures cover the canonical bytes. Verified byte-for-byte against
  a Nile testnet node.
- **Arbitrum, BSC, Polygon:** recipient addresses are validated (length, hex,
  EIP-55 checksum) instead of being silently truncated or padded into another
  valid address. New `evm.ParseAddress`.
- **DKLs23 core:** a malicious signer can no longer abort the host process by
  making the `s_1` values sum to zero; combining returns an error instead.
- **Android example:** the JNI layer rejects message hashes that are not exactly
  32 bytes instead of reading past the array.
- **DKLs23 FFI — rounds run exactly once:** re-running a DKG or signing round on
  the same state, or running rounds out of order, is refused. A failure inside
  the protocol code makes the state unusable (start a new session); malformed
  input or wrong senders do not, so callers can still retry with correct
  messages.
- **DKLs23 FFI — ranked keys:** rank vectors that no signer set could ever use
  are rejected at init (they used to abort the process in the last DKG round),
  and `dkls23_derive_keyshare` only shifts rank-0 shares, so derived ranked
  keyshares sign again.
- **DKLs23 FFI — keyshare validation:** `dkls23_dsg_init` rejects inconsistent
  keyshares (e.g. a relabelled `party_id`) instead of panicking; found by
  fuzzing.
- **DKLs23 FFI — thresholds:** `t < 2` and `t > n` are rejected at init.
- **FROST FFI:** `frost_derive_public_key` / `frost_derive_keyshare` reject any
  path other than `"m"` instead of silently returning the root key (Ed25519
  child derivation is not implemented).
- **Both FFIs:** JSON parse errors no longer echo quoted input values (which
  could contain key material) into the last-error string.

### Changed

- `pkg/chain/cosmos` is documented as experimental: its sign document is JSON,
  not the protobuf `SIGN_MODE_DIRECT` encoding Cosmos chains verify.
- cgo link paths use `${SRCDIR}`.

### Added

- Golden tests that pin the keyshare and protocol-message formats, so a
  dependency update cannot silently break stored keyshares.
- Exhaustive tests for ranked (hierarchical) signer sets.
- Coverage-guided fuzzing of every FFI entry point (`internal/rust/fuzz`, 18
  targets), run briefly on pull requests and weekly in CI.
- `examples/testnet`: threshold-signs real testnet transactions (Bitcoin,
  Sepolia, Solana devnet, Tron Nile, NEAR) with live chain data; dry run by
  default, mainnet refused.

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

[Unreleased]: https://github.com/didenkolab/mpc-sdk/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/didenkolab/mpc-sdk/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/didenkolab/mpc-sdk/releases/tag/v0.1.0
