# iOS example (Swift)

SwiftUI app that runs 2-of-2 key generation and signing for both protocols —
DKLs23 (ECDSA secp256k1) and FROST (Ed25519) — with both parties in one
process, calling the Rust FFI directly through `MpcCore.xcframework`.

| File | Purpose |
|------|---------|
| `MpcDemo/NativeMpc.swift` | Swift bindings to every DKLS23 and FROST FFI function |
| `MpcDemo/Dkls23Demo.swift` | DKLs23 flow: 4-round key generation, 3-round signing |
| `MpcDemo/FrostDemo.swift` | FROST flow: 2-round key generation, 1-round signing, local verification |
| `MpcDemo/MpcJson.swift` | Message routing helpers |
| `MpcDemo/ContentView.swift` | UI: a button per protocol, prints public key and signature |
| `MpcDemoTests/` | XCTest for both flows; FROST signatures are also checked with CryptoKit |
| `MpcCore/include/` | C headers and module map for the FFI |
| `build_xcframework.sh` | Builds the Rust FFI and packages `Frameworks/MpcCore.xcframework` |
| `project.yml` | [XcodeGen](https://github.com/yonaskolb/XcodeGen) spec for `MpcDemo.xcodeproj` |

## Run

Requirements: Xcode 15+, Rust (`rustup`), and the targets are installed by the script.

```sh
cd examples/ios
./build_xcframework.sh          # builds Frameworks/MpcCore.xcframework
open MpcDemo.xcodeproj          # run the MpcDemo scheme on a simulator or device
```

Tests from the command line:

```sh
xcodebuild test -project MpcDemo.xcodeproj -scheme MpcDemo \
  -destination 'platform=iOS Simulator,name=iPhone 16'
```

After editing `project.yml`, regenerate the project with `xcodegen generate`.

## Using it in your app

1. Copy `Frameworks/MpcCore.xcframework` and `MpcDemo/NativeMpc.swift` into your project
   (link the framework, do not embed — it is a static library).
2. Run each party on its own device and send the JSON messages over your transport.
   The demos show which messages go where: broadcast messages are passed to every
   other party, P2P messages only to the party in their `to_id`. FROST party ids start
   at 1 while its `to_id` is zero-based; FROST signs the raw message, DKLs23 a 32-byte hash.
3. Store keyshares in the Keychain; never send them anywhere.

Linking the DKLS23 library brings in code under the Silence Laboratories
Non-Commercial License — see the repository [NOTICE](../../NOTICE).
