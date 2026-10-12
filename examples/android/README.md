# Android example (Kotlin + JNI)

Android app that runs 2-of-2 key generation and signing for both protocols —
DKLs23 (ECDSA secp256k1) and FROST (Ed25519) — with both parties in one
process, calling the Rust FFI through a small JNI layer.

| File | Purpose |
|------|---------|
| `app/src/main/cpp/mpc_jni.cpp` | JNI wrapper over every DKLS23 and FROST FFI function |
| `app/src/main/cpp/CMakeLists.txt` | Links the Rust static libraries into `libmpc_jni.so` |
| `app/src/main/java/.../NativeMpc.kt` | Kotlin `external` declarations |
| `app/src/main/java/.../Dkls23Demo.kt` | DKLs23 flow: 4-round key generation, 3-round signing |
| `app/src/main/java/.../FrostDemo.kt` | FROST flow: 2-round key generation, 1-round signing, local verification |
| `app/src/main/java/.../MpcJson.kt` | Message routing helpers |
| `app/src/main/java/.../MainActivity.kt` | UI: a button per protocol, prints public key and signature |
| `app/src/androidTest/` | Instrumented tests for both flows; signatures are checked with BouncyCastle |

## Run

Requirements: Android Studio (or SDK + NDK), JDK 17, Rust (`rustup`).

1. Build the Rust FFI for arm64-v8a and x86_64 from the repository root:
   ```sh
   ANDROID_NDK_HOME=/path/to/android-ndk tools/mobile/build_rust_mobile.sh android
   ```
   The libraries land in `internal/rust/target/<triple>/release/`, where CMake picks them up.
2. Open `examples/android` in Android Studio and run the `app` configuration, or:
   ```sh
   cd examples/android
   ./gradlew installDebug
   ./gradlew connectedAndroidTest   # with an emulator or device attached
   ```

## Using it in your app

1. Copy `mpc_jni.cpp`, `CMakeLists.txt` and `NativeMpc.kt`. If you change the Kotlin
   package, rename the `Java_com_didenkolab_mpcsdk_demo_NativeMpc_*` symbols in
   `mpc_jni.cpp` to match — JNI resolves functions by package and class name.
2. Run each party on its own device and send the JSON messages over your transport.
   The demos show which messages go where: broadcast messages are passed to every
   other party, P2P messages only to the party in their `to_id`. FROST party ids start
   at 1 while its `to_id` is zero-based; FROST signs the raw message, DKLs23 a 32-byte hash.
3. Store keyshares encrypted (Android Keystore); never send them anywhere.

Failed FFI calls throw `IllegalStateException` with the Rust error message;
`*Init` functions return `0` instead (read the reason with `getLastError()`).

Linking the DKLS23 library brings in code under the Silence Laboratories
Non-Commercial License — see the repository [NOTICE](../../NOTICE).
