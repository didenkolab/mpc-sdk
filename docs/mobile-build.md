# Mobile build cheatsheet (iOS / Android)

This project can ship the DKLs23/FROST FFI as static libraries for mobile. The steps below assume
the Rust and Go toolchains are installed. `tools/mobile/build_rust_mobile.sh` is a Bash script
(use WSL or Git Bash on Windows).

## iOS
1. Install targets:
   ```sh
   rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
   ```
2. Build Rust FFIs:
   ```sh
   tools/mobile/build_rust_mobile.sh ios
   ```
   Device libs land in `internal/rust/target/ios-universal` (picked up by cgo `darwin,ios` directives),
   simulator libs (arm64 + x86_64) in `internal/rust/target/ios-simulator`.
   For a native Swift app, build an XCFramework instead: `examples/ios/build_xcframework.sh`
   (see [examples/ios](../examples/ios)).
3. Build Go bindings with gomobile (the gomobile-compatible API lives in `pkg/mobile`):
   ```sh
   gomobile bind -target=ios/arm64 -o MpcSdk.xcframework ./pkg/mobile
   ```
   The cgo `darwin,ios` directives link against the device libraries only, so Go bindings target
   devices (`ios/arm64`). The native XCFramework from step 2 covers both device and simulator.
   Ensure `CGO_ENABLED=1` and the Xcode command-line tools are present.

## Android
1. Install targets:
   ```sh
   rustup target add aarch64-linux-android x86_64-linux-android
   ```
2. Set `ANDROID_NDK_HOME` to your NDK root, then build Rust FFIs per ABI:
   ```sh
   ANDROID_NDK_HOME=/path/to/android-ndk tools/mobile/build_rust_mobile.sh android
   ```
   Artifacts: `internal/rust/target/<target>/release/libmpc_{dkls23,frost}_ffi.a`.
3. Build Go bindings with gomobile for the ABIs built in step 2:
   ```sh
   gomobile bind -target=android/arm64,android/amd64 -androidapi 21 -o mpc-sdk.aar ./pkg/mobile
   ```
   Cgo links against the per-ABI libraries via the `android,*` LDFLAGS in `pkg/dkls23` and
   `pkg/frost`. Plain `-target=android` also builds `arm` and `386`, which need FFI libraries
   for `armv7-linux-androideabi` and `i686-linux-android` that the script does not build.
   For a native Kotlin app using JNI, see [examples/android](../examples/android).

## Notes
- The release profile uses `panic = "abort"`: a Rust panic terminates the host process instead of
  unwinding across the FFI boundary.
- The FFI crates are built as `staticlib` (plus `cdylib`); mobile integrations link the `.a` archives.
- If you keep custom library locations, set `CGO_LDFLAGS` or adjust the `-L` paths accordingly.
- Always rebuild both the DKLs23 and FROST FFI crates for every target you need.

## Windows environment

On Windows, point the Android tooling and `build_rust_mobile.sh` at your local SDK/NDK (adjust
paths to your machine):
```powershell
$env:ANDROID_HOME="$env:LOCALAPPDATA\Android\Sdk"
$env:ANDROID_SDK_ROOT=$env:ANDROID_HOME
$env:ANDROID_NDK_HOME="$env:ANDROID_HOME\ndk\23.1.7779620"
```
