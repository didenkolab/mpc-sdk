#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUST_DIR="$ROOT/internal/rust"

build_ios() {
  local targets=("aarch64-apple-ios" "aarch64-apple-ios-sim" "x86_64-apple-ios")
  for tgt in "${targets[@]}"; do
    rustup target add "$tgt" >/dev/null
    cargo build --locked -p dkls23-ffi --release --target "$tgt" --manifest-path "$RUST_DIR/Cargo.toml"
    cargo build --locked -p frost-ffi  --release --target "$tgt" --manifest-path "$RUST_DIR/Cargo.toml"
  done

  # Device and simulator both contain arm64, so they cannot share one fat
  # library: device libs go to ios-universal (used by the cgo `darwin,ios`
  # directives), simulator arm64+x86_64 libs to ios-simulator. For an app,
  # package both as an XCFramework (see examples/ios/build_xcframework.sh).
  local device="$RUST_DIR/target/ios-universal"
  local simulator="$RUST_DIR/target/ios-simulator"
  mkdir -p "$device" "$simulator"

  local lib
  for lib in libmpc_dkls23_ffi.a libmpc_frost_ffi.a; do
    cp "$RUST_DIR/target/aarch64-apple-ios/release/$lib" "$device/$lib"
    lipo -create \
      "$RUST_DIR/target/aarch64-apple-ios-sim/release/$lib" \
      "$RUST_DIR/target/x86_64-apple-ios/release/$lib" \
      -output "$simulator/$lib"
  done

  echo "iOS device libs ready at: $device"
  echo "iOS simulator libs ready at: $simulator"
}

build_android() {
  if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
    echo "ANDROID_NDK_HOME is not set; skipping Android build."
    return
  fi

  local host_dir
  host_dir="$(find "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt" -maxdepth 1 -mindepth 1 -type d | head -n1)"
  if [[ ! -d "$host_dir/bin" ]]; then
    echo "Failed to locate NDK clang toolchain under $ANDROID_NDK_HOME"
    exit 1
  fi
  local cc_aarch64="$host_dir/bin/aarch64-linux-android21-clang"
  local cc_x86_64="$host_dir/bin/x86_64-linux-android21-clang"
  local llvm_ar="$host_dir/bin/llvm-ar"

  # macOS still ships Bash 3.2, which does not support associative arrays.
  local targets=("aarch64-linux-android" "x86_64-linux-android")
  local compilers=("$cc_aarch64" "$cc_x86_64")
  local linker_vars=(
    "CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER"
    "CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER"
  )
  local cc_vars=("CC_aarch64_linux_android" "CC_x86_64_linux_android")
  local ar_vars=("AR_aarch64_linux_android" "AR_x86_64_linux_android")
  local index tgt
  for index in "${!targets[@]}"; do
    tgt="${targets[$index]}"
    rustup target add "$tgt" >/dev/null
    env \
      "${linker_vars[$index]}=${compilers[$index]}" \
      "${cc_vars[$index]}=${compilers[$index]}" \
      "${ar_vars[$index]}=$llvm_ar" \
      cargo build --locked -p dkls23-ffi --release --target "$tgt" --manifest-path "$RUST_DIR/Cargo.toml"
    env \
      "${linker_vars[$index]}=${compilers[$index]}" \
      "${cc_vars[$index]}=${compilers[$index]}" \
      "${ar_vars[$index]}=$llvm_ar" \
      cargo build --locked -p frost-ffi --release --target "$tgt" --manifest-path "$RUST_DIR/Cargo.toml"
    echo "Built Android target: $tgt"
  done
}

case "${1:-all}" in
  ios) build_ios ;;
  android) build_android ;;
  all)
    build_ios
    build_android
    ;;
  *)
    echo "Usage: $0 [ios|android|all]"
    exit 1
    ;;
esac
