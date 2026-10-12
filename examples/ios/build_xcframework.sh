#!/usr/bin/env bash
# Builds Frameworks/MpcCore.xcframework from the mpc-sdk Rust FFI crates
# (dkls23-ffi + frost-ffi) for iOS devices and simulators.
set -euo pipefail

EXAMPLE_DIR="$(cd "$(dirname "$0")" && pwd)"
RUST_DIR="$(cd "${EXAMPLE_DIR}/../../internal/rust" && pwd)"
TARGET_DIR="${RUST_DIR}/target"
BUILD_DIR="${EXAMPLE_DIR}/build"
HEADERS="${EXAMPLE_DIR}/MpcCore/include"
OUTPUT="${EXAMPLE_DIR}/Frameworks/MpcCore.xcframework"

TARGETS=(aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios)

echo "==> Building Rust FFI for ${TARGETS[*]}"
for target in "${TARGETS[@]}"; do
  rustup target add "${target}" >/dev/null
  cargo build --locked --release -p dkls23-ffi -p frost-ffi \
    --target "${target}" --manifest-path "${RUST_DIR}/Cargo.toml"
done

mkdir -p "${BUILD_DIR}" "$(dirname "${OUTPUT}")"

echo "==> Merging dkls23 + frost into one static library per slice"
merge() {
  libtool -static -o "$1" \
    "${TARGET_DIR}/$2/release/libmpc_dkls23_ffi.a" \
    "${TARGET_DIR}/$2/release/libmpc_frost_ffi.a"
}
merge "${BUILD_DIR}/libMpcCore-ios.a" aarch64-apple-ios
merge "${BUILD_DIR}/libMpcCore-sim-arm64.a" aarch64-apple-ios-sim
merge "${BUILD_DIR}/libMpcCore-sim-x86_64.a" x86_64-apple-ios
lipo -create "${BUILD_DIR}/libMpcCore-sim-arm64.a" "${BUILD_DIR}/libMpcCore-sim-x86_64.a" \
  -output "${BUILD_DIR}/libMpcCore-sim.a"

echo "==> Creating XCFramework"
rm -rf "${OUTPUT}"
xcodebuild -create-xcframework \
  -library "${BUILD_DIR}/libMpcCore-ios.a" -headers "${HEADERS}" \
  -library "${BUILD_DIR}/libMpcCore-sim.a" -headers "${HEADERS}" \
  -output "${OUTPUT}"

echo "==> Done: ${OUTPUT}"
