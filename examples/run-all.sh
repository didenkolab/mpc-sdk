#!/usr/bin/env sh
# Runs every Go example and stops at the first failure.
#
# Usage (from anywhere):  examples/run-all.sh
# Requires the FFI libraries: run `make build-ffi` first.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

# Linux needs the runtime linker to find the shared FFI libraries.
lib="$root/internal/rust/target/release"
export LD_LIBRARY_PATH="$lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

examples="
basic-dkls23
ranked-participants-example
bitcoin-mpc
litecoin-mpc
ethereum-mpc
tron-mpc
cosmos-mpc
solana-frost-mpc
near-frost-mpc
"

for ex in $examples; do
	printf '\n### %s\n\n' "$ex"
	go run "./examples/$ex"
done

printf '\nAll examples passed.\n'
