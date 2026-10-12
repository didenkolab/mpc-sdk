.PHONY: help build-ffi test test-rust test-go coverage lint fmt clean install-deps mobile-ios mobile-android mobile-all

help:
	@echo "mpc-sdk - Build Commands"
	@echo ""
	@echo "Available targets:"
	@echo "  build-ffi      Build Rust FFI libraries (DKLS23 + FROST)"
	@echo "  test           Run Rust + Go tests"
	@echo "  coverage       Go test coverage report (coverage.html)"
	@echo "  lint           golangci-lint, cargo fmt --check, cargo clippy"
	@echo "  fmt            Format Go and Rust code"
	@echo "  mobile-ios     Build Rust FFI libs for iOS (device + simulator)"
	@echo "  mobile-android Build Rust FFI libs for Android (arm64-v8a, x86_64)"
	@echo "  mobile-all     Build Rust FFI libs for both mobile targets"
	@echo "  clean          Clean build artifacts"

build-ffi:
	@echo "Building Rust FFI libraries (DKLS23 + FROST)..."
	cd internal/rust && cargo build -p dkls23-ffi --release && cargo build -p frost-ffi --release
	@echo "FFI libraries built at: internal/rust/target/release (libmpc_dkls23_ffi*, libmpc_frost_ffi*)"

test-rust:
	@echo "Running Rust tests..."
	cd internal/rust && cargo test --locked --release -p dkls23-ll -p dkls23-ffi -p frost-ffi

test-go: build-ffi
	@echo "Running Go tests..."
	go test ./pkg/...

test: test-rust test-go
	@echo "All tests passed!"

coverage: build-ffi
	go test -coverprofile=coverage.out ./pkg/...
	go tool cover -func=coverage.out | tail -1
	go tool cover -html=coverage.out -o coverage.html

lint:
	golangci-lint run ./...
	cd internal/rust && cargo fmt --check -p dkls23-ffi -p frost-ffi
	cd internal/rust && cargo clippy --locked -p dkls23-ffi -p frost-ffi --all-targets -- -D warnings

fmt:
	golangci-lint fmt ./...
	cd internal/rust && cargo fmt -p dkls23-ffi -p frost-ffi

clean:
	@echo "Cleaning build artifacts..."
	cd internal/rust && cargo clean
	@echo "Clean complete!"

install-deps:
	@echo "Installing dependencies..."
	@which cargo > /dev/null || (echo "Rust not found. Install from https://rustup.rs/" && exit 1)
	@which go > /dev/null || (echo "Go not found. Install from https://golang.org/" && exit 1)
	go mod download
	@echo "Dependencies installed!"

mobile-ios:
	@echo "Building iOS universal Rust FFIs..."
	tools/mobile/build_rust_mobile.sh ios

mobile-android:
	@echo "Building Android Rust FFIs (requires ANDROID_NDK_HOME)..."
	tools/mobile/build_rust_mobile.sh android

mobile-all: mobile-ios mobile-android

.DEFAULT_GOAL := help
