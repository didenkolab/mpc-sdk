//! Fuzz harness for the DKLs23 (`mpc_dkls23_ffi`) and FROST
//! (`mpc_frost_ffi`) C ABIs.
//!
//! The FFI crates are built as `staticlib` + `cdylib` only (an `rlib` crate
//! type would disable LTO for the shipped libraries), so they cannot be used
//! as ordinary dependencies. Instead their `lib.rs` files are compiled into
//! this crate as modules. The code under test is therefore byte-for-byte the
//! shipped source, and the FFI crates need no fuzz-specific changes.
//!
//! Every target calls the exported `extern "C"` functions exactly like a
//! foreign caller: NUL-terminated strings in, owned strings out. Release
//! builds use `panic = "abort"`, so any panic reached here would kill the
//! host application; libFuzzer reports it as a crash.

#[allow(dead_code, clippy::all)]
#[path = "../../ffi/src/lib.rs"]
pub mod dkls23;

#[allow(dead_code, clippy::all)]
#[path = "../../frost-ffi/src/lib.rs"]
pub mod frost;

pub mod dkls_fixture;
pub mod frost_fixture;
pub mod input;
pub mod targets;
