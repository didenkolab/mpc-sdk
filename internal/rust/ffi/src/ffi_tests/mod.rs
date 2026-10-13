//! Integration tests that drive the C ABI the way a foreign caller would.
//! They live inside the crate so the library does not need an `rlib`
//! crate type, which would disable LTO for the shipped static library.

mod common;
mod dkg_signing;
mod golden;
mod negative;
mod ranked;
