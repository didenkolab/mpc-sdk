#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    mpc_ffi_fuzz::targets::dkls_dkg_msg4(data)
});
