cmake_minimum_required(VERSION 3.22)

project("mpc_jni")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(mpc_jni SHARED mpc_jni.cpp)

# Static libraries built by tools/mobile/build_rust_mobile.sh android
set(RUST_TARGET_DIR "${CMAKE_SOURCE_DIR}/../../../../../../internal/rust/target")

if(${ANDROID_ABI} STREQUAL "arm64-v8a")
    set(RUST_TRIPLE "aarch64-linux-android")
elseif(${ANDROID_ABI} STREQUAL "x86_64")
    set(RUST_TRIPLE "x86_64-linux-android")
else()
    message(FATAL_ERROR "Unsupported ABI: ${ANDROID_ABI}")
endif()

add_library(mpc_dkls23_ffi STATIC IMPORTED)
set_target_properties(mpc_dkls23_ffi PROPERTIES
    IMPORTED_LOCATION "${RUST_TARGET_DIR}/${RUST_TRIPLE}/release/libmpc_dkls23_ffi.a")

add_library(mpc_frost_ffi STATIC IMPORTED)
set_target_properties(mpc_frost_ffi PROPERTIES
    IMPORTED_LOCATION "${RUST_TARGET_DIR}/${RUST_TRIPLE}/release/libmpc_frost_ffi.a")

find_library(log-lib log)

# Both Rust static libraries embed the Rust runtime (rust_eh_personality etc.)
target_link_options(mpc_jni PRIVATE "-Wl,--allow-multiple-definition")

target_link_libraries(mpc_jni mpc_dkls23_ffi mpc_frost_ffi ${log-lib} dl m c)

target_compile_options(mpc_jni PRIVATE -Wall -Wextra -Wno-unused-parameter -fvisibility=hidden)
