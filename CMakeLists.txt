cmake_minimum_required(VERSION 3.14)
project(libbitcoinpqc C)

include(FetchContent)
find_package(Threads REQUIRED)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Set version
set(BITCOINPQC_VERSION_MAJOR 0)
set(BITCOINPQC_VERSION_MINOR 1)
set(BITCOINPQC_VERSION_PATCH 0)

# Library output settings
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Custom randombytes implementation
set(CUSTOM_RANDOMBYTES
    src/randombytes_custom.c
)

# ML-DSA-44 (Dilithium) source files
set(ML_DSA_SOURCES
    dilithium/ref/sign.c
    dilithium/ref/packing.c
    dilithium/ref/polyvec.c
    dilithium/ref/poly.c
    dilithium/ref/ntt.c
    dilithium/ref/reduce.c
    dilithium/ref/rounding.c
    dilithium/ref/fips202.c
    dilithium/ref/symmetric-shake.c
)

# SLH-DSA-SHA2-128s (SPHINCS+) source files
set(SLH_DSA_SOURCES
    sphincsplus/ref/address.c
    sphincsplus/ref/fors.c
    sphincsplus/ref/hash_sha2.c
    sphincsplus/ref/merkle.c
    sphincsplus/ref/sign.c
    sphincsplus/ref/thash_sha2_simple.c
    sphincsplus/ref/utils.c
    sphincsplus/ref/utilsx1.c
    sphincsplus/ref/wots.c
    sphincsplus/ref/wotsx1.c
    sphincsplus/ref/sha2.c
)

# libsecp256k1 (BIP-340 Schnorr + x-only keys)
FetchContent_Declare(
    secp256k1
    GIT_REPOSITORY https://github.com/bitcoin-core/secp256k1.git
    GIT_TAG v0.5.0
)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(SECP256K1_DISABLE_SHARED ON CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_SCHNORRSIG ON CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_EXTRAKEYS ON CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_BENCHMARK OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXHAUSTIVE_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(secp256k1)

install(TARGETS secp256k1
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

# libbitcoinpqc source files
set(BITCOINPQC_SOURCES
    src/bitcoinpqc.c
    src/secp256k1_schnorr.c
    src/ml_dsa/utils.c
    src/ml_dsa/keygen.c
    src/ml_dsa/sign.c
    src/ml_dsa/verify.c
    src/slh_dsa/utils.c
    src/slh_dsa/keygen.c
    src/slh_dsa/sign.c
    src/slh_dsa/verify.c
)

set(ALL_SOURCES
    ${BITCOINPQC_SOURCES}
    ${ML_DSA_SOURCES}
    ${SLH_DSA_SOURCES}
    ${CUSTOM_RANDOMBYTES}
)

# Helper to apply common settings to a target
function(configure_target target)
    # Set include directories for the target
    target_include_directories(${target} PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/dilithium/ref
        ${CMAKE_CURRENT_SOURCE_DIR}/sphincsplus/ref
    )
    target_link_libraries(${target} PUBLIC secp256k1 Threads::Threads)
    # Set compile definitions for the target
    target_compile_definitions(${target} PRIVATE
        DILITHIUM_MODE=2
        PARAMS=sphincs-sha2-128s
        CUSTOM_RANDOMBYTES=1
    )
endfunction()

# Define the static library targets
add_library(bitcoinpqc STATIC ${ALL_SOURCES})
configure_target(bitcoinpqc)

# Define the shared object target
add_library(bitcoinpqc_shared SHARED ${ALL_SOURCES})
configure_target(bitcoinpqc_shared)
set_target_properties(bitcoinpqc_shared PROPERTIES OUTPUT_NAME bitcoinpqc)


# Configure install paths
install(TARGETS bitcoinpqc bitcoinpqc_shared
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
    DESTINATION include
    FILES_MATCHING PATTERN "*.h"
)

# Optional examples and tests
option(BUILD_EXAMPLES "Build example programs" OFF)
option(BUILD_TESTS "Build and register CTest targets" ON)

if(BUILD_EXAMPLES)
    add_executable(entropy_demo examples/entropy_demo.c)
    target_link_libraries(entropy_demo PRIVATE bitcoinpqc)
    target_include_directories(entropy_demo PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
endif()

if(BUILD_TESTS)
    enable_testing()

    add_executable(slh_dsa_sha2_test tests/slh_dsa_sha2_test.c)
    target_link_libraries(slh_dsa_sha2_test PRIVATE bitcoinpqc)
    target_include_directories(slh_dsa_sha2_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/tests
    )

    add_test(NAME slh_dsa_sha2_api COMMAND slh_dsa_sha2_test)

    add_executable(secp256k1_schnorr_test tests/secp256k1_schnorr_test.c)
    target_link_libraries(secp256k1_schnorr_test PRIVATE bitcoinpqc)
    target_include_directories(secp256k1_schnorr_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    add_test(NAME secp256k1_schnorr_e2e COMMAND secp256k1_schnorr_test)

    add_executable(ml_dsa_44_test tests/ml_dsa_44_test.c)
    target_link_libraries(ml_dsa_44_test PRIVATE bitcoinpqc)
    target_include_directories(ml_dsa_44_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    add_test(NAME ml_dsa_44_e2e COMMAND ml_dsa_44_test)
endif()
