# libbitcoinpqc

A C library for Post-Quantum Cryptographic (PQC) signature algorithms. This library implements two NIST PQC standard signature algorithms for use with [BIP-360](https://github.com/cryptoquick/bips/blob/p2qrh/bip-0360.mediawiki) and the Bitcoin QuBit soft fork:

1. **ML-DSA-44** (formerly CRYSTALS-Dilithium): A structured lattice-based digital signature scheme that is part of the NIST PQC standardization.
2. **SLH-DSA-SHA2-128s** (formerly SPHINCS+): A stateless hash-based signature scheme with minimal security assumptions. Uses SHA-256, aligning with Bitcoin's native hash primitive.

Notice that all PQC signature algorithms used are certified according to the Federal Information Processing Standards, or FIPS. This should help in the future with native hardware support.

## Bitcoin QuBit Integration

This library serves as the cryptographic foundation for the Bitcoin QuBit soft fork, which aims to make Bitcoin's signature verification quantum-resistant through the implementation of BIP-360. QuBit introduces new post-quantum secure transaction types that can protect Bitcoin from potential threats posed by quantum computers.

## Features

- Clean, unified C API for all three signature algorithms
- User-provided entropy (bring your own randomness)
- Key generation, signing, and verification functions
- Minimal dependencies

## Key Characteristics

| Algorithm          | Public Key Size | Secret Key Size | Signature Size | Security Level |
| ------------------ | --------------- | --------------- | -------------- | -------------- |
| secp256k1          | 32 bytes        | 32 bytes        | 64 bytes       | Classical      |
| ML-DSA-44          | 1,312 bytes     | 2,560 bytes     | 2,420 bytes    | NIST Level 2   |
| SLH-DSA-SHA2-128s  | 32 bytes        | 64 bytes        | 7,856 bytes    | NIST Level 1   |

## Security Notes

- This library does not provide its own random number generation. It is essential that the user provide entropy from a cryptographically secure source.
- Random data is required for key generation, but not for signing. All signatures are deterministic from the message and secret key (see [docs/user_provided_entropy.md](docs/user_provided_entropy.md#signing-determinism)).
- The implementations are based on reference code from the NIST PQC standardization process and are not production-hardened.
- Care should be taken to securely manage secret keys in applications.

## Entropy length requirement

The API requires a minimum of **128 bytes** of entropy for key generation, enforced uniformly
across all algorithms regardless of their individual seed sizes:

```c
if (!keypair || !random_data)       return BITCOIN_PQC_ERROR_BAD_ARG;
if (random_data_size < 128)         return BITCOIN_PQC_ERROR_BAD_ARG;
```

The actual entropy consumed by each algorithm is less than this minimum:

| Algorithm          | Bytes consumed | Source in spec                                                                      |
| ------------------ | -------------- | ----------------------------------------------------------------------------------- |
| ML-DSA-44          | 32 bytes       | FIPS 204 — one `SEEDBYTES`-wide draw fed into SHAKE-256 expansion                   |
| SLH-DSA-SHA2-128s  | 48 bytes       | FIPS 205 — three independent *n*-byte values (SK.seed ‖ SK.prf ‖ PK.seed), *n* = 16 |

Bytes beyond these amounts are accepted but **silently ignored** by the underlying
reference implementations. A caller reading the 128-byte requirement should not infer
that all 128 bytes contribute to key material — only the first 32 or 48 bytes (depending
on algorithm) do.

The 128-byte floor is a deliberate policy choice rather than a per-algorithm technical
requirement, motivated by:

- **Uniform API** — callers do not need to know per-algorithm seed sizes.
- **Quality signal** — a caller that can supply 128 bytes from a secure source is less
  likely to be misusing a low-entropy value padded to the minimum.
- **Headroom** — a future algorithm in the same API could require more entropy without
  a breaking change to the interface contract.

## BIP-360 Compliance

This library implements the cryptographic primitives required by [BIP-360](https://github.com/bitcoin/bips/blob/master/bip-0360.mediawiki), which defines the standard for post-quantum resistant signatures in Bitcoin. It supports all three recommended algorithms with the specified parameter sets.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Language Bindings

Language bindings for libbitcoinpqc are maintained separately at:

https://github.com/cryptoquick/libbitcoinpqc-bindings

## Dependencies

Cryptographic dependencies included in this project:

- https://github.com/sphincs/sphincsplus - `7ec789ace6874d875f4bb84cb61b81155398167e`
- https://github.com/pq-crystals/dilithium - `444cdcc84eb36b66fe27b3a2529ee48f6d8150c2`

## Migrating from SHAKE-128s

SLH-DSA was switched from SHAKE-128s to SHA2-128s. Update C symbol names as follows:

| Old (SHAKE-128s) | New (SHA2-128s) |
| ---------------- | --------------- |
| `BITCOIN_PQC_SLH_DSA_SHAKE_128S` | `BITCOIN_PQC_SLH_DSA_SHA2_128S` |
| `SLH_DSA_SHAKE_128S_PUBLIC_KEY_SIZE` | `SLH_DSA_SHA2_128S_PUBLIC_KEY_SIZE` |
| `SLH_DSA_SHAKE_128S_SECRET_KEY_SIZE` | `SLH_DSA_SHA2_128S_SECRET_KEY_SIZE` |
| `SLH_DSA_SHAKE_128S_SIGNATURE_SIZE` | `SLH_DSA_SHA2_128S_SIGNATURE_SIZE` |
| `slh_dsa_shake_128s_keygen()` | `slh_dsa_sha2_128s_keygen()` |
| `slh_dsa_shake_128s_sign()` | `slh_dsa_sha2_128s_sign()` |
| `slh_dsa_shake_128s_verify()` | `slh_dsa_sha2_128s_verify()` |
| `void slh_dsa_derandomize(...)` | `int slh_dsa_derandomize(...)` (returns `0` on success, non-zero on bad args) |

The enum wire value `BITCOIN_PQC_SLH_DSA_SHA2_128S = 2` is unchanged. Key and signature buffer sizes (32/64/7856 bytes) are unchanged.

**Re-keying required:** keys and signatures from SHAKE-128s are cryptographically incompatible with SHA2-128s. After upgrading, generate new key pairs — renaming symbols alone is not sufficient.

## Building the Library

### Prerequisites

- CMake 3.10 or higher
- C99 compiler

### Building

```bash
# Clone the Repository
git clone https://github.com/cryptoquick/libbitcoinpqc.git
cd libbitcoinpqc

# Build the C Library
chmod +x build.sh
./build.sh
```

This produces:

- `build/lib/libbitcoinpqc.a` — static library
- `build/lib/libbitcoinpqc.so` — shared library (`bitcoinpqc_shared` CMake target, installed as `libbitcoinpqc.so`)

### Running Tests

```bash
cd build
ctest
```

The `slh_dsa_sha2_api` test (enabled by default via `BUILD_TESTS=ON`) checks:

- Golden 32-byte public key and 7856-byte signature vectors
- Signature determinism (two signs produce identical bytes)
- Valid verify, tampered-signature rejection, wrong-message rejection
- NULL `secret_key` rejection at sign (`BITCOIN_PQC_ERROR_BAD_ARG`)
- Short signature rejection and short public-key rejection at verify
- 127-byte entropy rejection at keygen

Regenerate golden vectors after intentional crypto changes:

```bash
gcc -o /tmp/gen_slh_dsa_sha2_vectors scripts/gen_slh_dsa_sha2_vectors.c \
    -Iinclude -Itests build/lib/libbitcoinpqc.a -lm
/tmp/gen_slh_dsa_sha2_vectors
```

To also build the entropy demo example:

```bash
cmake -S . -B build -DBUILD_EXAMPLES=ON
cmake --build build
./build/bin/entropy_demo < /path/to/128_bytes_entropy.bin
```

## C API Usage

```c
#include <libbitcoinpqc/bitcoinpqc.h>

// Generate random data (from a secure source in production)
uint8_t random_data[256];
// Fill random_data with entropy...

// Generate a key pair
bitcoin_pqc_keypair_t keypair;
bitcoin_pqc_keygen(BITCOIN_PQC_ML_DSA_44, &keypair, random_data, sizeof(random_data));

// Sign a message
const uint8_t message[] = "Message to sign";
bitcoin_pqc_signature_t signature;
bitcoin_pqc_sign(BITCOIN_PQC_ML_DSA_44, keypair.secret_key, keypair.secret_key_size,
                message, sizeof(message) - 1, &signature);

// Verify the signature
bitcoin_pqc_error_t result = bitcoin_pqc_verify(BITCOIN_PQC_ML_DSA_44,
                                             keypair.public_key, keypair.public_key_size,
                                             message, sizeof(message) - 1,
                                             signature.signature, signature.signature_size);

// Clean up resources
bitcoin_pqc_signature_free(&signature);
bitcoin_pqc_keypair_free(&keypair);
```

## Acknowledgments

- The original NIST PQC competition teams for their reference implementations
- The NIST PQC standardization process for advancing post-quantum cryptography
- The Bitcoin QuBit soft fork contributors and BIP-360 contributors
