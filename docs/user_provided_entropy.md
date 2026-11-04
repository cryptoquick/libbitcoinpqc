# User-Provided Entropy

libbitcoinpqc does not generate its own randomness. Instead, the caller is
responsible for supplying entropy to key generation functions. This document
explains why, what the library does with the entropy you provide, and how to
choose a suitable source.

## Why "Bring Your Own Randomness"?

Cryptographic key generation requires high-quality random data. Different
deployment environments have different trust models for where that randomness
should come from:

- A Bitcoin node may already maintain its own CSPRNG seeded from multiple
  hardware and OS sources.
- A regulated environment may require randomness from a FIPS 140-2/3 certified
  HSM.
- An air-gapped signing device may use a dedicated hardware TRNG.
- A test harness may need deterministic keys from a fixed seed.

By accepting entropy as a parameter rather than sourcing it internally, the
library avoids making assumptions about the caller's security requirements.
The production library target does not read operating system entropy and does
not provide a hidden fallback RNG.

## How the Library Consumes Entropy

### secp256k1 Schnorr (BIP 340)

`secp256k1_schnorr_keygen()` copies the first **32 bytes** of the caller's
input directly into the secret key and rejects the value if it is not a valid
secp256k1 scalar. Signing calls `secp256k1_schnorrsig_sign32()` with
`aux_rand32 = NULL`, so libsecp256k1 uses its deterministic no-auxiliary-data
path. Neither operation calls a library RNG.

### ML-DSA-44 (CRYSTALS-Dilithium)

`ml_dsa_44_keygen()` passes the first **32 bytes** of your entropy buffer to
the explicit `crypto_sign_seed_keypair()` entry point. The seed is expanded
deterministically by ML-DSA's internal key derivation. No shared RNG state or
`randombytes()` hook is involved.

### SLH-DSA-SHA2-128s (SPHINCS+)

`slh_dsa_sha2_128s_keygen()` passes your entropy buffer directly to
`crypto_sign_seed_keypair()`, which uses the first `3 * SPX_N` bytes as the
seed. For SHA2-128s, `SPX_N = 16`, so **48 bytes** are consumed. No shared
RNG state or `randombytes()` hook is involved.

### The 128-Byte Minimum

Both PQC keygen functions reject buffers smaller than 128 bytes. This minimum
provides a comfortable margin above the actual consumption (32 or 48 bytes)
and ensures callers provide a meaningful amount of entropy rather than a
handful of bytes that might be poorly generated. secp256k1 key generation has
a separate 32-byte minimum because the input is used directly as its secret
scalar.

### Key generation determinism

Providing identical entropy produces identical keys. This is by design:

- It enables reproducible test vectors.
- The security of your keys depends entirely on the quality and secrecy of
  the entropy you provide.

### Signing determinism

Signing does **not** accept caller-provided entropy. Both algorithms use
explicit deterministic inputs:

**ML-DSA-44** uses SHAKE-256 over `sk ‖ m` and passes the first 32 bytes of
the derived value directly as the reference implementation's `rnd` input
with an empty context. This preserves the library's deterministic
hedged-signing policy without a `randombytes()` hook.

**SLH-DSA-SHA2-128s** uses domain-separated SHA-256:

```
seed[0..31]  = SHA-256(sk ‖ m ‖ 0x00)
seed[32..63] = SHA-256(sk ‖ m ‖ 0x01)
```

The first `SPX_N` bytes of that derived value are passed directly as
`optrand` to `crypto_sign_signature_with_optrand()`. The reference
implementation does not call `randombytes()`.

This is a **libbitcoinpqc policy** for reproducible signatures. It is not a
FIPS 205 pure/hedged mode selector — it layers deterministic signing on the
vendored reference implementation.

Identical `(sk, m)` pairs therefore produce identical signatures.

## RNG Isolation Audit

The CMake library targets define `LIBBITCOINPQC_EXPLICIT_ENTROPY`. In this
mode:

- ML-DSA key generation uses an explicit 32-byte seed entry point.
- ML-DSA signing uses an explicit SHAKE-derived `rnd` input.
- SLH-DSA key generation uses the existing explicit 48-byte seed entry point.
- SLH-DSA signing uses an explicit caller-supplied `optrand` entry point.
- secp256k1 key generation and signing use their explicit key and no-auxiliary-data inputs.
- The unseeded vendored key generation and signing entry points are excluded
  from the library build.
- No `randombytes()` implementation is linked into `libbitcoinpqc`.

The vendored source trees still contain their original `randombytes.c` and
NIST KAT RNG files. Those files support the upstream standalone Makefiles and
test-vector tools. They are not part of the `libbitcoinpqc` CMake targets and
are not reachable through the installed public API.

The `rng_isolation` regression test links a trap implementation of
`randombytes()` and exercises all three public key generation, signing, and
verification paths. The test fails if a public algorithm path calls the
legacy hook.

Callers that compile the vendored reference implementations independently are
outside this library contract and must review the RNG selected by the
corresponding upstream Makefile.

## Choosing an Entropy Source

### Requirements

Your entropy source must be:

1. **Unpredictable** - an attacker must not be able to guess or influence the
   output.
2. **Sufficient entropy density** - the bytes you provide should contain close
   to 8 bits of entropy per byte (i.e., indistinguishable from uniform random).
3. **Secret** - the entropy must not be logged, transmitted, or otherwise
   exposed.

### Suitable Sources

**Operating system CSPRNG** - The simplest and most common choice. On Linux,
`/dev/urandom` or the `getrandom(2)` syscall provides kernel-mixed entropy
that is suitable for cryptographic use after the system has initialized.

**Hardware Security Modules (HSMs)** - Devices such as Thales Luna, Utimaco
CryptoServer, or cloud-managed HSMs (AWS CloudHSM, Azure Dedicated HSM)
provide FIPS-certified hardware random number generation. Use these when
regulatory compliance requires a certified entropy source.

**CPU hardware RNG** - Modern x86 processors expose the `RDRAND` and `RDSEED`
instructions, which draw from an on-die entropy source. ARM v8.5+ provides
the equivalent `RNDR` instruction. These can be used directly or as an
additional seed input to a CSPRNG.

**Trusted Platform Modules (TPMs)** - TPM 2.0 chips, present in most
enterprise hardware, expose a hardware RNG accessible via `tpm2-tools` or
OS interfaces. Suitable as a supplementary entropy source.

**Dedicated TRNGs / QRNGs** - Devices such as Quantis (ID Quantique) or
ComScire provide high-throughput true random number generation. Quantum RNGs
base their entropy on physical quantum processes.

### Sources to Avoid

- `rand()`, `random()`, or any userspace PRNG seeded from `time()` or PIDs.
- `/dev/random` when blocking behavior is undesirable (on modern Linux
  kernels, `/dev/urandom` is equally suitable after initialization).
- Entropy gathered solely from low-resolution timers or predictable system
  state.
- Network-based randomness beacons (e.g., NIST Beacon, drand) for secret key
  material - these are public and unsuitable for keying.

## Trying It Out on Linux

This walkthrough builds the library from source, acquires entropy from the
command line, and pipes it into the included `examples/entropy_demo.c`
program. The demo reads exactly 128 bytes of entropy from **stdin**, then
generates ML-DSA-44 and SLH-DSA-SHA2-128s key pairs, signs a message with
each, and verifies the signatures.

### Prerequisites

```bash
# Debian/Ubuntu
sudo apt-get install build-essential cmake

# Fedora
sudo dnf install gcc gcc-c++ cmake make
```

### Step 1: Build the Library

```bash
git clone https://github.com/cryptoquick/libbitcoinpqc.git
cd libbitcoinpqc

mkdir build && cd build
cmake ..
make
```

This produces `build/lib/libbitcoinpqc.a`.

### Step 2: Compile the Demo

```bash
cd ..
gcc -o /tmp/entropy_demo examples/entropy_demo.c \
    -Iinclude \
    -Lbuild/lib -lbitcoinpqc \
    -lm
```

### Step 3: Acquire Entropy and Run

The demo expects exactly 128 bytes of raw entropy on stdin. There are
several ways to provide it from the command line.

**Option A: `/dev/urandom` (simplest)**

Read 128 bytes from the kernel CSPRNG and pipe them in:

```bash
dd if=/dev/urandom bs=128 count=1 2>/dev/null | /tmp/entropy_demo
```

**Option B: OpenSSL**

Use `openssl rand` to generate 128 cryptographically secure bytes:

```bash
openssl rand 128 | /tmp/entropy_demo
```

**Option C: `getrandom(2)` via Python one-liner**

Calls the `getrandom` syscall under the hood:

```bash
python3 -c "import os,sys; sys.stdout.buffer.write(os.urandom(128))" | /tmp/entropy_demo
```

**Option D: Hardware RNG (`/dev/hwrng`)**

If the system has a hardware TRNG exposed by the kernel (e.g., Intel
RDRAND via `rng-tools`, a TPM, or a USB TRNG):

```bash
sudo dd if=/dev/hwrng bs=128 count=1 2>/dev/null | /tmp/entropy_demo
```

> Note: `/dev/hwrng` requires root or membership in the appropriate group.
> Not all systems expose this device by default; you may need to load the
> `rng-core` module or install `rng-tools`.

Expected output (hex values will differ each run):

```
Entropy (first 16 bytes): 7a3f1c...

ML-DSA-44 key pair generated successfully.
  Public key size: 1312 bytes
  Secret key size: 2560 bytes
  Public key (first 16 bytes): 9b2e4d...

Signature size: 2420 bytes
Verification: PASS

SLH-DSA-SHA2-128s key pair generated successfully.
  Public key size: 32 bytes
  Secret key size: 64 bytes
  Public key (first 16 bytes): c4a81f...

Signature size: 7856 bytes
Verification: PASS
```

### Step 4: Verify Determinism

Save entropy to a file and feed it to the demo twice. The public key
bytes will be identical both times:

```bash
dd if=/dev/urandom of=/tmp/saved_entropy.bin bs=128 count=1 2>/dev/null

/tmp/entropy_demo < /tmp/saved_entropy.bin
/tmp/entropy_demo < /tmp/saved_entropy.bin
```

### Cleanup

```bash
rm -f /tmp/entropy_demo saved_entropy.bin
```
