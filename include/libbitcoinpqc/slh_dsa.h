/**
 * @file slh_dsa.h
 * @brief SLH-DSA-SHA2-128s (SPHINCS+) specific functions
 */

#ifndef BITCOIN_PQC_SLH_DSA_H
#define BITCOIN_PQC_SLH_DSA_H

#include <stddef.h>
#include <stdint.h>

/* SLH-DSA-SHA2-128s constants */
#define SLH_DSA_SHA2_128S_PUBLIC_KEY_SIZE 32
#define SLH_DSA_SHA2_128S_SECRET_KEY_SIZE 64
#define SLH_DSA_SHA2_128S_SIGNATURE_SIZE 7856

/* Key Generation Functions */

/**
 * @brief Generate an SLH-DSA-SHA2-128s key pair
 *
 * @param pk Output public key (must have space for SLH_DSA_SHA2_128S_PUBLIC_KEY_SIZE bytes)
 * @param sk Output secret key (must have space for SLH_DSA_SHA2_128S_SECRET_KEY_SIZE bytes)
 * @param random_data User-provided random data (entropy)
 * @param random_data_size Size of random data, must be >= 128 bytes
 * @return 0 on success, non-zero on failure
 */
int slh_dsa_sha2_128s_keygen(
    uint8_t *pk,
    uint8_t *sk,
    const uint8_t *random_data,
    size_t random_data_size
);

/**
 * @brief Sign a message using SLH-DSA-SHA2-128s
 *
 * Signing is deterministic: randomness is derived from (sk, m) via
 * slh_dsa_derandomize(). No external entropy is accepted.
 *
 * @param sig Output signature (must have space for SLH_DSA_SHA2_128S_SIGNATURE_SIZE bytes)
 * @param siglen Output signature length
 * @param m Message to sign
 * @param mlen Message length
 * @param sk Secret key
 * @return 0 on success, non-zero on failure
 */
int slh_dsa_sha2_128s_sign(
    uint8_t *sig,
    size_t *siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *sk
);

/**
 * @brief Verify an SLH-DSA-SHA2-128s signature
 *
 * @param sig Signature
 * @param siglen Signature length
 * @param m Message
 * @param mlen Message length
 * @param pk Public key
 * @return 0 if signature is valid, non-zero otherwise
 */
int slh_dsa_sha2_128s_verify(
    const uint8_t *sig,
    size_t siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *pk
);

/**
 * @brief Derive deterministic signing randomness from secret key and message
 *
 * Fills seed with SHA-256(sk ‖ m ‖ 0x00) ‖ SHA-256(sk ‖ m ‖ 0x01).
 * Used internally by slh_dsa_sha2_128s_sign() before calling the reference
 * randombytes hook.
 *
 * @param seed Output buffer (64 bytes)
 * @param m Message to sign
 * @param mlen Message length
 * @param sk Secret key (SLH_DSA_SHA2_128S_SECRET_KEY_SIZE bytes)
 * @return 0 on success, -1 if any pointer argument is NULL
 */
int slh_dsa_derandomize(uint8_t *seed, const uint8_t *m, size_t mlen, const uint8_t *sk);

#endif /* BITCOIN_PQC_SLH_DSA_H */