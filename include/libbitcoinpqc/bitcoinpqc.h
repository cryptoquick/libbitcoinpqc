/**
 * @file bitcoinpqc.h
 * @brief Main header file for the Bitcoin PQC library
 *
 * Signature primitives for Bitcoin quantum-resistance work. Post-quantum
 * signatures are a separate effort from BIP 360 (Pay-to-Merkle-Root / P2MR),
 * which is a consensus output type and does not define PQC schemes.
 *
 * Algorithms:
 * - ML-DSA-44 (CRYSTALS-Dilithium, FIPS 204) — NIST Level 2
 * - SLH-DSA-SHA2-128s (SPHINCS+, FIPS 205) — NIST Level 1
 * - secp256k1 Schnorr (BIP 340)
 */

#ifndef BITCOIN_PQC_H
#define BITCOIN_PQC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/* Algorithm identifiers */
typedef enum {
    BITCOIN_PQC_SECP256K1_SCHNORR = 0,  /* BIP 340 Schnorr + X-Only */
    BITCOIN_PQC_ML_DSA_44 = 1,          /* FIPS 204 - CRYSTALS-Dilithium Level 2 */
    BITCOIN_PQC_SLH_DSA_SHA2_128S = 2  /* FIPS 205 - SLH-DSA-SHA2-128s Level 1 */
} bitcoin_pqc_algorithm_t;

/* Common error codes */
typedef enum {
    BITCOIN_PQC_OK = 0,
    BITCOIN_PQC_ERROR_BAD_ARG = -1,
    BITCOIN_PQC_ERROR_BAD_KEY = -2,
    BITCOIN_PQC_ERROR_BAD_SIGNATURE = -3,
    BITCOIN_PQC_ERROR_NOT_IMPLEMENTED = -4
} bitcoin_pqc_error_t;

/**
 * @brief Key pair structure
 */
typedef struct {
    bitcoin_pqc_algorithm_t algorithm;
    void *public_key;
    void *secret_key;
    size_t public_key_size;
    size_t secret_key_size;
} bitcoin_pqc_keypair_t;

/**
 * @brief Signature structure
 */
typedef struct {
    bitcoin_pqc_algorithm_t algorithm;
    uint8_t *signature;
    size_t signature_size;
} bitcoin_pqc_signature_t;

/**
 * @brief Get the public key size for an algorithm
 *
 * @param algorithm The algorithm identifier
 * @return The size in bytes, or 0 if the algorithm is not supported
 */
size_t bitcoin_pqc_public_key_size(bitcoin_pqc_algorithm_t algorithm);

/**
 * @brief Get the secret key size for an algorithm
 *
 * @param algorithm The algorithm identifier
 * @return The size in bytes, or 0 if the algorithm is not supported
 */
size_t bitcoin_pqc_secret_key_size(bitcoin_pqc_algorithm_t algorithm);

/**
 * @brief Get the signature size for an algorithm
 *
 * @param algorithm The algorithm identifier
 * @return The size in bytes, or 0 if the algorithm is not supported
 */
size_t bitcoin_pqc_signature_size(bitcoin_pqc_algorithm_t algorithm);

/**
 * @brief Generate a key pair
 *
 * @param algorithm The algorithm to use
 * @param keypair Pointer to keypair structure to populate
 * @param random_data User-provided random data (entropy)
 * @param random_data_size Size of random data:
 *     - BITCOIN_PQC_SECP256K1_SCHNORR: must be >= 32 bytes (first 32 used as secret key)
 *     - PQC algorithms: must be >= 128 bytes
 * @return BITCOIN_PQC_OK on success, error code otherwise
 */
bitcoin_pqc_error_t bitcoin_pqc_keygen(
    bitcoin_pqc_algorithm_t algorithm,
    bitcoin_pqc_keypair_t *keypair,
    const uint8_t *random_data,
    size_t random_data_size
);

/**
 * @brief Free resources associated with a keypair
 *
 * @param keypair The keypair to free
 */
void bitcoin_pqc_keypair_free(bitcoin_pqc_keypair_t *keypair);

/**
 * @brief Sign a message
 *
 * @param algorithm The algorithm to use
 * @param secret_key The secret key to sign with
 * @param secret_key_size Size of the secret key
 * @param message The message to sign
 * @param message_size Size of the message:
 *     - BITCOIN_PQC_SECP256K1_SCHNORR: must be >= 32 bytes; first 32 used as
 *       pre-hashed message (BIP 340)
 *     - PQC algorithms: raw message of any length
 * @param signature Pointer to signature structure to populate
 * @return BITCOIN_PQC_OK on success, error code otherwise
 */
bitcoin_pqc_error_t bitcoin_pqc_sign(
    bitcoin_pqc_algorithm_t algorithm,
    const uint8_t *secret_key,
    size_t secret_key_size,
    const uint8_t *message,
    size_t message_size,
    bitcoin_pqc_signature_t *signature
);

/**
 * @brief Free resources associated with a signature
 *
 * @param signature The signature to free
 */
void bitcoin_pqc_signature_free(bitcoin_pqc_signature_t *signature);

/**
 * @brief Verify a signature
 *
 * @param algorithm The algorithm to use
 * @param public_key The public key to verify with
 * @param public_key_size Size of the public key
 * @param message The message to verify
 * @param message_size Size of the message:
 *     - BITCOIN_PQC_SECP256K1_SCHNORR: must be >= 32 bytes; first 32 used as
 *       pre-hashed message (BIP 340)
 *     - PQC algorithms: raw message of any length
 * @param signature The signature to verify
 * @param signature_size Size of the signature
 * @return BITCOIN_PQC_OK if signature is valid, error code otherwise
 */
bitcoin_pqc_error_t bitcoin_pqc_verify(
    bitcoin_pqc_algorithm_t algorithm,
    const uint8_t *public_key,
    size_t public_key_size,
    const uint8_t *message,
    size_t message_size,
    const uint8_t *signature,
    size_t signature_size
);

/* Algorithm-specific header includes */
#include "ml_dsa.h"
#include "slh_dsa.h"

#ifdef __cplusplus
}
#endif

#endif /* BITCOIN_PQC_H */
