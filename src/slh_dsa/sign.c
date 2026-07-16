#include <string.h>
#include "libbitcoinpqc/slh_dsa.h"
#include <stdio.h>

/*
 * This file implements the signing function for SLH-DSA-SHA2-128s (SPHINCS+)
 */

/* Include necessary headers from SPHINCS+ reference implementation */
#include "../../sphincsplus/ref/api.h"
#include "../../sphincsplus/ref/randombytes.h"
#include "../../sphincsplus/ref/params.h"

/* Debug mode flag - set to 0 to disable debug output */
#define SLH_DSA_DEBUG 0

/* Conditional debug print macro */
#define DEBUG_PRINT(fmt, ...) \
    do { if (SLH_DSA_DEBUG) printf(fmt, ##__VA_ARGS__); } while (0)

/*
 * External declaration for the random data utilities
 * These are implemented in src/slh_dsa/utils.c
 */
extern void slh_dsa_init_random_source(const uint8_t *random_data, size_t random_data_size);
extern void slh_dsa_setup_custom_random(void);
extern void slh_dsa_restore_original_random(void);

int slh_dsa_sha2_128s_sign(
    uint8_t *sig,
    size_t *siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *sk
) {
    if (!sig || !siglen || !m || !sk) {
        return -1;
    }

    DEBUG_PRINT("SLH-DSA sign: Starting to sign message of length %zu\n", mlen);

    /* Create deterministic randomness from message and secret key */
    uint8_t deterministic_seed[64];
    if (slh_dsa_derandomize(deterministic_seed, m, mlen, sk) != 0) {
        return -1;
    }
    slh_dsa_init_random_source(deterministic_seed, sizeof(deterministic_seed));
    slh_dsa_setup_custom_random();
    DEBUG_PRINT("SLH-DSA sign: Using deterministic signing\n");

    /* The reference implementation prepends the message to the signature
     * but we want just the signature, so we need to use the detached API
     */
    int result = crypto_sign_signature(sig, siglen, m, mlen, sk);
    DEBUG_PRINT("SLH-DSA sign: signature result = %d, length = %zu\n", result, *siglen);

    /* Restore original random bytes function */
    slh_dsa_restore_original_random();

    return result;
}
