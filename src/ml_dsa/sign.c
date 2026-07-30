#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "libbitcoinpqc/ml_dsa.h"

/*
 * This file implements the signing function for ML-DSA-44 (CRYSTALS-Dilithium)
 */

/* Include necessary headers from Dilithium reference implementation */
#include "../../dilithium/ref/api.h"
#include "../../dilithium/ref/params.h"
#include "../../dilithium/ref/sign.h"

/* Debug mode flag - set to 0 to disable debug output */
#define ML_DSA_DEBUG 0

/* Conditional debug print macro */
#define DEBUG_PRINT(fmt, ...) \
    do { if (ML_DSA_DEBUG) printf(fmt, ##__VA_ARGS__); } while (0)

extern void ml_dsa_derandomize(uint8_t *seed, const uint8_t *m, size_t mlen, const uint8_t *sk);

int ml_dsa_44_sign(
    uint8_t *sig,
    size_t *siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *sk
) {
    if (!sig || !siglen || !m || !sk) {
        fprintf(stderr, "ML-DSA sign: Invalid arguments\n");
        return -1;
    }

    DEBUG_PRINT("ML-DSA sign: Starting to sign message of length %zu\n", mlen);

    /* Preserve the library's deterministic hedged-signing policy explicitly. */
    uint8_t deterministic_seed[64];
    uint8_t rnd[RNDBYTES];
    const uint8_t pre[2] = {0, 0};
    ml_dsa_derandomize(deterministic_seed, m, mlen, sk);
    memcpy(rnd, deterministic_seed, sizeof(rnd));
    DEBUG_PRINT("ML-DSA sign: Using deterministic signing\n");

    /* Using fixed size buffer to avoid memory issues */
    uint8_t temp_sig[CRYPTO_BYTES + 1024]; /* Add some extra space for safety */
    size_t temp_siglen = 0;

    DEBUG_PRINT("ML-DSA sign: Calling crypto_sign_signature with CRYPTO_BYTES = %d\n", CRYPTO_BYTES);

    /* Call the explicit-randomness reference entry point with an empty context. */
    int result = crypto_sign_signature_internal(
        temp_sig,
        &temp_siglen,
        m,
        mlen,
        pre,
        sizeof(pre),
        rnd,
        sk
    );

    DEBUG_PRINT("ML-DSA sign: crypto_sign_signature_internal returned %d, temp_siglen = %zu\n", result, temp_siglen);

    /* Only copy the signature if it was successful */
    if (result == 0) {
        /* Double-check the signature size */
        if (temp_siglen > 0 && temp_siglen <= CRYPTO_BYTES) {
            /* Copy the signature to the output */
            memcpy(sig, temp_sig, temp_siglen);
            *siglen = temp_siglen;

            DEBUG_PRINT("ML-DSA sign: Signature copied successfully, size = %zu\n", *siglen);

            /* Debug: Print first few bytes of signature */
            DEBUG_PRINT("ML-DSA sign: Signature prefix: ");
            for (size_t i = 0; i < (temp_siglen < 8 ? temp_siglen : 8); i++) {
                if (ML_DSA_DEBUG) printf("%02x", sig[i]);
            }
            if (ML_DSA_DEBUG) printf("...\n");
        } else {
            fprintf(stderr, "ML-DSA sign: Invalid signature size: %zu\n", temp_siglen);
            return -1;
        }
    } else {
        fprintf(stderr, "ML-DSA sign: Signing failed with result: %d\n", result);
    }

    return result;
}
