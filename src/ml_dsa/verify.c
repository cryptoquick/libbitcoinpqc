#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "libbitcoinpqc/ml_dsa.h"

/*
 * This file implements the verification function for ML-DSA-44 (CRYSTALS-Dilithium)
 */

/* Include necessary headers from Dilithium reference implementation */
#include "../../dilithium/ref/api.h"
#include "../../dilithium/ref/sign.h"
#include "../../dilithium/ref/params.h"

int ml_dsa_44_verify(
    const uint8_t *sig,
    size_t siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *pk
) {
    if (!sig || !m || !pk) {
        fprintf(stderr, "ML-DSA verify: Invalid arguments\n");
        return -1;
    }

    printf("ML-DSA verify: Verifying signature of length %zu for message of length %zu\n", siglen, mlen);

    /* Check signature size */
    if (siglen == 0 || siglen > CRYPTO_BYTES) {
        fprintf(stderr, "ML-DSA verify: Invalid signature size: %zu (max: %d)\n", siglen, CRYPTO_BYTES);
        return -1;
    }

    /* Debug: Print first few bytes of signature */
    printf("ML-DSA verify: Signature prefix: ");
    for (size_t i = 0; i < (siglen < 8 ? siglen : 8); i++) {
        printf("%02x", sig[i]);
    }
    printf("...\n");

    /* Set up empty context */
    uint8_t ctx[1] = {0};
    size_t ctxlen = 0;

    /* Call the reference implementation's verification function */
    int result = crypto_sign_verify(sig, siglen, m, mlen, ctx, ctxlen, pk);

    printf("ML-DSA verify: crypto_sign_verify returned %d\n", result);

    return result;
}
