#include <stdlib.h>
#include <string.h>
#include "libbitcoinpqc/slh_dsa.h"
#include <stdio.h>

/*
 * This file implements the signing function for SLH-DSA-SHA2-128s (SPHINCS+)
 */

/* Include necessary headers from SPHINCS+ reference implementation */
#include "../../sphincsplus/ref/api.h"
#include "../../sphincsplus/ref/params.h"

/* Debug mode flag - set to 0 to disable debug output */
#define SLH_DSA_DEBUG 0

/* Conditional debug print macro */
#define DEBUG_PRINT(fmt, ...) \
    do { if (SLH_DSA_DEBUG) printf(fmt, ##__VA_ARGS__); } while (0)

/*
 * FIPS 205 pure mode with an empty context. Implemented in
 * src/slh_dsa/external_message.c. Optional randomness is the explicit
 * optrand argument, not a randombytes() hook.
 */
extern int slh_dsa_external_message(
    uint8_t **out,
    size_t *out_len,
    const uint8_t *m,
    size_t mlen
);

int slh_dsa_sha2_128s_sign(
    uint8_t *sig,
    size_t *siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *sk
) {
    uint8_t *external_message = NULL;
    size_t external_message_len = 0;
    int result;

    if (!sig || !siglen || !m || !sk) {
        return -1;
    }

    DEBUG_PRINT("SLH-DSA sign: Starting to sign message of length %zu\n", mlen);

    /* Derandomize hashes the raw message. The 0x00 domain byte there is
     * not the FIPS 205 pure-mode prefix.
     */
    uint8_t deterministic_seed[64];
    if (slh_dsa_derandomize(deterministic_seed, m, mlen, sk) != 0) {
        return -1;
    }
    DEBUG_PRINT("SLH-DSA sign: Using deterministic signing\n");

    if (slh_dsa_external_message(&external_message, &external_message_len, m, mlen) != 0) {
        return -1;
    }

    /* The reference implementation prepends the message to the signature
     * but we want just the signature, so we need to use the detached API.
     * Pass the pure-mode prefix exactly once, with caller-provided optrand.
     */
    result = crypto_sign_signature_with_optrand(
        sig,
        siglen,
        external_message,
        external_message_len,
        deterministic_seed,
        sk
    );
    free(external_message);
    DEBUG_PRINT("SLH-DSA sign: signature result = %d, length = %zu\n", result, *siglen);

    return result;
}
