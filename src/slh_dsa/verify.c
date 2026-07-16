#include "libbitcoinpqc/slh_dsa.h"

/*
 * This file implements the verification function for SLH-DSA-SHA2-128s (SPHINCS+)
 */

/* Include necessary headers from SPHINCS+ reference implementation */
#include "../../sphincsplus/ref/api.h"

int slh_dsa_sha2_128s_verify(
    const uint8_t *sig,
    size_t siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *pk
) {
    if (!sig || !m || !pk) {
        return -1;
    }

    /* Call the reference implementation's verification function */
    return crypto_sign_verify(sig, siglen, m, mlen, pk);
}
