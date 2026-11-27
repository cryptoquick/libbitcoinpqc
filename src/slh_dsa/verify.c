#include "libbitcoinpqc/slh_dsa.h"

#include <stdlib.h>

/*
 * This file implements the verification function for SLH-DSA-SHA2-128s (SPHINCS+)
 */

/* Include necessary headers from SPHINCS+ reference implementation */
#include "../../sphincsplus/ref/api.h"

extern int slh_dsa_external_message(
    uint8_t **out,
    size_t *out_len,
    const uint8_t *m,
    size_t mlen
);

int slh_dsa_sha2_128s_verify(
    const uint8_t *sig,
    size_t siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *pk
) {
    uint8_t *external_message = NULL;
    size_t external_message_len = 0;
    int result;

    if (!sig || !m || !pk) {
        return -1;
    }

    if (slh_dsa_external_message(&external_message, &external_message_len, m, mlen) != 0) {
        return -1;
    }

    /* Reference verify stays the internal interface and sees the prefix once. */
    result = crypto_sign_verify(
        sig, siglen, external_message, external_message_len, pk
    );
    free(external_message);
    return result;
}
