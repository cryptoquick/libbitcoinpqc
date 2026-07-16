#include <stdlib.h>
#include <string.h>
#include "libbitcoinpqc/slh_dsa.h"

/*
 * This file implements the key generation function for SLH-DSA-SHA2-128s (SPHINCS+)
 */

/* Include necessary headers from SPHINCS+ reference implementation */
#include "../../sphincsplus/ref/api.h"
#include "../../sphincsplus/ref/params.h"

int slh_dsa_sha2_128s_keygen(
    uint8_t *pk,
    uint8_t *sk,
    const uint8_t *random_data,
    size_t random_data_size
) {
    if (!pk || !sk || !random_data || random_data_size < 128) {
        return -1;
    }

    /*
     * For fully deterministic key generation, use the first 3*SPX_N bytes
     * of the random data directly as the seed instead of going through
     * the random data wrapper.
     */
    return crypto_sign_seed_keypair(pk, sk, random_data);
}