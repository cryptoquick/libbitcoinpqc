#include <stdlib.h>
#include <string.h>
#include "libbitcoinpqc/ml_dsa.h"

/*
 * This file implements the key generation function for ML-DSA-44 (CRYSTALS-Dilithium)
 */

/* Include necessary headers from Dilithium reference implementation */
#include "../../dilithium/ref/api.h"
#include "../../dilithium/ref/params.h"
#include "../../dilithium/ref/sign.h"

int ml_dsa_44_keygen(
    uint8_t *pk,
    uint8_t *sk,
    const uint8_t *random_data,
    size_t random_data_size
) {
    if (!pk || !sk || !random_data || random_data_size < 128) {
        return -1;
    }

    return crypto_sign_seed_keypair(pk, sk, random_data);
}
