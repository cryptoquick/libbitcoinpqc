#include <string.h>
#include <stdint.h>
#include "../../sphincsplus/ref/api.h"
#include "../../sphincsplus/ref/context.h"
#include "../../sphincsplus/ref/sha2.h"
#include "libbitcoinpqc/slh_dsa.h"
#include "../randombytes_custom.h"

/*
 * This file implements utility functions for SLH-DSA-SHA2-128s (SPHINCS+)
 * particularly related to random data handling
 */

typedef char slh_dsa_sk_whole_sha256_blocks[
    (CRYPTO_SECRETKEYBYTES % SPX_SHA256_BLOCK_BYTES) == 0 ? 1 : -1];

/* Initialize the random data source */
void slh_dsa_init_random_source(const uint8_t *random_data, size_t random_data_size) {
    pqc_randombytes_init(random_data, random_data_size);
}

/* Setup custom random function - this is called before keygen/sign */
void slh_dsa_setup_custom_random() {
    /* Nothing to do here, as our randombytes function is already set up */
}

/* Restore original random function - this is called after keygen/sign */
void slh_dsa_restore_original_random() {
    pqc_randombytes_cleanup();
}

static void sha256_sk_m_domain(
    uint8_t *out,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *sk,
    uint8_t domain_byte
) {
    uint8_t state[40];
    size_t sk_blocks = CRYPTO_SECRETKEYBYTES / SPX_SHA256_BLOCK_BYTES;
    size_t full_blocks = mlen / SPX_SHA256_BLOCK_BYTES;
    size_t m_remainder = mlen % SPX_SHA256_BLOCK_BYTES;
    uint8_t tail[SPX_SHA256_BLOCK_BYTES];
    size_t tail_len = 0;

    sha256_inc_init(state);
    sha256_inc_blocks(state, sk, sk_blocks);
    if (full_blocks > 0) {
        sha256_inc_blocks(state, m, full_blocks);
    }
    if (m_remainder > 0) {
        memcpy(tail, m + full_blocks * SPX_SHA256_BLOCK_BYTES, m_remainder);
        tail_len = m_remainder;
    }
    tail[tail_len++] = domain_byte;
    sha256_inc_finalize(out, state, tail, tail_len);
}

/* Derive deterministic signing randomness from secret key and message via SHA-256 */
int slh_dsa_derandomize(uint8_t *seed, const uint8_t *m, size_t mlen, const uint8_t *sk) {
    if (!seed || !m || !sk) {
        return -1;
    }

    sha256_sk_m_domain(seed, m, mlen, sk, 0x00);
    sha256_sk_m_domain(seed + SPX_SHA256_OUTPUT_BYTES, m, mlen, sk, 0x01);
    return 0;
}