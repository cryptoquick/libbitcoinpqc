/*
 * Compare libbitcoinpqc golden signature against sphincsplus ref with the
 * same deterministic seed injection as slh_dsa_sha2_128s_sign().
 *
 * Build (from repo root):
 *   gcc -o /tmp/crosscheck_sig scripts/crosscheck_slh_dsa_sha2_sig.c \
 *       src/slh_dsa/utils.c src/randombytes_custom.c \
 *       sphincsplus/ref/{address,merkle,wots,wotsx1,utils,utilsx1,fors,sign,sha2,hash_sha2,thash_sha2_simple}.c \
 *       -Isphincsplus/ref -Iinclude -Itests -DPARAMS=sphincs-sha2-128s \
 *       -DCUSTOM_RANDOMBYTES=1 -std=c99 -O2
 */

#include <stdio.h>
#include <string.h>
#include "../../tests/vectors/slh_dsa_sha2_128s_vectors.h"
#include "../../sphincsplus/ref/api.h"
#include "libbitcoinpqc/slh_dsa.h"

extern void slh_dsa_init_random_source(const uint8_t *random_data, size_t random_data_size);
extern void slh_dsa_restore_original_random(void);

int main(void) {
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    unsigned char sig[CRYPTO_BYTES];
    size_t siglen;
    uint8_t deterministic_seed[64];
    const size_t message_len = strlen(SLH_DSA_SHA2_TEST_MESSAGE);

    if (crypto_sign_seed_keypair(pk, sk, SLH_DSA_SHA2_TEST_ENTROPY) != 0) {
        fprintf(stderr, "crypto_sign_seed_keypair failed\n");
        return 1;
    }

    if (slh_dsa_derandomize(
            deterministic_seed,
            (const uint8_t *)SLH_DSA_SHA2_TEST_MESSAGE,
            message_len,
            sk
        ) != 0) {
        fprintf(stderr, "slh_dsa_derandomize failed\n");
        return 1;
    }

    slh_dsa_init_random_source(deterministic_seed, sizeof(deterministic_seed));

    if (crypto_sign_signature(
            sig,
            &siglen,
            (const uint8_t *)SLH_DSA_SHA2_TEST_MESSAGE,
            message_len,
            sk
        ) != 0) {
        fprintf(stderr, "crypto_sign_signature failed\n");
        slh_dsa_restore_original_random();
        return 1;
    }

    slh_dsa_restore_original_random();

    if (siglen != SLH_DSA_SHA2_EXPECTED_SIG_SIZE ||
        memcmp(sig, SLH_DSA_SHA2_EXPECTED_SIG, SLH_DSA_SHA2_EXPECTED_SIG_SIZE) != 0) {
        fprintf(stderr, "SIG mismatch: ref sign != libbitcoinpqc golden vector\n");
        return 1;
    }

    printf("crosscheck OK: ref signature matches libbitcoinpqc golden vector\n");
    return 0;
}