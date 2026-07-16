/*
 * Compare libbitcoinpqc golden PK against sphincsplus ref crypto_sign_seed_keypair.
 *
 * Build (from repo root):
 *   cd sphincsplus/ref && make PARAMS=sphincs-sha2-128s THASH=simple \
 *     ../build/crosscheck_slh_dsa_sha2_pk scripts/crosscheck_slh_dsa_sha2_pk.c
 *
 * Or from repo root after ref objects exist:
 *   gcc -o /tmp/crosscheck_pk scripts/crosscheck_slh_dsa_sha2_pk.c \
 *       sphincsplus/ref/{address,merkle,wots,wotsx1,utils,utilsx1,fors,sign,sha2,hash_sha2,thash_sha2_simple,randombytes}.c \
 *       -Isphincsplus/ref -Iinclude -Itests -DPARAMS=sphincs-sha2-128s -std=c99 -O2
 */

#include <stdio.h>
#include <string.h>
#include "../../tests/vectors/slh_dsa_sha2_128s_vectors.h"
#include "../../sphincsplus/ref/api.h"

int main(void) {
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];

    if (crypto_sign_seed_keypair(pk, sk, SLH_DSA_SHA2_TEST_ENTROPY) != 0) {
        fprintf(stderr, "crypto_sign_seed_keypair failed\n");
        return 1;
    }

    if (memcmp(pk, SLH_DSA_SHA2_EXPECTED_PK, SLH_DSA_SHA2_EXPECTED_PK_SIZE) != 0) {
        fprintf(stderr, "PK mismatch: ref seed_keypair != libbitcoinpqc golden vector\n");
        return 1;
    }

    printf("crosscheck OK: ref PK matches libbitcoinpqc golden vector\n");
    return 0;
}