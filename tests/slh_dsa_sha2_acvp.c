/*
 * Frozen ACVP subset for SLH-DSA-SHA2-128s.
 *
 * KeyGen places skSeed, skPrf, and pkSeed in the first 48 bytes of the
 * 128-byte entropy buffer. slh_dsa_sha2_128s_keygen passes that buffer to
 * crypto_sign_seed_keypair, which copies CRYPTO_SEEDBYTES (3 * n, n = 16)
 * as SK_SEED || SK_PRF || PUB_SEED. Bytes after those 48 are ignored.
 *
 * External pure sigVer goes through bitcoin_pqc_verify. A valid vector must
 * return BITCOIN_PQC_OK. An invalid vector must not.
 */

#include <stdio.h>
#include <string.h>
#include <libbitcoinpqc/bitcoinpqc.h>
#include <libbitcoinpqc/slh_dsa.h>
#include "vectors/slh_dsa_sha2_128s_acvp.h"

static int run_keygen(void) {
    int failures = 0;
    size_t i;

    for (i = 0; i < SLH_DSA_ACVP_KEYGEN_COUNT; i++) {
        const slh_dsa_acvp_keygen_case_t *vector = &SLH_DSA_ACVP_KEYGEN_CASES[i];
        uint8_t entropy[128];
        uint8_t pk[SLH_DSA_SHA2_128S_PUBLIC_KEY_SIZE];
        uint8_t sk[SLH_DSA_SHA2_128S_SECRET_KEY_SIZE];
        int result;

        memset(entropy, 0, sizeof entropy);
        if (SLH_ACVP_KG1_SK_SEED_LEN != 16
            || SLH_ACVP_KG1_SK_PRF_LEN != 16
            || SLH_ACVP_KG1_PK_SEED_LEN != 16
            || SLH_ACVP_KG1_PK_LEN != SLH_DSA_SHA2_128S_PUBLIC_KEY_SIZE) {
            fprintf(stderr, "FAIL: keygen tc %d unexpected field length\n", vector->tc_id);
            failures++;
            continue;
        }

        memcpy(entropy, vector->sk_seed, 16);
        memcpy(entropy + 16, vector->sk_prf, 16);
        memcpy(entropy + 32, vector->pk_seed, 16);

        result = slh_dsa_sha2_128s_keygen(pk, sk, entropy, sizeof entropy);
        printf("keygen tc %d: result %d\n", vector->tc_id, result);
        fflush(stdout);
        if (result != 0 || memcmp(pk, vector->pk, SLH_DSA_SHA2_128S_PUBLIC_KEY_SIZE) != 0) {
            fprintf(stderr, "FAIL: keygen tc %d\n", vector->tc_id);
            failures++;
        }
    }

    return failures;
}

static int run_sigver(void) {
    int failures = 0;
    size_t i;

    for (i = 0; i < SLH_DSA_ACVP_SIGVER_COUNT; i++) {
        const slh_dsa_acvp_sigver_case_t *vector = &SLH_DSA_ACVP_SIGVER_CASES[i];
        bitcoin_pqc_error_t got;

        if (vector->message == NULL || vector->pk == NULL || vector->signature == NULL) {
            fprintf(stderr, "FAIL: sigver tc %d null pointer\n", vector->tc_id);
            failures++;
            continue;
        }

        got = bitcoin_pqc_verify(
            BITCOIN_PQC_SLH_DSA_SHA2_128S,
            vector->pk,
            SLH_DSA_SHA2_128S_PUBLIC_KEY_SIZE,
            vector->message,
            vector->message_len,
            vector->signature,
            vector->signature_len
        );
        printf("sigver tc %d: got %d expect_ok %d\n", vector->tc_id, (int)got, vector->expect_ok);
        fflush(stdout);
        if (vector->expect_ok) {
            if (got != BITCOIN_PQC_OK) {
                fprintf(stderr, "FAIL: sigver tc %d\n", vector->tc_id);
                failures++;
            }
        } else if (got == BITCOIN_PQC_OK) {
            fprintf(stderr, "FAIL: sigver tc %d accepted\n", vector->tc_id);
            failures++;
        }
    }

    return failures;
}

int main(void) {
    int failures = 0;

    failures += run_keygen();
    failures += run_sigver();
    printf("%d failed\n", failures);
    return failures == 0 ? 0 : 1;
}
