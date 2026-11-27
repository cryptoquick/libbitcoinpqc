/*
 * Frozen ACVP subset for ML-DSA-44.
 *
 * KeyGen places the 32-byte ACVP seed in the first bytes of the 128-byte
 * entropy buffer. ml_dsa_44_keygen passes that buffer to
 * crypto_sign_seed_keypair, which consumes SEEDBYTES as the seed. The
 * public key and the secret key must match the NIST vectors byte for byte.
 *
 * External pure sigVer goes through bitcoin_pqc_verify, which applies an
 * empty context. A valid vector must return BITCOIN_PQC_OK. An invalid
 * vector must not.
 */

#include <stdio.h>
#include <string.h>
#include <libbitcoinpqc/bitcoinpqc.h>
#include <libbitcoinpqc/ml_dsa.h>
#include "vectors/ml_dsa_44_acvp.h"

static int run_keygen(void) {
    int failures = 0;
    size_t i;

    for (i = 0; i < ML_DSA_ACVP_KEYGEN_COUNT; i++) {
        const ml_dsa_acvp_keygen_case_t *vector = &ML_DSA_ACVP_KEYGEN_CASES[i];
        uint8_t entropy[128];
        uint8_t pk[ML_DSA_44_PUBLIC_KEY_SIZE];
        uint8_t sk[ML_DSA_44_SECRET_KEY_SIZE];
        int result;

        if (vector->seed_len != 32
            || vector->pk_len != ML_DSA_44_PUBLIC_KEY_SIZE
            || vector->sk_len != ML_DSA_44_SECRET_KEY_SIZE) {
            fprintf(stderr, "FAIL: keygen tc %d unexpected field length\n", vector->tc_id);
            failures++;
            continue;
        }

        memset(entropy, 0, sizeof entropy);
        memcpy(entropy, vector->seed, vector->seed_len);

        result = ml_dsa_44_keygen(pk, sk, entropy, sizeof entropy);
        printf("keygen tc %d: result %d\n", vector->tc_id, result);
        fflush(stdout);
        if (result != 0
            || memcmp(pk, vector->pk, ML_DSA_44_PUBLIC_KEY_SIZE) != 0
            || memcmp(sk, vector->sk, ML_DSA_44_SECRET_KEY_SIZE) != 0) {
            fprintf(stderr, "FAIL: keygen tc %d\n", vector->tc_id);
            failures++;
        }
    }

    return failures;
}

static int run_sigver(void) {
    int failures = 0;
    size_t i;

    for (i = 0; i < ML_DSA_ACVP_SIGVER_COUNT; i++) {
        const ml_dsa_acvp_sigver_case_t *vector = &ML_DSA_ACVP_SIGVER_CASES[i];
        bitcoin_pqc_error_t got;

        if (vector->message == NULL || vector->pk == NULL || vector->signature == NULL) {
            fprintf(stderr, "FAIL: sigver tc %d null pointer\n", vector->tc_id);
            failures++;
            continue;
        }

        got = bitcoin_pqc_verify(
            BITCOIN_PQC_ML_DSA_44,
            vector->pk,
            vector->pk_len,
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
