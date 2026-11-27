/*
 * OpenSSL ML-DSA-44 accept and refuse cases via bitcoin_pqc_verify.
 * Empty message: non-NULL pointer, length 0.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <libbitcoinpqc/bitcoinpqc.h>

#include "vectors/ml_dsa_44_openssl.h"

static int failures;

static const struct {
    const char *name;
    int accept;
    const uint8_t *public_key;
    size_t public_key_size;
    const uint8_t *message;
    size_t message_size;
    const uint8_t *signature;
    size_t signature_size;
} cases[] = {
    {
        ML_DSA_44_OPENSSL_0_NAME,
        ML_DSA_44_OPENSSL_0_ACCEPT,
        ML_DSA_44_OPENSSL_0_PK,
        sizeof(ML_DSA_44_OPENSSL_0_PK),
        ML_DSA_44_OPENSSL_0_MSG,
        ML_DSA_44_OPENSSL_0_MSG_SIZE,
        ML_DSA_44_OPENSSL_0_SIG,
        sizeof(ML_DSA_44_OPENSSL_0_SIG),
    },
    {
        ML_DSA_44_OPENSSL_1_NAME,
        ML_DSA_44_OPENSSL_1_ACCEPT,
        ML_DSA_44_OPENSSL_1_PK,
        sizeof(ML_DSA_44_OPENSSL_1_PK),
        ML_DSA_44_OPENSSL_1_MSG,
        ML_DSA_44_OPENSSL_1_MSG_SIZE,
        ML_DSA_44_OPENSSL_1_SIG,
        sizeof(ML_DSA_44_OPENSSL_1_SIG),
    },
    {
        ML_DSA_44_OPENSSL_2_NAME,
        ML_DSA_44_OPENSSL_2_ACCEPT,
        ML_DSA_44_OPENSSL_2_PK,
        sizeof(ML_DSA_44_OPENSSL_2_PK),
        ML_DSA_44_OPENSSL_2_MSG,
        ML_DSA_44_OPENSSL_2_MSG_SIZE,
        ML_DSA_44_OPENSSL_2_SIG,
        sizeof(ML_DSA_44_OPENSSL_2_SIG),
    },
    {
        ML_DSA_44_OPENSSL_3_NAME,
        ML_DSA_44_OPENSSL_3_ACCEPT,
        ML_DSA_44_OPENSSL_3_PK,
        sizeof(ML_DSA_44_OPENSSL_3_PK),
        ML_DSA_44_OPENSSL_3_MSG,
        ML_DSA_44_OPENSSL_3_MSG_SIZE,
        ML_DSA_44_OPENSSL_3_SIG,
        sizeof(ML_DSA_44_OPENSSL_3_SIG),
    },
    {
        ML_DSA_44_OPENSSL_4_NAME,
        ML_DSA_44_OPENSSL_4_ACCEPT,
        ML_DSA_44_OPENSSL_4_PK,
        sizeof(ML_DSA_44_OPENSSL_4_PK),
        ML_DSA_44_OPENSSL_4_MSG,
        ML_DSA_44_OPENSSL_4_MSG_SIZE,
        ML_DSA_44_OPENSSL_4_SIG,
        sizeof(ML_DSA_44_OPENSSL_4_SIG),
    },
    {
        ML_DSA_44_OPENSSL_5_NAME,
        ML_DSA_44_OPENSSL_5_ACCEPT,
        ML_DSA_44_OPENSSL_5_PK,
        sizeof(ML_DSA_44_OPENSSL_5_PK),
        ML_DSA_44_OPENSSL_5_MSG,
        ML_DSA_44_OPENSSL_5_MSG_SIZE,
        ML_DSA_44_OPENSSL_5_SIG,
        sizeof(ML_DSA_44_OPENSSL_5_SIG),
    },
    {
        ML_DSA_44_OPENSSL_6_NAME,
        ML_DSA_44_OPENSSL_6_ACCEPT,
        ML_DSA_44_OPENSSL_6_PK,
        sizeof(ML_DSA_44_OPENSSL_6_PK),
        ML_DSA_44_OPENSSL_6_MSG,
        ML_DSA_44_OPENSSL_6_MSG_SIZE,
        ML_DSA_44_OPENSSL_6_SIG,
        sizeof(ML_DSA_44_OPENSSL_6_SIG),
    },
};

int main(void) {
    size_t i;
    size_t n;
    int accepts;
    int refuses;

    n = sizeof(cases) / sizeof(cases[0]);
    if (n != ML_DSA_44_OPENSSL_CASE_COUNT || n != 7) {
        fprintf(stderr, "FAIL: case count\n");
        return 1;
    }

    accepts = 0;
    refuses = 0;
    for (i = 0; i < n; i++) {
        bitcoin_pqc_error_t err;
        bitcoin_pqc_error_t want;
        const uint8_t *message;

        if (cases[i].message == NULL) {
            fprintf(stderr, "FAIL: %s\n", cases[i].name);
            failures++;
            continue;
        }
        if (cases[i].public_key_size != ML_DSA_44_OPENSSL_PUBLIC_KEY_SIZE ||
            cases[i].signature_size != ML_DSA_44_OPENSSL_SIGNATURE_SIZE) {
            fprintf(stderr, "FAIL: %s\n", cases[i].name);
            failures++;
            continue;
        }

        message = cases[i].message;
        err = bitcoin_pqc_verify(
            BITCOIN_PQC_ML_DSA_44,
            cases[i].public_key,
            cases[i].public_key_size,
            message,
            cases[i].message_size,
            cases[i].signature,
            cases[i].signature_size
        );
        if (cases[i].accept) {
            want = BITCOIN_PQC_OK;
            accepts++;
        } else {
            want = BITCOIN_PQC_ERROR_BAD_SIGNATURE;
            refuses++;
        }
        if (err != want) {
            fprintf(stderr, "FAIL: %s\n", cases[i].name);
            failures++;
        }
    }

    if (accepts != 2 || refuses != 5) {
        fprintf(stderr, "FAIL: case count\n");
        return 1;
    }
    if (failures != 0) {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }

    puts("ml_dsa_44_openssl: all 7 cases passed");
    return 0;
}
