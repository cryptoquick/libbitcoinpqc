/*
 * SLH-DSA-SHA2-128s pure-mode vectors from an independent OpenSSL signer.
 *
 * Every case goes through bitcoin_pqc_verify. An accept must return
 * BITCOIN_PQC_OK. A refusal, including a wrong signature length, must return
 * BITCOIN_PQC_ERROR_BAD_SIGNATURE.
 */

#include <stdio.h>
#include <libbitcoinpqc/bitcoinpqc.h>
#include "vectors/slh_dsa_sha2_128s_openssl.h"

int main(void) {
    int failures = 0;
    size_t i;

    for (i = 0; i < SLH_DSA_SHA2_OPENSSL_CASE_COUNT; i++) {
        const slh_dsa_sha2_openssl_case_t *vector = &SLH_DSA_SHA2_OPENSSL_CASES[i];
        bitcoin_pqc_error_t expected = vector->accept
            ? BITCOIN_PQC_OK
            : BITCOIN_PQC_ERROR_BAD_SIGNATURE;
        bitcoin_pqc_error_t got;

        if (vector->message == NULL) {
            fprintf(stderr, "FAIL: %s null message pointer\n", vector->name);
            failures++;
            continue;
        }

        got = bitcoin_pqc_verify(
            BITCOIN_PQC_SLH_DSA_SHA2_128S,
            vector->public_key,
            vector->public_key_len,
            vector->message,
            vector->message_len,
            vector->signature,
            vector->signature_len
        );
        printf("%s: got %d expected %d\n", vector->name, (int)got, (int)expected);
        fflush(stdout);
        if (got != expected) {
            fprintf(stderr, "FAIL: %s\n", vector->name);
            failures++;
        }
    }

    printf("%d failed\n", failures);
    return failures == 0 ? 0 : 1;
}
