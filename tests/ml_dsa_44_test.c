/*
 * ML-DSA-44 E2E tests via the public bitcoin_pqc_* API.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <libbitcoinpqc/bitcoinpqc.h>

#include "vectors/ml_dsa_44_vectors.h"

static int failures;

static void expect_true(int condition, const char *test_name) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", test_name);
        failures++;
    }
}

static void test_ml_dsa_44_e2e(void) {
    bitcoin_pqc_keypair_t keypair;
    bitcoin_pqc_signature_t signature;
    bitcoin_pqc_error_t err;
    char tampered_message[64];

    err = bitcoin_pqc_keygen(
        BITCOIN_PQC_ML_DSA_44,
        &keypair,
        ML_DSA_44_TEST_ENTROPY,
        sizeof(ML_DSA_44_TEST_ENTROPY)
    );
    expect_true(err == BITCOIN_PQC_OK, "test_ml_dsa_44_e2e: keygen succeeds");
    if (err != BITCOIN_PQC_OK) {
        return;
    }

    expect_true(
        keypair.public_key_size == ML_DSA_44_PUBLIC_KEY_SIZE,
        "test_ml_dsa_44_e2e: public key size"
    );
    expect_true(
        keypair.secret_key_size == ML_DSA_44_SECRET_KEY_SIZE,
        "test_ml_dsa_44_e2e: secret key size"
    );

    expect_true(
        memcmp(keypair.public_key, ML_DSA_44_EXPECTED_PK, ML_DSA_44_EXPECTED_PK_SIZE) == 0,
        "test_ml_dsa_44_e2e: public key matches golden vector"
    );

    err = bitcoin_pqc_sign(
        BITCOIN_PQC_ML_DSA_44,
        keypair.secret_key,
        keypair.secret_key_size,
        (const uint8_t *)ML_DSA_44_TEST_MESSAGE,
        strlen(ML_DSA_44_TEST_MESSAGE),
        &signature
    );
    expect_true(err == BITCOIN_PQC_OK, "test_ml_dsa_44_e2e: sign succeeds");
    if (err != BITCOIN_PQC_OK) {
        bitcoin_pqc_keypair_free(&keypair);
        return;
    }

    expect_true(
        signature.signature_size == ML_DSA_44_SIGNATURE_SIZE,
        "test_ml_dsa_44_e2e: signature size"
    );

    expect_true(
        memcmp(signature.signature, ML_DSA_44_EXPECTED_SIG, ML_DSA_44_EXPECTED_SIG_SIZE) == 0,
        "test_ml_dsa_44_e2e: signature matches golden vector"
    );

    err = bitcoin_pqc_verify(
        BITCOIN_PQC_ML_DSA_44,
        keypair.public_key,
        keypair.public_key_size,
        (const uint8_t *)ML_DSA_44_TEST_MESSAGE,
        strlen(ML_DSA_44_TEST_MESSAGE),
        signature.signature,
        signature.signature_size
    );
    expect_true(err == BITCOIN_PQC_OK,
                "test_ml_dsa_44_e2e: verify succeeds for original message");

    strcpy(tampered_message, ML_DSA_44_TEST_MESSAGE);
    tampered_message[strlen(tampered_message) - 1] ^= 0x01;

    err = bitcoin_pqc_verify(
        BITCOIN_PQC_ML_DSA_44,
        keypair.public_key,
        keypair.public_key_size,
        (const uint8_t *)tampered_message,
        strlen(tampered_message),
        signature.signature,
        signature.signature_size
    );
    expect_true(err == BITCOIN_PQC_ERROR_BAD_SIGNATURE,
                "test_ml_dsa_44_e2e: verify fails for tampered message");

    bitcoin_pqc_signature_free(&signature);
    bitcoin_pqc_keypair_free(&keypair);
}

int main(void) {
    test_ml_dsa_44_e2e();

    if (failures != 0) {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }

    puts("ml_dsa_44_e2e: all tests passed");
    return 0;
}