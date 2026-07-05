/*
 * ML-DSA-44 E2E tests via the public bitcoin_pqc_* API.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <libbitcoinpqc/bitcoinpqc.h>

static int failures;

static const uint8_t ML_DSA_TEST_ENTROPY[128] = {
    0x20, 0x73, 0x9d, 0x89, 0xb8, 0x73, 0x79, 0xe8,
    0x3a, 0x91, 0x5a, 0x07, 0x64, 0x36, 0x6e, 0xd1,
    0xe7, 0x2e, 0xb3, 0x07, 0xb3, 0xc7, 0x84, 0x6d,
    0xc1, 0x35, 0x93, 0x33, 0x70, 0xf0, 0x0b, 0x26,
    0x62, 0x77, 0x96, 0x1d, 0x53, 0x6b, 0x47, 0x02,
    0x6f, 0x7e, 0xb8, 0x74, 0x60, 0x33, 0x84, 0xe3,
    0xa2, 0xb9, 0xea, 0x51, 0xf0, 0x33, 0xaa, 0x42,
    0x57, 0xac, 0xd1, 0x76, 0x06, 0xd2, 0xcd, 0x86,
    0xbc, 0x6c, 0x2a, 0x67, 0x45, 0xd5, 0x9d, 0xcc,
    0x14, 0x8d, 0x5a, 0x87, 0x76, 0xbe, 0x46, 0xe1,
    0x27, 0xe3, 0xcc, 0xf5, 0x72, 0x12, 0xbd, 0x0e,
    0xef, 0x80, 0x85, 0xaa, 0x87, 0x1c, 0xc4, 0x0b,
    0x91, 0x69, 0x3f, 0xd9, 0xa7, 0x90, 0x34, 0x50,
    0x4f, 0x63, 0x9c, 0xea, 0x0e, 0x61, 0x85, 0x09,
    0xaf, 0xd8, 0x4d, 0x94, 0x3b, 0x39, 0x28, 0x52,
    0x4b, 0xec, 0xc4, 0x73, 0xc3, 0xfa, 0x3c, 0x2a
};

static const char ML_DSA_TEST_MESSAGE[] = "Hello, Bitcoin PQC!";

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
        ML_DSA_TEST_ENTROPY,
        sizeof(ML_DSA_TEST_ENTROPY)
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

    err = bitcoin_pqc_sign(
        BITCOIN_PQC_ML_DSA_44,
        keypair.secret_key,
        keypair.secret_key_size,
        (const uint8_t *)ML_DSA_TEST_MESSAGE,
        strlen(ML_DSA_TEST_MESSAGE),
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

    err = bitcoin_pqc_verify(
        BITCOIN_PQC_ML_DSA_44,
        keypair.public_key,
        keypair.public_key_size,
        (const uint8_t *)ML_DSA_TEST_MESSAGE,
        strlen(ML_DSA_TEST_MESSAGE),
        signature.signature,
        signature.signature_size
    );
    expect_true(err == BITCOIN_PQC_OK,
                "test_ml_dsa_44_e2e: verify succeeds for original message");

    strcpy(tampered_message, ML_DSA_TEST_MESSAGE);
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