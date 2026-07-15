/*
 * secp256k1 Schnorr (BIP-340) E2E tests via the public bitcoin_pqc_* API.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <libbitcoinpqc/bitcoinpqc.h>

#include "vectors/secp256k1_bip340_vectors.h"

static int failures;

static void expect_true(int condition, const char *test_name) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", test_name);
        failures++;
    }
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
    size_t hex_len = strlen(hex);

    if (hex_len != out_len * 2) {
        return -1;
    }

    for (size_t i = 0; i < out_len; i++) {
        unsigned int byte;
        if (sscanf(hex + (i * 2), "%2x", &byte) != 1) {
            return -1;
        }
        out[i] = (uint8_t)byte;
    }

    return 0;
}

static int mem_eq_hex(const uint8_t *bytes, size_t len, const char *hex) {
    uint8_t expected[64];

    if (len > sizeof(expected) || hex_to_bytes(hex, expected, len) != 0) {
        return 0;
    }

    return memcmp(bytes, expected, len) == 0;
}

static void test_bip340_row0_e2e(void) {
    uint8_t tampered_message[SECP256K1_BIP340_MESSAGE_SIZE];
    bitcoin_pqc_keypair_t keypair;
    bitcoin_pqc_signature_t signature;
    bitcoin_pqc_error_t err;

    memcpy(tampered_message, SECP256K1_BIP340_ROW0_MESSAGE, sizeof(tampered_message));
    tampered_message[31] ^= 0x01;

    err = bitcoin_pqc_keygen(
        BITCOIN_PQC_SECP256K1_SCHNORR,
        &keypair,
        SECP256K1_BIP340_ROW0_SECRET,
        sizeof(SECP256K1_BIP340_ROW0_SECRET)
    );
    expect_true(err == BITCOIN_PQC_OK, "test_bip340_row0_e2e: keygen succeeds");
    if (err != BITCOIN_PQC_OK) {
        return;
    }

    expect_true(
        memcmp(keypair.public_key, SECP256K1_BIP340_ROW0_EXPECTED_PK,
               SECP256K1_BIP340_PK_SIZE) == 0,
        "test_bip340_row0_e2e: public key matches BIP-340 row 0"
    );
    expect_true(
        memcmp(keypair.secret_key, SECP256K1_BIP340_ROW0_SECRET,
               SECP256K1_BIP340_SECRET_SIZE) == 0,
        "test_bip340_row0_e2e: secret key matches input seed"
    );

    err = bitcoin_pqc_sign(
        BITCOIN_PQC_SECP256K1_SCHNORR,
        keypair.secret_key,
        keypair.secret_key_size,
        SECP256K1_BIP340_ROW0_MESSAGE,
        sizeof(SECP256K1_BIP340_ROW0_MESSAGE),
        &signature
    );
    expect_true(err == BITCOIN_PQC_OK, "test_bip340_row0_e2e: sign succeeds");
    if (err != BITCOIN_PQC_OK) {
        bitcoin_pqc_keypair_free(&keypair);
        return;
    }

    expect_true(signature.signature_size == SECP256K1_BIP340_SIG_SIZE,
                "test_bip340_row0_e2e: signature size is 64 bytes");

    expect_true(
        memcmp(signature.signature, SECP256K1_BIP340_ROW0_EXPECTED_SIG,
               SECP256K1_BIP340_SIG_SIZE) == 0,
        "test_bip340_row0_e2e: signature matches golden vector (no aux_rand)"
    );

    err = bitcoin_pqc_verify(
        BITCOIN_PQC_SECP256K1_SCHNORR,
        keypair.public_key,
        keypair.public_key_size,
        SECP256K1_BIP340_ROW0_MESSAGE,
        sizeof(SECP256K1_BIP340_ROW0_MESSAGE),
        signature.signature,
        signature.signature_size
    );
    expect_true(err == BITCOIN_PQC_OK,
                "test_bip340_row0_e2e: verify succeeds for original message");

    err = bitcoin_pqc_verify(
        BITCOIN_PQC_SECP256K1_SCHNORR,
        keypair.public_key,
        keypair.public_key_size,
        tampered_message,
        sizeof(tampered_message),
        signature.signature,
        signature.signature_size
    );
    expect_true(err == BITCOIN_PQC_ERROR_BAD_SIGNATURE,
                "test_bip340_row0_e2e: verify fails for tampered message");

    bitcoin_pqc_signature_free(&signature);
    bitcoin_pqc_keypair_free(&keypair);
}

static void test_rejects_bad_inputs(void) {
    uint8_t short_seed[31];
    uint8_t zero_secret[32];
    uint8_t short_message[31];
    uint8_t secret[32];
    uint8_t message[32];
    bitcoin_pqc_keypair_t keypair;
    bitcoin_pqc_signature_t signature;
    bitcoin_pqc_error_t err;

    memset(short_seed, 0xAB, sizeof(short_seed));
    err = bitcoin_pqc_keygen(
        BITCOIN_PQC_SECP256K1_SCHNORR,
        &keypair,
        short_seed,
        sizeof(short_seed)
    );
    expect_true(err == BITCOIN_PQC_ERROR_BAD_ARG,
                "test_rejects_bad_inputs: 31-byte seed rejected");

    memset(zero_secret, 0, sizeof(zero_secret));
    err = bitcoin_pqc_keygen(
        BITCOIN_PQC_SECP256K1_SCHNORR,
        &keypair,
        zero_secret,
        sizeof(zero_secret)
    );
    expect_true(err == BITCOIN_PQC_ERROR_BAD_KEY,
                "test_rejects_bad_inputs: zero secret rejected");

    expect_true(hex_to_bytes(
                    "0000000000000000000000000000000000000000000000000000000000000003",
                    secret,
                    sizeof(secret)) == 0,
                "test_rejects_bad_inputs: decode secret hex");

    err = bitcoin_pqc_keygen(
        BITCOIN_PQC_SECP256K1_SCHNORR,
        &keypair,
        secret,
        sizeof(secret)
    );
    expect_true(err == BITCOIN_PQC_OK,
                "test_rejects_bad_inputs: valid keygen succeeds");
    if (err != BITCOIN_PQC_OK) {
        return;
    }

    memset(short_message, 0xCD, sizeof(short_message));
    err = bitcoin_pqc_sign(
        BITCOIN_PQC_SECP256K1_SCHNORR,
        keypair.secret_key,
        keypair.secret_key_size,
        short_message,
        sizeof(short_message),
        &signature
    );
    expect_true(err == BITCOIN_PQC_ERROR_BAD_ARG,
                "test_rejects_bad_inputs: 31-byte message rejected");

    memset(message, 0, sizeof(message));
    err = bitcoin_pqc_sign(
        BITCOIN_PQC_SECP256K1_SCHNORR,
        keypair.secret_key,
        keypair.secret_key_size,
        message,
        sizeof(message),
        &signature
    );
    expect_true(err == BITCOIN_PQC_OK,
                "test_rejects_bad_inputs: valid sign succeeds");
    if (err != BITCOIN_PQC_OK) {
        bitcoin_pqc_keypair_free(&keypair);
        return;
    }

    memset(keypair.secret_key, 0, keypair.secret_key_size);
    err = bitcoin_pqc_sign(
        BITCOIN_PQC_SECP256K1_SCHNORR,
        keypair.secret_key,
        keypair.secret_key_size,
        message,
        sizeof(message),
        &signature
    );
    expect_true(err == BITCOIN_PQC_ERROR_BAD_KEY,
                "test_rejects_bad_inputs: invalid secret key maps to BAD_KEY");

    memset(keypair.public_key, 0, keypair.public_key_size);
    err = bitcoin_pqc_verify(
        BITCOIN_PQC_SECP256K1_SCHNORR,
        keypair.public_key,
        keypair.public_key_size,
        message,
        sizeof(message),
        signature.signature,
        signature.signature_size
    );
    expect_true(err == BITCOIN_PQC_ERROR_BAD_KEY,
                "test_rejects_bad_inputs: invalid pubkey maps to BAD_KEY");

    bitcoin_pqc_signature_free(&signature);
    bitcoin_pqc_keypair_free(&keypair);
}

int main(void) {
    test_bip340_row0_e2e();
    test_rejects_bad_inputs();

    if (failures != 0) {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }

    puts("secp256k1_schnorr_e2e: all tests passed");
    return 0;
}