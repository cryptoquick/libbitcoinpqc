/*
 * SLH-DSA-SHA2-128s regression tests via the public bitcoin_pqc_* API.
 *
 * Coverage: golden key/signature vectors, determinism, valid verify,
 * tampered signature, wrong message, bad sig/pk sizes, NULL secret key,
 * short entropy rejection.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <libbitcoinpqc/bitcoinpqc.h>
#include "vectors/slh_dsa_sha2_128s_vectors.h"

static int failures;

static void expect_true(int condition, const char *test_name) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", test_name);
        failures++;
    }
}

static int keygen_with_entropy(
    const uint8_t *entropy,
    size_t entropy_size,
    bitcoin_pqc_keypair_t *keypair,
    bitcoin_pqc_error_t *err_out
) {
    bitcoin_pqc_error_t err = bitcoin_pqc_keygen(
        BITCOIN_PQC_SLH_DSA_SHA2_128S,
        keypair,
        entropy,
        entropy_size
    );

    if (err_out != NULL) {
        *err_out = err;
    }
    return err == BITCOIN_PQC_OK ? 0 : 1;
}

static int sign_test_message(
    const bitcoin_pqc_keypair_t *keypair,
    bitcoin_pqc_signature_t *signature
) {
    const size_t message_len = strlen(SLH_DSA_SHA2_TEST_MESSAGE);

    return bitcoin_pqc_sign(
        BITCOIN_PQC_SLH_DSA_SHA2_128S,
        keypair->secret_key,
        keypair->secret_key_size,
        (const uint8_t *)SLH_DSA_SHA2_TEST_MESSAGE,
        message_len,
        signature
    ) == BITCOIN_PQC_OK ? 0 : 1;
}

static void test_keygen_sizes(void) {
    bitcoin_pqc_keypair_t keypair;
    bitcoin_pqc_error_t err;

    expect_true(
        keygen_with_entropy(
            SLH_DSA_SHA2_TEST_ENTROPY,
            sizeof(SLH_DSA_SHA2_TEST_ENTROPY),
            &keypair,
            &err
        ) == 0,
        "test_keygen_sizes: keygen succeeds"
    );
    if (err != BITCOIN_PQC_OK) {
        return;
    }

    expect_true(
        keypair.public_key_size == SLH_DSA_SHA2_128S_PUBLIC_KEY_SIZE,
        "test_keygen_sizes: public key size"
    );
    expect_true(
        keypair.secret_key_size == SLH_DSA_SHA2_128S_SECRET_KEY_SIZE,
        "test_keygen_sizes: secret key size"
    );
    bitcoin_pqc_keypair_free(&keypair);
}

static void test_keygen_golden_pk(void) {
    bitcoin_pqc_keypair_t keypair;
    bitcoin_pqc_error_t err;
    const uint8_t *pk;

    if (keygen_with_entropy(
            SLH_DSA_SHA2_TEST_ENTROPY,
            sizeof(SLH_DSA_SHA2_TEST_ENTROPY),
            &keypair,
            &err
        ) != 0) {
        expect_true(0, "test_keygen_golden_pk: keygen succeeds");
        return;
    }

    pk = (const uint8_t *)keypair.public_key;
    expect_true(
        memcmp(pk, SLH_DSA_SHA2_EXPECTED_PK, SLH_DSA_SHA2_EXPECTED_PK_SIZE) == 0,
        "test_keygen_golden_pk: full public key matches golden vector"
    );
    bitcoin_pqc_keypair_free(&keypair);
}

static void test_sign_determinism(void) {
    bitcoin_pqc_keypair_t keypair;
    bitcoin_pqc_signature_t signature1;
    bitcoin_pqc_signature_t signature2;

    if (keygen_with_entropy(
            SLH_DSA_SHA2_TEST_ENTROPY,
            sizeof(SLH_DSA_SHA2_TEST_ENTROPY),
            &keypair,
            NULL
        ) != 0) {
        expect_true(0, "test_sign_determinism: keygen succeeds");
        return;
    }

    expect_true(sign_test_message(&keypair, &signature1) == 0,
                "test_sign_determinism: first sign succeeds");
    expect_true(sign_test_message(&keypair, &signature2) == 0,
                "test_sign_determinism: second sign succeeds");
    expect_true(signature1.signature != NULL,
                "test_sign_determinism: first signature buffer allocated");
    expect_true(signature2.signature != NULL,
                "test_sign_determinism: second signature buffer allocated");

    if (signature1.signature != NULL && signature2.signature != NULL) {
        expect_true(
            signature1.signature_size == signature2.signature_size &&
            memcmp(
                signature1.signature,
                signature2.signature,
                signature1.signature_size
            ) == 0,
            "test_sign_determinism: signatures are identical"
        );
    }

    bitcoin_pqc_signature_free(&signature2);
    bitcoin_pqc_signature_free(&signature1);
    bitcoin_pqc_keypair_free(&keypair);
}

static void test_sign_golden_sig(void) {
    bitcoin_pqc_keypair_t keypair;
    bitcoin_pqc_signature_t signature;

    if (keygen_with_entropy(
            SLH_DSA_SHA2_TEST_ENTROPY,
            sizeof(SLH_DSA_SHA2_TEST_ENTROPY),
            &keypair,
            NULL
        ) != 0) {
        expect_true(0, "test_sign_golden_sig: keygen succeeds");
        return;
    }

    expect_true(sign_test_message(&keypair, &signature) == 0,
                "test_sign_golden_sig: sign succeeds");
    expect_true(
        signature.signature_size == SLH_DSA_SHA2_128S_SIGNATURE_SIZE,
        "test_sign_golden_sig: signature size"
    );

    if (signature.signature != NULL) {
        expect_true(
            memcmp(
                signature.signature,
                SLH_DSA_SHA2_EXPECTED_SIG,
                SLH_DSA_SHA2_EXPECTED_SIG_SIZE
            ) == 0,
            "test_sign_golden_sig: signature matches golden vector"
        );
    }

    bitcoin_pqc_signature_free(&signature);
    bitcoin_pqc_keypair_free(&keypair);
}

static void test_verify_valid(void) {
    bitcoin_pqc_keypair_t keypair;
    bitcoin_pqc_signature_t signature;
    bitcoin_pqc_error_t err;
    const size_t message_len = strlen(SLH_DSA_SHA2_TEST_MESSAGE);

    if (keygen_with_entropy(
            SLH_DSA_SHA2_TEST_ENTROPY,
            sizeof(SLH_DSA_SHA2_TEST_ENTROPY),
            &keypair,
            NULL
        ) != 0 ||
        sign_test_message(&keypair, &signature) != 0) {
        expect_true(0, "test_verify_valid: keygen and sign succeed");
        bitcoin_pqc_keypair_free(&keypair);
        return;
    }

    err = bitcoin_pqc_verify(
        BITCOIN_PQC_SLH_DSA_SHA2_128S,
        keypair.public_key,
        keypair.public_key_size,
        (const uint8_t *)SLH_DSA_SHA2_TEST_MESSAGE,
        message_len,
        signature.signature,
        signature.signature_size
    );
    expect_true(err == BITCOIN_PQC_OK, "test_verify_valid: verify succeeds");

    bitcoin_pqc_signature_free(&signature);
    bitcoin_pqc_keypair_free(&keypair);
}

static void test_verify_tampered_sig(void) {
    bitcoin_pqc_keypair_t keypair;
    bitcoin_pqc_signature_t signature;
    bitcoin_pqc_error_t err;
    const size_t message_len = strlen(SLH_DSA_SHA2_TEST_MESSAGE);

    if (keygen_with_entropy(
            SLH_DSA_SHA2_TEST_ENTROPY,
            sizeof(SLH_DSA_SHA2_TEST_ENTROPY),
            &keypair,
            NULL
        ) != 0 ||
        sign_test_message(&keypair, &signature) != 0 ||
        signature.signature == NULL) {
        expect_true(0, "test_verify_tampered_sig: keygen and sign succeed");
        bitcoin_pqc_signature_free(&signature);
        bitcoin_pqc_keypair_free(&keypair);
        return;
    }

    signature.signature[0] ^= 0x01;

    err = bitcoin_pqc_verify(
        BITCOIN_PQC_SLH_DSA_SHA2_128S,
        keypair.public_key,
        keypair.public_key_size,
        (const uint8_t *)SLH_DSA_SHA2_TEST_MESSAGE,
        message_len,
        signature.signature,
        signature.signature_size
    );
    expect_true(
        err == BITCOIN_PQC_ERROR_BAD_SIGNATURE,
        "test_verify_tampered_sig: tampered signature rejected"
    );

    bitcoin_pqc_signature_free(&signature);
    bitcoin_pqc_keypair_free(&keypair);
}

static void test_verify_wrong_message(void) {
    bitcoin_pqc_keypair_t keypair;
    bitcoin_pqc_signature_t signature;
    bitcoin_pqc_error_t err;
    static const char wrong_message[] = "wrong message for SLH-DSA verify test";

    if (keygen_with_entropy(
            SLH_DSA_SHA2_TEST_ENTROPY,
            sizeof(SLH_DSA_SHA2_TEST_ENTROPY),
            &keypair,
            NULL
        ) != 0 ||
        sign_test_message(&keypair, &signature) != 0) {
        expect_true(0, "test_verify_wrong_message: keygen and sign succeed");
        bitcoin_pqc_signature_free(&signature);
        bitcoin_pqc_keypair_free(&keypair);
        return;
    }

    err = bitcoin_pqc_verify(
        BITCOIN_PQC_SLH_DSA_SHA2_128S,
        keypair.public_key,
        keypair.public_key_size,
        (const uint8_t *)wrong_message,
        strlen(wrong_message),
        signature.signature,
        signature.signature_size
    );
    expect_true(
        err == BITCOIN_PQC_ERROR_BAD_SIGNATURE,
        "test_verify_wrong_message: wrong message rejected"
    );

    bitcoin_pqc_signature_free(&signature);
    bitcoin_pqc_keypair_free(&keypair);
}

static void test_sign_null_secret_key(void) {
    bitcoin_pqc_signature_t signature;
    bitcoin_pqc_error_t err;
    const size_t message_len = strlen(SLH_DSA_SHA2_TEST_MESSAGE);

    err = bitcoin_pqc_sign(
        BITCOIN_PQC_SLH_DSA_SHA2_128S,
        NULL,
        SLH_DSA_SHA2_128S_SECRET_KEY_SIZE,
        (const uint8_t *)SLH_DSA_SHA2_TEST_MESSAGE,
        message_len,
        &signature
    );
    expect_true(
        err == BITCOIN_PQC_ERROR_BAD_ARG,
        "test_sign_null_secret_key: NULL secret_key rejected"
    );
}

static void test_verify_bad_sig_size(void) {
    bitcoin_pqc_keypair_t keypair;
    bitcoin_pqc_signature_t signature;
    bitcoin_pqc_error_t err;
    const size_t message_len = strlen(SLH_DSA_SHA2_TEST_MESSAGE);

    if (keygen_with_entropy(
            SLH_DSA_SHA2_TEST_ENTROPY,
            sizeof(SLH_DSA_SHA2_TEST_ENTROPY),
            &keypair,
            NULL
        ) != 0 ||
        sign_test_message(&keypair, &signature) != 0 ||
        signature.signature == NULL) {
        expect_true(0, "test_verify_bad_sig_size: keygen and sign succeed");
        bitcoin_pqc_signature_free(&signature);
        bitcoin_pqc_keypair_free(&keypair);
        return;
    }

    err = bitcoin_pqc_verify(
        BITCOIN_PQC_SLH_DSA_SHA2_128S,
        keypair.public_key,
        keypair.public_key_size,
        (const uint8_t *)SLH_DSA_SHA2_TEST_MESSAGE,
        message_len,
        signature.signature,
        signature.signature_size - 1
    );
    expect_true(
        err == BITCOIN_PQC_ERROR_BAD_SIGNATURE,
        "test_verify_bad_sig_size: short signature rejected"
    );

    bitcoin_pqc_signature_free(&signature);
    bitcoin_pqc_keypair_free(&keypair);
}

static void test_verify_bad_pk_size(void) {
    bitcoin_pqc_keypair_t keypair;
    bitcoin_pqc_signature_t signature;
    bitcoin_pqc_error_t err;
    const size_t message_len = strlen(SLH_DSA_SHA2_TEST_MESSAGE);
    const uint8_t *pk;

    if (keygen_with_entropy(
            SLH_DSA_SHA2_TEST_ENTROPY,
            sizeof(SLH_DSA_SHA2_TEST_ENTROPY),
            &keypair,
            NULL
        ) != 0 ||
        sign_test_message(&keypair, &signature) != 0) {
        expect_true(0, "test_verify_bad_pk_size: keygen and sign succeed");
        bitcoin_pqc_signature_free(&signature);
        bitcoin_pqc_keypair_free(&keypair);
        return;
    }

    pk = (const uint8_t *)keypair.public_key;
    err = bitcoin_pqc_verify(
        BITCOIN_PQC_SLH_DSA_SHA2_128S,
        pk,
        keypair.public_key_size - 1,
        (const uint8_t *)SLH_DSA_SHA2_TEST_MESSAGE,
        message_len,
        signature.signature,
        signature.signature_size
    );
    expect_true(
        err == BITCOIN_PQC_ERROR_BAD_KEY,
        "test_verify_bad_pk_size: short public key rejected"
    );

    bitcoin_pqc_signature_free(&signature);
    bitcoin_pqc_keypair_free(&keypair);
}

static void test_keygen_short_entropy(void) {
    bitcoin_pqc_keypair_t keypair;
    bitcoin_pqc_error_t err;
    uint8_t short_entropy[127];

    memset(short_entropy, 0xab, sizeof(short_entropy));

    err = bitcoin_pqc_keygen(
        BITCOIN_PQC_SLH_DSA_SHA2_128S,
        &keypair,
        short_entropy,
        sizeof(short_entropy)
    );
    expect_true(
        err == BITCOIN_PQC_ERROR_BAD_ARG,
        "test_keygen_short_entropy: 127-byte entropy rejected"
    );
}

int main(void) {
    failures = 0;

    test_keygen_sizes();
    test_keygen_golden_pk();
    test_sign_determinism();
    test_sign_golden_sig();
    test_verify_valid();
    test_verify_tampered_sig();
    test_verify_wrong_message();
    test_sign_null_secret_key();
    test_verify_bad_sig_size();
    test_verify_bad_pk_size();
    test_keygen_short_entropy();

    if (failures != 0) {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }

    return 0;
}