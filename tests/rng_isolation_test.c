/*
 * Verify that the public PQC paths do not call the legacy randombytes hook.
 *
 * The test supplies a trap implementation so an accidental dependency still
 * links but is observable at runtime.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <libbitcoinpqc/bitcoinpqc.h>

static int failures;
static int randombytes_calls;

void randombytes(uint8_t *out, size_t outlen) {
    randombytes_calls++;
    memset(out, 0xa5, outlen);
}

static void expect_true(int condition, const char *test_name) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", test_name);
        failures++;
    }
}

static void exercise_algorithm(bitcoin_pqc_algorithm_t algorithm, const char *name) {
    uint8_t entropy[128];
    static const uint8_t message[] = "explicit entropy isolation test vector";
    bitcoin_pqc_keypair_t keypair = {0};
    bitcoin_pqc_signature_t signature = {0};
    bitcoin_pqc_error_t err;

    for (size_t i = 0; i < sizeof(entropy); i++) {
        entropy[i] = (uint8_t)i;
    }

    err = bitcoin_pqc_keygen(algorithm, &keypair, entropy, sizeof(entropy));
    expect_true(err == BITCOIN_PQC_OK, name);
    if (err != BITCOIN_PQC_OK) {
        return;
    }

    err = bitcoin_pqc_sign(
        algorithm,
        keypair.secret_key,
        keypair.secret_key_size,
        message,
        sizeof(message) - 1,
        &signature
    );
    expect_true(err == BITCOIN_PQC_OK, name);
    if (err == BITCOIN_PQC_OK) {
        err = bitcoin_pqc_verify(
            algorithm,
            keypair.public_key,
            keypair.public_key_size,
            message,
            sizeof(message) - 1,
            signature.signature,
            signature.signature_size
        );
        expect_true(err == BITCOIN_PQC_OK, name);
        bitcoin_pqc_signature_free(&signature);
    }

    bitcoin_pqc_keypair_free(&keypair);
}

int main(void) {
    exercise_algorithm(BITCOIN_PQC_SECP256K1_SCHNORR, "secp256k1 explicit entropy path");
    exercise_algorithm(BITCOIN_PQC_ML_DSA_44, "ML-DSA explicit entropy path");
    exercise_algorithm(BITCOIN_PQC_SLH_DSA_SHA2_128S, "SLH-DSA explicit entropy path");
    expect_true(randombytes_calls == 0, "legacy randombytes hook is not called");

    if (failures != 0) {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }

    puts("rng_isolation: all tests passed");
    return 0;
}
