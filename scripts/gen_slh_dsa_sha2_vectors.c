/*
 * Emit golden SLH-DSA-SHA2-128s vectors for tests/vectors/slh_dsa_sha2_128s_vectors.h.
 *
 * Build (from repo root, after ./build.sh):
 *   gcc -o /tmp/gen_slh_dsa_sha2_vectors scripts/gen_slh_dsa_sha2_vectors.c \
 *       -Iinclude -Itests build/lib/libbitcoinpqc.a -lm
 */

#include <stdio.h>
#include <string.h>
#include <libbitcoinpqc/bitcoinpqc.h>
#include "../tests/vectors/slh_dsa_sha2_128s_vectors.h"

static void print_hex_array(
    const char *name,
    const char *size_macro,
    const uint8_t *buf,
    size_t len
) {
    size_t i;

    printf("static const uint8_t %s[%s] = {\n", name, size_macro);
    for (i = 0; i < len; i++) {
        if (i % 8 == 0) {
            printf("    ");
        }
        printf("0x%02x", buf[i]);
        if (i + 1 < len) {
            printf(", ");
        }
        if (i % 8 == 7 || i + 1 == len) {
            printf("\n");
        }
    }
    printf("};\n\n");
}

int main(void) {
    bitcoin_pqc_keypair_t keypair;
    bitcoin_pqc_signature_t signature;
    bitcoin_pqc_error_t err;
    const size_t message_len = strlen(SLH_DSA_SHA2_TEST_MESSAGE);

    err = bitcoin_pqc_keygen(
        BITCOIN_PQC_SLH_DSA_SHA2_128S,
        &keypair,
        SLH_DSA_SHA2_TEST_ENTROPY,
        sizeof(SLH_DSA_SHA2_TEST_ENTROPY)
    );
    if (err != BITCOIN_PQC_OK) {
        fprintf(stderr, "keygen failed: %d\n", err);
        return 1;
    }

    err = bitcoin_pqc_sign(
        BITCOIN_PQC_SLH_DSA_SHA2_128S,
        keypair.secret_key,
        keypair.secret_key_size,
        (const uint8_t *)SLH_DSA_SHA2_TEST_MESSAGE,
        message_len,
        &signature
    );
    if (err != BITCOIN_PQC_OK) {
        fprintf(stderr, "sign failed: %d\n", err);
        bitcoin_pqc_keypair_free(&keypair);
        return 1;
    }

    printf("/* Paste into tests/vectors/slh_dsa_sha2_128s_vectors.h */\n\n");
    if (keypair.public_key_size != SLH_DSA_SHA2_EXPECTED_PK_SIZE ||
        signature.signature_size != SLH_DSA_SHA2_EXPECTED_SIG_SIZE) {
        fprintf(stderr, "unexpected key/signature size (pk=%zu sig=%zu)\n",
                keypair.public_key_size, signature.signature_size);
        bitcoin_pqc_signature_free(&signature);
        bitcoin_pqc_keypair_free(&keypair);
        return 1;
    }

    print_hex_array(
        "SLH_DSA_SHA2_EXPECTED_PK",
        "SLH_DSA_SHA2_EXPECTED_PK_SIZE",
        (const uint8_t *)keypair.public_key,
        keypair.public_key_size
    );
    print_hex_array(
        "SLH_DSA_SHA2_EXPECTED_SIG",
        "SLH_DSA_SHA2_EXPECTED_SIG_SIZE",
        signature.signature,
        signature.signature_size
    );

    bitcoin_pqc_signature_free(&signature);
    bitcoin_pqc_keypair_free(&keypair);
    return 0;
}