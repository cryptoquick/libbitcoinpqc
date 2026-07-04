/*
 * entropy_demo.c - Demonstrates user-provided entropy with libbitcoinpqc.
 *
 * Reads exactly 128 bytes of entropy from stdin, then uses it to generate
 * ML-DSA-44 and SLH-DSA-SHA2-128s key pairs, sign a message, and verify
 * the signatures.
 *
 * Usage:
 *   dd if=/dev/urandom bs=128 count=1 2>/dev/null | ./entropy_demo
 *   ./entropy_demo < saved_entropy.bin
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <libbitcoinpqc/bitcoinpqc.h>

#define ENTROPY_SIZE 128

int main(void) {
    uint8_t entropy[ENTROPY_SIZE];
    size_t total = 0;

    /* Read exactly ENTROPY_SIZE bytes from stdin */
    while (total < ENTROPY_SIZE) {
        size_t n = fread(entropy + total, 1, ENTROPY_SIZE - total, stdin);
        if (n == 0) {
            fprintf(stderr,
                "Error: need %d bytes of entropy on stdin, got %zu\n",
                ENTROPY_SIZE, total);
            return 1;
        }
        total += n;
    }

    /* Show a hex preview of the entropy received */
    printf("Entropy (first 16 bytes): ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", entropy[i]);
    }
    printf("...\n\n");

    /* Generate an ML-DSA-44 key pair */
    bitcoin_pqc_keypair_t keypair;
    bitcoin_pqc_error_t err = bitcoin_pqc_keygen(
        BITCOIN_PQC_ML_DSA_44, &keypair, entropy, ENTROPY_SIZE
    );

    if (err != BITCOIN_PQC_OK) {
        fprintf(stderr, "Key generation failed: %d\n", err);
        return 1;
    }

    printf("ML-DSA-44 key pair generated successfully.\n");
    printf("  Public key size: %zu bytes\n", keypair.public_key_size);
    printf("  Secret key size: %zu bytes\n", keypair.secret_key_size);

    const uint8_t *pk = (const uint8_t *)keypair.public_key;
    printf("  Public key (first 16 bytes): ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", pk[i]);
    }
    printf("...\n\n");

    /* Sign a message */
    const char *msg_text = "Hello, post-quantum world!";
    const uint8_t *message = (const uint8_t *)msg_text;
    size_t message_len = strlen(msg_text);

    bitcoin_pqc_signature_t sig;
    err = bitcoin_pqc_sign(
        BITCOIN_PQC_ML_DSA_44,
        keypair.secret_key, keypair.secret_key_size,
        message, message_len,
        &sig
    );

    if (err != BITCOIN_PQC_OK) {
        fprintf(stderr, "Signing failed: %d\n", err);
        bitcoin_pqc_keypair_free(&keypair);
        return 1;
    }

    printf("Signature size: %zu bytes\n", sig.signature_size);

    /* Verify the signature */
    err = bitcoin_pqc_verify(
        BITCOIN_PQC_ML_DSA_44,
        keypair.public_key, keypair.public_key_size,
        message, message_len,
        sig.signature, sig.signature_size
    );

    printf("Verification: %s\n\n", err == BITCOIN_PQC_OK ? "PASS" : "FAIL");

    bitcoin_pqc_signature_free(&sig);
    bitcoin_pqc_keypair_free(&keypair);

    if (err != BITCOIN_PQC_OK)
        return 1;

    /* Generate an SLH-DSA-SHA2-128s key pair using the same entropy */
    bitcoin_pqc_keypair_t slh_keypair;
    err = bitcoin_pqc_keygen(
        BITCOIN_PQC_SLH_DSA_SHA2_128S, &slh_keypair, entropy, ENTROPY_SIZE
    );

    if (err != BITCOIN_PQC_OK) {
        fprintf(stderr, "SLH-DSA key generation failed: %d\n", err);
        return 1;
    }

    printf("SLH-DSA-SHA2-128s key pair generated successfully.\n");
    printf("  Public key size: %zu bytes\n", slh_keypair.public_key_size);
    printf("  Secret key size: %zu bytes\n", slh_keypair.secret_key_size);

    const uint8_t *slh_pk = (const uint8_t *)slh_keypair.public_key;
    printf("  Public key (first 16 bytes): ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", slh_pk[i]);
    }
    printf("...\n\n");

    /* Sign with SLH-DSA */
    bitcoin_pqc_signature_t slh_sig;
    err = bitcoin_pqc_sign(
        BITCOIN_PQC_SLH_DSA_SHA2_128S,
        slh_keypair.secret_key, slh_keypair.secret_key_size,
        message, message_len,
        &slh_sig
    );

    if (err != BITCOIN_PQC_OK) {
        fprintf(stderr, "SLH-DSA signing failed: %d\n", err);
        bitcoin_pqc_keypair_free(&slh_keypair);
        return 1;
    }

    printf("Signature size: %zu bytes\n", slh_sig.signature_size);

    /* Verify the SLH-DSA signature */
    err = bitcoin_pqc_verify(
        BITCOIN_PQC_SLH_DSA_SHA2_128S,
        slh_keypair.public_key, slh_keypair.public_key_size,
        message, message_len,
        slh_sig.signature, slh_sig.signature_size
    );

    printf("Verification: %s\n", err == BITCOIN_PQC_OK ? "PASS" : "FAIL");

    bitcoin_pqc_signature_free(&slh_sig);
    bitcoin_pqc_keypair_free(&slh_keypair);

    return (err != BITCOIN_PQC_OK);
}
