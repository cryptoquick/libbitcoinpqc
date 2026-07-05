#include <pthread.h>
#include <string.h>

#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_extrakeys.h>

#include "secp256k1_schnorr.h"

#define SECP256K1_SECRET_KEY_SIZE 32
#define SECP256K1_PUBLIC_KEY_SIZE 32
#define SECP256K1_SIGNATURE_SIZE 64

static secp256k1_context *secp256k1_ctx = NULL;
static pthread_once_t secp256k1_ctx_once = PTHREAD_ONCE_INIT;

static void secp256k1_ctx_init(void) {
    secp256k1_ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY
    );
}

static int secp256k1_ctx_ensure(void) {
    if (pthread_once(&secp256k1_ctx_once, secp256k1_ctx_init) != 0) {
        return SECP256K1_SCHNORR_ERR_ARG;
    }

    if (secp256k1_ctx == NULL) {
        return SECP256K1_SCHNORR_ERR_ARG;
    }

    return SECP256K1_SCHNORR_OK;
}

int secp256k1_schnorr_keygen(
    uint8_t *pk,
    uint8_t *sk,
    const uint8_t *seed,
    size_t seed_size
) {
    secp256k1_keypair keypair;
    secp256k1_xonly_pubkey xonly_pk;

    if (!pk || !sk || !seed || seed_size < SECP256K1_SECRET_KEY_SIZE) {
        return SECP256K1_SCHNORR_ERR_ARG;
    }

    if (secp256k1_ctx_ensure() != SECP256K1_SCHNORR_OK) {
        return SECP256K1_SCHNORR_ERR_ARG;
    }

    memcpy(sk, seed, SECP256K1_SECRET_KEY_SIZE);

    if (!secp256k1_ec_seckey_verify(secp256k1_ctx, sk)) {
        return SECP256K1_SCHNORR_ERR_KEY;
    }

    if (!secp256k1_keypair_create(secp256k1_ctx, &keypair, sk)) {
        return SECP256K1_SCHNORR_ERR_KEY;
    }

    if (!secp256k1_keypair_xonly_pub(
            secp256k1_ctx,
            &xonly_pk,
            NULL,
            &keypair)) {
        return SECP256K1_SCHNORR_ERR_KEY;
    }

    if (!secp256k1_xonly_pubkey_serialize(secp256k1_ctx, pk, &xonly_pk)) {
        return SECP256K1_SCHNORR_ERR_KEY;
    }

    return SECP256K1_SCHNORR_OK;
}

int secp256k1_schnorr_sign(
    uint8_t *sig,
    size_t *sig_len,
    const uint8_t *sk,
    const uint8_t *msg,
    size_t msg_size
) {
    secp256k1_keypair keypair;
    uint8_t msg32[SECP256K1_SECRET_KEY_SIZE];

    if (!sig || !sig_len || !sk || !msg || msg_size < SECP256K1_SECRET_KEY_SIZE) {
        return SECP256K1_SCHNORR_ERR_ARG;
    }

    if (secp256k1_ctx_ensure() != SECP256K1_SCHNORR_OK) {
        return SECP256K1_SCHNORR_ERR_ARG;
    }

    memcpy(msg32, msg, SECP256K1_SECRET_KEY_SIZE);

    if (!secp256k1_ec_seckey_verify(secp256k1_ctx, sk)) {
        return SECP256K1_SCHNORR_ERR_KEY;
    }

    if (!secp256k1_keypair_create(secp256k1_ctx, &keypair, sk)) {
        return SECP256K1_SCHNORR_ERR_KEY;
    }

    if (!secp256k1_schnorrsig_sign32(secp256k1_ctx, sig, msg32, &keypair, NULL)) {
        return SECP256K1_SCHNORR_ERR_SIG;
    }

    *sig_len = SECP256K1_SIGNATURE_SIZE;
    return SECP256K1_SCHNORR_OK;
}

int secp256k1_schnorr_verify(
    const uint8_t *sig,
    size_t sig_len,
    const uint8_t *msg,
    size_t msg_size,
    const uint8_t *pk
) {
    secp256k1_xonly_pubkey xonly_pk;

    if (!sig || !msg || !pk) {
        return SECP256K1_SCHNORR_ERR_ARG;
    }

    if (sig_len != SECP256K1_SIGNATURE_SIZE ||
        msg_size < SECP256K1_SECRET_KEY_SIZE) {
        return SECP256K1_SCHNORR_ERR_ARG;
    }

    if (secp256k1_ctx_ensure() != SECP256K1_SCHNORR_OK) {
        return SECP256K1_SCHNORR_ERR_ARG;
    }

    if (!secp256k1_xonly_pubkey_parse(secp256k1_ctx, &xonly_pk, pk)) {
        return SECP256K1_SCHNORR_ERR_KEY;
    }

    if (secp256k1_schnorrsig_verify(
            secp256k1_ctx,
            sig,
            msg,
            SECP256K1_SECRET_KEY_SIZE,
            &xonly_pk)) {
        return SECP256K1_SCHNORR_OK;
    }

    return SECP256K1_SCHNORR_ERR_SIG;
}