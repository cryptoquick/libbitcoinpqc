#ifndef SECP256K1_SCHNORR_H
#define SECP256K1_SCHNORR_H

#include <stddef.h>
#include <stdint.h>

/**
 * BIP-340 Schnorr helpers backed by libsecp256k1.
 */
#define SECP256K1_SCHNORR_OK       0
#define SECP256K1_SCHNORR_ERR_ARG -1
#define SECP256K1_SCHNORR_ERR_KEY -2
#define SECP256K1_SCHNORR_ERR_SIG -3

int secp256k1_schnorr_keygen(
    uint8_t *pk,
    uint8_t *sk,
    const uint8_t *seed,
    size_t seed_size
);

int secp256k1_schnorr_sign(
    uint8_t *sig,
    size_t *sig_len,
    const uint8_t *sk,
    const uint8_t *msg,
    size_t msg_size
);

int secp256k1_schnorr_verify(
    const uint8_t *sig,
    size_t sig_len,
    const uint8_t *msg,
    size_t msg_size,
    const uint8_t *pk
);

#endif /* SECP256K1_SCHNORR_H */