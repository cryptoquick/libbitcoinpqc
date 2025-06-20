#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "libbitcoinpqc/bitcoinpqc.h"
#include "libbitcoinpqc/ml_dsa.h"
#include "libbitcoinpqc/slh_dsa.h"

// Debug mode flag - set to 0 to disable debug output
#define BITCOIN_PQC_DEBUG 0

// Conditional debug print macro
#define DEBUG_PRINT(fmt, ...) \
    do { if (BITCOIN_PQC_DEBUG) printf(fmt, ##__VA_ARGS__); } while (0)

size_t bitcoin_pqc_public_key_size(bitcoin_pqc_algorithm_t algorithm) {
    switch (algorithm) {
        case BITCOIN_PQC_SECP256K1_SCHNORR:
            return 32; // X-only public key size for secp256k1
        case BITCOIN_PQC_ML_DSA_44:
            return ML_DSA_44_PUBLIC_KEY_SIZE;
        case BITCOIN_PQC_SLH_DSA_SHAKE_128S:
            return SLH_DSA_SHAKE_128S_PUBLIC_KEY_SIZE;
        default:
            return 0;
    }
}

size_t bitcoin_pqc_secret_key_size(bitcoin_pqc_algorithm_t algorithm) {
    switch (algorithm) {
        case BITCOIN_PQC_SECP256K1_SCHNORR:
            return 32; // Private key size for secp256k1
        case BITCOIN_PQC_ML_DSA_44:
            return ML_DSA_44_SECRET_KEY_SIZE;
        case BITCOIN_PQC_SLH_DSA_SHAKE_128S:
            return SLH_DSA_SHAKE_128S_SECRET_KEY_SIZE;
        default:
            return 0;
    }
}

size_t bitcoin_pqc_signature_size(bitcoin_pqc_algorithm_t algorithm) {
    switch (algorithm) {
        case BITCOIN_PQC_SECP256K1_SCHNORR:
            return 64; // Schnorr signature size for secp256k1
        case BITCOIN_PQC_ML_DSA_44:
            return ML_DSA_44_SIGNATURE_SIZE;
        case BITCOIN_PQC_SLH_DSA_SHAKE_128S:
            return SLH_DSA_SHAKE_128S_SIGNATURE_SIZE;
        default:
            return 0;
    }
}

bitcoin_pqc_error_t bitcoin_pqc_keygen(
    bitcoin_pqc_algorithm_t algorithm,
    bitcoin_pqc_keypair_t *keypair,
    const uint8_t *random_data,
    size_t random_data_size
) {
    if (!keypair || !random_data) {
        return BITCOIN_PQC_ERROR_BAD_ARG;
    }

    if (random_data_size < 128) {
        return BITCOIN_PQC_ERROR_BAD_ARG;
    }

    // Get key sizes
    size_t pk_size = bitcoin_pqc_public_key_size(algorithm);
    size_t sk_size = bitcoin_pqc_secret_key_size(algorithm);

    if (pk_size == 0 || sk_size == 0) {
        return BITCOIN_PQC_ERROR_BAD_ARG;
    }

    // Allocate memory for keys
    uint8_t *pk = malloc(pk_size);
    uint8_t *sk = malloc(sk_size);

    if (!pk || !sk) {
        free(pk);
        free(sk);
        return BITCOIN_PQC_ERROR_BAD_ARG;
    }

    int result;
    switch (algorithm) {
        case BITCOIN_PQC_SECP256K1_SCHNORR:
            // Placeholder for BIP-340 Schnorr key generation
            // In a real implementation, this would call secp256k1 functions
            result = -1; // Not implemented yet
            break;
        case BITCOIN_PQC_ML_DSA_44:
            result = ml_dsa_44_keygen(pk, sk, random_data, random_data_size);
            break;
        case BITCOIN_PQC_SLH_DSA_SHAKE_128S:
            result = slh_dsa_shake_128s_keygen(pk, sk, random_data, random_data_size);
            break;
        default:
            free(pk);
            free(sk);
            return BITCOIN_PQC_ERROR_NOT_IMPLEMENTED;
    }

    if (result != 0) {
        free(pk);
        free(sk);
        return BITCOIN_PQC_ERROR_BAD_KEY;
    }

    // Initialize the keypair structure
    keypair->algorithm = algorithm;
    keypair->public_key = pk;
    keypair->secret_key = sk;
    keypair->public_key_size = pk_size;
    keypair->secret_key_size = sk_size;

    return BITCOIN_PQC_OK;
}

void bitcoin_pqc_keypair_free(bitcoin_pqc_keypair_t *keypair) {
    if (keypair) {
        if (keypair->public_key) {
            // Clear public key memory before freeing
            memset(keypair->public_key, 0, keypair->public_key_size);
            free(keypair->public_key);
            keypair->public_key = NULL;
        }

        if (keypair->secret_key) {
            // Clear secret key memory before freeing
            memset(keypair->secret_key, 0, keypair->secret_key_size);
            free(keypair->secret_key);
            keypair->secret_key = NULL;
        }

        // Reset structure fields
        keypair->public_key_size = 0;
        keypair->secret_key_size = 0;
        keypair->algorithm = 0;
    }
}

bitcoin_pqc_error_t bitcoin_pqc_sign(
    bitcoin_pqc_algorithm_t algorithm,
    const uint8_t *secret_key,
    size_t secret_key_size,
    const uint8_t *message,
    size_t message_size,
    bitcoin_pqc_signature_t *signature
) {
    if (!secret_key || !message || !signature) {
        return BITCOIN_PQC_ERROR_BAD_ARG;
    }

    DEBUG_PRINT("bitcoin_pqc_sign: algorithm=%d, message_size=%zu, secret_key_size=%zu\n",
           algorithm, message_size, secret_key_size);

    // Check if secret key size matches the expected size for the algorithm
    if (secret_key_size != bitcoin_pqc_secret_key_size(algorithm)) {
        DEBUG_PRINT("bitcoin_pqc_sign: Bad key size. Expected %zu, got %zu\n",
               bitcoin_pqc_secret_key_size(algorithm), secret_key_size);
        return BITCOIN_PQC_ERROR_BAD_KEY;
    }

    // Get signature size for buffer allocation
    size_t sig_size = bitcoin_pqc_signature_size(algorithm);
    if (sig_size == 0) {
        DEBUG_PRINT("bitcoin_pqc_sign: Bad algorithm or signature size. Size=%zu\n", sig_size);
        return BITCOIN_PQC_ERROR_BAD_ARG;
    }

    // Allocate signature buffer
    uint8_t *sig = malloc(sig_size);
    if (!sig) {
        DEBUG_PRINT("bitcoin_pqc_sign: Memory allocation failed\n");
        return BITCOIN_PQC_ERROR_BAD_ARG;
    }

    size_t actual_sig_len;
    int result;

    switch (algorithm) {
        case BITCOIN_PQC_SECP256K1_SCHNORR:
            // Placeholder for BIP-340 Schnorr signing
            // In a real implementation, this would call secp256k1 functions
            DEBUG_PRINT("bitcoin_pqc_sign: Schnorr signing not implemented yet\n");
            result = -1; // Not implemented yet
            break;
        case BITCOIN_PQC_ML_DSA_44:
            DEBUG_PRINT("bitcoin_pqc_sign: Calling ml_dsa_44_sign\n");
            result = ml_dsa_44_sign(sig, &actual_sig_len, message, message_size,
                                  secret_key);
            break;
        case BITCOIN_PQC_SLH_DSA_SHAKE_128S:
            DEBUG_PRINT("bitcoin_pqc_sign: Calling slh_dsa_shake_128s_sign\n");
            result = slh_dsa_shake_128s_sign(sig, &actual_sig_len, message, message_size,
                                           secret_key);
            break;
        default:
            free(sig);
            DEBUG_PRINT("bitcoin_pqc_sign: Unsupported algorithm %d\n", algorithm);
            return BITCOIN_PQC_ERROR_NOT_IMPLEMENTED;
    }

    DEBUG_PRINT("bitcoin_pqc_sign: Algorithm-specific sign function returned %d, actual_sig_len=%zu\n",
           result, actual_sig_len);

    if (result != 0) {
        free(sig);
        return BITCOIN_PQC_ERROR_BAD_SIGNATURE;
    }

    // Initialize the signature structure
    signature->algorithm = algorithm;
    signature->signature = sig;
    signature->signature_size = actual_sig_len;

    DEBUG_PRINT("bitcoin_pqc_sign: Signature created successfully, size=%zu\n", signature->signature_size);

    return BITCOIN_PQC_OK;
}

void bitcoin_pqc_signature_free(bitcoin_pqc_signature_t *signature) {
    if (signature) {
        if (signature->signature) {
            // Clear signature memory before freeing
            memset(signature->signature, 0, signature->signature_size);
            free(signature->signature);
            signature->signature = NULL;
        }

        // Reset structure fields
        signature->signature_size = 0;
        signature->algorithm = 0;
    }
}

bitcoin_pqc_error_t bitcoin_pqc_verify(
    bitcoin_pqc_algorithm_t algorithm,
    const uint8_t *public_key,
    size_t public_key_size,
    const uint8_t *message,
    size_t message_size,
    const uint8_t *signature,
    size_t signature_size
) {
    if (!public_key || !message || !signature) {
        DEBUG_PRINT("bitcoin_pqc_verify: Invalid arguments\n");
        return BITCOIN_PQC_ERROR_BAD_ARG;
    }

    DEBUG_PRINT("bitcoin_pqc_verify: algorithm=%d, message_size=%zu, public_key_size=%zu, signature_size=%zu\n",
           algorithm, message_size, public_key_size, signature_size);

    // Check if key size matches the expected size for the algorithm
    if (public_key_size != bitcoin_pqc_public_key_size(algorithm)) {
        DEBUG_PRINT("bitcoin_pqc_verify: Bad public key size. Expected %zu, got %zu\n",
               bitcoin_pqc_public_key_size(algorithm), public_key_size);
        return BITCOIN_PQC_ERROR_BAD_KEY;
    }

    // Get expected signature size
    size_t expected_sig_size = bitcoin_pqc_signature_size(algorithm);
    if (signature_size != expected_sig_size) {
      DEBUG_PRINT("bitcoin_pqc_verify: Bad signature size. Expected %zu, got %zu\n",
                  expected_sig_size, signature_size);
      return BITCOIN_PQC_ERROR_BAD_SIGNATURE;
    }

    int result;
    switch (algorithm) {
        case BITCOIN_PQC_SECP256K1_SCHNORR:
            // Placeholder for BIP-340 Schnorr verification
            // In a real implementation, this would call secp256k1 functions
            DEBUG_PRINT("bitcoin_pqc_verify: Schnorr verification not implemented yet\n");
            result = -1; // Not implemented yet
            break;
        case BITCOIN_PQC_ML_DSA_44:
            DEBUG_PRINT("bitcoin_pqc_verify: Calling ml_dsa_44_verify\n");
            result = ml_dsa_44_verify(signature, signature_size, message, message_size, public_key);
            break;
        case BITCOIN_PQC_SLH_DSA_SHAKE_128S:
            DEBUG_PRINT("bitcoin_pqc_verify: Calling slh_dsa_shake_128s_verify\n");
            result = slh_dsa_shake_128s_verify(signature, signature_size, message, message_size, public_key);
            break;
        default:
            DEBUG_PRINT("bitcoin_pqc_verify: Unsupported algorithm %d\n", algorithm);
            return BITCOIN_PQC_ERROR_NOT_IMPLEMENTED;
    }

    DEBUG_PRINT("bitcoin_pqc_verify: Algorithm-specific verify function returned %d\n", result);

    if (result != 0) {
        return BITCOIN_PQC_ERROR_BAD_SIGNATURE;
    }

    return BITCOIN_PQC_OK;
}
