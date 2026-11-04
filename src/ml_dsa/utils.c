#include <stddef.h>
#include <stdint.h>

#include "../../dilithium/ref/api.h"
#include "../../dilithium/ref/fips202.h"
#include "../../dilithium/ref/params.h"
#include "libbitcoinpqc/ml_dsa.h"

void ml_dsa_derandomize(uint8_t *seed, const uint8_t *m, size_t mlen, const uint8_t *sk) {
    keccak_state state;

    shake256_init(&state);
    shake256_absorb(&state, sk, CRYPTO_SECRETKEYBYTES);
    shake256_absorb(&state, m, mlen);
    shake256_finalize(&state);
    shake256_squeeze(seed, 64, &state);
}
