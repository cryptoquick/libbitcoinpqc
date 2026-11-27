#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/*
 * FIPS 205 pure mode with an empty context is the two-byte prefix
 * 0x00 || 0x00 in front of the message. The reference sign and verify
 * functions stay the internal interface and must see that prefix once.
 * Length 0 is legal. Allocation failure returns -1 and leaves nothing
 * allocated.
 */
int slh_dsa_external_message(
    uint8_t **out,
    size_t *out_len,
    const uint8_t *m,
    size_t mlen
) {
    uint8_t *buf;

    if (!out || !out_len) {
        return -1;
    }
    *out = NULL;
    *out_len = 0;

    if (mlen > SIZE_MAX - 2) {
        return -1;
    }
    if (mlen > 0 && !m) {
        return -1;
    }

    buf = malloc(mlen + 2);
    if (!buf) {
        return -1;
    }

    buf[0] = 0x00;
    buf[1] = 0x00;
    if (mlen > 0) {
        memcpy(buf + 2, m, mlen);
    }

    *out = buf;
    *out_len = mlen + 2;
    return 0;
}
