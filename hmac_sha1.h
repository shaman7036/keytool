#ifndef HMAC_SHA1_H
#define HMAC_SHA1_H

#include <stdint.h>
#include <stddef.h>

void sha1(const uint8_t *data, size_t len, uint8_t out[20]);

void hmac_sha1(
    const uint8_t *key, size_t key_len,
    const uint8_t *msg, size_t msg_len,
    uint8_t out[20]
);

#endif
