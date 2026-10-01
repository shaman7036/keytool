#include "hmac_sha1.h"

#include <string.h>

static uint32_t rol32(uint32_t x, unsigned n)
{
    return (x << n) | (x >> (32 - n));
}

static void sha1_block(uint32_t h[5], const uint8_t block[64])
{
    uint32_t w[80];
    uint32_t a, b, c, d, e, f, k, tmp;
    unsigned i;

    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }
    for (i = 16; i < 80; i++) {
        w[i] = rol32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    a = h[0];
    b = h[1];
    c = h[2];
    d = h[3];
    e = h[4];

    for (i = 0; i < 80; i++) {
        if (i < 20) {
            f = (b & c) | (~b & d);
            k = 0x5a827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ed9eba1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8f1bbcdc;
        } else {
            f = b ^ c ^ d;
            k = 0xca62c1d6;
        }

        tmp = rol32(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rol32(b, 30);
        b = a;
        a = tmp;
    }

    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
}

void sha1(const uint8_t *data, size_t len, uint8_t out[20])
{
    uint32_t h[5] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };
    uint64_t bits = (uint64_t)len * 8;
    uint8_t pad[128];
    size_t pad_len;
    size_t i;

    while (len >= 64) {
        sha1_block(h, data);
        data += 64;
        len -= 64;
    }

    memset(pad, 0, sizeof(pad));
    if (len) {
        memcpy(pad, data, len);
    }
    pad[len] = 0x80;
    pad_len = (len < 56) ? 64 : 128;

    for (i = 0; i < 8; i++) {
        pad[pad_len - 1 - i] = (uint8_t)(bits >> (i * 8));
    }

    sha1_block(h, pad);
    if (pad_len == 128) {
        sha1_block(h, pad + 64);
    }

    for (i = 0; i < 5; i++) {
        out[i * 4] = (uint8_t)(h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)h[i];
    }
}

void hmac_sha1(
    const uint8_t *key, size_t key_len,
    const uint8_t *msg, size_t msg_len,
    uint8_t out[20])
{
    uint8_t k[64];
    uint8_t ipad[64];
    uint8_t opad[64];
    uint8_t inner[20];
    size_t i;

    memset(k, 0, sizeof(k));
    if (key_len > 64) {
        sha1(key, key_len, k);
    } else {
        memcpy(k, key, key_len);
    }

    for (i = 0; i < 64; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }

    /* inner = SHA1(ipad || msg) */
    {
        uint32_t h[5] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };
        uint64_t bits;
        size_t total = 64 + msg_len;
        size_t len = msg_len;
        const uint8_t *p = msg;
        uint8_t tail[128];
        size_t tail_len;

        sha1_block(h, ipad);

        while (len >= 64) {
            sha1_block(h, p);
            p += 64;
            len -= 64;
        }

        memset(tail, 0, sizeof(tail));
        if (len) {
            memcpy(tail, p, len);
        }
        tail[len] = 0x80;
        tail_len = (len < 56) ? 64 : 128;
        bits = (uint64_t)total * 8;
        for (i = 0; i < 8; i++) {
            tail[tail_len - 1 - i] = (uint8_t)(bits >> (i * 8));
        }
        sha1_block(h, tail);
        if (tail_len == 128) {
            sha1_block(h, tail + 64);
        }

        for (i = 0; i < 5; i++) {
            inner[i * 4] = (uint8_t)(h[i] >> 24);
            inner[i * 4 + 1] = (uint8_t)(h[i] >> 16);
            inner[i * 4 + 2] = (uint8_t)(h[i] >> 8);
            inner[i * 4 + 3] = (uint8_t)h[i];
        }
    }

    /* outer = SHA1(opad || inner) */
    {
        uint8_t tmp[84];

        memcpy(tmp, opad, 64);
        memcpy(tmp + 64, inner, 20);
        sha1(tmp, 84, out);
    }
}
