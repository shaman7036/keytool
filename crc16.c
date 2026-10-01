#include "crc16.h"

uint16_t yk_crc16(const uint8_t *buf, size_t len)
{
    uint16_t crc = 0xffff;

    while (len--) {
        crc ^= *buf++;
        for (int i = 0; i < 8; i++) {
            uint16_t lsb = crc & 1;
            crc >>= 1;
            if (lsb) {
                crc ^= 0x8408;
            }
        }
    }

    return crc;
}
