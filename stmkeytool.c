/*
 * stkeytool — CLI для STM32-клона YubiKey 4 (MAC-SHA1 challenge-response,
 * сумісний із KeePassXC). Працює через 8-байтові feature-звіти HID:
 * статус — GET_REPORT, команди — кадрами 67 байт із CRC16 (протокол ykcore).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>

#include <libusb-1.0/libusb.h>

#include "crc16.c"
#include "hmac_sha1.c"

#define VID 0x1050   /* Yubico */
#define PID 0x0401   /* YubiKey 4 (OTP/CCID-варіант із challenge-response) */

/* Розміри протоколу: feature-звіт HID — 8 байт, кадр — 64 payload + cmd + crc16 */
#define FEATURE_RPT_SIZE 8
#define FRAME_PAYLOAD 64
#define FRAME_SIZE 67

/* Прапорці статусного байту та сигнали протоколу */
#define SLOT_WRITE_FLAG 0x80
#define RESP_PENDING_FLAG 0x40
#define DUMMY_REPORT_WRITE 0x8f
#define YK_CRC_OK_RESIDUAL 0xf0b8 /* залишкове значення CRC16 «усе правильно» */
#define WAIT_FOR_WRITE_FLAG 1150   /* загальний ліміт очікування, мс */

/* Команди-ідентифікатори слотів (запис/читання конфігурації) */
#define SLOT_CONFIG 0x01
#define SLOT_CONFIG2 0x03
#define SLOT_DEVICE_SERIAL 0x10
#define SLOT_CHAL_HMAC1 0x30
#define SLOT_CHAL_HMAC2 0x38

/* Прапорці конфігурації слота: challenge-response HMAC-SHA1 */
#define TKTFLAG_CHAL_RESP 0x40
#define CFGFLAG_CHAL_HMAC 0x22

/* Розмітка записуваної конфігурації слота */
#define CFG_CRC_OFFSET 50 /* CRC16 рахується для перших 50 байтів */
#define CONFIG_SIZE 52
#define ACC_CODE_SIZE 6 /* повний блок запису = 52 + 6 = 58 байтів */

/* Глобальний дескриптор відкритого пристрою (єдиний на весь процес). */
static libusb_device_handle *devh;

/* Друкує помилку у stderr і завершує процес із кодом 1. */
static void die(const char *msg)
{
    fprintf(stderr, "error: %s\n", msg);
    exit(1);
}

/* Зчитує feature-звіт; повертає 1 лише якщо прочитано рівно 8 байтів. */
static int usb_read(uint8_t data[FEATURE_RPT_SIZE])
{
    int n = libusb_control_transfer(
        devh,
        LIBUSB_REQUEST_TYPE_CLASS | LIBUSB_RECIPIENT_INTERFACE | LIBUSB_ENDPOINT_IN,
        0x01,             /* GET_REPORT */
        0x0300,           /* тип: feature, report id 0 */
        0,
        data,
        FEATURE_RPT_SIZE,
        1000);

    return n == FEATURE_RPT_SIZE;
}

/* Записує feature-звіт; повертає 1 лише якщо передано рівно 8 байтів. */
static int usb_write(const uint8_t data[FEATURE_RPT_SIZE])
{
    int n = libusb_control_transfer(
        devh,
        LIBUSB_REQUEST_TYPE_CLASS | LIBUSB_RECIPIENT_INTERFACE | LIBUSB_ENDPOINT_OUT,
        0x09,             /* SET_REPORT */
        0x0300,
        0,
        (unsigned char *)data,
        FEATURE_RPT_SIZE,
        1000);

    return n == FEATURE_RPT_SIZE;
}

/*
 * «Порожній» запис із кодом 0x8f: змушує пристрій скинути поточний стан
 * і припинити очікування відповіді, якщо обмін зірвався (аналог ykcore).
 */
static int force_key_update(void)
{
    uint8_t data[FEATURE_RPT_SIZE];

    memset(data, 0, sizeof(data));
    data[FEATURE_RPT_SIZE - 1] = DUMMY_REPORT_WRITE;
    return usb_write(data);
}

/*
 * Чекає, поки пристрій очистить SLOT_WRITE_FLAG у статусному байті.
 * Затримка експоненційна (1, 2, 4, ... 500 мс), загальний ліміт 1150 мс.
 */
static int wait_write_clear(void)
{
    unsigned slept = 0;
    unsigned sleepval = 1;
    uint8_t data[FEATURE_RPT_SIZE];

    while (slept < WAIT_FOR_WRITE_FLAG) {
        usleep(sleepval * 1000);
        slept += sleepval;
        sleepval *= 2;
        if (sleepval > 500) {
            sleepval = 500;
        }

        if (!usb_read(data)) {
            return 0;
        }
        if (!(data[FEATURE_RPT_SIZE - 1] & SLOT_WRITE_FLAG)) {
            return 1;
        }
    }

    return 0;
}

/*
 * Зчитує статус пристрою: версія firmware (3 байти, offset 1),
 * pgmSeq (байт 4), touchLevel (little-endian uint16 у байтах 5-6).
 * Будь-який аргумент може бути NULL, якщо поле не потрібне.
 */
static int get_status(uint8_t *version, uint8_t *pgm_seq, uint16_t *touch)
{
    uint8_t data[FEATURE_RPT_SIZE];

    if (!usb_read(data)) {
        return 0;
    }
    if (version) {
        memcpy(version, data + 1, 3);
    }
    if (pgm_seq) {
        *pgm_seq = data[4];
    }
    if (touch) {
        *touch = (uint16_t)data[5] | ((uint16_t)data[6] << 8); /* little-endian */
    }
    return 1;
}

/*
 * Посилає кадр 67 байт { payload[64], cmd, crc[2] } по 7-байтових шматках,
 * data[7] = 0x80 | seq. Проміжні шматки, що складаються лише з нулів,
 * пропускаються (як у ykcore), останній шматок завжди надсилається.
 * Перед кожним записом чекаємо зняття SLOT_WRITE_FLAG.
 */
static int write_to_key(uint8_t cmd, const uint8_t *buf, int len)
{
    uint8_t frame[FRAME_SIZE + 3];
    uint8_t repbuf[FEATURE_RPT_SIZE];
    uint16_t crc;
    int seq, off;

    if (len > FRAME_PAYLOAD) {
        return 0;
    }

    memset(frame, 0, sizeof(frame));
    if (len > 0) {
        memcpy(frame, buf, len);
    }
    frame[64] = cmd;
    crc = yk_crc16(frame, FRAME_PAYLOAD);
    frame[65] = (uint8_t)(crc & 0xff);
    frame[66] = (uint8_t)(crc >> 8);

    for (seq = 0, off = 0; off < FRAME_SIZE; seq++, off += 7) {
        int all_zeros = 1;
        int i;

        memset(repbuf, 0, sizeof(repbuf));
        for (i = 0; i < 7; i++) {
            if (off + i < FRAME_SIZE) {
                repbuf[i] = frame[off + i];
            }
            if (repbuf[i]) {
                all_zeros = 0;
            }
        }

        /* пропускаємо нульові проміжні шматки, але останній — завжди */
        if (all_zeros && seq > 0 && off + 7 < FRAME_SIZE) {
            continue;
        }

        repbuf[7] = (uint8_t)(seq | SLOT_WRITE_FLAG); /* seq | 0x80 */

        if (!wait_write_clear()) {
            return 0;
        }
        if (!usb_write(repbuf)) {
            return 0;
        }
    }

    return 1;
}

/*
 * Порт yk_read_response_from_key(): збирає розбиту відповідь пристрою
 * у буфер `out`; `expect` — очікувана довжина корисного навантаження в байтах
 * (0 = не перевіряти). Коректність підтверджується CRC16 (залишок 0xf0b8).
 */
static int read_response(uint8_t *out, unsigned bufsize, unsigned expect)
{
    uint8_t data[FEATURE_RPT_SIZE];
    unsigned bytes_read = 0;
    unsigned slept = 0;
    unsigned sleepval = 1;

    memset(out, 0, bufsize);

    /* чекаємо RESP_PENDING_FLAG; перший шматок приходить разом із ним */
    for (;;) {
        if (slept >= 1000) {
            force_key_update();
            fprintf(stderr, "error: timeout waiting for response\n");
            return 0;
        }
        usleep(sleepval * 1000);
        slept += sleepval;
        sleepval *= 2;
        if (sleepval > 500) {
            sleepval = 500;
        }

        if (!usb_read(data)) {
            force_key_update();
            return 0;
        }
        if (data[FEATURE_RPT_SIZE - 1] & RESP_PENDING_FLAG) {
            memcpy(out, data, 7);
            bytes_read = 7;
            break;
        }
    }

    while (bytes_read + FEATURE_RPT_SIZE <= bufsize) {
        if (!usb_read(data)) {
            force_key_update();
            return 0;
        }

        if (!(data[FEATURE_RPT_SIZE - 1] & RESP_PENDING_FLAG)) {
            force_key_update();
            fprintf(stderr, "error: response aborted by device\n");
            return 0;
        }

        if ((data[FEATURE_RPT_SIZE - 1] & 31) == 0) {
            /* сигнальний байт: seq скинуто в 0 — відповідь повна */
            if (expect > 0) {
                unsigned e = expect + 2; /* +2 байти CRC16 */

                if (yk_crc16(out, e) != YK_CRC_OK_RESIDUAL) {
                    force_key_update();
                    fprintf(stderr, "error: response CRC mismatch\n");
                    return 0;
                }
                if (e % 7 != 0) {
                    e += 7 - (e % 7); /* округлення вгору до цілих шматків */
                }
                if (bytes_read != e) {
                    force_key_update();
                    fprintf(stderr, "error: response size %u, expected %u\n",
                            bytes_read, e);
                    return 0;
                }
            }
            force_key_update();
            return 1;
        }

        memcpy(out + bytes_read, data, 7);
        bytes_read += 7;
    }

    force_key_update();
    fprintf(stderr, "error: response buffer too small\n");
    return 0;
}

/* Значення однієї hex-символи; -1, якщо символ не hex. */
static int hexval(int c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

/*
 * Розбирає hex-рядок у байти; повертає кількість байтів або -1
 * (непарна довжина, забагато байтів для `max` або не hex).
 */
static int hex_decode(const char *hex, uint8_t *out, int max)
{
    int len = (int)strlen(hex);

    if (len % 2 != 0 || len / 2 > max) {
        return -1;
    }
    for (int i = 0; i < len / 2; i++) {
        int hi = hexval((unsigned char)hex[i * 2]);
        int lo = hexval((unsigned char)hex[i * 2 + 1]);

        if (hi < 0 || lo < 0) {
            return -1;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return len / 2;
}

/* Друкує байти як hex без пробілів, у кінці — перехід рядка. */
static void print_hex(const uint8_t *buf, int len)
{
    for (int i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

/*
 * Готує 64-байтовий payload для challenge: hex-рядок (1..64 байти) або "-",
 * тоді до 64 сирих байтів із stdin. Коротший за 64 байти доповнюється
 * «по-PKCS7»: байти [n..63] заповнюються значенням 64-n. Саме доповнений
 * 64-байтовий блок потрапляє в HMAC — padding і HMAC мають лишатися в унісоні.
 */
static int load_challenge(const char *arg, uint8_t payload[64])
{
    if (strcmp(arg, "-") == 0) {
        int n = (int)fread(payload, 1, 64, stdin);

        if (n <= 0) {
            return -1;
        }
        if (n < 64) {
            memset(payload + n, 64 - n, 64 - n);
        }
        return 0;
    }

    uint8_t raw[64];
    int n = hex_decode(arg, raw, 64);

    if (n <= 0 || n > 64) {
        return -1;
    }
    memcpy(payload, raw, n);
    if (n < 64) {
        memset(payload + n, 64 - n, 64 - n);
    }
    return 0;
}

/*
 * Друкує стан пристрою. Біти 0/1 touchLevel тлумачаться як
 * «слот 1 / слот 2 налаштовано» — саме так це виводить офіційний ykinfo.
 */
static int cmd_status(void)
{
    uint8_t version[3];
    uint8_t pgm_seq;
    uint16_t touch;

    if (!get_status(version, &pgm_seq, &touch)) {
        die("GET_REPORT failed");
    }

    printf("version    %u.%u.%u\n", version[0], version[1], version[2]);
    printf("pgmSeq     %u\n", pgm_seq);
    printf("touchLevel 0x%04x\n", touch);
    printf("slot1      %s\n", (touch & 0x01) ? "valid" : "not configured");
    printf("slot2      %s\n", (touch & 0x02) ? "valid" : "not configured");
    return 0;
}

/* Запитує серійний номер (4 байти, big-endian) і друкує його десятково. */
static int cmd_serial(void)
{
    uint8_t out[64];

    if (!write_to_key(SLOT_DEVICE_SERIAL, NULL, 0)) {
        die("write failed");
    }
    if (!read_response(out, sizeof(out), 4)) {
        die("no response");
    }

    printf("serial     %u\n",
           ((uint32_t)out[0] << 24) | ((uint32_t)out[1] << 16) |
           ((uint32_t)out[2] << 8) | (uint32_t)out[3]);
    return 0;
}

/*
 * Надсилає 64-байтовий payload у слот (1 чи 2) і друкує HMAC-SHA1-відповідь
 * (20 байт). Якщо передано ключ — рахує HMAC локально, порівнює з відповіддю
 * пристрою; повертає 1 при розбіжності.
 */
static int do_challenge(int slot, uint8_t payload[64], const uint8_t *key)
{
    uint8_t cmd = (slot == 1) ? SLOT_CHAL_HMAC1 : SLOT_CHAL_HMAC2;
    uint8_t out[64];

    if (!write_to_key(cmd, payload, 64)) {
        die("write failed");
    }
    if (!read_response(out, sizeof(out), 20)) {
        die("no response");
    }

    printf("response   ");
    print_hex(out, 20);

    if (key) {
        uint8_t expected[20];

        hmac_sha1(key, 20, payload, 64, expected);
        if (memcmp(expected, out, 20) == 0) {
            printf("local hmac MATCH\n");
        } else {
            printf("local hmac MISMATCH\n");
            return 1;
        }
    }
    return 0;
}

/* Команда chal: готує payload (див. load_challenge), валідує ключ (40 hex). */
static int cmd_chal(int slot, const char *challenge_hex, const char *key_hex)
{
    uint8_t payload[64];
    uint8_t key[20];

    if (load_challenge(challenge_hex, payload) < 0) {
        die("bad challenge (hex, max 64 bytes, or '-' for stdin)");
    }

    const uint8_t *keyp = NULL;

    if (key_hex) {
        if (hex_decode(key_hex, key, 20) != 20) {
            die("key must be 40 hex chars (20 bytes)");
        }
        keyp = key;
    }

    return do_challenge(slot, payload, keyp);
}

/* Швидка перевірка слота випадковим 1-байтовим challenge, без локального HMAC. */
static int cmd_test(int slot)
{
    uint8_t payload[64];
    uint8_t rnd;

    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0 || read(fd, &rnd, 1) != 1) {
        die("cannot read /dev/urandom");
    }
    close(fd);

    /* та сама форма, що й performTestChallenge у KeePassXC: 1 байт + доповнення PKCS7 */
    payload[0] = rnd;
    memset(payload + 1, 63, 63);

    printf("challenge  %02x\n", rnd);
    return do_challenge(slot, payload, NULL);
}

/*
 * Програмує слот під HMAC-SHA1 challenge-response заданим ключем.
 * Записується повна конфігурація слота (58 байт) — усе, що там було,
 * перезаписується. Успіх фіксується ЛИШЕ за зміною pgmSeq: слот із access
 * code відхиляє запис «мовчки», тому цю перевірку прибирати не можна.
 */
static int cmd_program(int slot, const char *key_hex)
{
    uint8_t cfg[CONFIG_SIZE + ACC_CODE_SIZE];
    uint8_t key[20];
    uint8_t pgm_before, pgm_after;
    uint16_t crc;

    if (hex_decode(key_hex, key, 20) != 20) {
        die("key must be 40 hex chars (20 bytes)");
    }

    if (!get_status(NULL, &pgm_before, NULL)) {
        die("GET_REPORT failed");
    }

    memset(cfg, 0, sizeof(cfg));
    memcpy(cfg + 16, key + 16, 4);   /* uid[0..3] = останні 4 байти ключа */
    memcpy(cfg + 22, key, 16);       /* key[0..15] (перші 16 байтів ключа) */
    cfg[46] = TKTFLAG_CHAL_RESP;     /* tktFlags */
    cfg[47] = CFGFLAG_CHAL_HMAC;     /* cfgFlags */
    crc = (uint16_t)(~yk_crc16(cfg, CFG_CRC_OFFSET)); /* CRC16 з інверсією */
    cfg[50] = (uint8_t)(crc & 0xff);
    cfg[51] = (uint8_t)(crc >> 8);   /* little-endian у байтах 50-51 */

    if (!write_to_key(slot == 1 ? SLOT_CONFIG : SLOT_CONFIG2,
                      cfg, sizeof(cfg))) {
        die("config write failed");
    }
    if (!wait_write_clear()) {
        die("device did not finish programming");
    }
    if (!get_status(NULL, &pgm_after, NULL)) {
        die("GET_REPORT failed");
    }

    if (pgm_after == pgm_before) {
        /* пристрій відхилив запис (access code / захист слота) */
        fprintf(stderr, "error: pgmSeq unchanged (%u), write rejected\n",
                pgm_after);
        return 1;
    }

    printf("programmed slot %u, pgmSeq %u -> %u\n",
           slot, pgm_before, pgm_after);
    return 0;
}

/* Генерує 20 випадкових байтів із /dev/urandom, друкує 40 hex-символів. */
static int cmd_keygen(void)
{
    uint8_t key[20];
    int fd = open("/dev/urandom", O_RDONLY);

    if (fd < 0 || read(fd, key, sizeof(key)) != (ssize_t)sizeof(key)) {
        die("cannot read /dev/urandom");
    }
    close(fd);

    print_hex(key, 20);
    return 0;
}

/* Підказка із використанням; код виходу 2 = помилка аргументів. */
static void usage(void)
{
    fprintf(stderr,
	"===================================================================\n"
	"=   stm32 yubikey clone programming tool (shaman7036@gmail.com)   =\n"
	"===================================================================\n\n\n"
        "usage: stkeytool status\n"
        "       stkeytool serial\n"
        "       stkeytool chal <1|2> <hex|-> [40-hex-key]\n"
        "       stkeytool test <1|2>\n"
        "       stkeytool program <1|2> <40-hex-key>\n"
        "       stkeytool keygen\n\n\n\n");
    exit(2);
}

/*
 * Точка входу: відкриває пристрій 1050:0401, знімає kernel-драйвер
 * з інтерфейсу 0, диспетчеризує команду. Без пристрою жодна команда
 * не працює — відкриття стоїть ДО розбору аргументів (окрім usage).
 */
int main(int argc, char **argv)
{
    libusb_context *ctx = NULL;
    int rc;

    if (argc < 2) {
        usage();
    }

    if (libusb_init(&ctx) != 0) {
        die("libusb_init failed");
    }

    devh = libusb_open_device_with_vid_pid(ctx, VID, PID);
    if (!devh) {
        die("device 1050:0401 not found (is it plugged in? check udev rule)");
    }

    if (libusb_kernel_driver_active(devh, 0) == 1) {
        libusb_detach_kernel_driver(devh, 0);
    }
    rc = libusb_claim_interface(devh, 0);
    if (rc != 0) {
        fprintf(stderr, "error: cannot claim interface 0: %s\n",
                libusb_error_name(rc));
        return 1;
    }

    int ret;

    /* розбір аргументів: команда + слот <1|2>; невідома команда → usage (exit 2) */
    if (strcmp(argv[1], "status") == 0) {
        ret = cmd_status();
    } else if (strcmp(argv[1], "serial") == 0) {
        ret = cmd_serial();
    } else if (strcmp(argv[1], "chal") == 0 && argc >= 4) {
        if (argv[2][0] != '1' && argv[2][0] != '2') {
            usage();
        }
        ret = cmd_chal(argv[2][0] - '0', argv[3],
                       argc > 4 ? argv[4] : NULL);
    } else if (strcmp(argv[1], "test") == 0 && argc == 3) {
        if (argv[2][0] != '1' && argv[2][0] != '2') {
            usage();
        }
        ret = cmd_test(argv[2][0] - '0');
    } else if (strcmp(argv[1], "program") == 0 && argc == 4) {
        if (argv[2][0] != '1' && argv[2][0] != '2') {
            usage();
        }
        ret = cmd_program(argv[2][0] - '0', argv[3]);
    } else if (strcmp(argv[1], "keygen") == 0) {
        ret = cmd_keygen();
    } else {
        usage();
    }

    libusb_release_interface(devh, 0);
    libusb_close(devh);
    libusb_exit(ctx);
    return ret;
}
