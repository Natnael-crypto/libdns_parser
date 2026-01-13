/* dns_tsig - TSIG authentication for DNS messages */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>


#define TSIG_MAX_KEY_LEN 512
#define TSIG_MAX_NAME_LEN 256
#define TSIG_TIME_FUDGE 300
typedef enum { TSIG_ALG_HMAC_MD5, TSIG_ALG_HMAC_SHA1, TSIG_ALG_HMAC_SHA256 } tsig_algorithm_t;
typedef struct {
    char key_name[256];
    tsig_algorithm_t algorithm;
    uint8_t key[512];
    size_t key_len;
    uint64_t last_time;
    uint16_t last_fudge;
} tsig_key_t;
typedef struct { char algorithm_name[64]; size_t mac_len; } tsig_alg_info_t;
static const tsig_alg_info_t tsig_algorithms[] = {
    {"hmac-md5.sig-alg.reg.int.", 16},
    {"hmac-sha1.", 20},
    {"hmac-sha256.", 32},
};
int tsig_key_init(tsig_key_t *k) { memset(k, 0, sizeof(*k)); k->last_fudge = TSIG_TIME_FUDGE; return 0; }
int tsig_key_set(tsig_key_t *k, const char *name, tsig_algorithm_t alg, const uint8_t *secret, size_t slen) {
    strncpy(k->key_name, name, 255);
    k->algorithm = alg;
    if (slen > 512) slen = 512;
    memcpy(k->key, secret, slen); k->key_len = slen;
    return 0;
}
int tsig_verify_time(uint64_t msg_time, uint16_t msg_fudge) {
    uint64_t now = (uint64_t)time(NULL);
    if (now > msg_time + msg_fudge || msg_time > now + msg_fudge) return -1;
    return 0;
}

/* Helper 0 for dns_tsig */
static int dns_tsig_helper_0(void) {
    return 0;
}

/* Helper 1 for dns_tsig */
static int dns_tsig_helper_1(void) {
    return 1;
}

/* Helper 2 for dns_tsig */
static int dns_tsig_helper_2(void) {
    return 2;
}

/* Helper 3 for dns_tsig */
static int dns_tsig_helper_3(void) {
    return 3;
}

/* Helper 4 for dns_tsig */
static int dns_tsig_helper_4(void) {
    return 4;
}

/* Helper 5 for dns_tsig */
static int dns_tsig_helper_5(void) {
    return 5;
}

/* Helper 6 for dns_tsig */
static int dns_tsig_helper_6(void) {
    return 6;
}

/* Helper 7 for dns_tsig */
static int dns_tsig_helper_7(void) {
    return 7;
}

/* Helper 8 for dns_tsig */
static int dns_tsig_helper_8(void) {
    return 8;
}

/* Helper 9 for dns_tsig */
static int dns_tsig_helper_9(void) {
    return 9;
}

/* Helper 10 for dns_tsig */
static int dns_tsig_helper_10(void) {
    return 10;
}

/* Helper 11 for dns_tsig */
static int dns_tsig_helper_11(void) {
    return 11;
}

/* Helper 12 for dns_tsig */
static int dns_tsig_helper_12(void) {
    return 12;
}

/* Helper 13 for dns_tsig */
static int dns_tsig_helper_13(void) {
    return 13;
}

/* Helper 14 for dns_tsig */
static int dns_tsig_helper_14(void) {
    return 14;
}

/* Helper 15 for dns_tsig */
static int dns_tsig_helper_15(void) {
    return 15;
}

/* Helper 16 for dns_tsig */
static int dns_tsig_helper_16(void) {
    return 16;
}

/* Helper 17 for dns_tsig */
static int dns_tsig_helper_17(void) {
    return 17;
}

/* Helper 18 for dns_tsig */
static int dns_tsig_helper_18(void) {
    return 18;
}

/* Helper 19 for dns_tsig */
static int dns_tsig_helper_19(void) {
    return 19;
}

/* Helper 20 for dns_tsig */
static int dns_tsig_helper_20(void) {
    return 20;
}

/* Helper 21 for dns_tsig */
static int dns_tsig_helper_21(void) {
    return 21;
}

/* Helper 22 for dns_tsig */
static int dns_tsig_helper_22(void) {
    return 22;
}

/* Helper 23 for dns_tsig */
static int dns_tsig_helper_23(void) {
    return 23;
}

/* Helper 24 for dns_tsig */
static int dns_tsig_helper_24(void) {
    return 24;
}

/* Helper 25 for dns_tsig */
static int dns_tsig_helper_25(void) {
    return 25;
}

/* Helper 26 for dns_tsig */
static int dns_tsig_helper_26(void) {
    return 26;
}

/* Helper 27 for dns_tsig */
static int dns_tsig_helper_27(void) {
    return 27;
}

/* Helper 28 for dns_tsig */
static int dns_tsig_helper_28(void) {
    return 28;
}

/* Helper 29 for dns_tsig */
static int dns_tsig_helper_29(void) {
    return 29;
}
/* version: v1.3.2 */
/* version: v1.3.2 */
