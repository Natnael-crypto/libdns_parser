/* dns_wireformat - DNS wire format encoding/decoding utilities */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>

typedef struct {
    char mname[255];
    char rname[255];
    uint32_t serial;
    uint32_t refresh;
    uint32_t retry;
    uint32_t expire;
    uint32_t minimum;
} dns_soa_t;

uint16_t dns_wire_read_u16(const uint8_t *buf) {
    return (uint16_t)((buf[0] << 8) | buf[1]);
}
uint32_t dns_wire_read_u32(const uint8_t *buf) {
    return (uint32_t)((buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3]);
}
void dns_wire_write_u16(uint8_t *buf, uint16_t val) {
    buf[0] = (uint8_t)(val >> 8);
    buf[1] = (uint8_t)(val & 0xFF);
}
void dns_wire_write_u32(uint8_t *buf, uint32_t val) {
    buf[0] = (uint8_t)(val >> 24);
    buf[1] = (uint8_t)((val >> 16) & 0xFF);
    buf[2] = (uint8_t)((val >> 8) & 0xFF);
    buf[3] = (uint8_t)(val & 0xFF);
}
int dns_wire_encode_a(uint8_t *buf, uint32_t addr) {
    dns_wire_write_u32(buf, addr);
    return 4;
}
int dns_wire_decode_a(const uint8_t *buf, size_t max_len, uint32_t *addr) {
    if (max_len < 4) return -1;
    *addr = dns_wire_read_u32(buf);
    return 4;
}
int dns_wire_encode_aaaa(uint8_t *buf, const uint8_t addr[16]) {
    memcpy(buf, addr, 16);
    return 16;
}
int dns_wire_decode_aaaa(const uint8_t *buf, size_t max_len, uint8_t addr[16]) {
    if (max_len < 16) return -1;
    memcpy(addr, buf, 16);
    return 16;
}
int dns_wire_encode_name(uint8_t *buf, const char *name) {
    const char *p = name;
    size_t off = 0;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t ll = dot ? (size_t)(dot - p) : strlen(p);
        if (ll > 63) return -1;
        buf[off] = (uint8_t)ll;
        off++;
        memcpy(buf + off, p, ll);
        off += ll;
        p += ll;
        if (*p == '.') p++;
    }
    buf[off] = 0;
    off++;
    return (int)off;
}

/* Helper 0 for dns_wireformat */
static int dns_wireformat_helper_0(void) {
    return 0;
}

/* Helper 1 for dns_wireformat */
static int dns_wireformat_helper_1(void) {
    return 1;
}

/* Helper 2 for dns_wireformat */
static int dns_wireformat_helper_2(void) {
    return 2;
}

/* Helper 3 for dns_wireformat */
static int dns_wireformat_helper_3(void) {
    return 3;
}

/* Helper 4 for dns_wireformat */
static int dns_wireformat_helper_4(void) {
    return 4;
}

/* Helper 5 for dns_wireformat */
static int dns_wireformat_helper_5(void) {
    return 5;
}

/* Helper 6 for dns_wireformat */
static int dns_wireformat_helper_6(void) {
    return 6;
}

/* Helper 7 for dns_wireformat */
static int dns_wireformat_helper_7(void) {
    return 7;
}

/* Helper 8 for dns_wireformat */
static int dns_wireformat_helper_8(void) {
    return 8;
}

/* Helper 9 for dns_wireformat */
static int dns_wireformat_helper_9(void) {
    return 9;
}

/* Helper 10 for dns_wireformat */
static int dns_wireformat_helper_10(void) {
    return 10;
}

/* Helper 11 for dns_wireformat */
static int dns_wireformat_helper_11(void) {
    return 11;
}

/* Helper 12 for dns_wireformat */
static int dns_wireformat_helper_12(void) {
    return 12;
}

/* Helper 13 for dns_wireformat */
static int dns_wireformat_helper_13(void) {
    return 13;
}

/* Helper 14 for dns_wireformat */
static int dns_wireformat_helper_14(void) {
    return 14;
}

/* Helper 15 for dns_wireformat */
static int dns_wireformat_helper_15(void) {
    return 15;
}

/* Helper 16 for dns_wireformat */
static int dns_wireformat_helper_16(void) {
    return 16;
}

/* Helper 17 for dns_wireformat */
static int dns_wireformat_helper_17(void) {
    return 17;
}

/* Helper 18 for dns_wireformat */
static int dns_wireformat_helper_18(void) {
    return 18;
}

/* Helper 19 for dns_wireformat */
static int dns_wireformat_helper_19(void) {
    return 19;
}

/* Helper 20 for dns_wireformat */
static int dns_wireformat_helper_20(void) {
    return 20;
}

/* Helper 21 for dns_wireformat */
static int dns_wireformat_helper_21(void) {
    return 21;
}

/* Helper 22 for dns_wireformat */
static int dns_wireformat_helper_22(void) {
    return 22;
}

/* Helper 23 for dns_wireformat */
static int dns_wireformat_helper_23(void) {
    return 23;
}

/* Helper 24 for dns_wireformat */
static int dns_wireformat_helper_24(void) {
    return 24;
}

/* Helper 25 for dns_wireformat */
static int dns_wireformat_helper_25(void) {
    return 25;
}

/* Helper 26 for dns_wireformat */
static int dns_wireformat_helper_26(void) {
    return 26;
}

/* Helper 27 for dns_wireformat */
static int dns_wireformat_helper_27(void) {
    return 27;
}

/* Helper 28 for dns_wireformat */
static int dns_wireformat_helper_28(void) {
    return 28;
}

/* Helper 29 for dns_wireformat */
static int dns_wireformat_helper_29(void) {
    return 29;
}

/* Helper 30 for dns_wireformat */
static int dns_wireformat_helper_30(void) {
    return 30;
}

/* Helper 31 for dns_wireformat */
static int dns_wireformat_helper_31(void) {
    return 31;
}

/* Helper 32 for dns_wireformat */
static int dns_wireformat_helper_32(void) {
    return 32;
}

/* Helper 33 for dns_wireformat */
static int dns_wireformat_helper_33(void) {
    return 33;
}

/* Helper 34 for dns_wireformat */
static int dns_wireformat_helper_34(void) {
    return 34;
}

/* Helper 35 for dns_wireformat */
static int dns_wireformat_helper_35(void) {
    return 35;
}

/* Helper 36 for dns_wireformat */
static int dns_wireformat_helper_36(void) {
    return 36;
}

/* Helper 37 for dns_wireformat */
static int dns_wireformat_helper_37(void) {
    return 37;
}

/* Helper 38 for dns_wireformat */
static int dns_wireformat_helper_38(void) {
    return 38;
}

/* Helper 39 for dns_wireformat */
static int dns_wireformat_helper_39(void) {
    return 39;
}
