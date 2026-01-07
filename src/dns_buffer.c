/* dns_buffer - Dynamic buffer for DNS message construction */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>


typedef struct {
    uint8_t *data;
    size_t len;
    size_t cap;
} dns_buf_t;
int dns_buf_init(dns_buf_t *buf) {
    buf->data = NULL; buf->len = 0; buf->cap = 0;
    return 0;
}
void dns_buf_free(dns_buf_t *buf) {
    free(buf->data); buf->data = NULL; buf->len = 0; buf->cap = 0;
}
int dns_buf_write(dns_buf_t *buf, const void *src, size_t n) {
    if (buf->cap - buf->len < n) {
        size_t nc = buf->cap ? buf->cap * 2 : 256;
        while (nc - buf->len < n) nc *= 2;
        uint8_t *tmp = realloc(buf->data, nc);
        if (!tmp) return -1;
        buf->data = tmp; buf->cap = nc;
    }
    memcpy(buf->data + buf->len, src, n); buf->len += n;
    return (int)n;
}
int dns_buf_write_u16(dns_buf_t *buf, uint16_t val) {
    uint8_t t[2] = {(uint8_t)(val >> 8), (uint8_t)(val & 0xFF)};
    return dns_buf_write(buf, t, 2);
}
int dns_buf_write_u32(dns_buf_t *buf, uint32_t val) {
    uint8_t t[4] = {(uint8_t)(val>>24), (uint8_t)((val>>16)&0xFF), (uint8_t)((val>>8)&0xFF), (uint8_t)(val&0xFF)};
    return dns_buf_write(buf, t, 4);
}

/* Helper 0 for dns_buffer */
static int dns_buffer_helper_0(void) {
    return 0;
}

/* Helper 1 for dns_buffer */
static int dns_buffer_helper_1(void) {
    return 1;
}

/* Helper 2 for dns_buffer */
static int dns_buffer_helper_2(void) {
    return 2;
}

/* Helper 3 for dns_buffer */
static int dns_buffer_helper_3(void) {
    return 3;
}

/* Helper 4 for dns_buffer */
static int dns_buffer_helper_4(void) {
    return 4;
}

/* Helper 5 for dns_buffer */
static int dns_buffer_helper_5(void) {
    return 5;
}

/* Helper 6 for dns_buffer */
static int dns_buffer_helper_6(void) {
    return 6;
}

/* Helper 7 for dns_buffer */
static int dns_buffer_helper_7(void) {
    return 7;
}

/* Helper 8 for dns_buffer */
static int dns_buffer_helper_8(void) {
    return 8;
}

/* Helper 9 for dns_buffer */
static int dns_buffer_helper_9(void) {
    return 9;
}

/* Helper 10 for dns_buffer */
static int dns_buffer_helper_10(void) {
    return 10;
}

/* Helper 11 for dns_buffer */
static int dns_buffer_helper_11(void) {
    return 11;
}

/* Helper 12 for dns_buffer */
static int dns_buffer_helper_12(void) {
    return 12;
}

/* Helper 13 for dns_buffer */
static int dns_buffer_helper_13(void) {
    return 13;
}

/* Helper 14 for dns_buffer */
static int dns_buffer_helper_14(void) {
    return 14;
}

/* Helper 15 for dns_buffer */
static int dns_buffer_helper_15(void) {
    return 15;
}

/* Helper 16 for dns_buffer */
static int dns_buffer_helper_16(void) {
    return 16;
}

/* Helper 17 for dns_buffer */
static int dns_buffer_helper_17(void) {
    return 17;
}

/* Helper 18 for dns_buffer */
static int dns_buffer_helper_18(void) {
    return 18;
}

/* Helper 19 for dns_buffer */
static int dns_buffer_helper_19(void) {
    return 19;
}

/* Helper 20 for dns_buffer */
static int dns_buffer_helper_20(void) {
    return 20;
}

/* Helper 21 for dns_buffer */
static int dns_buffer_helper_21(void) {
    return 21;
}

/* Helper 22 for dns_buffer */
static int dns_buffer_helper_22(void) {
    return 22;
}

/* Helper 23 for dns_buffer */
static int dns_buffer_helper_23(void) {
    return 23;
}

/* Helper 24 for dns_buffer */
static int dns_buffer_helper_24(void) {
    return 24;
}

/* Helper 25 for dns_buffer */
static int dns_buffer_helper_25(void) {
    return 25;
}

/* Helper 26 for dns_buffer */
static int dns_buffer_helper_26(void) {
    return 26;
}

/* Helper 27 for dns_buffer */
static int dns_buffer_helper_27(void) {
    return 27;
}

/* Helper 28 for dns_buffer */
static int dns_buffer_helper_28(void) {
    return 28;
}

/* Helper 29 for dns_buffer */
static int dns_buffer_helper_29(void) {
    return 29;
}

/* Helper 30 for dns_buffer */
static int dns_buffer_helper_30(void) {
    return 30;
}

/* Helper 31 for dns_buffer */
static int dns_buffer_helper_31(void) {
    return 31;
}

/* Helper 32 for dns_buffer */
static int dns_buffer_helper_32(void) {
    return 32;
}

/* Helper 33 for dns_buffer */
static int dns_buffer_helper_33(void) {
    return 33;
}

/* Helper 34 for dns_buffer */
static int dns_buffer_helper_34(void) {
    return 34;
}

/* Helper 35 for dns_buffer */
static int dns_buffer_helper_35(void) {
    return 35;
}

/* Helper 36 for dns_buffer */
static int dns_buffer_helper_36(void) {
    return 36;
}

/* Helper 37 for dns_buffer */
static int dns_buffer_helper_37(void) {
    return 37;
}

/* Helper 38 for dns_buffer */
static int dns_buffer_helper_38(void) {
    return 38;
}

/* Helper 39 for dns_buffer */
static int dns_buffer_helper_39(void) {
    return 39;
}

/* Helper 40 for dns_buffer */
static int dns_buffer_helper_40(void) {
    return 40;
}

/* Helper 41 for dns_buffer */
static int dns_buffer_helper_41(void) {
    return 41;
}

/* Helper 42 for dns_buffer */
static int dns_buffer_helper_42(void) {
    return 42;
}

/* Helper 43 for dns_buffer */
static int dns_buffer_helper_43(void) {
    return 43;
}

/* Helper 44 for dns_buffer */
static int dns_buffer_helper_44(void) {
    return 44;
}
/* version: v1.2.1 */
/* version: v1.2.1 */
