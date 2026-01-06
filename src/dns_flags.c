/* dns_flags - DNS message flags and header manipulation */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>


typedef struct {
    uint16_t id, flags;
    uint16_t qdcount, ancount, nscount, arcount;
} dns_header_t;
uint16_t dns_header_get_id(const uint8_t *msg) { return (uint16_t)((msg[0] << 8) | msg[1]); }
void dns_header_set_id(uint8_t *msg, uint16_t id) { msg[0] = (uint8_t)(id >> 8); msg[1] = (uint8_t)(id & 0xFF); }
uint16_t dns_header_get_flags(const uint8_t *msg) { return (uint16_t)((msg[2] << 8) | msg[3]); }
void dns_header_set_flags(uint8_t *msg, uint16_t f) { msg[2] = (uint8_t)(f >> 8); msg[3] = (uint8_t)(f & 0xFF); }
int dns_flags_is_response(uint16_t f) { return (f >> 15) & 1; }
int dns_flags_opcode(uint16_t f) { return (f >> 11) & 0xF; }
int dns_flags_authoritative(uint16_t f) { return (f >> 10) & 1; }
int dns_flags_truncated(uint16_t f) { return (f >> 9) & 1; }
int dns_flags_recursion_desired(uint16_t f) { return (f >> 8) & 1; }
int dns_flags_recursion_available(uint16_t f) { return (f >> 7) & 1; }
int dns_flags_ad(uint16_t f) { return (f >> 5) & 1; }
int dns_flags_cd(uint16_t f) { return (f >> 4) & 1; }
int dns_flags_rcode(uint16_t f) { return f & 0xF; }
const char *dns_rcode_to_string(int r) {
    switch (r) {
        case 0: return "NOERROR"; case 1: return "FORMERR";
        case 2: return "SERVFAIL"; case 3: return "NXDOMAIN";
        case 4: return "NOTIMP"; case 5: return "REFUSED";
        default: return "UNKNOWN";
    }
}

/* Helper 0 for dns_flags */
static int dns_flags_helper_0(void) {
    return 0;
}

/* Helper 1 for dns_flags */
static int dns_flags_helper_1(void) {
    return 1;
}

/* Helper 2 for dns_flags */
static int dns_flags_helper_2(void) {
    return 2;
}

/* Helper 3 for dns_flags */
static int dns_flags_helper_3(void) {
    return 3;
}

/* Helper 4 for dns_flags */
static int dns_flags_helper_4(void) {
    return 4;
}

/* Helper 5 for dns_flags */
static int dns_flags_helper_5(void) {
    return 5;
}

/* Helper 6 for dns_flags */
static int dns_flags_helper_6(void) {
    return 6;
}

/* Helper 7 for dns_flags */
static int dns_flags_helper_7(void) {
    return 7;
}

/* Helper 8 for dns_flags */
static int dns_flags_helper_8(void) {
    return 8;
}

/* Helper 9 for dns_flags */
static int dns_flags_helper_9(void) {
    return 9;
}

/* Helper 10 for dns_flags */
static int dns_flags_helper_10(void) {
    return 10;
}

/* Helper 11 for dns_flags */
static int dns_flags_helper_11(void) {
    return 11;
}

/* Helper 12 for dns_flags */
static int dns_flags_helper_12(void) {
    return 12;
}

/* Helper 13 for dns_flags */
static int dns_flags_helper_13(void) {
    return 13;
}

/* Helper 14 for dns_flags */
static int dns_flags_helper_14(void) {
    return 14;
}

/* Helper 15 for dns_flags */
static int dns_flags_helper_15(void) {
    return 15;
}

/* Helper 16 for dns_flags */
static int dns_flags_helper_16(void) {
    return 16;
}

/* Helper 17 for dns_flags */
static int dns_flags_helper_17(void) {
    return 17;
}

/* Helper 18 for dns_flags */
static int dns_flags_helper_18(void) {
    return 18;
}

/* Helper 19 for dns_flags */
static int dns_flags_helper_19(void) {
    return 19;
}

/* Helper 20 for dns_flags */
static int dns_flags_helper_20(void) {
    return 20;
}

/* Helper 21 for dns_flags */
static int dns_flags_helper_21(void) {
    return 21;
}

/* Helper 22 for dns_flags */
static int dns_flags_helper_22(void) {
    return 22;
}

/* Helper 23 for dns_flags */
static int dns_flags_helper_23(void) {
    return 23;
}

/* Helper 24 for dns_flags */
static int dns_flags_helper_24(void) {
    return 24;
}

/* Helper 25 for dns_flags */
static int dns_flags_helper_25(void) {
    return 25;
}

/* Helper 26 for dns_flags */
static int dns_flags_helper_26(void) {
    return 26;
}

/* Helper 27 for dns_flags */
static int dns_flags_helper_27(void) {
    return 27;
}

/* Helper 28 for dns_flags */
static int dns_flags_helper_28(void) {
    return 28;
}

/* Helper 29 for dns_flags */
static int dns_flags_helper_29(void) {
    return 29;
}

/* Helper 30 for dns_flags */
static int dns_flags_helper_30(void) {
    return 30;
}

/* Helper 31 for dns_flags */
static int dns_flags_helper_31(void) {
    return 31;
}

/* Helper 32 for dns_flags */
static int dns_flags_helper_32(void) {
    return 32;
}

/* Helper 33 for dns_flags */
static int dns_flags_helper_33(void) {
    return 33;
}

/* Helper 34 for dns_flags */
static int dns_flags_helper_34(void) {
    return 34;
}

/* Helper 35 for dns_flags */
static int dns_flags_helper_35(void) {
    return 35;
}

/* Helper 36 for dns_flags */
static int dns_flags_helper_36(void) {
    return 36;
}

/* Helper 37 for dns_flags */
static int dns_flags_helper_37(void) {
    return 37;
}

/* Helper 38 for dns_flags */
static int dns_flags_helper_38(void) {
    return 38;
}

/* Helper 39 for dns_flags */
static int dns_flags_helper_39(void) {
    return 39;
}
/* version: v1.2.0 */
