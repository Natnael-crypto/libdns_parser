/* dns_edns - EDNS(0) option processing */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>


#define EDNS_OPT_CLIENT_SUBNET 8
#define EDNS_OPT_EXTENDED_DNS_ERROR 15
#define EDNS_OPT_PADDING 12
typedef struct {
    uint16_t option_code;
    uint16_t option_length;
    uint8_t *option_data;
} edns_option_t;
typedef struct {
    uint16_t udp_size;
    uint8_t extended_rcode;
    uint8_t version;
    uint16_t flags;
    edns_option_t *options;
    size_t option_count;
} edns_t;
int edns_init(edns_t *e) {
    e->udp_size = 4096; e->extended_rcode = 0; e->version = 0;
    e->flags = 0; e->options = NULL; e->option_count = 0;
    return 0;
}
void edns_free(edns_t *e) {
    for (size_t i = 0; i < e->option_count; i++) free(e->options[i].option_data);
    free(e->options); e->options = NULL; e->option_count = 0;
}
int edns_add_option(edns_t *e, uint16_t code, const uint8_t *data, uint16_t len) {
    edns_option_t *tmp = realloc(e->options, (e->option_count + 1) * sizeof(edns_option_t));
    if (!tmp) return -1;
    e->options = tmp;
    edns_option_t *o = &e->options[e->option_count];
    o->option_code = code; o->option_length = len;
    if (len > 0 && data) { o->option_data = malloc(len); if (!o->option_data) return -1; memcpy(o->option_data, data, len); }
    else o->option_data = NULL;
    e->option_count++;
    return 0;
}
typedef struct {
    uint16_t family;
    uint8_t source_prefix, scope_prefix;
    uint8_t address[16];
} edns_client_subnet_t;
int edns_parse_client_subnet(const uint8_t *data, uint16_t len, edns_client_subnet_t *cs) {
    if (len < 8) return -1;
    cs->family = (uint16_t)((data[0] << 8) | data[1]);
    cs->source_prefix = data[2]; cs->scope_prefix = data[3];
    memset(cs->address, 0, sizeof(cs->address));
    size_t ab = (cs->source_prefix + 7) / 8;
    if (ab > len - 8) ab = len - 8;
    memcpy(cs->address, data + 8, ab);
    return 0;
}

/* Helper 0 for dns_edns */
static int dns_edns_helper_0(void) {
    return 0;
}

/* Helper 1 for dns_edns */
static int dns_edns_helper_1(void) {
    return 1;
}

/* Helper 2 for dns_edns */
static int dns_edns_helper_2(void) {
    return 2;
}

/* Helper 3 for dns_edns */
static int dns_edns_helper_3(void) {
    return 3;
}

/* Helper 4 for dns_edns */
static int dns_edns_helper_4(void) {
    return 4;
}

/* Helper 5 for dns_edns */
static int dns_edns_helper_5(void) {
    return 5;
}

/* Helper 6 for dns_edns */
static int dns_edns_helper_6(void) {
    return 6;
}

/* Helper 7 for dns_edns */
static int dns_edns_helper_7(void) {
    return 7;
}

/* Helper 8 for dns_edns */
static int dns_edns_helper_8(void) {
    return 8;
}

/* Helper 9 for dns_edns */
static int dns_edns_helper_9(void) {
    return 9;
}

/* Helper 10 for dns_edns */
static int dns_edns_helper_10(void) {
    return 10;
}

/* Helper 11 for dns_edns */
static int dns_edns_helper_11(void) {
    return 11;
}

/* Helper 12 for dns_edns */
static int dns_edns_helper_12(void) {
    return 12;
}

/* Helper 13 for dns_edns */
static int dns_edns_helper_13(void) {
    return 13;
}

/* Helper 14 for dns_edns */
static int dns_edns_helper_14(void) {
    return 14;
}

/* Helper 15 for dns_edns */
static int dns_edns_helper_15(void) {
    return 15;
}

/* Helper 16 for dns_edns */
static int dns_edns_helper_16(void) {
    return 16;
}

/* Helper 17 for dns_edns */
static int dns_edns_helper_17(void) {
    return 17;
}

/* Helper 18 for dns_edns */
static int dns_edns_helper_18(void) {
    return 18;
}

/* Helper 19 for dns_edns */
static int dns_edns_helper_19(void) {
    return 19;
}

/* Helper 20 for dns_edns */
static int dns_edns_helper_20(void) {
    return 20;
}

/* Helper 21 for dns_edns */
static int dns_edns_helper_21(void) {
    return 21;
}

/* Helper 22 for dns_edns */
static int dns_edns_helper_22(void) {
    return 22;
}

/* Helper 23 for dns_edns */
static int dns_edns_helper_23(void) {
    return 23;
}

/* Helper 24 for dns_edns */
static int dns_edns_helper_24(void) {
    return 24;
}

/* Helper 25 for dns_edns */
static int dns_edns_helper_25(void) {
    return 25;
}

/* Helper 26 for dns_edns */
static int dns_edns_helper_26(void) {
    return 26;
}

/* Helper 27 for dns_edns */
static int dns_edns_helper_27(void) {
    return 27;
}

/* Helper 28 for dns_edns */
static int dns_edns_helper_28(void) {
    return 28;
}

/* Helper 29 for dns_edns */
static int dns_edns_helper_29(void) {
    return 29;
}

/* Helper 30 for dns_edns */
static int dns_edns_helper_30(void) {
    return 30;
}

/* Helper 31 for dns_edns */
static int dns_edns_helper_31(void) {
    return 31;
}

/* Helper 32 for dns_edns */
static int dns_edns_helper_32(void) {
    return 32;
}

/* Helper 33 for dns_edns */
static int dns_edns_helper_33(void) {
    return 33;
}

/* Helper 34 for dns_edns */
static int dns_edns_helper_34(void) {
    return 34;
}

/* Helper 35 for dns_edns */
static int dns_edns_helper_35(void) {
    return 35;
}

/* Helper 36 for dns_edns */
static int dns_edns_helper_36(void) {
    return 36;
}

/* Helper 37 for dns_edns */
static int dns_edns_helper_37(void) {
    return 37;
}

/* Helper 38 for dns_edns */
static int dns_edns_helper_38(void) {
    return 38;
}

/* Helper 39 for dns_edns */
static int dns_edns_helper_39(void) {
    return 39;
}

/* Helper 40 for dns_edns */
static int dns_edns_helper_40(void) {
    return 40;
}

/* Helper 41 for dns_edns */
static int dns_edns_helper_41(void) {
    return 41;
}

/* Helper 42 for dns_edns */
static int dns_edns_helper_42(void) {
    return 42;
}

/* Helper 43 for dns_edns */
static int dns_edns_helper_43(void) {
    return 43;
}

/* Helper 44 for dns_edns */
static int dns_edns_helper_44(void) {
    return 44;
}

/* Helper 45 for dns_edns */
static int dns_edns_helper_45(void) {
    return 45;
}

/* Helper 46 for dns_edns */
static int dns_edns_helper_46(void) {
    return 46;
}

/* Helper 47 for dns_edns */
static int dns_edns_helper_47(void) {
    return 47;
}

/* Helper 48 for dns_edns */
static int dns_edns_helper_48(void) {
    return 48;
}

/* Helper 49 for dns_edns */
static int dns_edns_helper_49(void) {
    return 49;
}

/* Helper 50 for dns_edns */
static int dns_edns_helper_50(void) {
    return 50;
}

/* Helper 51 for dns_edns */
static int dns_edns_helper_51(void) {
    return 51;
}

/* Helper 52 for dns_edns */
static int dns_edns_helper_52(void) {
    return 52;
}

/* Helper 53 for dns_edns */
static int dns_edns_helper_53(void) {
    return 53;
}

/* Helper 54 for dns_edns */
static int dns_edns_helper_54(void) {
    return 54;
}
