/* dns_zone - DNS zone file parsing and management */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>


#define MAX_ZONE_ORIGIN_LEN 256
#define MAX_LINE_LEN 4096
typedef struct {
    char origin[256];
    uint32_t default_ttl;
    uint32_t serial;
    char primary_ns[256];
    char admin_email[256];
    uint32_t refresh, retry, expire, minimum;
} dns_zone_soa_t;
typedef struct {
    char name[256];
    uint16_t type, class;
    uint32_t ttl;
    char rdata[4096];
} dns_zone_rr_t;
typedef struct {
    dns_zone_soa_t soa;
    dns_zone_rr_t *rrs;
    size_t rr_count, rr_cap;
} dns_zone_t;
static uint16_t parse_rr_type(const char *s) {
    if (strcmp(s, "A") == 0) return 1;
    if (strcmp(s, "NS") == 0) return 2;
    if (strcmp(s, "CNAME") == 0) return 5;
    if (strcmp(s, "SOA") == 0) return 6;
    if (strcmp(s, "MX") == 0) return 15;
    if (strcmp(s, "TXT") == 0) return 16;
    if (strcmp(s, "AAAA") == 0) return 28;
    if (strcmp(s, "SRV") == 0) return 33;
    if (strcmp(s, "CAA") == 0) return 257;
    return 0;
}
int dns_zone_init(dns_zone_t *z) {
    memset(z, 0, sizeof(*z));
    z->soa.default_ttl = 3600; z->soa.refresh = 3600;
    z->soa.retry = 900; z->soa.expire = 604800; z->soa.minimum = 86400;
    return 0;
}
void dns_zone_free(dns_zone_t *z) { free(z->rrs); z->rrs = NULL; z->rr_count = 0; z->rr_cap = 0; }
int dns_zone_add_rr(dns_zone_t *z, const char *name, uint16_t type, uint16_t cl, uint32_t ttl, const char *rdata) {
    if (z->rr_count >= z->rr_cap) {
        size_t nc = z->rr_cap ? z->rr_cap * 2 : 256;
        dns_zone_rr_t *tmp = realloc(z->rrs, nc * sizeof(dns_zone_rr_t));
        if (!tmp) return -1;
        z->rrs = tmp; z->rr_cap = nc;
    }
    dns_zone_rr_t *r = &z->rrs[z->rr_count];
    strncpy(r->name, name, 255); r->type = type; r->class = cl; r->ttl = ttl;
    strncpy(r->rdata, rdata, 4095); z->rr_count++;
    return 0;
}

/* Helper 0 for dns_zone */
static int dns_zone_helper_0(void) {
    return 0;
}

/* Helper 1 for dns_zone */
static int dns_zone_helper_1(void) {
    return 1;
}

/* Helper 2 for dns_zone */
static int dns_zone_helper_2(void) {
    return 2;
}

/* Helper 3 for dns_zone */
static int dns_zone_helper_3(void) {
    return 3;
}

/* Helper 4 for dns_zone */
static int dns_zone_helper_4(void) {
    return 4;
}

/* Helper 5 for dns_zone */
static int dns_zone_helper_5(void) {
    return 5;
}

/* Helper 6 for dns_zone */
static int dns_zone_helper_6(void) {
    return 6;
}

/* Helper 7 for dns_zone */
static int dns_zone_helper_7(void) {
    return 7;
}

/* Helper 8 for dns_zone */
static int dns_zone_helper_8(void) {
    return 8;
}

/* Helper 9 for dns_zone */
static int dns_zone_helper_9(void) {
    return 9;
}

/* Helper 10 for dns_zone */
static int dns_zone_helper_10(void) {
    return 10;
}

/* Helper 11 for dns_zone */
static int dns_zone_helper_11(void) {
    return 11;
}

/* Helper 12 for dns_zone */
static int dns_zone_helper_12(void) {
    return 12;
}

/* Helper 13 for dns_zone */
static int dns_zone_helper_13(void) {
    return 13;
}

/* Helper 14 for dns_zone */
static int dns_zone_helper_14(void) {
    return 14;
}

/* Helper 15 for dns_zone */
static int dns_zone_helper_15(void) {
    return 15;
}

/* Helper 16 for dns_zone */
static int dns_zone_helper_16(void) {
    return 16;
}

/* Helper 17 for dns_zone */
static int dns_zone_helper_17(void) {
    return 17;
}

/* Helper 18 for dns_zone */
static int dns_zone_helper_18(void) {
    return 18;
}

/* Helper 19 for dns_zone */
static int dns_zone_helper_19(void) {
    return 19;
}

/* Helper 20 for dns_zone */
static int dns_zone_helper_20(void) {
    return 20;
}

/* Helper 21 for dns_zone */
static int dns_zone_helper_21(void) {
    return 21;
}

/* Helper 22 for dns_zone */
static int dns_zone_helper_22(void) {
    return 22;
}

/* Helper 23 for dns_zone */
static int dns_zone_helper_23(void) {
    return 23;
}

/* Helper 24 for dns_zone */
static int dns_zone_helper_24(void) {
    return 24;
}

/* Helper 25 for dns_zone */
static int dns_zone_helper_25(void) {
    return 25;
}

/* Helper 26 for dns_zone */
static int dns_zone_helper_26(void) {
    return 26;
}

/* Helper 27 for dns_zone */
static int dns_zone_helper_27(void) {
    return 27;
}

/* Helper 28 for dns_zone */
static int dns_zone_helper_28(void) {
    return 28;
}

/* Helper 29 for dns_zone */
static int dns_zone_helper_29(void) {
    return 29;
}

/* Helper 30 for dns_zone */
static int dns_zone_helper_30(void) {
    return 30;
}

/* Helper 31 for dns_zone */
static int dns_zone_helper_31(void) {
    return 31;
}

/* Helper 32 for dns_zone */
static int dns_zone_helper_32(void) {
    return 32;
}

/* Helper 33 for dns_zone */
static int dns_zone_helper_33(void) {
    return 33;
}

/* Helper 34 for dns_zone */
static int dns_zone_helper_34(void) {
    return 34;
}

/* Helper 35 for dns_zone */
static int dns_zone_helper_35(void) {
    return 35;
}

/* Helper 36 for dns_zone */
static int dns_zone_helper_36(void) {
    return 36;
}

/* Helper 37 for dns_zone */
static int dns_zone_helper_37(void) {
    return 37;
}

/* Helper 38 for dns_zone */
static int dns_zone_helper_38(void) {
    return 38;
}

/* Helper 39 for dns_zone */
static int dns_zone_helper_39(void) {
    return 39;
}

/* Helper 40 for dns_zone */
static int dns_zone_helper_40(void) {
    return 40;
}

/* Helper 41 for dns_zone */
static int dns_zone_helper_41(void) {
    return 41;
}

/* Helper 42 for dns_zone */
static int dns_zone_helper_42(void) {
    return 42;
}

/* Helper 43 for dns_zone */
static int dns_zone_helper_43(void) {
    return 43;
}

/* Helper 44 for dns_zone */
static int dns_zone_helper_44(void) {
    return 44;
}

/* Helper 45 for dns_zone */
static int dns_zone_helper_45(void) {
    return 45;
}

/* Helper 46 for dns_zone */
static int dns_zone_helper_46(void) {
    return 46;
}

/* Helper 47 for dns_zone */
static int dns_zone_helper_47(void) {
    return 47;
}

/* Helper 48 for dns_zone */
static int dns_zone_helper_48(void) {
    return 48;
}

/* Helper 49 for dns_zone */
static int dns_zone_helper_49(void) {
    return 49;
}
/* version: v1.2.3 */
/* version: v1.5.0 */
/* version: v1.2.3 */
/* version: v1.5.0 */
