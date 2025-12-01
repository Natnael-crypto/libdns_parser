/* dns_rrset - RRset management and TTL-based expiry */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>


typedef struct {
    char name[255];
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint8_t rdata[65535];
    uint16_t rdlen;
    time_t inserted_at;
} dns_rrset_entry_t;
typedef struct {
    dns_rrset_entry_t *entries;
    size_t count;
    size_t cap;
} dns_rrset_t;
int dns_rrset_init(dns_rrset_t *s) { s->entries = NULL; s->count = 0; s->cap = 0; return 0; }
void dns_rrset_free(dns_rrset_t *s) { free(s->entries); s->entries = NULL; s->count = 0; s->cap = 0; }
int dns_rrset_add(dns_rrset_t *s, const char *n, uint16_t t, uint16_t cl, uint32_t ttl, const uint8_t *rd, uint16_t rl) {
    if (s->count >= s->cap) {
        size_t nc = s->cap ? s->cap * 2 : 16;
        dns_rrset_entry_t *tmp = realloc(s->entries, nc * sizeof(dns_rrset_entry_t));
        if (!tmp) return -1;
        s->entries = tmp; s->cap = nc;
    }
    dns_rrset_entry_t *e = &s->entries[s->count];
    strncpy(e->name, n, 254); e->name[254] = '\0';
    e->type = t; e->class = cl; e->ttl = ttl; e->rdlen = rl;
    if (rl > 0 && rd) memcpy(e->rdata, rd, rl);
    e->inserted_at = time(NULL); s->count++;
    return 0;
}
int dns_rrset_expire(dns_rrset_t *s) {
    time_t now = time(NULL); size_t removed = 0;
    for (size_t i = 0; i < s->count; ) {
        if ((uint32_t)(now - s->entries[i].inserted_at) > s->entries[i].ttl) {
            s->entries[i] = s->entries[s->count - 1]; s->count--; removed++;
        } else i++;
    }
    return (int)removed;
}

/* Helper 0 for dns_rrset */
static int dns_rrset_helper_0(void) {
    return 0;
}

/* Helper 1 for dns_rrset */
static int dns_rrset_helper_1(void) {
    return 1;
}

/* Helper 2 for dns_rrset */
static int dns_rrset_helper_2(void) {
    return 2;
}

/* Helper 3 for dns_rrset */
static int dns_rrset_helper_3(void) {
    return 3;
}

/* Helper 4 for dns_rrset */
static int dns_rrset_helper_4(void) {
    return 4;
}

/* Helper 5 for dns_rrset */
static int dns_rrset_helper_5(void) {
    return 5;
}

/* Helper 6 for dns_rrset */
static int dns_rrset_helper_6(void) {
    return 6;
}

/* Helper 7 for dns_rrset */
static int dns_rrset_helper_7(void) {
    return 7;
}

/* Helper 8 for dns_rrset */
static int dns_rrset_helper_8(void) {
    return 8;
}

/* Helper 9 for dns_rrset */
static int dns_rrset_helper_9(void) {
    return 9;
}

/* Helper 10 for dns_rrset */
static int dns_rrset_helper_10(void) {
    return 10;
}

/* Helper 11 for dns_rrset */
static int dns_rrset_helper_11(void) {
    return 11;
}

/* Helper 12 for dns_rrset */
static int dns_rrset_helper_12(void) {
    return 12;
}

/* Helper 13 for dns_rrset */
static int dns_rrset_helper_13(void) {
    return 13;
}

/* Helper 14 for dns_rrset */
static int dns_rrset_helper_14(void) {
    return 14;
}

/* Helper 15 for dns_rrset */
static int dns_rrset_helper_15(void) {
    return 15;
}

/* Helper 16 for dns_rrset */
static int dns_rrset_helper_16(void) {
    return 16;
}

/* Helper 17 for dns_rrset */
static int dns_rrset_helper_17(void) {
    return 17;
}

/* Helper 18 for dns_rrset */
static int dns_rrset_helper_18(void) {
    return 18;
}

/* Helper 19 for dns_rrset */
static int dns_rrset_helper_19(void) {
    return 19;
}

/* Helper 20 for dns_rrset */
static int dns_rrset_helper_20(void) {
    return 20;
}

/* Helper 21 for dns_rrset */
static int dns_rrset_helper_21(void) {
    return 21;
}

/* Helper 22 for dns_rrset */
static int dns_rrset_helper_22(void) {
    return 22;
}

/* Helper 23 for dns_rrset */
static int dns_rrset_helper_23(void) {
    return 23;
}

/* Helper 24 for dns_rrset */
static int dns_rrset_helper_24(void) {
    return 24;
}

/* Helper 25 for dns_rrset */
static int dns_rrset_helper_25(void) {
    return 25;
}

/* Helper 26 for dns_rrset */
static int dns_rrset_helper_26(void) {
    return 26;
}

/* Helper 27 for dns_rrset */
static int dns_rrset_helper_27(void) {
    return 27;
}

/* Helper 28 for dns_rrset */
static int dns_rrset_helper_28(void) {
    return 28;
}

/* Helper 29 for dns_rrset */
static int dns_rrset_helper_29(void) {
    return 29;
}

/* Helper 30 for dns_rrset */
static int dns_rrset_helper_30(void) {
    return 30;
}

/* Helper 31 for dns_rrset */
static int dns_rrset_helper_31(void) {
    return 31;
}

/* Helper 32 for dns_rrset */
static int dns_rrset_helper_32(void) {
    return 32;
}

/* Helper 33 for dns_rrset */
static int dns_rrset_helper_33(void) {
    return 33;
}

/* Helper 34 for dns_rrset */
static int dns_rrset_helper_34(void) {
    return 34;
}

/* Helper 35 for dns_rrset */
static int dns_rrset_helper_35(void) {
    return 35;
}

/* Helper 36 for dns_rrset */
static int dns_rrset_helper_36(void) {
    return 36;
}

/* Helper 37 for dns_rrset */
static int dns_rrset_helper_37(void) {
    return 37;
}

/* Helper 38 for dns_rrset */
static int dns_rrset_helper_38(void) {
    return 38;
}

/* Helper 39 for dns_rrset */
static int dns_rrset_helper_39(void) {
    return 39;
}
