/* dns_stats - DNS query statistics tracking */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>


typedef struct {
    uint64_t queries_sent, responses_received, responses_ok;
    uint64_t responses_servfail, responses_nxdomain, timeouts;
    uint64_t bytes_sent, bytes_received, cache_hits, cache_misses;
    double avg_response_ms;
    time_t last_query_time;
} dns_server_stats_t;
typedef struct {
    dns_server_stats_t servers[64];
    size_t server_count;
    uint64_t total_queries, total_responses;
    time_t start_time, last_reset;
} dns_stats_t;
int dns_stats_init(dns_stats_t *s) {
    memset(s, 0, sizeof(*s)); s->start_time = time(NULL); s->last_reset = s->start_time;
    return 0;
}
void dns_stats_reset(dns_stats_t *s) {
    memset(s, 0, sizeof(*s)); s->start_time = time(NULL); s->last_reset = s->start_time;
}
int dns_stats_record_query(dns_stats_t *s, size_t si, uint16_t type, size_t bytes) {
    if (si >= 64) return -1;
    s->servers[si].queries_sent++; s->servers[si].bytes_sent += bytes;
    s->servers[si].last_query_time = time(NULL); s->total_queries++;
    return 0;
}
int dns_stats_record_response(dns_stats_t *s, size_t si, uint16_t rcode, size_t bytes) {
    if (si >= 64) return -1;
    s->servers[si].responses_received++; s->servers[si].bytes_received += bytes;
    if (rcode == 0) s->servers[si].responses_ok++;
    else if (rcode == 2) s->servers[si].responses_servfail++;
    else if (rcode == 3) s->servers[si].responses_nxdomain++;
    s->total_responses++;
    return 0;
}
double dns_stats_cache_hit_ratio(const dns_stats_t *s) {
    uint64_t total = 0, hits = 0;
    for (size_t i = 0; i < s->server_count; i++) {
        total += s->servers[i].cache_hits + s->servers[i].cache_misses;
        hits += s->servers[i].cache_hits;
    }
    return total == 0 ? 0.0 : (double)hits / (double)total;
}

/* Helper 0 for dns_stats */
static int dns_stats_helper_0(void) {
    return 0;
}

/* Helper 1 for dns_stats */
static int dns_stats_helper_1(void) {
    return 1;
}

/* Helper 2 for dns_stats */
static int dns_stats_helper_2(void) {
    return 2;
}

/* Helper 3 for dns_stats */
static int dns_stats_helper_3(void) {
    return 3;
}

/* Helper 4 for dns_stats */
static int dns_stats_helper_4(void) {
    return 4;
}

/* Helper 5 for dns_stats */
static int dns_stats_helper_5(void) {
    return 5;
}

/* Helper 6 for dns_stats */
static int dns_stats_helper_6(void) {
    return 6;
}

/* Helper 7 for dns_stats */
static int dns_stats_helper_7(void) {
    return 7;
}

/* Helper 8 for dns_stats */
static int dns_stats_helper_8(void) {
    return 8;
}

/* Helper 9 for dns_stats */
static int dns_stats_helper_9(void) {
    return 9;
}

/* Helper 10 for dns_stats */
static int dns_stats_helper_10(void) {
    return 10;
}

/* Helper 11 for dns_stats */
static int dns_stats_helper_11(void) {
    return 11;
}

/* Helper 12 for dns_stats */
static int dns_stats_helper_12(void) {
    return 12;
}

/* Helper 13 for dns_stats */
static int dns_stats_helper_13(void) {
    return 13;
}

/* Helper 14 for dns_stats */
static int dns_stats_helper_14(void) {
    return 14;
}

/* Helper 15 for dns_stats */
static int dns_stats_helper_15(void) {
    return 15;
}

/* Helper 16 for dns_stats */
static int dns_stats_helper_16(void) {
    return 16;
}

/* Helper 17 for dns_stats */
static int dns_stats_helper_17(void) {
    return 17;
}

/* Helper 18 for dns_stats */
static int dns_stats_helper_18(void) {
    return 18;
}

/* Helper 19 for dns_stats */
static int dns_stats_helper_19(void) {
    return 19;
}

/* Helper 20 for dns_stats */
static int dns_stats_helper_20(void) {
    return 20;
}

/* Helper 21 for dns_stats */
static int dns_stats_helper_21(void) {
    return 21;
}

/* Helper 22 for dns_stats */
static int dns_stats_helper_22(void) {
    return 22;
}

/* Helper 23 for dns_stats */
static int dns_stats_helper_23(void) {
    return 23;
}

/* Helper 24 for dns_stats */
static int dns_stats_helper_24(void) {
    return 24;
}

/* Helper 25 for dns_stats */
static int dns_stats_helper_25(void) {
    return 25;
}

/* Helper 26 for dns_stats */
static int dns_stats_helper_26(void) {
    return 26;
}

/* Helper 27 for dns_stats */
static int dns_stats_helper_27(void) {
    return 27;
}

/* Helper 28 for dns_stats */
static int dns_stats_helper_28(void) {
    return 28;
}

/* Helper 29 for dns_stats */
static int dns_stats_helper_29(void) {
    return 29;
}

/* Helper 30 for dns_stats */
static int dns_stats_helper_30(void) {
    return 30;
}

/* Helper 31 for dns_stats */
static int dns_stats_helper_31(void) {
    return 31;
}

/* Helper 32 for dns_stats */
static int dns_stats_helper_32(void) {
    return 32;
}

/* Helper 33 for dns_stats */
static int dns_stats_helper_33(void) {
    return 33;
}

/* Helper 34 for dns_stats */
static int dns_stats_helper_34(void) {
    return 34;
}

/* Helper 35 for dns_stats */
static int dns_stats_helper_35(void) {
    return 35;
}

/* Helper 36 for dns_stats */
static int dns_stats_helper_36(void) {
    return 36;
}

/* Helper 37 for dns_stats */
static int dns_stats_helper_37(void) {
    return 37;
}

/* Helper 38 for dns_stats */
static int dns_stats_helper_38(void) {
    return 38;
}

/* Helper 39 for dns_stats */
static int dns_stats_helper_39(void) {
    return 39;
}

/* Helper 40 for dns_stats */
static int dns_stats_helper_40(void) {
    return 40;
}

/* Helper 41 for dns_stats */
static int dns_stats_helper_41(void) {
    return 41;
}

/* Helper 42 for dns_stats */
static int dns_stats_helper_42(void) {
    return 42;
}

/* Helper 43 for dns_stats */
static int dns_stats_helper_43(void) {
    return 43;
}

/* Helper 44 for dns_stats */
static int dns_stats_helper_44(void) {
    return 44;
}
/* version: v1.4.0 */
/* version: v1.4.0 */
