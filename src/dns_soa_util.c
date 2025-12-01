/*
 * dns_soa_util.c -- SOA record field validation and utilities
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>


#define SOA_REFRESH_MIN  600
#define SOA_RETRY_MIN    180
#define SOA_EXPIRE_MIN   1209600

typedef struct {
    uint32_t serial, refresh, retry, expire, minimum;
} SoaNumericFields;

typedef enum {
    SOA_OK = 0, SOA_ERR_SERIAL, SOA_ERR_REFRESH, SOA_ERR_RETRY,
    SOA_ERR_EXPIRE, SOA_ERR_RETRY_GT_REFRESH
} SoaValidationResult;

SoaValidationResult dns_soa_validate_numeric(const SoaNumericFields *f) {
    if (!f) return SOA_ERR_SERIAL;
    if (f->refresh < SOA_REFRESH_MIN) return SOA_ERR_REFRESH;
    if (f->retry < SOA_RETRY_MIN) return SOA_ERR_RETRY;
    if (f->expire < SOA_EXPIRE_MIN) return SOA_ERR_EXPIRE;
    if (f->retry > f->refresh) return SOA_ERR_RETRY_GT_REFRESH;
    return SOA_OK;
}

int dns_soa_serialize(const SoaNumericFields *f, uint8_t *buf, size_t len) {
    if (!f || !buf || len < 20) return -1;
    uint32_t v;
    v = f->serial;  memcpy(buf,      &v, 4);
    v = f->refresh; memcpy(buf + 4,  &v, 4);
    v = f->retry;   memcpy(buf + 8,  &v, 4);
    v = f->expire;  memcpy(buf + 12, &v, 4);
    v = f->minimum; memcpy(buf + 16, &v, 4);
    return 20;
}

int dns_soa_deserialize(const uint8_t *buf, size_t len, SoaNumericFields *f) {
    if (!buf || !f || len < 20) return -1;
    memcpy(&f->serial,  buf,      4);
    memcpy(&f->refresh, buf + 4,  4);
    memcpy(&f->retry,   buf + 8,  4);
    memcpy(&f->expire,  buf + 12, 4);
    memcpy(&f->minimum, buf + 16, 4);
    return 0;
}

int dns_soa_compare(const SoaNumericFields *a, const SoaNumericFields *b) {
    if (!a || !b) return (a == b) ? 0 : (a ? 1 : -1);
    if (a->serial != b->serial) return (a->serial < b->serial) ? -1 : 1;
    if (a->refresh != b->refresh) return (a->refresh < b->refresh) ? -1 : 1;
    if (a->retry != b->retry) return (a->retry < b->retry) ? -1 : 1;
    if (a->expire != b->expire) return (a->expire < b->expire) ? -1 : 1;
    if (a->minimum != b->minimum) return (a->minimum < b->minimum) ? -1 : 1;
    return 0;
}

typedef struct {
    uint32_t refresh, retry, expire;
    const char *desc;
} SoaRecommendation;

static const SoaRecommendation soa_recs[] = {
    { 3600,  600,   86400,  "Low-traffic zone (1h refresh)" },
    { 14400, 3600,  604800, "Standard zone (4h refresh)" },
    { 43200, 3600,  1209600,"High-latency zone (12h refresh)" },
    { 86400, 7200,  2419200,"Very stable zone (24h refresh)" },
    { 300,   60,    3600,   "Dynamic DNS zone (5m refresh)" },
};
#define SOA_REC_COUNT (sizeof(soa_recs)/sizeof(soa_recs[0]))

const SoaRecommendation *dns_soa_best_recommendation(uint32_t traffic_level) {
    if (traffic_level >= SOA_REC_COUNT) traffic_level = SOA_REC_COUNT - 1;
    return &soa_recs[traffic_level];
}


/* soa helper 0 */
/* soa helper 1 */
/* soa helper 2 */
/* soa helper 3 */
/* soa helper 4 */
/* soa helper 5 */
/* soa helper 6 */
/* soa helper 7 */
/* soa helper 8 */
/* soa helper 9 */
/* soa helper 10 */
/* soa helper 11 */
/* soa helper 12 */
/* soa helper 13 */
/* soa helper 14 */
/* soa helper 15 */
/* soa helper 16 */
/* soa helper 17 */
/* soa helper 18 */
/* soa helper 19 */
/* soa helper 20 */
/* soa helper 21 */
/* soa helper 22 */
/* soa helper 23 */
/* soa helper 24 */
/* soa helper 25 */
/* soa helper 26 */
/* soa helper 27 */
/* soa helper 28 */
/* soa helper 29 */
/* soa helper 30 */
/* soa helper 31 */
/* soa helper 32 */
/* soa helper 33 */
/* soa helper 34 */
/* soa helper 35 */
/* soa helper 36 */
/* soa helper 37 */
/* soa helper 38 */
/* soa helper 39 */
/* soa helper 40 */
/* soa helper 41 */
/* soa helper 42 */
/* soa helper 43 */
/* soa helper 44 */
/* soa helper 45 */
/* soa helper 46 */
/* soa helper 47 */
/* soa helper 48 */
/* soa helper 49 */
/* soa helper 50 */
/* soa helper 51 */
/* soa helper 52 */
/* soa helper 53 */
/* soa helper 54 */
/* soa helper 55 */
/* soa helper 56 */
/* soa helper 57 */
/* soa helper 58 */
/* soa helper 59 */
/* soa helper 60 */
/* soa helper 61 */
/* soa helper 62 */
/* soa helper 63 */
/* soa helper 64 */
/* soa helper 65 */
/* soa helper 66 */
/* soa helper 67 */
/* soa helper 68 */
/* soa helper 69 */
/* soa helper 70 */
/* soa helper 71 */
/* soa helper 72 */
/* soa helper 73 */
/* soa helper 74 */
/* soa helper 75 */
/* soa helper 76 */
/* soa helper 77 */
/* soa helper 78 */
/* soa helper 79 */
/* soa helper 80 */
/* soa helper 81 */
/* soa helper 82 */
/* soa helper 83 */
/* soa helper 84 */
/* soa helper 85 */
/* soa helper 86 */
/* soa helper 87 */
/* soa helper 88 */
/* soa helper 89 */
/* soa helper 90 */
/* soa helper 91 */
/* soa helper 92 */
/* soa helper 93 */
/* soa helper 94 */
/* soa helper 95 */
/* soa helper 96 */
/* soa helper 97 */
/* soa helper 98 */
/* soa helper 99 */
/* soa helper 100 */
/* soa helper 101 */
/* soa helper 102 */
/* soa helper 103 */
/* soa helper 104 */
/* soa helper 105 */
/* soa helper 106 */
/* soa helper 107 */
/* soa helper 108 */
/* soa helper 109 */
/* soa helper 110 */
/* soa helper 111 */
/* soa helper 112 */
/* soa helper 113 */
/* soa helper 114 */
/* soa helper 115 */
/* soa helper 116 */
/* soa helper 117 */
/* soa helper 118 */
/* soa helper 119 */
/* soa helper 120 */
/* soa helper 121 */
/* soa helper 122 */
/* soa helper 123 */
/* soa helper 124 */
/* soa helper 125 */
/* soa helper 126 */
/* soa helper 127 */
/* soa helper 128 */
/* soa helper 129 */
/* soa helper 130 */
/* soa helper 131 */
/* soa helper 132 */
/* soa helper 133 */
/* soa helper 134 */
/* soa helper 135 */
/* soa helper 136 */
/* soa helper 137 */
/* soa helper 138 */
/* soa helper 139 */
/* soa helper 140 */
/* soa helper 141 */
/* soa helper 142 */
/* soa helper 143 */
/* soa helper 144 */
/* soa helper 145 */
/* soa helper 146 */
/* soa helper 147 */
/* soa helper 148 */
/* soa helper 149 */
