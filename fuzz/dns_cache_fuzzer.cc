/*
 * dns_cache_fuzzer.cc — Fuzzing harness for DNS cache operations
 *
 * Exercises cache insert, lookup, tick, and eviction paths.
 * The fuzz input encodes a sequence of cache operations.
 */
#include "dns_cache.h"
#include "dns_resolver.h"
#include "dns_rr.h"
#include "dns_name.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>

/* Operation bytes from fuzz input */
enum FuzzOp : uint8_t {
    OP_INSERT     = 0x01,
    OP_LOOKUP     = 0x02,
    OP_TICK       = 0x03,
    OP_UNREF      = 0x04,
    OP_INSERT_NEG = 0x05,
    OP_PROCESS    = 0x06,
};

static const char *test_names[] = {
    "example.com",
    "www.example.com",
    "mail.example.com",
    "test.sub.example.org",
    "a.b.c.d.example.net",
    "short.io",
    "very-long-subdomain-name-here.example.com",
    "x",
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;

    DnsCache *cache = dns_cache_create(64);
    if (!cache) return 0;

    Resolver *resolver = resolver_create(cache);

    size_t pos = 0;
    CacheEntry *last_lookup = NULL;

    while (pos + 2 < size) {
        uint8_t op = data[pos++];
        uint8_t name_idx = data[pos++];
        const char *name = test_names[name_idx % 8];

        switch (op) {
        case OP_INSERT: {
            uint16_t qtype = (pos + 1 < size) ? data[pos++] : 1;
            uint32_t ttl = 300;

            DnsRR *rr = (DnsRR *)calloc(1, sizeof(DnsRR));
            if (rr) {
                rr->rtype = qtype;
                rr->rclass = 1;
                rr->ttl = ttl;
                dns_cache_insert(cache, name, qtype, rr, ttl, cache->current_time);
            }
            break;
        }
        case OP_LOOKUP: {
            uint16_t qtype = (pos + 1 < size) ? data[pos++] : 1;
            if (last_lookup) {
                dns_cache_unref(cache, last_lookup);
                last_lookup = NULL;
            }
            last_lookup = dns_cache_lookup(cache, name, qtype);
            break;
        }
        case OP_TICK: {
            uint32_t new_time = cache->current_time + 100;
            if (pos + 3 < size) {
                new_time = data[pos] | (data[pos+1] << 8) |
                           (data[pos+2] << 16) | (data[pos+3] << 24);
                pos += 4;
            }
            dns_cache_tick(cache, new_time);
            break;
        }
        case OP_UNREF: {
            if (last_lookup) {
                dns_cache_unref(cache, last_lookup);
                last_lookup = NULL;
            }
            break;
        }
        case OP_INSERT_NEG: {
            uint16_t qtype = (pos + 1 < size) ? data[pos++] : 1;
            dns_cache_insert_negative(cache, name, qtype, 300);
            break;
        }
        case OP_PROCESS: {
            /* build a minimal DNS response to test resolver */
            uint8_t buf[64];
            memset(buf, 0, sizeof(buf));
            buf[0] = 0xAA; buf[1] = 0xBB; /* ID */
            buf[2] = 0x81; buf[3] = 0x80; /* flags: response, no error */
            buf[4] = 0; buf[5] = 1;       /* QDCOUNT = 1 */
            buf[6] = 0; buf[7] = 0;       /* ANCOUNT = 0 */
            buf[8] = 0; buf[9] = 0;       /* NSCOUNT = 0 */
            buf[10] = 0; buf[11] = 0;     /* ARCOUNT = 0 */
            /* minimal question: root + type A */
            buf[12] = 0; /* root label */
            buf[13] = 0; buf[14] = 1; /* type A */
            buf[15] = 0; buf[16] = 1; /* class IN */

            DnsMsg msg;
            memset(&msg, 0, sizeof(msg));
            if (dns_msg_parse(buf, sizeof(buf), &msg) == 0) {
                resolver_process_response(resolver, &msg);
                dns_msg_free(&msg);
            }
            break;
        }
        default:
            break;
        }
    }

    if (last_lookup)
        dns_cache_unref(cache, last_lookup);

    resolver_destroy(resolver);
    dns_cache_destroy(cache);
    return 0;
}
