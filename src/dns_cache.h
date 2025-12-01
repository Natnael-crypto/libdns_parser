#ifndef DNS_PARSER_DNS_CACHE_H
#define DNS_PARSER_DNS_CACHE_H

#include "dns.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DNS_CACHE_BUCKETS 128
#define DNS_CACHE_MAX_ENTRIES 4096

typedef struct CacheEntry {
    char            key[DNS_MAX_NAME];  /* "name\0qtype" */
    uint16_t        qtype;
    DnsRR          *records;
    uint32_t        expire_time;    /* absolute time of expiry */
    int             refs;           /* reference count */
    bool            evicted;        /* set when entry is evicted */
    bool            negative;       /* true for NXDOMAIN cache entries */
    uint32_t        neg_ttl;        /* negative TTL (for NXDOMAIN) */
    struct CacheEntry *next;        /* bucket chain */
    struct CacheEntry *heap_next;   /* heap for eviction ordering */
} CacheEntry;

typedef struct DnsCache {
    CacheEntry  *buckets[DNS_CACHE_BUCKETS];
    CacheEntry **heap;           /* min-heap by expire_time */
    size_t       heap_size;
    size_t       heap_cap;
    uint32_t     current_time;
    size_t       count;
    size_t       max_entries;
} DnsCache;

DnsCache *dns_cache_create(size_t max_entries);
void      dns_cache_destroy(DnsCache *cache);

/* Insert or update a cache entry */
int dns_cache_insert(DnsCache *cache, const char *name, uint16_t qtype,
                     DnsRR *records, uint32_t ttl, uint32_t current_time);

/* Insert a negative (NXDOMAIN) cache entry */
int dns_cache_insert_negative(DnsCache *cache, const char *name, uint16_t qtype,
                              uint32_t neg_ttl);

/* Lookup; bumps refcount on returned entry (caller must unref) */
CacheEntry *dns_cache_lookup(DnsCache *cache, const char *name, uint16_t qtype);

/* Drop reference; frees entry if refs reaches 0 */
void dns_cache_unref(DnsCache *cache, CacheEntry *entry);

/* Advance clock; evict expired entries */
void dns_cache_tick(DnsCache *cache, uint32_t new_time);

/* Internal heap helpers */
void cache_heap_insert(DnsCache *cache, CacheEntry *entry);
void cache_heap_remove(DnsCache *cache, size_t idx);
void cache_heap_sift_down(DnsCache *cache, size_t idx);
void cache_heap_sift_up(DnsCache *cache, size_t idx);

#ifdef __cplusplus
}
#endif

#endif /* DNS_PARSER_DNS_CACHE_H */
