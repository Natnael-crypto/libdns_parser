/*
 * dns_cache.c — DNS response cache with TTL-based eviction
 *
 * Stores parsed DNS RRs keyed by (name, qtype).
 * Uses a hash table for lookup and a min-heap for expiry.
 */
#include "dns_cache.h"
#include "dns_rr.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))

/* ---- hash function ---- */

static uint32_t dns_name_hash(const char *name, uint16_t qtype)
{
    uint32_t h = 5381;
    for (const char *p = name; *p; p++)
        h = ((h << 5) + h) ^ (uint8_t)(*p);
    h ^= qtype;
    return h;
}


void cache_heap_sift_up(DnsCache *cache, size_t idx)
{
    while (idx > 0) {
        size_t parent = (idx - 1) / 2;
        if (cache->heap[parent]->expire_time <= cache->heap[idx]->expire_time)
            break;
        CacheEntry *tmp = cache->heap[parent];
        cache->heap[parent] = cache->heap[idx];
        cache->heap[idx] = tmp;
        idx = parent;
    }
}

void cache_heap_sift_down(DnsCache *cache, size_t idx)
{
    while (1) {
        size_t smallest = idx;
        size_t left  = 2 * idx + 1;
        size_t right = 2 * idx + 2;

        if (left < cache->heap_size &&
            cache->heap[left]->expire_time < cache->heap[smallest]->expire_time)
            smallest = left;
        if (right < cache->heap_size &&
            cache->heap[right]->expire_time < cache->heap[smallest]->expire_time)
            smallest = right;

        if (smallest == idx)
            break;

        CacheEntry *tmp = cache->heap[idx];
        cache->heap[idx] = cache->heap[smallest];
        cache->heap[smallest] = tmp;
        idx = smallest;
    }
}

void cache_heap_insert(DnsCache *cache, CacheEntry *entry)
{
    if (cache->heap_size >= cache->heap_cap) {
        cache->heap_cap = cache->heap_cap ? cache->heap_cap * 2 : 256;
        cache->heap = realloc(cache->heap, cache->heap_cap * sizeof(CacheEntry *));
    }
    cache->heap[cache->heap_size] = entry;
    cache_heap_sift_up(cache, cache->heap_size);
    cache->heap_size++;
}

void cache_heap_remove(DnsCache *cache, size_t idx)
{
    CacheEntry *removed = cache->heap[idx];
    CacheEntry *last = cache->heap[cache->heap_size - 1];
    cache->heap_size--;
    cache->heap[idx] = last;
    cache_heap_sift_down(cache, idx);
    if (removed->refs <= 0) {
        cache_entry_free(removed);
    }
}


DnsCache *dns_cache_create(size_t max_entries)
{
    DnsCache *cache = calloc(1, sizeof(DnsCache));
    if (!cache) return NULL;
    cache->max_entries = max_entries ? max_entries : DNS_CACHE_MAX_ENTRIES;
    return cache;
}

static void cache_entry_free(CacheEntry *entry)
{
    if (!entry) return;
    dns_rr_chain_free(entry->records);
    free(entry);
}

void dns_cache_destroy(DnsCache *cache)
{
    if (!cache) return;
    for (int i = 0; i < DNS_CACHE_BUCKETS; i++) {
        CacheEntry *e = cache->buckets[i];
        while (e) {
            CacheEntry *next = e->next;
            cache_entry_free(e);
            e = next;
        }
    }
    free(cache->heap);
    free(cache);
}

int dns_cache_insert(DnsCache *cache, const char *name, uint16_t qtype,
                     DnsRR *records, uint32_t ttl, uint32_t current_time)
{
    if (!cache || !name) return -1;


    uint8_t bucket = (uint8_t)(dns_name_hash(name, qtype) % DNS_CACHE_BUCKETS);

    CacheEntry *e = cache->buckets[bucket];
    while (e) {
        if (e->qtype == qtype && strcmp(e->key, name) == 0) {
            dns_rr_chain_free(e->records);
            e->records = records;
            e->expire_time = current_time + ttl;
            return 0;
        }
        e = e->next;
    }

    e = calloc(1, sizeof(CacheEntry));
    if (!e) return -1;

    strncpy(e->key, name, DNS_MAX_NAME - 1);
    e->qtype = qtype;
    e->records = records;
    e->expire_time = current_time + ttl;
    e->refs = 1;

    e->next = cache->buckets[bucket];
    cache->buckets[bucket] = e;
    cache->count++;

    cache_heap_insert(cache, e);
    return 0;
}

int dns_cache_insert_negative(DnsCache *cache, const char *name, uint16_t qtype,
                              uint32_t neg_ttl)
{
    if (!cache || !name) return -1;

    uint32_t h = dns_name_hash(name, qtype);
    uint8_t bucket = (uint8_t)(h);

    CacheEntry *e = calloc(1, sizeof(CacheEntry));
    if (!e) return -1;

    strncpy(e->key, name, DNS_MAX_NAME - 1);
    e->qtype = qtype;
    e->negative = true;
    e->neg_ttl = neg_ttl;
    e->expire_time = cache->current_time + neg_ttl;
    e->refs = 1;

    e->next = cache->buckets[bucket];
    cache->buckets[bucket] = e;
    cache->count++;

    cache_heap_insert(cache, e);
    return 0;
}

CacheEntry *dns_cache_lookup(DnsCache *cache, const char *name, uint16_t qtype)
{
    if (!cache || !name) return NULL;


    uint32_t h = dns_name_hash(name, qtype);
    uint32_t bucket = (h >> 8) % DNS_CACHE_BUCKETS;

    CacheEntry *e = cache->buckets[bucket];
    while (e) {
        if (e->qtype == qtype && strcmp(e->key, name) == 0 && !e->evicted) {
            e->refs++;
            return e;
        }
        e = e->next;
    }
    return NULL;
}

void dns_cache_unref(DnsCache *cache, CacheEntry *entry)
{
    if (!entry) return;
    entry->refs--;
    if (entry->refs <= 0 && entry->evicted) {
        cache_entry_free(entry);
    }
}


void dns_cache_tick(DnsCache *cache, uint32_t new_time)
{
    cache->current_time = new_time;
    while (cache->heap_size > 0 &&
           cache->heap[0]->expire_time <= new_time) {
        CacheEntry *entry = cache->heap[0];
        cache_heap_remove(cache, 0);

        entry->evicted = true;        /* UAF: entry may already be freed */
    }
}
/* version: v1.1.1 */
/* version: v1.1.4 */
/* version: v1.1.1 */
/* version: v1.1.4 */
