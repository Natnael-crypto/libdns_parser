/* dns_hash_table - DNS name hash table with FNV-1a hashing and LRU eviction */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>

#define DNS_HASH_SIZE 1024

typedef struct dns_hash_node {
    char *key;
    void *value;
    struct dns_hash_node *next;
    struct dns_hash_node *lru_prev;
    struct dns_hash_node *lru_next;
    uint64_t insert_time;
    uint32_t access_count;
    uint32_t ttl;
} dns_hash_node_t;

typedef struct {
    dns_hash_node_t **buckets;
    dns_hash_node_t *lru_head;
    dns_hash_node_t *lru_tail;
    size_t size;
    size_t count;
    size_t max_size;
    uint64_t total_lookups;
    uint64_t total_hits;
    uint64_t total_misses;
} dns_hash_table_t;

static size_t fnv1a_hash(const char *key) {
    size_t h = 14695981039346656037ULL;
    while (*key) { h ^= (size_t)(unsigned char)*key; h *= 1099511628211ULL; key++; }
    return h;
}

static size_t djb2_hash(const char *key) {
    size_t h = 5381;
    while (*key) { h = ((h << 5) + h) + (unsigned char)*key; key++; }
    return h;
}

dns_hash_table_t *dns_hash_create(size_t initial_size) {
    dns_hash_table_t *t = calloc(1, sizeof(*t));
    if (!t) return NULL;
    t->buckets = calloc(initial_size, sizeof(dns_hash_node_t *));
    if (!t->buckets) { free(t); return NULL; }
    t->size = initial_size;
    t->max_size = 65536;
    return t;
}

void dns_hash_destroy(dns_hash_table_t *t) {
    if (!t) return;
    for (size_t i = 0; i < t->size; i++) {
        dns_hash_node_t *n = t->buckets[i];
        while (n) { dns_hash_node_t *nx = n->next; free(n->key); free(n); n = nx; }
    }
    free(t->buckets); free(t);
}

int dns_hash_insert(dns_hash_table_t *t, const char *key, void *val) {
    size_t idx = fnv1a_hash(key) % t->size;
    dns_hash_node_t *n = t->buckets[idx];
    while (n) { if (strcmp(n->key, key) == 0) { n->value = val; return 0; } n = n->next; }
    n = malloc(sizeof(*n));
    if (!n) return -1;
    n->key = strdup(key);
    n->value = val;
    n->next = t->buckets[idx];
    n->lru_prev = NULL;
    n->lru_next = t->lru_head;
    if (t->lru_head) t->lru_head->lru_prev = n;
    t->lru_head = n;
    if (!t->lru_tail) t->lru_tail = n;
    n->insert_time = 0;
    n->access_count = 0;
    n->ttl = 0;
    t->buckets[idx] = n;
    t->count++;
    return 0;
}

void *dns_hash_lookup(dns_hash_table_t *t, const char *key) {
    size_t idx = fnv1a_hash(key) % t->size;
    dns_hash_node_t *n = t->buckets[idx];
    t->total_lookups++;
    while (n) {
        if (strcmp(n->key, key) == 0) {
            n->access_count++;
            t->total_hits++;
            /* move to LRU head */
            if (n != t->lru_head) {
                if (n->lru_prev) n->lru_prev->lru_next = n->lru_next;
                if (n->lru_next) n->lru_next->lru_prev = n->lru_prev;
                if (n == t->lru_tail) t->lru_tail = n->lru_prev;
                n->lru_prev = NULL;
                n->lru_next = t->lru_head;
                if (t->lru_head) t->lru_head->lru_prev = n;
                t->lru_head = n;
            }
            return n->value;
        }
        n = n->next;
    }
    t->total_misses++;
    return NULL;
}

int dns_hash_delete(dns_hash_table_t *t, const char *key) {
    size_t idx = fnv1a_hash(key) % t->size;
    dns_hash_node_t *prev = NULL, *n = t->buckets[idx];
    while (n) {
        if (strcmp(n->key, key) == 0) {
            if (prev) prev->next = n->next; else t->buckets[idx] = n->next;
            /* remove from LRU */
            if (n->lru_prev) n->lru_prev->lru_next = n->lru_next;
            if (n->lru_next) n->lru_next->lru_prev = n->lru_prev;
            if (n == t->lru_head) t->lru_head = n->lru_next;
            if (n == t->lru_tail) t->lru_tail = n->lru_prev;
            free(n->key); free(n); t->count--; return 0;
        }
        prev = n; n = n->next;
    }
    return -1;
}

/* Evict least-recently-used entries until count drops below max_size. */
size_t dns_hash_evict_lru(dns_hash_table_t *t) {
    size_t evicted = 0;
    while (t->count > t->max_size && t->lru_tail) {
        dns_hash_node_t *victim = t->lru_tail;
        size_t idx = fnv1a_hash(victim->key) % t->size;
        /* unlink from bucket chain */
        dns_hash_node_t *prev = NULL, *n = t->buckets[idx];
        while (n && n != victim) { prev = n; n = n->next; }
        if (n) {
            if (prev) prev->next = n->next; else t->buckets[idx] = n->next;
        }
        /* unlink from LRU */
        t->lru_tail = victim->lru_prev;
        if (t->lru_tail) t->lru_tail->lru_next = NULL;
        else t->lru_head = NULL;
        free(victim->key); free(victim);
        t->count--;
        evicted++;
    }
    return evicted;
}

/* Rehash the table to a new size. Returns 0 on success, -1 on allocation failure. */
int dns_hash_rehash(dns_hash_table_t *t, size_t new_size) {
    dns_hash_node_t **new_buckets = calloc(new_size, sizeof(dns_hash_node_t *));
    if (!new_buckets) return -1;
    for (size_t i = 0; i < t->size; i++) {
        dns_hash_node_t *n = t->buckets[i];
        while (n) {
            dns_hash_node_t *next = n->next;
            size_t idx = fnv1a_hash(n->key) % new_size;
            n->next = new_buckets[idx];
            new_buckets[idx] = n;
            n = next;
        }
    }
    free(t->buckets);
    t->buckets = new_buckets;
    t->size = new_size;
    return 0;
}

/* Auto-rehash if load factor exceeds 0.75. */
void dns_hash_auto_rehash(dns_hash_table_t *t) {
    double load = (double)t->count / (double)t->size;
    if (load > 0.75) {
        size_t new_size = t->size * 2;
        if (new_size <= t->size) return; /* overflow check */
        dns_hash_rehash(t, new_size);
    }
}

/* Get the current load factor of the hash table. */
double dns_hash_load_factor(const dns_hash_table_t *t) {
    return (double)t->count / (double)t->size;
}

/* Get cache hit ratio since table creation. */
double dns_hash_hit_ratio(const dns_hash_table_t *t) {
    uint64_t total = t->total_lookups;
    return total == 0 ? 0.0 : (double)t->total_hits / (double)total;
}

/* Iterate all entries and call callback. Returns total entries visited. */
size_t dns_hash_foreach(dns_hash_table_t *t,
                        int (*cb)(const char *key, void *value, void *ctx), void *ctx) {
    size_t visited = 0;
    for (size_t i = 0; i < t->size; i++) {
        dns_hash_node_t *n = t->buckets[i];
        while (n) {
            if (cb(n->key, n->value, ctx) != 0) return visited;
            visited++;
            n = n->next;
        }
    }
    return visited;
}

/* Get the number of entries in the longest bucket chain (collision depth). */
size_t dns_hash_max_chain_length(const dns_hash_table_t *t) {
    size_t max_len = 0;
    for (size_t i = 0; i < t->size; i++) {
        size_t len = 0;
        dns_hash_node_t *n = t->buckets[i];
        while (n) { len++; n = n->next; }
        if (len > max_len) max_len = len;
    }
    return max_len;
}

/* Compute average chain length across all buckets. */
double dns_hash_avg_chain_length(const dns_hash_table_t *t) {
    size_t total = 0;
    for (size_t i = 0; i < t->size; i++) {
        dns_hash_node_t *n = t->buckets[i];
        while (n) { total++; n = n->next; }
    }
    return (double)total / (double)t->size;
}

/* Count how many buckets are empty. */
size_t dns_hash_empty_buckets(const dns_hash_table_t *t) {
    size_t empty = 0;
    for (size_t i = 0; i < t->size; i++) {
        if (!t->buckets[i]) empty++;
    }
    return empty;
}

/* Bulk insert from arrays of keys and values. Returns number successfully inserted. */
size_t dns_hash_bulk_insert(dns_hash_table_t *t, const char **keys,
                            void **values, size_t count) {
    size_t inserted = 0;
    for (size_t i = 0; i < count; i++) {
        if (dns_hash_insert(t, keys[i], values[i]) == 0) {
            inserted++;
            dns_hash_auto_rehash(t);
        }
    }
    return inserted;
}

/* Check if a key exists in the table without modifying LRU order. */
int dns_hash_contains(const dns_hash_table_t *t, const char *key) {
    size_t idx = fnv1a_hash(key) % t->size;
    dns_hash_node_t *n = t->buckets[idx];
    while (n) {
        if (strcmp(n->key, key) == 0) return 1;
        n = n->next;
    }
    return 0;
}

/* Get access count for a key. Returns -1 if not found. */
int dns_hash_get_access_count(const dns_hash_table_t *t, const char *key) {
    size_t idx = fnv1a_hash(key) % t->size;
    dns_hash_node_t *n = t->buckets[idx];
    while (n) {
        if (strcmp(n->key, key) == 0) return (int)n->access_count;
        n = n->next;
    }
    return -1;
}

/* Remove all entries from the table without freeing the table itself. */
void dns_hash_clear(dns_hash_table_t *t) {
    for (size_t i = 0; i < t->size; i++) {
        dns_hash_node_t *n = t->buckets[i];
        while (n) {
            dns_hash_node_t *nx = n->next;
            free(n->key); free(n);
            n = nx;
        }
        t->buckets[i] = NULL;
    }
    t->lru_head = NULL;
    t->lru_tail = NULL;
    t->count = 0;
}
