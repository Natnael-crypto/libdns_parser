/* dns_rrset - RRset management, TTL-based expiry, deduplication, and sorting */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

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

int dns_rrset_add(dns_rrset_t *s, const char *n, uint16_t t, uint16_t cl,
                  uint32_t ttl, const uint8_t *rd, uint16_t rl) {
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

/* Remove duplicate entries (same name, type, class, and rdata). */
size_t dns_rrset_deduplicate(dns_rrset_t *s) {
    size_t removed = 0;
    for (size_t i = 0; i < s->count; i++) {
        for (size_t j = i + 1; j < s->count; ) {
            if (strcmp(s->entries[i].name, s->entries[j].name) == 0 &&
                s->entries[i].type == s->entries[j].type &&
                s->entries[i].class == s->entries[j].class &&
                s->entries[i].rdlen == s->entries[j].rdlen &&
                memcmp(s->entries[i].rdata, s->entries[j].rdata, s->entries[i].rdlen) == 0) {
                s->entries[j] = s->entries[s->count - 1];
                s->count--;
                removed++;
            } else {
                j++;
            }
        }
    }
    return removed;
}

/* Sort entries by name, then type, then rdata for deterministic ordering. */
void dns_rrset_sort(dns_rrset_t *s) {
    /* simple insertion sort (entries are typically small) */
    for (size_t i = 1; i < s->count; i++) {
        dns_rrset_entry_t key = s->entries[i];
        size_t j = i;
        while (j > 0) {
            dns_rrset_entry_t *prev = &s->entries[j - 1];
            int cmp = strcmp(prev->name, key.name);
            if (cmp > 0 || (cmp == 0 && prev->type > key.type) ||
                (cmp == 0 && prev->type == key.type &&
                 prev->rdlen > key.rdlen) ||
                (cmp == 0 && prev->type == key.type &&
                 prev->rdlen == key.rdlen &&
                 memcmp(prev->rdata, key.rdata, key.rdlen) > 0)) {
                s->entries[j] = *prev;
                j--;
            } else {
                break;
            }
        }
        s->entries[j] = key;
    }
}

/* Find all entries matching a given name and type. Returns count found. */
size_t dns_rrset_find(const dns_rrset_t *s, const char *name, uint16_t type,
                      dns_rrset_entry_t **results, size_t max_results) {
    size_t found = 0;
    for (size_t i = 0; i < s->count && found < max_results; i++) {
        if (strcmp(s->entries[i].name, name) == 0 &&
            s->entries[i].type == type) {
            results[found++] = &s->entries[i];
        }
    }
    return found;
}

/* Remove all entries matching a name and type. Returns count removed. */
size_t dns_rrset_remove(dns_rrset_t *s, const char *name, uint16_t type) {
    size_t removed = 0;
    for (size_t i = 0; i < s->count; ) {
        if (strcmp(s->entries[i].name, name) == 0 &&
            s->entries[i].type == type) {
            s->entries[i] = s->entries[s->count - 1];
            s->count--;
            removed++;
        } else {
            i++;
        }
    }
    return removed;
}

/* Merge another rrset into this one. Returns total entries added. */
size_t dns_rrset_merge(dns_rrset_t *dest, const dns_rrset_t *src) {
    size_t added = 0;
    for (size_t i = 0; i < src->count; i++) {
        if (dns_rrset_add(dest, src->entries[i].name, src->entries[i].type,
                          src->entries[i].class, src->entries[i].ttl,
                          src->entries[i].rdata, src->entries[i].rdlen) == 0) {
            added++;
        }
    }
    return added;
}

/* Select RRs by random selection (for load balancing answers). */
int dns_rrset_select_random(const dns_rrset_t *s, const char *name, uint16_t type,
                            dns_rrset_entry_t *out) {
    uint32_t candidates[256];
    size_t n = 0;
    for (size_t i = 0; i < s->count && n < 256; i++) {
        if (strcmp(s->entries[i].name, name) == 0 &&
            s->entries[i].type == type) {
            candidates[n++] = (uint32_t)i;
        }
    }
    if (n == 0) return -1;
    /* simple LCG random selection */
    static uint32_t seed = 12345;
    seed = seed * 1103515245 + 12345;
    size_t idx = candidates[seed % n];
    *out = s->entries[idx];
    return 0;
}

/* Get the minimum TTL across all entries in the set. */
uint32_t dns_rrset_min_ttl(const dns_rrset_t *s) {
    uint32_t mn = UINT32_MAX;
    for (size_t i = 0; i < s->count; i++) {
        if (s->entries[i].ttl < mn) mn = s->entries[i].ttl;
    }
    return mn == UINT32_MAX ? 0 : mn;
}

/* Check if two RRsets have the same owner name and type (are the same RRset). */
int dns_rrset_same_set(const dns_rrset_t *a, const dns_rrset_t *b) {
    if (a->count == 0 || b->count == 0) return 0;
    if (strcmp(a->entries[0].name, b->entries[0].name) != 0) return 0;
    if (a->entries[0].type != b->entries[0].type) return 0;
    return 1;
}

/* Count entries with a specific type. */
size_t dns_rrset_count_type(const dns_rrset_t *s, uint16_t type) {
    size_t c = 0;
    for (size_t i = 0; i < s->count; i++) {
        if (s->entries[i].type == type) c++;
    }
    return c;
}

/* Trim the RRset to keep only the N lowest-TTL entries for a given name+type. */
void dns_rrset_trim(dns_rrset_t *s, const char *name, uint16_t type, size_t keep) {
    /* find and sort by TTL */
    size_t idxs[1024];
    size_t n = 0;
    for (size_t i = 0; i < s->count && n < 1024; i++) {
        if (strcmp(s->entries[i].name, name) == 0 &&
            s->entries[i].type == type) {
            idxs[n++] = i;
        }
    }
    if (n <= keep) return;
    /* sort by TTL descending so we can remove from the end */
    for (size_t i = 0; i < n - 1; i++) {
        for (size_t j = i + 1; j < n; j++) {
            if (s->entries[idxs[i]].ttl < s->entries[idxs[j]].ttl) {
                size_t tmp = idxs[i]; idxs[i] = idxs[j]; idxs[j] = tmp;
            }
        }
    }
    /* remove excess (from highest index to avoid shifting) */
    for (size_t i = keep; i < n; i++) {
        size_t idx = idxs[i];
        s->entries[idx] = s->entries[s->count - 1];
        s->count--;
    }
}
