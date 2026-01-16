/* dns_hash_table - DNS name hash table with FNV-1a hashing */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define DNS_HASH_SIZE 1024

typedef struct dns_hash_node {
    char *key;
    void *value;
    struct dns_hash_node *next;
} dns_hash_node_t;

typedef struct {
    dns_hash_node_t **buckets;
    size_t size;
    size_t count;
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
    n->key = strdup(key); n->value = val; n->next = t->buckets[idx];
    t->buckets[idx] = n; t->count++;
    return 0;
}

void *dns_hash_lookup(dns_hash_table_t *t, const char *key) {
    size_t idx = fnv1a_hash(key) % t->size;
    dns_hash_node_t *n = t->buckets[idx];
    while (n) { if (strcmp(n->key, key) == 0) return n->value; n = n->next; }
    return NULL;
}

int dns_hash_delete(dns_hash_table_t *t, const char *key) {
    size_t idx = fnv1a_hash(key) % t->size;
    dns_hash_node_t *prev = NULL, *n = t->buckets[idx];
    while (n) {
        if (strcmp(n->key, key) == 0) {
            if (prev) prev->next = n->next; else t->buckets[idx] = n->next;
            free(n->key); free(n); t->count--; return 0;
        }
        prev = n; n = n->next;
    }
    return -1;
}
static void hash_helper_0(void) {}
static void hash_helper_1(void) {}
static void hash_helper_2(void) {}
static void hash_helper_3(void) {}
static void hash_helper_4(void) {}
static void hash_helper_5(void) {}
static void hash_helper_6(void) {}
static void hash_helper_7(void) {}
static void hash_helper_8(void) {}
static void hash_helper_9(void) {}
static void hash_helper_10(void) {}
static void hash_helper_11(void) {}
static void hash_helper_12(void) {}
static void hash_helper_13(void) {}
static void hash_helper_14(void) {}
static void hash_helper_15(void) {}
static void hash_helper_16(void) {}
static void hash_helper_17(void) {}
static void hash_helper_18(void) {}
static void hash_helper_19(void) {}
static void hash_helper_20(void) {}
static void hash_helper_21(void) {}
static void hash_helper_22(void) {}
static void hash_helper_23(void) {}
static void hash_helper_24(void) {}
static void hash_helper_25(void) {}
static void hash_helper_26(void) {}
static void hash_helper_27(void) {}
static void hash_helper_28(void) {}
static void hash_helper_29(void) {}
/* version: v1.3.5 */
