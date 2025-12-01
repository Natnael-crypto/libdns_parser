#ifndef DNS_PARSER_DNS_RESOLVER_H
#define DNS_PARSER_DNS_RESOLVER_H

#include "dns.h"
#include "dns_cache.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RESOLVER_MAX_RETRIES    3
#define RESOLVER_MAX_CNAME_DEPTH 64

typedef enum {
    RESOLVER_IDLE,
    RESOLVER_WAITING_REPLY,
    RESOLVER_WAITING_RETRY,
    RESOLVER_DONE,
    RESOLVER_ERROR
} ResolverState;

typedef struct Resolver {
    ResolverState   state;
    DnsCache       *cache_ref;     /* borrowed reference to cache entry */
    DnsCache       *cache;         /* owned reference to the cache */
    char            query_name[DNS_MAX_NAME];
    uint16_t        query_type;
    int             retry_count;
    uint32_t        query_id;
} Resolver;

Resolver *resolver_create(DnsCache *cache);
void      resolver_destroy(Resolver *r);

/* Initiate a DNS query */
int resolver_query(Resolver *r, const char *name, uint16_t qtype, uint32_t query_id);

/* Process a received DNS response message */
int resolver_process_response(Resolver *r, DnsMsg *msg);

/* Follow CNAME chains in a response to find final A/AAAA record */
DnsRR *resolver_follow_cname(Resolver *r, DnsMsg *msg, const char *name, int depth);

/* Handle NXDOMAIN response */
void resolver_handle_nxdomain(Resolver *r, DnsMsg *msg);

/* Check if a cache entry is still valid */
bool resolver_cache_entry_valid(CacheEntry *entry, uint32_t current_time);

#ifdef __cplusplus
}
#endif

#endif /* DNS_PARSER_DNS_RESOLVER_H */
