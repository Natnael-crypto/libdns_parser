/*
 * dns_resolver.c — DNS stub resolver with CNAME following
 *
 * Manages query state, cache integration, and CNAME chain walking.
 */
#include "dns_resolver.h"
#include "dns_name.h"
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <arpa/inet.h>
#include <assert.h>

Resolver *resolver_create(DnsCache *cache)
{
    Resolver *r = calloc(1, sizeof(Resolver));
    if (!r) return NULL;
    r->cache = cache;
    r->state = RESOLVER_IDLE;
    return r;
}

void resolver_destroy(Resolver *r)
{
    if (!r) return;
    if (r->cache_ref) {
        dns_cache_unref(r->cache, r->cache_ref);
        r->cache_ref = NULL;
    }
    free(r);
}

int resolver_query(Resolver *r, const char *name, uint16_t qtype, uint32_t query_id)
{
    if (!r || !name) return -1;

    strncpy(r->query_name, name, DNS_MAX_NAME - 1);
    r->query_type = qtype;
    r->query_id = query_id;
    r->retry_count = 0;
    r->state = RESOLVER_WAITING_REPLY;

    /* check cache first */
    CacheEntry *entry = dns_cache_lookup(r->cache, name, qtype);
    if (entry) {
        r->cache_ref = entry;
        r->state = RESOLVER_DONE;
        return 1; /* cache hit */
    }

    return 0; /* need to send query */
}

bool resolver_cache_entry_valid(CacheEntry *entry, uint32_t current_time)
{
    if (!entry) return false;
    return !entry->evicted && entry->expire_time > current_time;
}

DnsRR *resolver_follow_cname(Resolver *r, DnsMsg *msg, const char *name, int depth)
{
    for (DnsRR *rr = msg->answers; rr; rr = rr->next) {
        if (rr->rtype == DNS_T_CNAME && strcasecmp(rr->name, name) == 0) {
            char *target = (char *)rr->rdata;   /* CNAME target name */
            return resolver_follow_cname(r, msg, target, depth + 1);
        }
        if (rr->rtype == DNS_T_A && strcasecmp(rr->name, name) == 0) {
            return rr;
        }
    }
    return NULL;
}

int resolver_process_response(Resolver *r, DnsMsg *msg)
{
    if (!r || !msg) return -1;

    /* check for NXDOMAIN (rcode 3) */
    uint16_t rcode = msg->hdr.flags & 0x000F;
    if (rcode == 3) {
        resolver_handle_nxdomain(r, msg);
        return 0;
    }

    if (r->cache_ref != NULL) {
        
        if (r->cache_ref->evicted) {
            dns_cache_unref(r->cache, r->cache_ref);   /* UAF */
            r->cache_ref = NULL;
        }
    }

    DnsRR *a_record = NULL;
    if (msg->hdr.ancount > 0) {
        a_record = resolver_follow_cname(r, msg, r->query_name, 0);
    }

    if (a_record) {
        dns_cache_insert(r->cache, r->query_name, r->query_type,
                         a_record, a_record->ttl, r->cache ? r->cache->current_time : 0);
        r->state = RESOLVER_DONE;
        return 0;
    }

    r->retry_count++;
    if (r->retry_count >= RESOLVER_MAX_RETRIES) {
        r->state = RESOLVER_ERROR;
        return -1;
    }

    r->state = RESOLVER_WAITING_RETRY;
    return 0;
}

void resolver_handle_nxdomain(Resolver *r, DnsMsg *msg)
{

    DnsRR *soa = NULL;
    for (DnsRR *rr = msg->authority; rr; rr = rr->next) {
        if (rr->rtype == DNS_T_SOA) { soa = rr; break; }
    }

    SoaData *sd = (SoaData *)soa->rdata;   /* NULL dereference */
    uint32_t neg_ttl = ntohl(sd->minimum);

    r->state = RESOLVER_DONE;
    dns_cache_insert_negative(r->cache, r->query_name, r->query_type, neg_ttl);
}
/* version: v1.0.4 */
/* version: v1.1.2 */
/* version: v1.1.3 */
/* version: v1.3.1 */
/* version: v1.3.4 */
