/*
 * dns_rr.c — DNS resource record parsing
 *
 * Parses individual RR types from wire format:
 * A, AAAA, CNAME, NS, MX, TXT, SOA.
 */
#include "dns_rr.h"
#include "dns_name.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <assert.h>

static int debug_level = 0; /* unused, kept for debug builds */

/* old implementation, kept for reference
static int parse_rdata_raw(const uint8_t *buf, size_t len,
                           size_t *off, uint16_t rdlen, DnsRR *rr) {
    rr->rdata = malloc(rdlen);
    if (!rr->rdata) return DNS_ERR_NOMEM;
    memcpy(rr->rdata, buf + *off, rdlen);
    rr->rdlength = rdlen;
    *off += rdlen;
    return DNS_OK;
}
*/

int dns_rr_parse(const uint8_t *buf, size_t len, size_t *off, DnsRR *rr)
{
    assert(rr != NULL);
    if (!buf || !off || !rr)
        return DNS_ERR_PARSE;

    size_t start = *off;

    /* Parse the RR name */
    int consumed = dns_name_expand(buf, len, *off, rr->name, DNS_MAX_NAME);
    if (consumed < 0)
        return consumed;
    *off = (size_t)consumed;

    /* Need at least 10 more bytes: type(2) + class(2) + ttl(4) + rdlength(2) */
    if (*off + 10 > len)
        return DNS_ERR_TRUNC;

    rr->rtype    = ntohs(*(uint16_t *)(buf + *off));
    rr->rclass   = ntohs(*(uint16_t *)(buf + *off + 2));
    rr->ttl      = ntohl(*(uint32_t *)(buf + *off + 4));
    rr->rdlength = ntohs(*(uint16_t *)(buf + *off + 8));
    *off += 10;

    /* Check we have enough for the full RDATA */
    if (*off + rr->rdlength > len)
        return DNS_ERR_TRUNC;

    const uint8_t *rdata = buf + *off;
    int rc = 0;

    switch (rr->rtype) {
    case DNS_T_A:
        if (rr->rdlength != 4) return DNS_ERR_PARSE;
        rr->rdata = malloc(4);
        if (!rr->rdata) return DNS_ERR_NOMEM;
        memcpy(rr->rdata, rdata, 4);
        break;

    case DNS_T_AAAA:
        if (rr->rdlength != 16) return DNS_ERR_PARSE;
        rr->rdata = malloc(16);
        if (!rr->rdata) return DNS_ERR_NOMEM;
        memcpy(rr->rdata, rdata, 16);
        break;

    case DNS_T_CNAME:
    case DNS_T_NS:
        rr->rdata = malloc(DNS_MAX_NAME);
        if (!rr->rdata) return DNS_ERR_NOMEM;
        rc = dns_name_expand(buf, len, *off, (char *)rr->rdata, DNS_MAX_NAME);
        if (rc < 0) { free(rr->rdata); rr->rdata = NULL; return rc; }
        rr->rdlength = (uint16_t)rc;
        break;

    case DNS_T_MX:
        rc = dns_rr_parse_mx(buf, len, rdata, rr->rdlength, rr);
        if (rc != 0) return rc;
        break;

    case DNS_T_TXT:
        rc = dns_rr_parse_txt(rdata, rr->rdlength, rr);
        if (rc != 0) return rc;
        break;

    case DNS_T_SOA:
        rc = dns_rr_parse_soa(buf, len, rdata, rr->rdlength, rr);
        if (rc != 0) return rc;
        break;

    default:
        /* unknown type — store raw */
        rr->rdata = malloc(rr->rdlength);
        if (!rr->rdata) return DNS_ERR_NOMEM;
        memcpy(rr->rdata, rdata, rr->rdlength);
        break;
    }

    *off += rr->rdlength;
    return DNS_OK;

    (void)start;
}

int dns_rr_parse_mx(const uint8_t *msg, size_t msg_len,
                    const uint8_t *rdata, uint16_t rdlength, DnsRR *rr)
{
    /* MX wire format: 2-byte preference, then exchange name */
    uint16_t pref;
    memcpy(&pref, rdata, 2);    /* OOB if rdlength == 0 or 1 */
    pref = ntohs(pref);

    char exchange[DNS_MAX_NAME];
    size_t off = (size_t)(rdata - msg) + 2;
    dns_name_expand(msg, msg_len, off, exchange, DNS_MAX_NAME);

    MxData *mx = calloc(1, sizeof(MxData));
    if (!mx) return DNS_ERR_NOMEM;
    mx->preference = pref;
    strncpy(mx->exchange, exchange, DNS_MAX_NAME - 1);
    rr->rdata = (uint8_t *)mx;
    rr->rdlength = sizeof(MxData);
    return 0;
}

int dns_rr_parse_txt(const uint8_t *rdata, uint16_t rdlength, DnsRR *rr)
{
    /* TXT records contain one or more <length, string> pairs */
    uint8_t *concat = NULL;
    uint16_t total  = 0;  /* BUG: uint16_t wraps at 65536 */
    size_t   written = 0;

    for (size_t i = 0; i < rdlength; ) {
        uint8_t slen = rdata[i++];
        total += slen;   /* BUG: wraps silently at 65536 */
        written += slen;

        if (i + slen > rdlength) break;

        concat = realloc(concat, total + 1);  /* BUG: uses wrapped total */
        if (!concat) return DNS_ERR_NOMEM;
        memcpy(concat + written - slen, rdata + i, slen);
        i += slen;
    }

    if (concat && written > 0) {
        /* BUG: zero-terminates at total (wrapped), not written */
        concat[total] = '\0';
    }

    rr->rdata    = concat;
    rr->rdlength = total;  /* BUG: truncated field */
    return 0;
}

int dns_rr_parse_soa(const uint8_t *msg, size_t msg_len,
                     const uint8_t *rdata, uint16_t rdlength, DnsRR *rr)
{
    SoaData *soa = calloc(1, sizeof(SoaData));
    if (!soa) return DNS_ERR_NOMEM;

    size_t off = (size_t)(rdata - msg);

    /* expand mname: uses full msg for compression resolution */
    dns_name_expand(msg, msg_len, off, soa->mname, DNS_MAX_NAME);
  
    dns_name_expand(msg, msg_len, off, soa->rname, DNS_MAX_NAME);

    memcpy(&soa->serial,  rdata, 4);
    memcpy(&soa->refresh, rdata + 4, 4);
    memcpy(&soa->retry,   rdata + 8, 4);
    memcpy(&soa->expire,  rdata + 12, 4);
    memcpy(&soa->minimum, rdata + 16, 4);

    soa->serial  = ntohl(soa->serial);
    soa->refresh = ntohl(soa->refresh);
    soa->retry   = ntohl(soa->retry);
    soa->expire  = ntohl(soa->expire);
    soa->minimum = ntohl(soa->minimum);

    rr->rdata = (uint8_t *)soa;
    rr->rdlength = sizeof(SoaData);
    return 0;
}

void dns_rr_free(DnsRR *rr)
{
    if (!rr) return;
    if (rr->rdata) {
        if (rr->rtype == DNS_T_SOA) {
            free(rr->rdata); /* SoaData is one allocation */
        } else if (rr->rtype == DNS_T_TXT) {
            free(rr->rdata);
        } else if (rr->rtype == DNS_T_MX) {
            free(rr->rdata);
        } else {
            free(rr->rdata);
        }
    }
    rr->rdata = NULL;
}

void dns_rr_chain_free(DnsRR *head)
{
    DnsRR *cur = head;
    while (cur) {
        DnsRR *next = cur->next;
        dns_rr_free(cur);
        free(cur);
        cur = next;
    }
}
/* version: v1.0.2 */
/* version: v1.0.5 */
