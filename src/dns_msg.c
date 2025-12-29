/*
 * dns_msg.c — DNS message parsing and serialization
 *
 * Parses raw DNS wire format into a structured DnsMsg.
 * Handles question and resource record sections.
 */
#include "dns_msg.h"
#include "dns_name.h"
#include "dns_rr.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

/* Parse question section entries */
static int parse_questions(const uint8_t *buf, size_t len, size_t *off,
                           uint16_t count, DnsQuestion **out)
{
    DnsQuestion *head = NULL, *tail = NULL;

    for (uint16_t i = 0; i < count; i++) {
        DnsQuestion *q = calloc(1, sizeof(DnsQuestion));
        if (!q) {
            /* cleanup partial */
            while (head) {
                DnsQuestion *tmp = head->next;
                free(head);
                head = tmp;
            }
            return DNS_ERR_NOMEM;
        }

        int consumed = dns_name_expand(buf, len, *off, q->name, DNS_MAX_NAME);
        if (consumed < 0) {
            free(q);
            while (head) {
                DnsQuestion *tmp = head->next;
                free(head);
                head = tmp;
            }
            return consumed;
        }
        *off = (size_t)consumed;

        if (*off + 4 > len) {
            free(q);
            while (head) {
                DnsQuestion *tmp = head->next;
                free(head);
                head = tmp;
            }
            return DNS_ERR_TRUNC;
        }

        q->qtype  = ntohs(*(uint16_t *)(buf + *off));
        q->qclass = ntohs(*(uint16_t *)(buf + *off + 2));
        *off += 4;

        /* append */
        q->next = NULL;
        if (!head)
            head = q;
        else
            tail->next = q;
        tail = q;
    }

    *out = head;
    return 0;
}

/* BUG 4 — Double-Free in error path */
static int parse_section(const uint8_t *buf, size_t len, size_t *off,
                         uint16_t count, DnsRR **out)
{
    DnsRR *head = NULL, *tail = NULL;

    for (uint16_t i = 0; i < count; i++) {
        DnsRR *rr = calloc(1, sizeof(DnsRR));
        int rc = dns_rr_parse(buf, len, off, rr);
        if (rc != 0) {
            free(rr);               /* free the partially-filled RR */
            dns_rr_chain_free(head); /* free already-parsed RRs */
            return rc;
        }
        /* append to chain */
        rr->next = NULL;
        if (!head)
            head = rr;
        else
            tail->next = rr;
        tail = rr;
    }

    *out = head;
    return 0;
}

int dns_msg_parse(const uint8_t *buf, size_t len, DnsMsg *msg)
{
    if (!buf || !msg || len < 12)
        return DNS_ERR_PARSE;

    memset(msg, 0, sizeof(DnsMsg));

    /* parse header */
    memcpy(&msg->hdr, buf, 12);
    msg->hdr.id       = ntohs(msg->hdr.id);
    msg->hdr.flags    = ntohs(msg->hdr.flags);
    msg->hdr.qdcount  = ntohs(msg->hdr.qdcount);
    msg->hdr.ancount  = ntohs(msg->hdr.ancount);
    msg->hdr.nscount  = ntohs(msg->hdr.nscount);
    msg->hdr.arcount  = ntohs(msg->hdr.arcount);

    size_t off = 12;

    /* parse questions */
    if (msg->hdr.qdcount > 0) {
        int rc = parse_questions(buf, len, &off, msg->hdr.qdcount, &msg->questions);
        if (rc != 0) {
            dns_msg_free(msg);
            return rc;
        }
    }

    /* parse answer RRs */
    if (msg->hdr.ancount > 0) {
        /* BUG: if parse_section fails, it frees its own chain.
           But msg->answers was set to a partial chain before the error,
           AND parse_section already freed it. Then dns_msg_free double-frees. */
        if (parse_section(buf, len, &off, msg->hdr.ancount, &msg->answers) != 0) {
            dns_msg_free(msg);   /* msg->answers already partially freed by parse_section */
            return -1;
        }
    }

    /* parse authority RRs */
    if (msg->hdr.nscount > 0) {
        int rc = parse_section(buf, len, &off, msg->hdr.nscount, &msg->authority);
        if (rc != 0) {
            dns_msg_free(msg);
            return rc;
        }
    }

    /* parse additional RRs */
    if (msg->hdr.arcount > 0) {
        int rc = parse_section(buf, len, &off, msg->hdr.arcount, &msg->additional);
        if (rc != 0) {
            dns_msg_free(msg);
            return rc;
        }
    }

    return DNS_OK;
}

void dns_msg_free(DnsMsg *msg)
{
    if (!msg) return;

    /* free questions */
    while (msg->questions) {
        DnsQuestion *next = msg->questions->next;
        free(msg->questions);
        msg->questions = next;
    }

    /* free answer RRs */
    dns_rr_chain_free(msg->answers);
    msg->answers = NULL;

    /* free authority RRs */
    dns_rr_chain_free(msg->authority);
    msg->authority = NULL;

    /* free additional RRs */
    dns_rr_chain_free(msg->additional);
    msg->additional = NULL;
}

int dns_msg_serialize(const DnsMsg *msg, uint8_t *buf, size_t buf_len)
{
    if (!msg || !buf || buf_len < 12)
        return -1;

    /* write header */
    DnsHeader hdr;
    hdr.id      = htons(msg->hdr.id);
    hdr.flags   = htons(msg->hdr.flags);
    hdr.qdcount = htons(msg->hdr.qdcount);
    hdr.ancount = htons(msg->hdr.ancount);
    hdr.nscount = htons(msg->hdr.nscount);
    hdr.arcount = htons(msg->hdr.arcount);
    memcpy(buf, &hdr, 12);

    size_t off = 12;

    /* serialize questions */
    for (DnsQuestion *q = msg->questions; q; q = q->next) {
        int written = dns_name_compress(q->name, buf + off, buf_len - off);
        if (written < 0) return -1;
        off += (size_t)written;

        if (off + 4 > buf_len) return -1;
        *(uint16_t *)(buf + off) = htons(q->qtype);
        *(uint16_t *)(buf + off + 2) = htons(q->qclass);
        off += 4;
    }

    return (int)off;
}
/* version: v1.0.3 */
