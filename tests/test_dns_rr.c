/*
 * test_dns_rr.c — Tests for DNS resource record parsing
 */
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "dns_rr.h"
#include "dns_name.h"

#define TEST(name) printf("  %-40s", #name);
#define PASS()     printf("PASS\n"); pass_count++;
#define FAIL(msg)  printf("FAIL: %s\n", msg); fail_count++;

static int pass_count = 0;
static int fail_count = 0;

/* build a minimal A record RR starting at offset 12 in buf */
static size_t build_a_rr(uint8_t *buf, size_t buflen)
{
    size_t off = 0;
    /* name: "test\0" */
    buf[off++] = 4;
    memcpy(buf + off, "test", 4); off += 4;
    buf[off++] = 0;
    /* type A, class IN, ttl 300, rdlen 4 */
    uint16_t t = htons(1); memcpy(buf + off, &t, 2); off += 2;
    uint16_t c = htons(1); memcpy(buf + off, &c, 2); off += 2;
    uint32_t ttl = htonl(300); memcpy(buf + off, &ttl, 4); off += 4;
    uint16_t rd = htons(4); memcpy(buf + off, &rd, 2); off += 2;
    /* rdata: 93.184.216.34 */
    buf[off++] = 93; buf[off++] = 184;
    buf[off++] = 216; buf[off++] = 34;
    return off;
}

static void test_parse_a_record(void)
{
    TEST(parse_a_record);
    uint8_t buf[64];
    memset(buf, 0, sizeof(buf));
    size_t len = build_a_rr(buf, sizeof(buf));
    size_t off = 0;
    DnsRR rr;
    memset(&rr, 0, sizeof(rr));
    int rc = dns_rr_parse(buf, len, &off, &rr);
    if (rc != 0) { FAIL("parse failed"); dns_rr_free(&rr); return; }
    if (rr.rtype != DNS_T_A) { FAIL("wrong type"); dns_rr_free(&rr); return; }
    if (rr.rdlength != 4) { FAIL("wrong rdlength"); dns_rr_free(&rr); return; }
    if (rr.rdata[0] != 93) { FAIL("wrong IP octet"); dns_rr_free(&rr); return; }
    dns_rr_free(&rr);
    PASS();
}

static void test_parse_cname_record(void)
{
    TEST(parse_cname_record);
    uint8_t buf[128];
    memset(buf, 0, sizeof(buf));
    size_t off = 0;
    /* name: "www\0" */
    buf[off++] = 3;
    memcpy(buf + off, "www", 3); off += 3;
    buf[off++] = 0;
    /* type CNAME=5, class IN, ttl 300 */
    uint16_t t = htons(5); memcpy(buf + off, &t, 2); off += 2;
    uint16_t c = htons(1); memcpy(buf + off, &c, 2); off += 2;
    uint32_t ttl = htonl(300); memcpy(buf + off, &ttl, 4); off += 4;
    /* rdata: "example.com\0" in wire format */
    uint8_t target[] = {7,'e','x','a','m','p','l','e',3,'c','o','m',0};
    uint16_t rd = htons(sizeof(target));
    memcpy(buf + off, &rd, 2); off += 2;
    memcpy(buf + off, target, sizeof(target));
    size_t len = off + sizeof(target);

    off = 0;
    DnsRR rr;
    memset(&rr, 0, sizeof(rr));
    int rc = dns_rr_parse(buf, len, &off, &rr);
    if (rc != 0) { FAIL("parse failed"); dns_rr_free(&rr); return; }
    if (rr.rtype != DNS_T_CNAME) { FAIL("wrong type"); dns_rr_free(&rr); return; }
    if (strcmp((char *)rr.rdata, "example.com") != 0) { FAIL("wrong CNAME target"); dns_rr_free(&rr); return; }
    dns_rr_free(&rr);
    PASS();
}

static void test_rr_chain_free(void)
{
    TEST(rr_chain_free);
    DnsRR *head = NULL;
    for (int i = 0; i < 5; i++) {
        DnsRR *rr = calloc(1, sizeof(DnsRR));
        rr->rtype = DNS_T_A;
        rr->rdata = malloc(4);
        rr->next = head;
        head = rr;
    }
    dns_rr_chain_free(head);
    /* if we get here without ASan error, PASS */
    PASS();
}

static void test_parse_truncated_rr(void)
{
    TEST(parse_truncated_rr);
    uint8_t buf[4] = {0xC0, 0x00, 0x00};
    size_t off = 0;
    DnsRR rr;
    memset(&rr, 0, sizeof(rr));
    int rc = dns_rr_parse(buf, 3, &off, &rr);
    if (rc != DNS_ERR_TRUNC) { FAIL("expected truncation error"); return; }
    PASS();
}

int main(void)
{
    printf("=== dns_rr tests ===\n");
    test_parse_a_record();
    test_parse_cname_record();
    test_rr_chain_free();
    test_parse_truncated_rr();
    printf("\n%d passed, %d failed\n", pass_count, fail_count);
    return fail_count > 0 ? 1 : 0;
}
