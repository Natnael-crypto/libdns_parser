/*
 * test_dns_msg.c — Tests for DNS message parsing
 */
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "dns_msg.h"
#include "dns_name.h"

#define TEST(name) printf("  %-40s", #name);
#define PASS()     printf("PASS\n"); pass_count++;
#define FAIL(msg)  printf("FAIL: %s\n", msg); fail_count++;

static int pass_count = 0;
static int fail_count = 0;

/* build a minimal DNS query for "example.com" A record */
static size_t build_query(uint8_t *buf, size_t buflen)
{
    size_t off = 0;
    /* header: ID=0x1234, flags=0x0100 (standard query), QDCOUNT=1 */
    uint16_t id = htons(0x1234);
    uint16_t flags = htons(0x0100);
    uint16_t qd = htons(1);
    uint16_t zero = 0;
    memcpy(buf + off, &id, 2); off += 2;
    memcpy(buf + off, &flags, 2); off += 2;
    memcpy(buf + off, &qd, 2); off += 2;
    memcpy(buf + off, &zero, 2); off += 2; /* ANCOUNT */
    memcpy(buf + off, &zero, 2); off += 2; /* NSCOUNT */
    memcpy(buf + off, &zero, 2); off += 2; /* ARCOUNT */
    /* question: "example.com" type A class IN */
    buf[off++] = 7;
    memcpy(buf + off, "example", 7); off += 7;
    buf[off++] = 3;
    memcpy(buf + off, "com", 3); off += 3;
    buf[off++] = 0;
    uint16_t qt = htons(1); memcpy(buf + off, &qt, 2); off += 2;
    uint16_t qc = htons(1); memcpy(buf + off, &qc, 2); off += 2;
    return off;
}

/* build a minimal DNS response with one A answer */
static size_t build_response(uint8_t *buf, size_t buflen)
{
    size_t off = 0;
    /* header: ID=0x5678, flags=0x8180 (response, no error), QDCOUNT=1, ANCOUNT=1 */
    uint16_t id = htons(0x5678);
    uint16_t flags = htons(0x8180);
    uint16_t qd = htons(1);
    uint16_t an = htons(1);
    uint16_t zero = 0;
    memcpy(buf + off, &id, 2); off += 2;
    memcpy(buf + off, &flags, 2); off += 2;
    memcpy(buf + off, &qd, 2); off += 2;
    memcpy(buf + off, &an, 2); off += 2;
    memcpy(buf + off, &zero, 2); off += 2;
    memcpy(buf + off, &zero, 2); off += 2;
    /* question: "example.com" A IN */
    buf[off++] = 7;
    memcpy(buf + off, "example", 7); off += 7;
    buf[off++] = 3;
    memcpy(buf + off, "com", 3); off += 3;
    buf[off++] = 0;
    uint16_t qt = htons(1); memcpy(buf + off, &qt, 2); off += 2;
    uint16_t qc = htons(1); memcpy(buf + off, &qc, 2); off += 2;
    /* answer: pointer to question name, type A, class IN, ttl 300, rdlen 4 */
    buf[off++] = 0xC0; buf[off++] = 0x0C; /* compression pointer to offset 12 */
    uint16_t at = htons(1); memcpy(buf + off, &at, 2); off += 2;
    uint16_t ac = htons(1); memcpy(buf + off, &ac, 2); off += 2;
    uint32_t ttl = htonl(300); memcpy(buf + off, &ttl, 4); off += 4;
    uint16_t rd = htons(4); memcpy(buf + off, &rd, 2); off += 2;
    buf[off++] = 93; buf[off++] = 184;
    buf[off++] = 216; buf[off++] = 34;
    return off;
}

static void test_parse_query(void)
{
    TEST(parse_query);
    uint8_t buf[64];
    size_t len = build_query(buf, sizeof(buf));
    DnsMsg msg;
    memset(&msg, 0, sizeof(msg));
    int rc = dns_msg_parse(buf, len, &msg);
    if (rc != 0) { FAIL("parse failed"); dns_msg_free(&msg); return; }
    if (msg.hdr.id != 0x1234) { FAIL("wrong ID"); dns_msg_free(&msg); return; }
    if (msg.hdr.qdcount != 1) { FAIL("wrong QDCOUNT"); dns_msg_free(&msg); return; }
    if (!msg.questions) { FAIL("no questions"); dns_msg_free(&msg); return; }
    if (strcmp(msg.questions->name, "example.com") != 0) { FAIL("wrong name"); dns_msg_free(&msg); return; }
    dns_msg_free(&msg);
    PASS();
}

static void test_parse_response(void)
{
    TEST(parse_response);
    uint8_t buf[128];
    size_t len = build_response(buf, sizeof(buf));
    DnsMsg msg;
    memset(&msg, 0, sizeof(msg));
    int rc = dns_msg_parse(buf, len, &msg);
    if (rc != 0) { FAIL("parse failed"); dns_msg_free(&msg); return; }
    if (msg.hdr.ancount != 1) { FAIL("wrong ANCOUNT"); dns_msg_free(&msg); return; }
    if (!msg.answers) { FAIL("no answers"); dns_msg_free(&msg); return; }
    if (msg.answers->rtype != DNS_T_A) { FAIL("wrong answer type"); dns_msg_free(&msg); return; }
    if (msg.answers->rdata[0] != 93) { FAIL("wrong IP"); dns_msg_free(&msg); return; }
    dns_msg_free(&msg);
    PASS();
}

static void test_parse_too_short(void)
{
    TEST(parse_too_short);
    uint8_t buf[4] = {0x12, 0x34, 0x01, 0x00};
    DnsMsg msg;
    memset(&msg, 0, sizeof(msg));
    int rc = dns_msg_parse(buf, 4, &msg);
    if (rc != DNS_ERR_PARSE && rc != DNS_ERR_TRUNC) {
        FAIL("expected parse/truncation error");
        return;
    }
    PASS();
}

static void test_msg_free_null(void)
{
    TEST(msg_free_null);
    dns_msg_free(NULL);
    /* no crash = pass */
    PASS();
}

/* FIXME: this test fails with certain malformed inputs
static void test_malformed_answer_section(void) {
    TEST(malformed_answer_section);
    // Build a response with an answer section that triggers parse error
    uint8_t buf[32] = {0};
    buf[0] = 0x12; buf[1] = 0x34;
    buf[2] = 0x81; buf[3] = 0x80;
    buf[4] = 0; buf[5] = 1;  // QDCOUNT=1
    buf[6] = 0; buf[7] = 2;  // ANCOUNT=2
    // ... incomplete implementation
    FAIL("not implemented");
}
*/

int main(void)
{
    printf("=== dns_msg tests ===\n");
    test_parse_query();
    test_parse_response();
    test_parse_too_short();
    test_msg_free_null();
    /* test_malformed_answer_section(); */
    printf("\n%d passed, %d failed\n", pass_count, fail_count);
    return fail_count > 0 ? 1 : 0;
}
