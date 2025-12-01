#ifndef DNS_PARSER_DNS_H
#define DNS_PARSER_DNS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* DNS record types */
#define DNS_T_A       1
#define DNS_T_NS      2
#define DNS_T_CNAME   5
#define DNS_T_SOA     6
#define DNS_T_MX      15
#define DNS_T_TXT     16
#define DNS_T_AAAA    28
#define DNS_T_ANY     255

/* DNS classes */
#define DNS_CLASS_IN  1

/* Maximum name length (wire format) */
#define DNS_MAX_NAME  256

/* Maximum compression pointer depth */
#define DNS_MAX_PTRS  128

/* Error codes */
#define DNS_OK        0
#define DNS_ERR_PARSE -1
#define DNS_ERR_TRUNC -2
#define DNS_ERR_LOOP  -3
#define DNS_ERR_NOMEM -4

/* DNS header (12 bytes, network byte order) */
typedef struct DnsHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;   /* question count */
    uint16_t ancount;   /* answer count */
    uint16_t nscount;   /* authority count */
    uint16_t arcount;   /* additional count */
} DnsHeader;

/* DNS question */
typedef struct DnsQuestion {
    char     name[DNS_MAX_NAME];
    uint16_t qtype;
    uint16_t qclass;
} DnsQuestion;

/* DNS resource record — linked list node */
typedef struct DnsRR {
    char            name[DNS_MAX_NAME];
    uint16_t        rtype;
    uint16_t        rclass;
    uint32_t        ttl;
    uint16_t        rdlength;
    uint8_t        *rdata;       /* heap-allocated raw RDATA */
    struct DnsRR   *next;        /* next RR in section chain */
} DnsRR;

/* Parsed DNS message */
typedef struct DnsMsg {
    DnsHeader   hdr;
    DnsQuestion *questions;     /* linked list of questions */
    DnsRR       *answers;       /* linked list of answer RRs */
    DnsRR       *authority;     /* linked list of authority RRs */
    DnsRR       *additional;    /* linked list of additional RRs */
} DnsMsg;

/* SOA-specific decoded data (stored in DnsRR.rdata) */
typedef struct {
    char     mname[DNS_MAX_NAME];
    char     rname[DNS_MAX_NAME];
    uint32_t serial;
    uint32_t refresh;
    uint32_t retry;
    uint32_t expire;
    uint32_t minimum;
} SoaData;

/* MX-specific decoded data */
typedef struct {
    uint16_t preference;
    char     exchange[DNS_MAX_NAME];
} MxData;

/* TXT-specific decoded data */
typedef struct {
    uint8_t *data;
    size_t   length;
} TxtData;

#ifdef __cplusplus
}
#endif

#endif /* DNS_PARSER_DNS_H */
