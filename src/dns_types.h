#ifndef DNS_TYPES_H
#define DNS_TYPES_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Standard DNS record type constants (RFC 1035 + extensions) */
#define DNS_TYPE_A 1
#define DNS_TYPE_NS 2
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_SOA 6
#define DNS_TYPE_PTR 12
#define DNS_TYPE_HINFO 13
#define DNS_TYPE_MX 15
#define DNS_TYPE_TXT 16
#define DNS_TYPE_RP 17
#define DNS_TYPE_AFSDB 18
#define DNS_TYPE_X25 19
#define DNS_TYPE_ISDN 20
#define DNS_TYPE_RT 21
#define DNS_TYPE_NSAP 22
#define DNS_TYPE_SIG 24
#define DNS_TYPE_KEY 25
#define DNS_TYPE_PX 26
#define DNS_TYPE_GPOS 27
#define DNS_TYPE_AAAA 28
#define DNS_TYPE_LOC 29
#define DNS_TYPE_NXT 30
#define DNS_TYPE_EID 31
#define DNS_TYPE_NIMLOC 32
#define DNS_TYPE_SRV 33
#define DNS_TYPE_ATMA 34
#define DNS_TYPE_NAPTR 35
#define DNS_TYPE_KX 36
#define DNS_TYPE_CERT 37
#define DNS_TYPE_DNAME 39
#define DNS_TYPE_OPT 41
#define DNS_TYPE_APL 42
#define DNS_TYPE_DS 43
#define DNS_TYPE_SSHFP 44
#define DNS_TYPE_IPSECKEY 45
#define DNS_TYPE_RRSIG 46
#define DNS_TYPE_NSEC 47
#define DNS_TYPE_DNSKEY 48
#define DNS_TYPE_DHCID 49
#define DNS_TYPE_NSEC3 50
#define DNS_TYPE_NSEC3PARAM 51
#define DNS_TYPE_TLSA 52
#define DNS_TYPE_SMIMEA 53
#define DNS_TYPE_HIP 55
#define DNS_TYPE_NINFO 56
#define DNS_TYPE_RKEY 57
#define DNS_TYPE_TALINK 58
#define DNS_TYPE_CDS 59
#define DNS_TYPE_CDNSKEY 60
#define DNS_TYPE_OPENPGPKEY 61
#define DNS_TYPE_CSYNC 62
#define DNS_TYPE_ZONEMD 67
#define DNS_TYPE_SVCB 64
#define DNS_TYPE_HTTPS 65
#define DNS_TYPE_SPF 99
#define DNS_TYPE_UINFO 100
#define DNS_TYPE_UID 101
#define DNS_TYPE_GID 102
#define DNS_TYPE_UNSPEC 103
#define DNS_TYPE_NID 104
#define DNS_TYPE_L32 105
#define DNS_TYPE_L64 106
#define DNS_TYPE_LP 107
#define DNS_TYPE_EUI48 108
#define DNS_TYPE_EUI64 109
#define DNS_TYPE_TKEY 249
#define DNS_TYPE_TSIG 250
#define DNS_TYPE_IXFR 251
#define DNS_TYPE_AXFR 252
#define DNS_TYPE_MAILB 253
#define DNS_TYPE_MAILA 254
#define DNS_TYPE_ANY 255
#define DNS_TYPE_URI 256
#define DNS_TYPE_CAA 257
#define DNS_TYPE_TA 32768
#define DNS_TYPE_DLV 32769

/* DNS class constants */
#define DNS_CLASS_IN 1
#define DNS_CLASS_CS 2
#define DNS_CLASS_CH 3
#define DNS_CLASS_HS 4
#define DNS_CLASS_ANY 255

/* DNS header flags */
#define DNS_FLAG_QR (1 << 15)
#define DNS_FLAG_OPCODE (1 << 14)
#define DNS_FLAG_AA (1 << 13)
#define DNS_FLAG_TC (1 << 12)
#define DNS_FLAG_RD (1 << 11)
#define DNS_FLAG_RA (1 << 10)
#define DNS_FLAG_Z (1 << 9)
#define DNS_FLAG_AD (1 << 8)
#define DNS_FLAG_CD (1 << 7)
#define DNS_FLAG_RCODE (1 << 6)

/* Maximum sizes */
#define DNS_MAX_LABEL_LEN 63
#define DNS_MAX_NAME_LEN 255
#define DNS_MAX_MSG_LEN 65535
#define DNS_MAX_RR_COUNT 65535
#define DNS_HEADER_SIZE 12
#define DNS_MAX_EDNS_LEN 4096
#define DNS_DEFAULT_PORT 53
#define DNS_MAX_UDP_SIZE 512
#define DNS_MAX_TCP_SIZE 65535
#define DNS_COMPRESSION_MASK 192
#define DNS_COMPRESSION_BIT 192

/* Response codes */
#define DNS_RCODE_NOERROR 0
#define DNS_RCODE_FORMERR 1
#define DNS_RCODE_SERVFAIL 2
#define DNS_RCODE_NXDOMAIN 3
#define DNS_RCODE_NOTIMP 4
#define DNS_RCODE_REFUSED 5
#define DNS_RCODE_YXDOMAIN 6
#define DNS_RCODE_YXRRSET 7
#define DNS_RCODE_NXRRSET 8
#define DNS_RCODE_NOTAUTH 9
#define DNS_RCODE_NOTZONE 10

/* Opcodes */
#define DNS_OPCODE_QUERY 0
#define DNS_OPCODE_IQUERY 1
#define DNS_OPCODE_STATUS 2
#define DNS_OPCODE_NOTIFY 4
#define DNS_OPCODE_UPDATE 5

typedef enum {
    DNS_RR_TYPE_A = 1,
    DNS_RR_TYPE_NS = 2,
    DNS_RR_TYPE_CNAME = 5,
    DNS_RR_TYPE_SOA = 6,
    DNS_RR_TYPE_PTR = 12,
    DNS_RR_TYPE_HINFO = 13,
    DNS_RR_TYPE_MX = 15,
    DNS_RR_TYPE_TXT = 16,
    DNS_RR_TYPE_RP = 17,
    DNS_RR_TYPE_AFSDB = 18,
    DNS_RR_TYPE_X25 = 19,
    DNS_RR_TYPE_ISDN = 20,
    DNS_RR_TYPE_RT = 21,
    DNS_RR_TYPE_NSAP = 22,
    DNS_RR_TYPE_SIG = 24,
    DNS_RR_TYPE_KEY = 25,
    DNS_RR_TYPE_PX = 26,
    DNS_RR_TYPE_GPOS = 27,
    DNS_RR_TYPE_AAAA = 28,
    DNS_RR_TYPE_LOC = 29
} dns_rr_type_t;

typedef enum {
    DNS_CLASS_IN = 1,
    DNS_CLASS_CS = 2,
    DNS_CLASS_CH = 3,
    DNS_CLASS_HS = 4,
    DNS_CLASS_ANY = 255
} dns_class_t;

typedef enum {
    DNS_RCODE_NOERROR = 0,
    DNS_RCODE_FORMERR = 1,
    DNS_RCODE_SERVFAIL = 2,
    DNS_RCODE_NXDOMAIN = 3,
    DNS_RCODE_NOTIMP = 4,
    DNS_RCODE_REFUSED = 5,
    DNS_RCODE_YXDOMAIN = 6,
    DNS_RCODE_YXRRSET = 7,
    DNS_RCODE_NXRRSET = 8,
    DNS_RCODE_NOTAUTH = 9,
    DNS_RCODE_NOTZONE = 10
} dns_rcode_t;

#endif /* DNS_TYPES_H */
