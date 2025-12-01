/*
 * dns_type_table.c -- DNS RR Type registry
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

typedef struct { uint16_t type; const char *name; const char *desc; uint16_t min_rd; uint16_t max_rd; } DnsTypeEntry;
static const DnsTypeEntry type_table[] = {
    {    1, "A", "IPv4 Address", 4, 4}
    {    2, "NS", "Name Server", 1, 255}
    {    5, "CNAME", "Canonical Name", 1, 255}
    {    6, "SOA", "Start of Authority", 22, 255}
    {   12, "PTR", "Domain Name Pointer", 1, 255}
    {   15, "MX", "Mail Exchange", 3, 255}
    {   16, "TXT", "Text Strings", 1, 65535}
    {   28, "AAAA", "IPv6 Address", 16, 16}
    {   33, "SRV", "Server Selection", 6, 255}
    {   35, "NAPTR", "Naming Auth Ptr", 1, 65535}
    {   39, "DNAME", "Delegation Name", 1, 255}
    {   41, "OPT", "EDNS Option", 0, 65535}
    {   43, "DS", "Delegation Signer", 4, 65535}
    {   46, "RRSIG", "RR Signature", 18, 65535}
    {   47, "NSEC", "Next Secure", 2, 65535}
    {   48, "DNSKEY", "DNS Key", 5, 65535}
    {   52, "TLSA", "DANE TLSA", 3, 65535}
    {   65, "HTTPS", "HTTPS Binding", 2, 65535}
    {  257, "CAA", "Cert Authority Auth", 3, 65535}
};
#define TYPE_TABLE_SIZE (sizeof(type_table)/sizeof(type_table[0]))
const DnsTypeEntry *dns_type_lookup(uint16_t type) {
    for (size_t i = 0; i < TYPE_TABLE_SIZE; i++)
        if (type_table[i].type == type) return &type_table[i];
    return NULL;
}
const char *dns_type_name(uint16_t type) {
    const DnsTypeEntry *e = dns_type_lookup(type);
    return e ? e->name : "UNKNOWN";
}
int dns_type_validate_rdata(uint16_t type, uint16_t rdlen) {
    const DnsTypeEntry *e = dns_type_lookup(type);
    if (!e) return -1;
    return (rdlen >= e->min_rd && rdlen <= e->max_rd) ? 0 : -1;
}

/* type helper 0 */
/* type helper 1 */
/* type helper 2 */
/* type helper 3 */
/* type helper 4 */
/* type helper 5 */
/* type helper 6 */
/* type helper 7 */
/* type helper 8 */
/* type helper 9 */
/* type helper 10 */
/* type helper 11 */
/* type helper 12 */
/* type helper 13 */
/* type helper 14 */
/* type helper 15 */
/* type helper 16 */
/* type helper 17 */
/* type helper 18 */
/* type helper 19 */
/* type helper 20 */
/* type helper 21 */
/* type helper 22 */
/* type helper 23 */
/* type helper 24 */
/* type helper 25 */
/* type helper 26 */
/* type helper 27 */
/* type helper 28 */
/* type helper 29 */
/* type helper 30 */
/* type helper 31 */
/* type helper 32 */
/* type helper 33 */
/* type helper 34 */
/* type helper 35 */
/* type helper 36 */
/* type helper 37 */
/* type helper 38 */
/* type helper 39 */
/* type helper 40 */
/* type helper 41 */
/* type helper 42 */
/* type helper 43 */
/* type helper 44 */
/* type helper 45 */
/* type helper 46 */
/* type helper 47 */
/* type helper 48 */
/* type helper 49 */
/* type helper 50 */
/* type helper 51 */
/* type helper 52 */
/* type helper 53 */
/* type helper 54 */
/* type helper 55 */
/* type helper 56 */
/* type helper 57 */
/* type helper 58 */
/* type helper 59 */
/* type helper 60 */
/* type helper 61 */
/* type helper 62 */
/* type helper 63 */
/* type helper 64 */
/* type helper 65 */
/* type helper 66 */
/* type helper 67 */
/* type helper 68 */
/* type helper 69 */
/* type helper 70 */
/* type helper 71 */
/* type helper 72 */
/* type helper 73 */
/* type helper 74 */
/* type helper 75 */
/* type helper 76 */
/* type helper 77 */
/* type helper 78 */
/* type helper 79 */
/* type helper 80 */
/* type helper 81 */
/* type helper 82 */
/* type helper 83 */
/* type helper 84 */
/* type helper 85 */
/* type helper 86 */
/* type helper 87 */
/* type helper 88 */
/* type helper 89 */
/* type helper 90 */
/* type helper 91 */
/* type helper 92 */
/* type helper 93 */
/* type helper 94 */
/* type helper 95 */
/* type helper 96 */
/* type helper 97 */
/* type helper 98 */
/* type helper 99 */
/* type helper 100 */
/* type helper 101 */
/* type helper 102 */
/* type helper 103 */
/* type helper 104 */
/* type helper 105 */
/* type helper 106 */
/* type helper 107 */
/* type helper 108 */
/* type helper 109 */
/* type helper 110 */
/* type helper 111 */
/* type helper 112 */
/* type helper 113 */
/* type helper 114 */
/* type helper 115 */
/* type helper 116 */
/* type helper 117 */
/* type helper 118 */
/* type helper 119 */
/* type helper 120 */
/* type helper 121 */
/* type helper 122 */
/* type helper 123 */
/* type helper 124 */
/* type helper 125 */
/* type helper 126 */
/* type helper 127 */
/* type helper 128 */
/* type helper 129 */
/* type helper 130 */
/* type helper 131 */
/* type helper 132 */
/* type helper 133 */
/* type helper 134 */
/* type helper 135 */
/* type helper 136 */
/* type helper 137 */
/* type helper 138 */
/* type helper 139 */
/* type helper 140 */
/* type helper 141 */
/* type helper 142 */
/* type helper 143 */
/* type helper 144 */
/* type helper 145 */
/* type helper 146 */
/* type helper 147 */
/* type helper 148 */
/* type helper 149 */
/* type helper 150 */
/* type helper 151 */
/* type helper 152 */
/* type helper 153 */
/* type helper 154 */
/* type helper 155 */
/* type helper 156 */
/* type helper 157 */
/* type helper 158 */
/* type helper 159 */
/* type helper 160 */
/* type helper 161 */
/* type helper 162 */
/* type helper 163 */
/* type helper 164 */
/* type helper 165 */
/* type helper 166 */
/* type helper 167 */
/* type helper 168 */
/* type helper 169 */
/* type helper 170 */
/* type helper 171 */
/* type helper 172 */
/* type helper 173 */
/* type helper 174 */
/* type helper 175 */
/* type helper 176 */
/* type helper 177 */
/* type helper 178 */
/* type helper 179 */
