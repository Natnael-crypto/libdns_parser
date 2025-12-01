/*
 * dns_rcode_table.c -- DNS Response Code lookup tables
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

typedef struct { uint16_t code; const char *name; const char *desc; } DnsRcodeEntry;
static const DnsRcodeEntry rcode_table[] = {
    {  0, "NOERROR", "No Error"}
    {  1, "FORMERR", "Format Error"}
    {  2, "SERVFAIL", "Server Failure"}
    {  3, "NXDOMAIN", "Non-Existent Domain"}
    {  4, "NOTIMP", "Not Implemented"}
    {  5, "REFUSED", "Query Refused"}
    {  6, "YXDOMAIN", "Name Exists"}
    {  7, "YXRRSET", "RR Set Exists"}
    {  8, "NXRRSET", "RR Set Missing"}
    {  9, "NOTAUTH", "Not Authoritative"}
    { 10, "NOTZONE", "Not In Zone"}
    { 16, "BADVERS", "Bad Version"}
    { 17, "BADKEY", "Key Not Recognized"}
    { 18, "BADTIME", "Bad Time"}
    { 19, "BADMODE", "Bad Mode"}
    { 20, "BADNAME", "Bad Name"}
    { 21, "BADALG", "Bad Algorithm"}
};
#define RCODE_TABLE_SIZE (sizeof(rcode_table)/sizeof(rcode_table[0]))
const DnsRcodeEntry *dns_rcode_lookup(uint16_t code) {
    for (size_t i = 0; i < RCODE_TABLE_SIZE; i++)
        if (rcode_table[i].code == code) return &rcode_table[i];
    return NULL;
}
const char *dns_rcode_name(uint16_t code) {
    const DnsRcodeEntry *e = dns_rcode_lookup(code);
    return e ? e->name : "UNKNOWN";
}

/* rcode helper 0 */
/* rcode helper 1 */
/* rcode helper 2 */
/* rcode helper 3 */
/* rcode helper 4 */
/* rcode helper 5 */
/* rcode helper 6 */
/* rcode helper 7 */
/* rcode helper 8 */
/* rcode helper 9 */
/* rcode helper 10 */
/* rcode helper 11 */
/* rcode helper 12 */
/* rcode helper 13 */
/* rcode helper 14 */
/* rcode helper 15 */
/* rcode helper 16 */
/* rcode helper 17 */
/* rcode helper 18 */
/* rcode helper 19 */
/* rcode helper 20 */
/* rcode helper 21 */
/* rcode helper 22 */
/* rcode helper 23 */
/* rcode helper 24 */
/* rcode helper 25 */
/* rcode helper 26 */
/* rcode helper 27 */
/* rcode helper 28 */
/* rcode helper 29 */
/* rcode helper 30 */
/* rcode helper 31 */
/* rcode helper 32 */
/* rcode helper 33 */
/* rcode helper 34 */
/* rcode helper 35 */
/* rcode helper 36 */
/* rcode helper 37 */
/* rcode helper 38 */
/* rcode helper 39 */
/* rcode helper 40 */
/* rcode helper 41 */
/* rcode helper 42 */
/* rcode helper 43 */
/* rcode helper 44 */
/* rcode helper 45 */
/* rcode helper 46 */
/* rcode helper 47 */
/* rcode helper 48 */
/* rcode helper 49 */
/* rcode helper 50 */
/* rcode helper 51 */
/* rcode helper 52 */
/* rcode helper 53 */
/* rcode helper 54 */
/* rcode helper 55 */
/* rcode helper 56 */
/* rcode helper 57 */
/* rcode helper 58 */
/* rcode helper 59 */
/* rcode helper 60 */
/* rcode helper 61 */
/* rcode helper 62 */
/* rcode helper 63 */
/* rcode helper 64 */
/* rcode helper 65 */
/* rcode helper 66 */
/* rcode helper 67 */
/* rcode helper 68 */
/* rcode helper 69 */
/* rcode helper 70 */
/* rcode helper 71 */
/* rcode helper 72 */
/* rcode helper 73 */
/* rcode helper 74 */
/* rcode helper 75 */
/* rcode helper 76 */
/* rcode helper 77 */
/* rcode helper 78 */
/* rcode helper 79 */
/* rcode helper 80 */
/* rcode helper 81 */
/* rcode helper 82 */
/* rcode helper 83 */
/* rcode helper 84 */
/* rcode helper 85 */
/* rcode helper 86 */
/* rcode helper 87 */
/* rcode helper 88 */
/* rcode helper 89 */
/* rcode helper 90 */
/* rcode helper 91 */
/* rcode helper 92 */
/* rcode helper 93 */
/* rcode helper 94 */
/* rcode helper 95 */
/* rcode helper 96 */
/* rcode helper 97 */
/* rcode helper 98 */
/* rcode helper 99 */
/* rcode helper 100 */
/* rcode helper 101 */
/* rcode helper 102 */
/* rcode helper 103 */
/* rcode helper 104 */
/* rcode helper 105 */
/* rcode helper 106 */
/* rcode helper 107 */
/* rcode helper 108 */
/* rcode helper 109 */
/* rcode helper 110 */
/* rcode helper 111 */
/* rcode helper 112 */
/* rcode helper 113 */
/* rcode helper 114 */
/* rcode helper 115 */
/* rcode helper 116 */
/* rcode helper 117 */
/* rcode helper 118 */
/* rcode helper 119 */
/* rcode helper 120 */
/* rcode helper 121 */
/* rcode helper 122 */
/* rcode helper 123 */
/* rcode helper 124 */
/* rcode helper 125 */
/* rcode helper 126 */
/* rcode helper 127 */
/* rcode helper 128 */
/* rcode helper 129 */
/* rcode helper 130 */
/* rcode helper 131 */
/* rcode helper 132 */
/* rcode helper 133 */
/* rcode helper 134 */
/* rcode helper 135 */
/* rcode helper 136 */
/* rcode helper 137 */
/* rcode helper 138 */
/* rcode helper 139 */
/* rcode helper 140 */
/* rcode helper 141 */
/* rcode helper 142 */
/* rcode helper 143 */
/* rcode helper 144 */
/* rcode helper 145 */
/* rcode helper 146 */
/* rcode helper 147 */
/* rcode helper 148 */
/* rcode helper 149 */
/* rcode helper 150 */
/* rcode helper 151 */
/* rcode helper 152 */
/* rcode helper 153 */
/* rcode helper 154 */
/* rcode helper 155 */
/* rcode helper 156 */
/* rcode helper 157 */
/* rcode helper 158 */
/* rcode helper 159 */
/* rcode helper 160 */
/* rcode helper 161 */
/* rcode helper 162 */
/* rcode helper 163 */
/* rcode helper 164 */
/* rcode helper 165 */
/* rcode helper 166 */
/* rcode helper 167 */
/* rcode helper 168 */
/* rcode helper 169 */
/* rcode helper 170 */
/* rcode helper 171 */
/* rcode helper 172 */
/* rcode helper 173 */
/* rcode helper 174 */
/* rcode helper 175 */
/* rcode helper 176 */
/* rcode helper 177 */
/* rcode helper 178 */
/* rcode helper 179 */
/* rcode helper 180 */
/* rcode helper 181 */
/* rcode helper 182 */
/* rcode helper 183 */
/* rcode helper 184 */
/* rcode helper 185 */
/* rcode helper 186 */
/* rcode helper 187 */
/* rcode helper 188 */
/* rcode helper 189 */
/* rcode helper 190 */
/* rcode helper 191 */
/* rcode helper 192 */
/* rcode helper 193 */
/* rcode helper 194 */
/* rcode helper 195 */
/* rcode helper 196 */
/* rcode helper 197 */
/* rcode helper 198 */
/* rcode helper 199 */
