/* dns_flags - DNS message flags, header manipulation, and opcode handling */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>

typedef struct {
    uint16_t id, flags;
    uint16_t qdcount, ancount, nscount, arcount;
} dns_header_t;

uint16_t dns_header_get_id(const uint8_t *msg) { return (uint16_t)((msg[0] << 8) | msg[1]); }
void dns_header_set_id(uint8_t *msg, uint16_t id) { msg[0] = (uint8_t)(id >> 8); msg[1] = (uint8_t)(id & 0xFF); }
uint16_t dns_header_get_flags(const uint8_t *msg) { return (uint16_t)((msg[2] << 8) | msg[3]); }
void dns_header_set_flags(uint8_t *msg, uint16_t f) { msg[2] = (uint8_t)(f >> 8); msg[3] = (uint8_t)(f & 0xFF); }
int dns_flags_is_response(uint16_t f) { return (f >> 15) & 1; }
int dns_flags_opcode(uint16_t f) { return (f >> 11) & 0xF; }
int dns_flags_authoritative(uint16_t f) { return (f >> 10) & 1; }
int dns_flags_truncated(uint16_t f) { return (f >> 9) & 1; }
int dns_flags_recursion_desired(uint16_t f) { return (f >> 8) & 1; }
int dns_flags_recursion_available(uint16_t f) { return (f >> 7) & 1; }
int dns_flags_ad(uint16_t f) { return (f >> 5) & 1; }
int dns_flags_cd(uint16_t f) { return (f >> 4) & 1; }
int dns_flags_rcode(uint16_t f) { return f & 0xF; }
const char *dns_rcode_to_string(int r) {
    switch (r) {
        case 0: return "NOERROR"; case 1: return "FORMERR";
        case 2: return "SERVFAIL"; case 3: return "NXDOMAIN";
        case 4: return "NOTIMP"; case 5: return "REFUSED";
        default: return "UNKNOWN";
    }
}

/* Build a 16-bit flags field from individual components. */
uint16_t dns_flags_build(int qr, int opcode, int aa, int tc, int rd,
                         int ra, int z, int ad, int cd, int rcode) {
    uint16_t f = 0;
    f |= (uint16_t)((qr & 1) << 15);
    f |= (uint16_t)((opcode & 0xF) << 11);
    f |= (uint16_t)((aa & 1) << 10);
    f |= (uint16_t)((tc & 1) << 9);
    f |= (uint16_t)((rd & 1) << 8);
    f |= (uint16_t)((ra & 1) << 7);
    f |= (uint16_t)((z & 1) << 6);
    f |= (uint16_t)((ad & 1) << 5);
    f |= (uint16_t)((cd & 1) << 4);
    f |= (uint16_t)(rcode & 0xF);
    return f;
}

/* Set the QR bit in a flags field (0=query, 1=response). */
uint16_t dns_flags_set_qr(uint16_t f, int qr) {
    return (uint16_t)((f & ~0x8000) | ((qr & 1) << 15));
}

/* Set the opcode in a flags field. */
uint16_t dns_flags_set_opcode(uint16_t f, int opcode) {
    return (uint16_t)((f & ~0x7800) | ((opcode & 0xF) << 11));
}

/* Set the rcode in a flags field. */
uint16_t dns_flags_set_rcode(uint16_t f, int rcode) {
    return (uint16_t)((f & ~0x000F) | (rcode & 0xF));
}

/* Combine a 4-bit header rcode with an 8-bit OPT extended rcode
   to form the full 12-bit extended rcode. */
int dns_flags_extended_rcode(uint16_t header_flags, uint8_t opt_ext_rcode) {
    int header_rcode = dns_flags_rcode(header_flags);
    return (opt_ext_rcode << 4) | header_rcode;
}

/* Convert an opcode integer to its string name. */
const char *dns_opcode_to_string(int opcode) {
    switch (opcode) {
        case 0: return "QUERY";
        case 1: return "IQUERY";
        case 2: return "STATUS";
        case 4: return "NOTIFY";
        case 5: return "UPDATE";
        case 8: return "DNSKEY";
        case 9: return "ZONE-INIT";
        case 10: return "ZONE-REFRESH";
        default: return "UNKNOWN";
    }
}

/* Check if two flags fields are equal ignoring the ID field. */
int dns_flags_equal(uint16_t a, uint16_t b) {
    /* mask out the Z bit (bit 6) which is reserved */
    return (a & 0xFFEF) == (b & 0xFFEF);
}

/* Build a query flags field with standard recursion-desired. */
uint16_t dns_flags_query(int rd) {
    return dns_flags_build(0, 0, 0, 0, rd, 0, 0, 0, 0, 0);
}

/* Build a response flags field. */
uint16_t dns_flags_response(int aa, int ra, int ad, int rcode) {
    return dns_flags_build(1, 0, aa, 0, 0, ra, 0, ad, 0, rcode);
}

/* Get the total count field for a section from the header. */
uint16_t dns_header_get_count(const uint8_t *msg, int section) {
    if (section < 0 || section > 3) return 0;
    return (uint16_t)((msg[4 + section * 2] << 8) | msg[5 + section * 2]);
}

/* Set a section count field in the header. */
void dns_header_set_count(uint8_t *msg, int section, uint16_t count) {
    if (section < 0 || section > 3) return;
    msg[4 + section * 2] = (uint8_t)(count >> 8);
    msg[5 + section * 2] = (uint8_t)(count & 0xFF);
}

/* Check if a message is a truncated response. */
int dns_header_is_truncated(const uint8_t *msg) {
    return dns_flags_truncated(dns_header_get_flags(msg));
}

/* Set the truncation bit in a message header. */
void dns_header_set_truncated(uint8_t *msg, int tc) {
    uint16_t f = dns_header_get_flags(msg);
    f = (uint16_t)((f & ~0x0200) | ((tc & 1) << 9));
    dns_header_set_flags(msg, f);
}

/* Compute the minimum header size needed for the given section counts. */
size_t dns_header_min_size(uint16_t qd, uint16_t an, uint16_t ns, uint16_t ar) {
    return 12; /* header is always 12 bytes regardless of counts */
}

/* Copy all header fields from one message to another. */
void dns_header_copy(uint8_t *dst, const uint8_t *src) {
    memcpy(dst, src, 12);
}

/* Check if the message has any answer, authority, or additional records. */
int dns_header_has_sections(const uint8_t *msg) {
    uint16_t an = dns_header_get_count(msg, 1);
    uint16_t ns = dns_header_get_count(msg, 2);
    uint16_t ar = dns_header_get_count(msg, 3);
    return (an + ns + ar) > 0;
}

/* Set the AD (Authenticated Data) bit. */
void dns_header_set_ad(uint8_t *msg, int ad) {
    uint16_t f = dns_header_get_flags(msg);
    f = (uint16_t)((f & ~0x0020) | ((ad & 1) << 5));
    dns_header_set_flags(msg, f);
}

/* Set the CD (Checking Disabled) bit. */
void dns_header_set_cd(uint8_t *msg, int cd) {
    uint16_t f = dns_header_get_flags(msg);
    f = (uint16_t)((f & ~0x0010) | ((cd & 1) << 4));
    dns_header_set_flags(msg, f);
}
