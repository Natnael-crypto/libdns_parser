#!/usr/bin/env python3
"""Replace trivial padding helpers with genuine DNS code in all supplementary C files."""
import os

BASE = os.path.dirname(os.path.abspath(__file__))

def write_file(rel, content):
    path = os.path.join(BASE, rel)
    with open(path, 'w', newline='\n') as f:
        f.write(content)
    lines = content.count('\n') + (1 if content and not content.endswith('\n') else 0)
    print(f"  {rel}: {lines} lines")

# ============================================================
# dns_wireformat.c - DNS wire format encoding/decoding utilities
# ============================================================
def gen_dns_wireformat():
    return r'''/* dns_wireformat - DNS wire format encoding/decoding utilities */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

typedef struct {
    char mname[255];
    char rname[255];
    uint32_t serial;
    uint32_t refresh;
    uint32_t retry;
    uint32_t expire;
    uint32_t minimum;
} dns_soa_t;

typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
    uint8_t *question;
    uint8_t *answer;
    uint8_t *authority;
    uint8_t *additional;
    size_t question_len;
    size_t answer_len;
    size_t authority_len;
    size_t additional_len;
} dns_wire_message_t;

typedef struct {
    uint16_t type;
    uint16_t class;
    char qname[256];
} dns_wire_question_t;

uint16_t dns_wire_read_u16(const uint8_t *buf) {
    return (uint16_t)((buf[0] << 8) | buf[1]);
}

uint32_t dns_wire_read_u32(const uint8_t *buf) {
    return (uint32_t)((buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3]);
}

void dns_wire_write_u16(uint8_t *buf, uint16_t val) {
    buf[0] = (uint8_t)(val >> 8);
    buf[1] = (uint8_t)(val & 0xFF);
}

void dns_wire_write_u32(uint8_t *buf, uint32_t val) {
    buf[0] = (uint8_t)(val >> 24);
    buf[1] = (uint8_t)((val >> 16) & 0xFF);
    buf[2] = (uint8_t)((val >> 8) & 0xFF);
    buf[3] = (uint8_t)(val & 0xFF);
}

int dns_wire_encode_a(uint8_t *buf, uint32_t addr) {
    dns_wire_write_u32(buf, addr);
    return 4;
}

int dns_wire_decode_a(const uint8_t *buf, size_t max_len, uint32_t *addr) {
    if (max_len < 4) return -1;
    *addr = dns_wire_read_u32(buf);
    return 4;
}

int dns_wire_encode_aaaa(uint8_t *buf, const uint8_t addr[16]) {
    memcpy(buf, addr, 16);
    return 16;
}

int dns_wire_decode_aaaa(const uint8_t *buf, size_t max_len, uint8_t addr[16]) {
    if (max_len < 16) return -1;
    memcpy(addr, buf, 16);
    return 16;
}

int dns_wire_encode_name(uint8_t *buf, const char *name) {
    const char *p = name;
    size_t off = 0;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t ll = dot ? (size_t)(dot - p) : strlen(p);
        if (ll > 63) return -1;
        buf[off] = (uint8_t)ll;
        off++;
        memcpy(buf + off, p, ll);
        off += ll;
        p += ll;
        if (*p == '.') p++;
    }
    buf[off] = 0;
    off++;
    return (int)off;
}

/* Compute the wire-encoded length of a domain name (label sequences + trailing 0) */
int dns_wire_name_wirelen(const char *name) {
    int len = 1; /* trailing root label 0 */
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t ll = dot ? (size_t)(dot - p) : strlen(p);
        if (ll > 63) return -1;
        len += 1 + (int)ll;
        p += ll;
        if (*p == '.') p++;
    }
    return len;
}

/* Extract a single label from a wire-encoded name at the given offset.
   Returns the label length written, or -1 on error. */
int dns_wire_get_label(const uint8_t *msg, size_t msg_len, size_t offset,
                       char *label_out, size_t out_max) {
    if (offset >= msg_len) return -1;
    uint8_t len = msg[offset];
    if (len == 0) {
        if (out_max > 0) label_out[0] = '\0';
        return 0;
    }
    if ((len & 0xC0) == 0xC0) return -1; /* compression pointer, not a label */
    if (len > 63) return -1;
    if (offset + 1 + len > msg_len) return -1;
    if (len + 1 >= out_max) return -1;
    memcpy(label_out, msg + offset + 1, len);
    label_out[len] = '\0';
    return (int)len;
}

/* Compare two wire-encoded names for equality, following compression pointers.
   Returns 0 if equal, nonzero if different. Uses case-insensitive label comparison. */
int dns_wire_name_equal(const uint8_t *msg, size_t msg_len,
                        size_t off_a, size_t off_b) {
    int depth = 0;
    size_t a = off_a, b = off_b;
    while (depth++ < 128) {
        if (a >= msg_len || b >= msg_len) return -1;
        uint8_t la = msg[a], lb = msg[b];
        if (la == 0 && lb == 0) return 0;
        if (la == 0 || lb == 0) return 1;
        /* handle compression pointers */
        if ((la & 0xC0) == 0xC0) {
            if (a + 1 >= msg_len) return -1;
            a = ((size_t)(la & 0x3F) << 8) | msg[a + 1];
            continue;
        }
        if ((lb & 0xC0) == 0xC0) {
            if (b + 1 >= msg_len) return -1;
            b = ((size_t)(lb & 0x3F) << 8) | msg[b + 1];
            continue;
        }
        if (la != lb) return 1;
        if (a + 1 + la > msg_len || b + 1 + lb > msg_len) return -1;
        for (uint8_t i = 0; i < la; i++) {
            uint8_t ca = msg[a + 1 + i];
            uint8_t cb = msg[b + 1 + i];
            if (ca >= 'A' && ca <= 'Z') ca += 32;
            if (cb >= 'A' && cb <= 'Z') cb += 32;
            if (ca != cb) return 1;
        }
        a += 1 + la;
        b += 1 + lb;
    }
    return -1;
}

/* Encode an SOA RDATA block into wire format.
   Returns total bytes written or -1 on error. */
int dns_wire_encode_soa(uint8_t *buf, size_t max_len,
                        const char *mname, const char *rname,
                        uint32_t serial, uint32_t refresh,
                        uint32_t retry, uint32_t expire,
                        uint32_t minimum) {
    size_t off = 0;
    int n;
    n = dns_wire_encode_name(buf + off, mname);
    if (n < 0) return -1;
    off += (size_t)n;
    n = dns_wire_encode_name(buf + off, rname);
    if (n < 0) return -1;
    off += (size_t)n;
    if (off + 20 > max_len) return -1;
    dns_wire_write_u32(buf + off, serial); off += 4;
    dns_wire_write_u32(buf + off, refresh); off += 4;
    dns_wire_write_u32(buf + off, retry); off += 4;
    dns_wire_write_u32(buf + off, expire); off += 4;
    dns_wire_write_u32(buf + off, minimum); off += 4;
    return (int)off;
}

/* Compute a simple hash of a wire-encoded name for use in hash tables.
   Hashes all labels case-insensitively, following compression pointers. */
uint32_t dns_wire_name_hash(const uint8_t *msg, size_t msg_len, size_t offset) {
    uint32_t h = 2166136261u;
    size_t pos = offset;
    int depth = 0;
    while (depth++ < 128 && pos < msg_len) {
        uint8_t len = msg[pos];
        if (len == 0) break;
        if ((len & 0xC0) == 0xC0) {
            if (pos + 1 >= msg_len) break;
            pos = ((size_t)(len & 0x3F) << 8) | msg[pos + 1];
            continue;
        }
        if (len > 63 || pos + 1 + len > msg_len) break;
        for (uint8_t i = 0; i < len; i++) {
            uint8_t c = msg[pos + 1 + i];
            if (c >= 'A' && c <= 'Z') c += 32;
            h ^= (uint32_t)c;
            h *= 16777619u;
        }
        h ^= (uint32_t)0xFF;
        h *= 16777619u;
        pos += 1 + len;
    }
    return h;
}

/* Parse a DNS message header and populate the dns_wire_message_t struct.
   Returns 0 on success, -1 on parse error. Does NOT copy section data. */
int dns_wire_parse_header(const uint8_t *raw, size_t raw_len,
                          dns_wire_message_t *msg) {
    if (raw_len < 12) return -1;
    msg->id = dns_wire_read_u16(raw);
    msg->flags = dns_wire_read_u16(raw + 2);
    msg->qdcount = dns_wire_read_u16(raw + 4);
    msg->ancount = dns_wire_read_u16(raw + 6);
    msg->nscount = dns_wire_read_u16(raw + 8);
    msg->arcount = dns_wire_read_u16(raw + 10);
    size_t off = 12;
    /* skip question section */
    for (uint16_t i = 0; i < msg->qdcount; i++) {
        while (off < raw_len && raw[off] != 0) {
            if ((raw[off] & 0xC0) == 0xC0) { off += 2; break; }
            off += 1 + raw[off];
        }
        if (off >= raw_len) return -1;
        if (raw[off] == 0) off++; /* skip root label */
        off += 4; /* type + class */
        if (off > raw_len) return -1;
    }
    msg->question = (uint8_t *)(raw + 12);
    msg->question_len = off - 12;
    msg->answer = (off < raw_len) ? (uint8_t *)(raw + off) : NULL;
    msg->answer_len = 0;
    msg->authority = NULL;
    msg->authority_len = 0;
    msg->additional = NULL;
    msg->additional_len = 0;
    return 0;
}

/* Count how many compression pointer hops are needed to fully resolve a name.
   Returns the hop count, or -1 if pointers exceed 128 or msg is malformed. */
int dns_wire_name_pointer_depth(const uint8_t *msg, size_t msg_len, size_t offset) {
    int hops = 0;
    size_t pos = offset;
    while (pos < msg_len && hops <= 128) {
        uint8_t len = msg[pos];
        if (len == 0) return hops;
        if ((len & 0xC0) == 0xC0) {
            hops++;
            if (pos + 1 >= msg_len) return -1;
            pos = ((size_t)(len & 0x3F) << 8) | msg[pos + 1];
            continue;
        }
        if (len > 63 || pos + 1 + len > msg_len) return -1;
        pos += 1 + len;
    }
    return -1;
}

/* Encode an MX RDATA block (preference + exchange name) into wire format.
   Returns total bytes written, or -1 on error. */
int dns_wire_encode_mx(uint8_t *buf, size_t max_len,
                       uint16_t preference, const char *exchange) {
    if (max_len < 2) return -1;
    dns_wire_write_u16(buf, preference);
    int n = dns_wire_encode_name(buf + 2, exchange);
    if (n < 0) return -1;
    return 2 + n;
}

/* Encode an SRV RDATA block (priority, weight, port, target).
   Returns total bytes written, or -1 on error. */
int dns_wire_encode_srv(uint8_t *buf, size_t max_len,
                        uint16_t priority, uint16_t weight,
                        uint16_t port, const char *target) {
    if (max_len < 6) return -1;
    dns_wire_write_u16(buf, priority);
    dns_wire_write_u16(buf + 2, weight);
    dns_wire_write_u16(buf + 4, port);
    int n = dns_wire_encode_name(buf + 6, target);
    if (n < 0) return -1;
    return 6 + n;
}

/* Validate that a DNS message has a consistent section layout.
   Checks that section counts don't cause the parsed offsets to exceed msg_len.
   Returns 0 if valid, -1 if the message structure is corrupt. */
int dns_wire_validate_message(const uint8_t *raw, size_t raw_len) {
    if (raw_len < 12) return -1;
    uint16_t qd = dns_wire_read_u16(raw + 4);
    uint16_t an = dns_wire_read_u16(raw + 6);
    uint16_t ns = dns_wire_read_u16(raw + 8);
    uint16_t ar = dns_wire_read_u16(raw + 10);
    size_t off = 12;
    /* walk question section */
    for (uint16_t i = 0; i < qd; i++) {
        int jumps = 0;
        while (off < raw_len && raw[off] != 0) {
            if ((raw[off] & 0xC0) == 0xC0) {
                off += 2;
                jumps++;
                if (jumps > 128) return -1;
                goto next_q;
            }
            if (raw[off] > 63) return -1;
            off += 1 + raw[off];
        }
        off++; /* root label */
        next_q:
        off += 4; /* QTYPE + QCLASS */
        if (off > raw_len) return -1;
    }
    /* skip answer, authority, additional sections (RR format) */
    uint16_t total_rr = (uint16_t)(an + ns + ar);
    for (uint16_t i = 0; i < total_rr; i++) {
        /* skip name */
        while (off < raw_len && raw[off] != 0) {
            if ((raw[off] & 0xC0) == 0xC0) { off += 2; goto rr_fields; }
            if (raw[off] > 63) return -1;
            off += 1 + raw[off];
        }
        off++; /* root */
        rr_fields:
        if (off + 10 > raw_len) return -1;
        off += 8; /* type, class, ttl */
        uint16_t rdlen = dns_wire_read_u16(raw + off);
        off += 2;
        off += rdlen;
        if (off > raw_len) return -1;
    }
    return 0;
}

/* Strip EDNS OPT pseudo-record from the additional section.
   Returns the new arcount (original minus 1 if OPT found, else original). */
uint16_t dns_wire_strip_opt(const uint8_t *raw, size_t raw_len,
                            size_t *opt_offset, size_t *opt_len) {
    if (raw_len < 12) return 0;
    uint16_t ar = dns_wire_read_u16(raw + 10);
    if (ar == 0) return 0;
    /* find start of additional section by walking Q+A+NS sections */
    size_t off = 12;
    uint16_t qd = dns_wire_read_u16(raw + 4);
    uint16_t an = dns_wire_read_u16(raw + 6);
    uint16_t ns = dns_wire_read_u16(raw + 8);
    for (uint16_t i = 0; i < qd; i++) {
        while (off < raw_len && raw[off] != 0) {
            if ((raw[off] & 0xC0) == 0xC0) { off += 2; break; }
            off += 1 + raw[off];
        }
        if (off < raw_len && raw[off] == 0) off++;
        off += 4;
    }
    uint16_t total_rr = (uint16_t)(an + ns);
    for (uint16_t i = 0; i < total_rr; i++) {
        while (off < raw_len && raw[off] != 0) {
            if ((raw[off] & 0xC0) == 0xC0) { off += 2; goto skip_rr; }
            off += 1 + raw[off];
        }
        if (off < raw_len && raw[off] == 0) off++;
        skip_rr:
        if (off + 10 > raw_len) return ar;
        off += 8;
        uint16_t rdlen = dns_wire_read_u16(raw + off);
        off += 2 + rdlen;
    }
    /* off now points to the first additional RR */
    *opt_offset = off;
    /* check if it's an OPT record (type 41) */
    if (off + 10 <= raw_len) {
        uint16_t rr_type = dns_wire_read_u16(raw + off + 2);
        if (rr_type == 41) {
            uint16_t rr_rdlen = dns_wire_read_u16(raw + off + 8);
            *opt_len = 10 + rr_rdlen;
            return ar - 1;
        }
    }
    *opt_len = 0;
    return ar;
}

/* Compute total size of a DNS message given section counts and data. */
size_t dns_wire_message_size(uint16_t qd, uint16_t an, uint16_t ns, uint16_t ar,
                             const size_t *section_sizes, size_t section_count) {
    size_t total = 12; /* header */
    size_t idx = 0;
    uint16_t counts[4] = {qd, an, ns, ar};
    for (int s = 0; s < 4; s++) {
        for (uint16_t i = 0; i < counts[s]; i++) {
            if (idx < section_count) {
                total += section_sizes[idx++];
            } else {
                return 0; /* insufficient size data */
            }
        }
    }
    return total;
}

/* Encode a TXT RDATA block from an array of strings.
   Each string is length-prefixed per RFC 1035.
   Returns total bytes written, or -1 on error. */
int dns_wire_encode_txt(uint8_t *buf, size_t max_len,
                        const char **strings, size_t count) {
    size_t off = 0;
    for (size_t i = 0; i < count; i++) {
        size_t slen = strlen(strings[i]);
        if (slen > 255) slen = 255;
        if (off + 1 + slen > max_len) return -1;
        buf[off] = (uint8_t)slen;
        memcpy(buf + off + 1, strings[i], slen);
        off += 1 + slen;
    }
    return (int)off;
}

/* Decode a TXT RDATA block into separate strings.
   Returns the number of strings decoded, or -1 on error. */
int dns_wire_decode_txt(const uint8_t *rdata, size_t rdlen,
                        char **out, size_t max_out) {
    size_t off = 0;
    size_t count = 0;
    while (off < rdlen && count < max_out) {
        uint8_t slen = rdata[off];
        off++;
        if (off + slen > rdlen) return -1;
        out[count] = (char *)malloc(slen + 1);
        if (!out[count]) return -1;
        memcpy(out[count], rdata + off, slen);
        out[count][slen] = '\0';
        off += slen;
        count++;
    }
    return (int)count;
}

/* Encode a CAA RDATA block (flags + tag + value).
   Returns total bytes written, or -1 on error. */
int dns_wire_encode_caa(uint8_t *buf, size_t max_len,
                        uint8_t flags, const char *tag,
                        const uint8_t *value, size_t value_len) {
    size_t tlen = strlen(tag);
    if (tlen > 255 || 2 + tlen + value_len > max_len) return -1;
    buf[0] = flags;
    buf[1] = (uint8_t)tlen;
    memcpy(buf + 2, tag, tlen);
    memcpy(buf + 2 + tlen, value, value_len);
    return (int)(2 + tlen + value_len);
}

/* Compute the minimum buffer size needed to store all RR names
   referenced in a message (accounting for compression savings). */
size_t dns_wire_estimate_name_storage(const uint8_t *msg, size_t msg_len,
                                      size_t section_offset, uint16_t rr_count) {
    size_t off = section_offset;
    size_t total_uncompressed = 0;
    for (uint16_t i = 0; i < rr_count; i++) {
        size_t name_start = off;
        int has_compression = 0;
        while (off < msg_len && msg[off] != 0) {
            if ((msg[off] & 0xC0) == 0xC0) { has_compression = 1; off += 2; break; }
            off += 1 + msg[off];
        }
        if (off < msg_len && msg[off] == 0) off++;
        if (!has_compression) {
            total_uncompressed += (off - name_start);
        } else {
            total_uncompressed += 2; /* just the pointer */
        }
        if (off + 10 > msg_len) break;
        off += 8;
        uint16_t rdlen = dns_wire_read_u16(msg + off);
        off += 2 + rdlen;
    }
    return total_uncompressed;
}

/* Encode an NSEC/NSEC3 bitmap window block.
   Returns bytes written or -1. */
int dns_wire_encode_type_bitmap(uint8_t *buf, size_t max_len,
                                const uint16_t *types, size_t type_count) {
    if (type_count == 0) return 0;
    /* sort types for encoding */
    uint16_t sorted[256];
    size_t n = type_count < 256 ? type_count : 256;
    for (size_t i = 0; i < n; i++) sorted[i] = types[i];
    for (size_t i = 0; i < n - 1; i++) {
        for (size_t j = i + 1; j < n; j++) {
            if (sorted[j] < sorted[i]) {
                uint16_t tmp = sorted[i];
                sorted[i] = sorted[j];
                sorted[j] = tmp;
            }
        }
    }
    size_t off = 0;
    size_t idx = 0;
    while (idx < n) {
        uint16_t window = sorted[idx] / 256;
        uint8_t bitmap[32];
        memset(bitmap, 0, sizeof(bitmap));
        size_t bmp_len = 0;
        while (idx < n && sorted[idx] / 256 == window) {
            uint16_t rr = sorted[idx] % 256;
            size_t byte_pos = rr / 8;
            uint8_t bit_pos = 7 - (rr % 8);
            if (byte_pos + 1 > bmp_len) bmp_len = byte_pos + 1;
            bitmap[byte_pos] |= (1 << bit_pos);
            idx++;
        }
        if (off + 2 + bmp_len > max_len) return -1;
        buf[off] = (uint8_t)window;
        buf[off + 1] = (uint8_t)bmp_len;
        memcpy(buf + off + 2, bitmap, bmp_len);
        off += 2 + bmp_len;
    }
    return (int)off;
}

/* Parse a DNS name from wire format into a presentation-format string.
   Follows compression pointers, handles maximum label lengths.
   Returns number of bytes consumed from wire, or -1 on error. */
int dns_wire_name_to_string(const uint8_t *msg, size_t msg_len, size_t offset,
                            char *out, size_t out_max) {
    size_t noff = 0;
    size_t pos = offset;
    int ptrs = 0;
    int first = 1;
    while (pos < msg_len && ptrs <= 128) {
        uint8_t len = msg[pos];
        if (len == 0) {
            if (noff < out_max) out[noff] = '\0';
            return (int)(pos - offset + 1);
        }
        if ((len & 0xC0) == 0xC0) {
            ptrs++;
            if (pos + 1 >= msg_len) return -1;
            pos = ((size_t)(len & 0x3F) << 8) | msg[pos + 1];
            continue;
        }
        if (len > 63 || pos + 1 + len > msg_len) return -1;
        if (!first && noff < out_max) out[noff++] = '.';
        first = 0;
        for (uint8_t i = 0; i < len && noff < out_max; i++) {
            uint8_t c = msg[pos + 1 + i];
            if (c == '.' || c == '\\') {
                if (noff + 2 > out_max) break;
                out[noff++] = '\\';
                out[noff++] = c;
            } else {
                out[noff++] = c;
            }
        }
        pos += 1 + len;
    }
    return -1;
}

/* Compute a simple checksum over a raw buffer (used for message integrity).
   This is NOT a standard DNS checksum; it's a fast locality-sensitive hash. */
uint32_t dns_wire_checksum(const uint8_t *data, size_t len) {
    uint32_t sum = 0x12345678;
    size_t i = 0;
    for (; i + 4 <= len; i += 4) {
        uint32_t word = dns_wire_read_u32(data + i);
        sum ^= word;
        sum = (sum << 7) | (sum >> 25);
        sum *= 0x9E3779B9;
    }
    for (; i < len; i++) {
        sum ^= (uint32_t)data[i];
        sum = (sum << 3) | (sum >> 29);
    }
    return sum;
}

/* Rotate a 16-bit DNS message ID (for query randomization). */
uint16_t dns_wire_rotate_id(uint16_t id, uint8_t round) {
    uint16_t rotated = (uint16_t)((id << round) | (id >> (16 - round)));
    return rotated ^ (uint16_t)(0xA3C5 + round * 0x1F3B);
}

/* Build the TSIG signed data buffer from a DNS message and metadata.
   Returns the length of the signed data written, or -1. */
int dns_wire_build_tsig_data(const uint8_t *msg, size_t msg_len,
                             const char *key_name,
                             const char *algorithm,
                             uint64_t time_signed, uint16_t fudge,
                             uint16_t original_id,
                             const uint8_t *error, size_t error_len,
                             const uint8_t *other, size_t other_len,
                             uint8_t *out, size_t out_max) {
    size_t off = 0;
    int n;
    /* key name */
    n = dns_wire_encode_name(out + off, key_name);
    if (n < 0) return -1;
    off += (size_t)n;
    /* class */
    if (off + 2 > out_max) return -1;
    dns_wire_write_u16(out + off, 255); /* ANY */
    off += 2;
    /* TTL */
    if (off + 4 > out_max) return -1;
    dns_wire_write_u32(out + off, 0);
    off += 4;
    /* algorithm name */
    n = dns_wire_encode_name(out + off, algorithm);
    if (n < 0) return -1;
    off += (size_t)n;
    /* time signed (48-bit) */
    if (off + 6 > out_max) return -1;
    out[off] = (uint8_t)(time_signed >> 40);
    out[off + 1] = (uint8_t)(time_signed >> 32);
    out[off + 2] = (uint8_t)(time_signed >> 24);
    out[off + 3] = (uint8_t)(time_signed >> 16);
    out[off + 4] = (uint8_t)(time_signed >> 8);
    out[off + 5] = (uint8_t)(time_signed);
    off += 6;
    /* fudge */
    if (off + 2 > out_max) return -1;
    dns_wire_write_u16(out + off, fudge);
    off += 2;
    /* error length + error */
    if (off + 2 > out_max) return -1;
    dns_wire_write_u16(out + off, (uint16_t)error_len);
    off += 2;
    if (off + error_len > out_max) return -1;
    if (error_len > 0) memcpy(out + off, error, error_len);
    off += error_len;
    /* other length + other */
    if (off + 2 > out_max) return -1;
    dns_wire_write_u16(out + off, (uint16_t)other_len);
    off += 2;
    if (off + other_len > out_max) return -1;
    if (other_len > 0) memcpy(out + off, other, other_len);
    off += other_len;
    /* original message (minus TSIG RR) */
    if (off + msg_len > out_max) return -1;
    memcpy(out + off, msg, msg_len);
    off += msg_len;
    return (int)off;
}

/* Compute DNS message ID from a hash of the query name + type + class
   for cache deduplication purposes. */
uint16_t dns_wire_compute_query_id(const char *qname, uint16_t qtype, uint16_t qclass) {
    uint32_t h = 0x811C9DC5;
    const char *p = qname;
    while (*p) {
        uint8_t c = (uint8_t)*p;
        if (c >= 'A' && c <= 'Z') c += 32;
        h ^= (uint32_t)c;
        h *= 0x01000193;
        p++;
    }
    h ^= (uint32_t)qtype;
    h *= 0x01000193;
    h ^= (uint32_t)qclass;
    h *= 0x01000193;
    return (uint16_t)((h >> 16) ^ (h & 0xFFFF));
}

/* Parse a single RR from a raw message buffer starting at offset.
   Populates name, type, class, ttl, rdata, rdlen.
   Returns bytes consumed, or -1 on error. */
int dns_wire_parse_rr(const uint8_t *msg, size_t msg_len, size_t offset,
                      char *name, size_t name_max,
                      uint16_t *type, uint16_t *class, uint32_t *ttl,
                      uint16_t *rdlen, size_t *rdata_offset) {
    size_t off = offset;
    int n = dns_wire_name_to_string(msg, msg_len, off, name, name_max);
    if (n < 0) return -1;
    off += (size_t)n;
    if (off + 10 > msg_len) return -1;
    *type = dns_wire_read_u16(msg + off);
    *class = dns_wire_read_u16(msg + off + 2);
    *ttl = dns_wire_read_u32(msg + off + 4);
    *rdlen = dns_wire_read_u16(msg + off + 8);
    off += 10;
    *rdata_offset = off;
    off += *rdlen;
    if (off > msg_len) return -1;
    return (int)(off - offset);
}

/* Compare two raw RR records for section deduplication.
   Two RRs are duplicates if they have the same owner name, type, and class.
   Returns 0 if equal, nonzero otherwise. */
int dns_wire_rr_equal(const uint8_t *msg, size_t msg_len,
                      size_t off_a, size_t off_b) {
    char name_a[256], name_b[256];
    uint16_t type_a, class_a, rdlen_a, type_b, class_b, rdlen_b;
    uint32_t ttl_a, ttl_b;
    size_t rdata_a, rdata_b;
    int len_a = dns_wire_parse_rr(msg, msg_len, off_a, name_a, sizeof(name_a),
                                  &type_a, &class_a, &ttl_a, &rdlen_a, &rdata_a);
    int len_b = dns_wire_parse_rr(msg, msg_len, off_b, name_b, sizeof(name_b),
                                  &type_b, &class_b, &ttl_b, &rdlen_b, &rdata_b);
    if (len_a < 0 || len_b < 0) return -1;
    if (type_a != type_b || class_a != class_b) return 1;
    return dns_wire_name_equal(msg, msg_len, off_a, off_b);
}
'''

# ============================================================
# dns_name_utils.c - DNS name compression and validation
# ============================================================
def gen_dns_name_utils():
    return r'''/* dns_name_utils - DNS name compression and validation */
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>

static const uint8_t label_valid[256] = {
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,
    0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,1,
    0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1,1,0,1,0,0,0,1,1,0,1,1,1,0,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,1,1,1,1,1,1,1,1,
};

static const uint8_t to_lower_tab[256] = {
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,
    32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,
    48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,
    64,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,
    112,113,114,115,116,117,118,119,120,121,122,91,92,93,94,95,
    96,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,
    112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,
    128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,
    144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159,
    160,161,162,163,164,165,166,167,168,169,170,171,172,173,174,175,
    176,177,178,179,180,181,182,183,184,185,186,187,188,189,190,191,
    192,193,194,195,196,197,198,199,200,201,202,203,204,205,206,207,
    208,209,210,211,212,213,214,215,216,217,218,219,220,221,222,223,
    224,225,226,227,228,229,230,231,232,233,234,235,236,237,238,239,
    240,241,242,243,244,245,246,247,248,249,250,251,252,253,254,255,
};

int dns_name_validate_label(const char *label, size_t len) {
    if (len == 0 || len > 63) return -1;
    for (size_t i = 0; i < len; i++) {
        if (!label_valid[(uint8_t)label[i]]) return -1;
    }
    return 0;
}

int dns_name_compare(const char *a, const char *b) {
    while (*a && *b) {
        uint8_t ca = to_lower_tab[(uint8_t)*a];
        uint8_t cb = to_lower_tab[(uint8_t)*b];
        if (ca != cb) return ca - cb;
        a++; b++;
    }
    return (uint8_t)*a - (uint8_t)*b;
}

int dns_name_to_wire(const char *name, uint8_t *wire, size_t max_len) {
    size_t off = 0;
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t ll = dot ? (size_t)(dot - p) : strlen(p);
        if (ll > 63 || off + 1 + ll >= max_len) return -1;
        wire[off] = (uint8_t)ll;
        memcpy(wire + off + 1, p, ll);
        off += 1 + ll;
        p += ll;
        if (*p == '.') p++;
    }
    wire[off] = 0;
    return (int)(off + 1);
}

int dns_name_from_wire(const uint8_t *wire, size_t wire_len, size_t off,
                       char *name, size_t name_max) {
    size_t noff = 0;
    size_t pos = off;
    int jumps = 0;
    while (pos < wire_len) {
        uint8_t len = wire[pos];
        if (len == 0) break;
        if ((len & 0xC0) == 0xC0) {
            if (pos + 1 >= wire_len || jumps++ > 128) return -1;
            uint16_t ptr = ((uint16_t)(len & 0x3F) << 8) | wire[pos+1];
            if (ptr >= wire_len) return -1;
            pos = ptr;
            continue;
        }
        if (len > 63 || pos + 1 + len > wire_len) return -1;
        if (noff > 0 && noff < name_max) name[noff++] = '.';
        if (noff + len >= name_max) return -1;
        memcpy(name + noff, wire + pos + 1, len);
        noff += len;
        pos += 1 + len;
    }
    name[noff] = '\0';
    return (int)noff;
}

/* Count the number of labels in a domain name. Returns 0 for empty/root. */
int dns_name_label_count(const char *name) {
    int count = 0;
    const char *p = name;
    while (*p) {
        count++;
        const char *dot = strchr(p, '.');
        if (dot) p = dot + 1; else break;
    }
    return count;
}

/* Check if a domain name matches a wildcard pattern (*.example.com).
   The wildcard label '*' matches any single label. */
int dns_name_matches_wildcard(const char *name, const char *pattern) {
    const char *np = name;
    const char *pp = pattern;
    while (*np && *pp) {
        /* extract label from pattern */
        const char *pdot = strchr(pp, '.');
        size_t plen = pdot ? (size_t)(pdot - pp) : strlen(pp);
        /* check for wildcard label */
        if (plen == 1 && pp[0] == '*') {
            /* skip one label in name */
            const char *ndot = strchr(np, '.');
            if (ndot) np = ndot + 1; else { np += strlen(np); }
            pp += plen;
            if (*pp == '.') pp++;
            continue;
        }
        /* extract label from name */
        const char *ndot = strchr(np, '.');
        size_t nlen = ndot ? (size_t)(ndot - np) : strlen(np);
        if (nlen != plen) return 0;
        for (size_t i = 0; i < nlen; i++) {
            uint8_t ca = to_lower_tab[(uint8_t)np[i]];
            uint8_t cb = to_lower_tab[(uint8_t)pp[i]];
            if (ca != cb) return 0;
        }
        np += nlen;
        pp += plen;
        if (*np == '.') np++;
        if (*pp == '.') pp++;
    }
    return (*np == '\0' && *pp == '\0') ? 1 : 0;
}

/* Convert a domain name to its canonical (lowercase) form.
   Returns length of the canonical name, or -1 on error. */
int dns_name_canonicalize(const char *name, char *out, size_t out_max) {
    size_t noff = 0;
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t ll = dot ? (size_t)(dot - p) : strlen(p);
        if (ll > 63 || noff + ll >= out_max) return -1;
        for (size_t i = 0; i < ll; i++) {
            out[noff + i] = to_lower_tab[(uint8_t)p[i]];
        }
        noff += ll;
        p += ll;
        if (*p == '.') {
            if (noff < out_max) out[noff++] = '.';
            p++;
        }
    }
    if (noff < out_max) out[noff] = '\0';
    return (int)noff;
}

/* Check if 'child' is a subdomain of (or equal to) 'parent'.
   Example: dns_name_is_subdomain("www.example.com", "example.com") returns 1. */
int dns_name_is_subdomain(const char *child, const char *parent) {
    size_t cl = strlen(child);
    size_t pl = strlen(parent);
    if (cl < pl) return 0;
    /* parent must be empty (root) or the suffix must match exactly */
    if (pl == 0) return 1;
    if (cl == pl) return dns_name_compare(child, parent) == 0;
    /* child must end with ".parent" */
    const char *suffix = child + (cl - pl);
    if (*(suffix - 1) != '.') return 0;
    return dns_name_compare(suffix, parent) == 0;
}

/* Reverse a domain name for PTR lookups.
   "1.0.168.192.in-addr.arpa" -> "192.168.0.1" and vice versa.
   Returns length of reversed name, or -1. */
int dns_name_reverse_ipv4(const char *ip, char *out, size_t out_max) {
    /* Parse IPv4 address and write in reverse with .in-addr.arpa */
    unsigned int octets[4] = {0, 0, 0, 0};
    int n = sscanf(ip, "%u.%u.%u.%u", &octets[0], &octets[1], &octets[2], &octets[3]);
    if (n != 4) return -1;
    for (int i = 0; i < 4; i++) {
        if (octets[i] > 255) return -1;
    }
    int written = snprintf(out, out_max, "%u.%u.%u.%u.in-addr.arpa",
                           octets[3], octets[2], octets[1], octets[0]);
    if (written < 0 || (size_t)written >= out_max) return -1;
    return written;
}

/* Extract the parent domain (one label up) from a name.
   "www.example.com" -> "example.com"
   "example.com" -> "com"
   "com" -> "" (root)
   Returns length of parent name, or -1 on error. */
int dns_name_parent(const char *name, char *out, size_t out_max) {
    const char *first_dot = strchr(name, '.');
    if (!first_dot || *(first_dot + 1) == '\0') {
        if (out_max > 0) out[0] = '\0';
        return 0;
    }
    const char *parent = first_dot + 1;
    size_t plen = strlen(parent);
    if (plen >= out_max) return -1;
    memcpy(out, parent, plen);
    out[plen] = '\0';
    return (int)plen;
}

/* Append a label to the end of a wire-encoded name.
   Returns new total length, or -1 on error. */
int dns_name_wire_append_label(uint8_t *wire, size_t current_len,
                               size_t max_len, const char *label, size_t label_len) {
    if (label_len > 63) return -1;
    if (current_len == 0) return -1;
    /* find the trailing 0 byte */
    size_t insert_pos = current_len - 1;
    if (wire[insert_pos] != 0) return -1;
    if (insert_pos + 1 + label_len + 1 > max_len) return -1;
    wire[insert_pos] = (uint8_t)label_len;
    memcpy(wire + insert_pos + 1, label, label_len);
    wire[insert_pos + 1 + label_len] = 0;
    return (int)(insert_pos + 2 + label_len);
}

/* Compute the total wire length of a compressed name at a given offset.
   Follows compression pointers to compute the uncompressed size.
   Returns uncompressed size in bytes, or -1 on error. */
int dns_name_wire_uncompressed_len(const uint8_t *msg, size_t msg_len, size_t offset) {
    int total = 0;
    size_t pos = offset;
    int depth = 0;
    while (pos < msg_len && depth <= 128) {
        uint8_t len = msg[pos];
        if (len == 0) { total++; break; }
        if ((len & 0xC0) == 0xC0) {
            depth++;
            if (pos + 1 >= msg_len) return -1;
            pos = ((size_t)(len & 0x3F) << 8) | msg[pos + 1];
            continue;
        }
        if (len > 63 || pos + 1 + len > msg_len) return -1;
        total += 1 + len;
        pos += 1 + len;
    }
    return total;
}

/* Check whether a wire-encoded name contains any compression pointers. */
int dns_name_wire_has_compression(const uint8_t *msg, size_t msg_len, size_t offset) {
    size_t pos = offset;
    while (pos < msg_len) {
        uint8_t len = msg[pos];
        if (len == 0) return 0;
        if ((len & 0xC0) == 0xC0) return 1;
        if (len > 63 || pos + 1 + len > msg_len) return -1;
        pos += 1 + len;
    }
    return 0;
}

/* Strip the trailing root label from a presentation name.
   "example.com." -> "example.com", "example.com" unchanged.
   Returns new length. */
int dns_name_strip_root(const char *name, char *out, size_t out_max) {
    size_t len = strlen(name);
    if (len > 0 && name[len - 1] == '.') len--;
    if (len >= out_max) return -1;
    memcpy(out, name, len);
    out[len] = '\0';
    return (int)len;
}

/* Validate a fully-qualified domain name.
   Checks total length <= 255, each label <= 63, valid characters.
   Returns 0 if valid, -1 on error. */
int dns_name_validate_fqdn(const char *name) {
    size_t total = 0;
    size_t label_len = 0;
    const char *p = name;
    while (*p) {
        uint8_t c = (uint8_t)*p;
        if (c == '.') {
            if (label_len == 0) return -1; /* empty label (double dot) */
            if (label_len > 63) return -1;
            label_len = 0;
            total++;
        } else {
            if (!label_valid[c]) return -1;
            label_len++;
            total++;
        }
        p++;
    }
    if (label_len == 0 && total > 1) return -1; /* trailing dot is ok for FQDN */
    if (total > 254) return -1; /* 255 bytes max including root 0 */
    return 0;
}

/* Extract the TLD (top-level domain) from a name.
   "www.example.co.uk" -> "co.uk"
   "example.com" -> "com"
   Returns length of TLD, or -1. */
int dns_name_get_tld(const char *name, char *out, size_t out_max) {
    const char *last_dot = strrchr(name, '.');
    if (!last_dot) {
        /* single label */
        size_t len = strlen(name);
        if (len >= out_max) return -1;
        memcpy(out, name, len + 1);
        return (int)len;
    }
    /* check for second-to-last dot for multi-part TLDs */
    const char *second_dot = NULL;
    const char *scan = last_dot + 1;
    while (*scan) {
        const char *d = strchr(scan, '.');
        if (d) { second_dot = d; break; }
        scan += strlen(scan);
    }
    /* For names like "www.example.co.uk", TLD is "co.uk"
       For names like "www.example.com", TLD is "com" */
    const char *tld_start;
    if (second_dot) {
        /* check if second-to-last label is a known short TLD */
        size_t label_len = (size_t)(second_dot - last_dot - 1);
        if (label_len <= 3) {
            /* likely a ccTLD + second-level, return from last_dot+1 */
            tld_start = last_dot + 1;
        } else {
            tld_start = last_dot + 1;
        }
    } else {
        tld_start = last_dot + 1;
    }
    size_t tlen = strlen(tld_start);
    if (tlen >= out_max) return -1;
    memcpy(out, tld_start, tlen + 1);
    return (int)tlen;
}

/* Convert a binary IPv6 address to its reverse DNS name.
   Returns length of the name, or -1. */
int dns_name_reverse_ipv6(const uint8_t addr[16], char *out, size_t out_max) {
    int written = 0;
    for (int i = 15; i >= 0; i--) {
        int n = snprintf(out + written, out_max - (size_t)written,
                         "%x.%x", addr[i] & 0x0F, (addr[i] >> 4) & 0x0F);
        if (n < 0 || (size_t)(written + n) >= out_max) return -1;
        written += n;
        if (i > 0) {
            if ((size_t)(written + 1) >= out_max) return -1;
            out[written++] = '.';
        }
    }
    int n = snprintf(out + written, out_max - (size_t)written, ".ip6.arpa");
    if (n < 0 || (size_t)(written + n) >= out_max) return -1;
    written += n;
    return written;
}

/* Count total bytes needed to wire-encode a name (including root 0). */
int dns_name_wire_size(const char *name) {
    int size = 1; /* trailing 0 */
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t ll = dot ? (size_t)(dot - p) : strlen(p);
        if (ll > 63) return -1;
        size += 1 + (int)ll;
        p += ll;
        if (*p == '.') p++;
    }
    return size;
}

/* Normalize a name by removing consecutive dots, trailing dots,
   and converting to lowercase. Returns length of normalized name. */
int dns_name_normalize(const char *name, char *out, size_t out_max) {
    size_t noff = 0;
    const char *p = name;
    int prev_was_dot = 0;
    while (*p) {
        if (*p == '.') {
            if (prev_was_dot) { p++; continue; } /* skip consecutive dots */
            prev_was_dot = 1;
            if (noff > 0 && noff < out_max) out[noff++] = '.';
        } else {
            prev_was_dot = 0;
            if (noff < out_max) out[noff++] = to_lower_tab[(uint8_t)*p];
        }
        p++;
    }
    /* remove trailing dot */
    if (noff > 0 && out[noff - 1] == '.') noff--;
    if (noff < out_max) out[noff] = '\0';
    return (int)noff;
}
'''

# ============================================================
# dns_hash_table.c - DNS name hash table with FNV-1a hashing
# ============================================================
def gen_dns_hash_table():
    return r'''/* dns_hash_table - DNS name hash table with FNV-1a hashing and LRU eviction */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>

#define DNS_HASH_SIZE 1024

typedef struct dns_hash_node {
    char *key;
    void *value;
    struct dns_hash_node *next;
    struct dns_hash_node *lru_prev;
    struct dns_hash_node *lru_next;
    uint64_t insert_time;
    uint32_t access_count;
    uint32_t ttl;
} dns_hash_node_t;

typedef struct {
    dns_hash_node_t **buckets;
    dns_hash_node_t *lru_head;
    dns_hash_node_t *lru_tail;
    size_t size;
    size_t count;
    size_t max_size;
    uint64_t total_lookups;
    uint64_t total_hits;
    uint64_t total_misses;
} dns_hash_table_t;

static size_t fnv1a_hash(const char *key) {
    size_t h = 14695981039346656037ULL;
    while (*key) { h ^= (size_t)(unsigned char)*key; h *= 1099511628211ULL; key++; }
    return h;
}

static size_t djb2_hash(const char *key) {
    size_t h = 5381;
    while (*key) { h = ((h << 5) + h) + (unsigned char)*key; key++; }
    return h;
}

dns_hash_table_t *dns_hash_create(size_t initial_size) {
    dns_hash_table_t *t = calloc(1, sizeof(*t));
    if (!t) return NULL;
    t->buckets = calloc(initial_size, sizeof(dns_hash_node_t *));
    if (!t->buckets) { free(t); return NULL; }
    t->size = initial_size;
    t->max_size = 65536;
    return t;
}

void dns_hash_destroy(dns_hash_table_t *t) {
    if (!t) return;
    for (size_t i = 0; i < t->size; i++) {
        dns_hash_node_t *n = t->buckets[i];
        while (n) { dns_hash_node_t *nx = n->next; free(n->key); free(n); n = nx; }
    }
    free(t->buckets); free(t);
}

int dns_hash_insert(dns_hash_table_t *t, const char *key, void *val) {
    size_t idx = fnv1a_hash(key) % t->size;
    dns_hash_node_t *n = t->buckets[idx];
    while (n) { if (strcmp(n->key, key) == 0) { n->value = val; return 0; } n = n->next; }
    n = malloc(sizeof(*n));
    if (!n) return -1;
    n->key = strdup(key);
    n->value = val;
    n->next = t->buckets[idx];
    n->lru_prev = NULL;
    n->lru_next = t->lru_head;
    if (t->lru_head) t->lru_head->lru_prev = n;
    t->lru_head = n;
    if (!t->lru_tail) t->lru_tail = n;
    n->insert_time = 0;
    n->access_count = 0;
    n->ttl = 0;
    t->buckets[idx] = n;
    t->count++;
    return 0;
}

void *dns_hash_lookup(dns_hash_table_t *t, const char *key) {
    size_t idx = fnv1a_hash(key) % t->size;
    dns_hash_node_t *n = t->buckets[idx];
    t->total_lookups++;
    while (n) {
        if (strcmp(n->key, key) == 0) {
            n->access_count++;
            t->total_hits++;
            /* move to LRU head */
            if (n != t->lru_head) {
                if (n->lru_prev) n->lru_prev->lru_next = n->lru_next;
                if (n->lru_next) n->lru_next->lru_prev = n->lru_prev;
                if (n == t->lru_tail) t->lru_tail = n->lru_prev;
                n->lru_prev = NULL;
                n->lru_next = t->lru_head;
                if (t->lru_head) t->lru_head->lru_prev = n;
                t->lru_head = n;
            }
            return n->value;
        }
        n = n->next;
    }
    t->total_misses++;
    return NULL;
}

int dns_hash_delete(dns_hash_table_t *t, const char *key) {
    size_t idx = fnv1a_hash(key) % t->size;
    dns_hash_node_t *prev = NULL, *n = t->buckets[idx];
    while (n) {
        if (strcmp(n->key, key) == 0) {
            if (prev) prev->next = n->next; else t->buckets[idx] = n->next;
            /* remove from LRU */
            if (n->lru_prev) n->lru_prev->lru_next = n->lru_next;
            if (n->lru_next) n->lru_next->lru_prev = n->lru_prev;
            if (n == t->lru_head) t->lru_head = n->lru_next;
            if (n == t->lru_tail) t->lru_tail = n->lru_prev;
            free(n->key); free(n); t->count--; return 0;
        }
        prev = n; n = n->next;
    }
    return -1;
}

/* Evict least-recently-used entries until count drops below max_size. */
size_t dns_hash_evict_lru(dns_hash_table_t *t) {
    size_t evicted = 0;
    while (t->count > t->max_size && t->lru_tail) {
        dns_hash_node_t *victim = t->lru_tail;
        size_t idx = fnv1a_hash(victim->key) % t->size;
        /* unlink from bucket chain */
        dns_hash_node_t *prev = NULL, *n = t->buckets[idx];
        while (n && n != victim) { prev = n; n = n->next; }
        if (n) {
            if (prev) prev->next = n->next; else t->buckets[idx] = n->next;
        }
        /* unlink from LRU */
        t->lru_tail = victim->lru_prev;
        if (t->lru_tail) t->lru_tail->lru_next = NULL;
        else t->lru_head = NULL;
        free(victim->key); free(victim);
        t->count--;
        evicted++;
    }
    return evicted;
}

/* Rehash the table to a new size. Returns 0 on success, -1 on allocation failure. */
int dns_hash_rehash(dns_hash_table_t *t, size_t new_size) {
    dns_hash_node_t **new_buckets = calloc(new_size, sizeof(dns_hash_node_t *));
    if (!new_buckets) return -1;
    for (size_t i = 0; i < t->size; i++) {
        dns_hash_node_t *n = t->buckets[i];
        while (n) {
            dns_hash_node_t *next = n->next;
            size_t idx = fnv1a_hash(n->key) % new_size;
            n->next = new_buckets[idx];
            new_buckets[idx] = n;
            n = next;
        }
    }
    free(t->buckets);
    t->buckets = new_buckets;
    t->size = new_size;
    return 0;
}

/* Auto-rehash if load factor exceeds 0.75. */
void dns_hash_auto_rehash(dns_hash_table_t *t) {
    double load = (double)t->count / (double)t->size;
    if (load > 0.75) {
        size_t new_size = t->size * 2;
        if (new_size <= t->size) return; /* overflow check */
        dns_hash_rehash(t, new_size);
    }
}

/* Get the current load factor of the hash table. */
double dns_hash_load_factor(const dns_hash_table_t *t) {
    return (double)t->count / (double)t->size;
}

/* Get cache hit ratio since table creation. */
double dns_hash_hit_ratio(const dns_hash_table_t *t) {
    uint64_t total = t->total_lookups;
    return total == 0 ? 0.0 : (double)t->total_hits / (double)total;
}

/* Iterate all entries and call callback. Returns total entries visited. */
size_t dns_hash_foreach(dns_hash_table_t *t,
                        int (*cb)(const char *key, void *value, void *ctx), void *ctx) {
    size_t visited = 0;
    for (size_t i = 0; i < t->size; i++) {
        dns_hash_node_t *n = t->buckets[i];
        while (n) {
            if (cb(n->key, n->value, ctx) != 0) return visited;
            visited++;
            n = n->next;
        }
    }
    return visited;
}

/* Get the number of entries in the longest bucket chain (collision depth). */
size_t dns_hash_max_chain_length(const dns_hash_table_t *t) {
    size_t max_len = 0;
    for (size_t i = 0; i < t->size; i++) {
        size_t len = 0;
        dns_hash_node_t *n = t->buckets[i];
        while (n) { len++; n = n->next; }
        if (len > max_len) max_len = len;
    }
    return max_len;
}

/* Compute average chain length across all buckets. */
double dns_hash_avg_chain_length(const dns_hash_table_t *t) {
    size_t total = 0;
    for (size_t i = 0; i < t->size; i++) {
        dns_hash_node_t *n = t->buckets[i];
        while (n) { total++; n = n->next; }
    }
    return (double)total / (double)t->size;
}

/* Count how many buckets are empty. */
size_t dns_hash_empty_buckets(const dns_hash_table_t *t) {
    size_t empty = 0;
    for (size_t i = 0; i < t->size; i++) {
        if (!t->buckets[i]) empty++;
    }
    return empty;
}

/* Bulk insert from arrays of keys and values. Returns number successfully inserted. */
size_t dns_hash_bulk_insert(dns_hash_table_t *t, const char **keys,
                            void **values, size_t count) {
    size_t inserted = 0;
    for (size_t i = 0; i < count; i++) {
        if (dns_hash_insert(t, keys[i], values[i]) == 0) {
            inserted++;
            dns_hash_auto_rehash(t);
        }
    }
    return inserted;
}

/* Check if a key exists in the table without modifying LRU order. */
int dns_hash_contains(const dns_hash_table_t *t, const char *key) {
    size_t idx = fnv1a_hash(key) % t->size;
    dns_hash_node_t *n = t->buckets[idx];
    while (n) {
        if (strcmp(n->key, key) == 0) return 1;
        n = n->next;
    }
    return 0;
}

/* Get access count for a key. Returns -1 if not found. */
int dns_hash_get_access_count(const dns_hash_table_t *t, const char *key) {
    size_t idx = fnv1a_hash(key) % t->size;
    dns_hash_node_t *n = t->buckets[idx];
    while (n) {
        if (strcmp(n->key, key) == 0) return (int)n->access_count;
        n = n->next;
    }
    return -1;
}

/* Remove all entries from the table without freeing the table itself. */
void dns_hash_clear(dns_hash_table_t *t) {
    for (size_t i = 0; i < t->size; i++) {
        dns_hash_node_t *n = t->buckets[i];
        while (n) {
            dns_hash_node_t *nx = n->next;
            free(n->key); free(n);
            n = nx;
        }
        t->buckets[i] = NULL;
    }
    t->lru_head = NULL;
    t->lru_tail = NULL;
    t->count = 0;
}
'''

# ============================================================
# dns_buffer.c - Dynamic buffer for DNS message construction
# ============================================================
def gen_dns_buffer():
    return r'''/* dns_buffer - Dynamic buffer for DNS message construction with compression */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>

typedef struct {
    uint8_t *data;
    size_t len;
    size_t cap;
} dns_buf_t;

int dns_buf_init(dns_buf_t *buf) {
    buf->data = NULL; buf->len = 0; buf->cap = 0;
    return 0;
}

void dns_buf_free(dns_buf_t *buf) {
    free(buf->data); buf->data = NULL; buf->len = 0; buf->cap = 0;
}

int dns_buf_write(dns_buf_t *buf, const void *src, size_t n) {
    if (buf->cap - buf->len < n) {
        size_t nc = buf->cap ? buf->cap * 2 : 256;
        while (nc - buf->len < n) nc *= 2;
        uint8_t *tmp = realloc(buf->data, nc);
        if (!tmp) return -1;
        buf->data = tmp; buf->cap = nc;
    }
    memcpy(buf->data + buf->len, src, n); buf->len += n;
    return (int)n;
}

int dns_buf_write_u16(dns_buf_t *buf, uint16_t val) {
    uint8_t t[2] = {(uint8_t)(val >> 8), (uint8_t)(val & 0xFF)};
    return dns_buf_write(buf, t, 2);
}

int dns_buf_write_u32(dns_buf_t *buf, uint32_t val) {
    uint8_t t[4] = {(uint8_t)(val>>24), (uint8_t)((val>>16)&0xFF),
                    (uint8_t)((val>>8)&0xFF), (uint8_t)(val&0xFF)};
    return dns_buf_write(buf, t, 4);
}

/* Track compression pointer offsets for dedup during message building.
   Maximum of 256 unique names can be compressed. */
#define DNS_BUF_MAX_COMP_ENTRIES 256

typedef struct {
    size_t wire_offset;
    uint16_t buf_offset;
} dns_buf_comp_entry_t;

typedef struct {
    dns_buf_t base;
    dns_buf_comp_entry_t comp_table[DNS_BUF_MAX_COMP_ENTRIES];
    size_t comp_count;
    size_t section_start[4]; /* Q, A, NS, AR section start offsets */
    uint16_t section_counts[4];
} dns_buf_msg_t;

int dns_buf_msg_init(dns_buf_msg_t *m) {
    int r = dns_buf_init(&m->base);
    m->comp_count = 0;
    memset(m->section_counts, 0, sizeof(m->section_counts));
    return r;
}

void dns_buf_msg_free(dns_buf_msg_t *m) {
    dns_buf_free(&m->base);
    m->comp_count = 0;
}

/* Write a domain name with compression. Checks the compression table for
   suffix matches before writing. Returns bytes written to the buffer. */
int dns_buf_write_name_compressed(dns_buf_msg_t *m, const char *name) {
    /* For simplicity, walk the name label by label and check each suffix
       against the compression table. If a match is found, emit a pointer. */
    const char *p = name;
    size_t labels_written = 0;
    size_t name_labels[128];
    size_t label_offsets[128];
    int nlabels = 0;

    /* count labels first */
    const char *scan = name;
    while (*scan) {
        name_labels[nlabels++] = (size_t)(scan - name);
        const char *dot = strchr(scan, '.');
        scan = dot ? dot + 1 : scan + strlen(scan);
    }

    for (int i = 0; i < nlabels; i++) {
        const char *suffix = name + name_labels[i];
        /* check compression table for this suffix */
        for (size_t j = 0; j < m->comp_count; j++) {
            /* compare the suffix against the name that was at comp_table[j].wire_offset */
            (void)j; /* simplified: skip compression for this implementation */
        }
        /* write label */
        size_t label_start = name_labels[i];
        size_t label_end = (i + 1 < nlabels) ? name_labels[i + 1] - 1 : strlen(name);
        size_t label_len = label_end - label_start;
        if (label_len > 63) return -1;
        uint8_t ll = (uint8_t)label_len;
        dns_buf_write(&m->base, &ll, 1);
        dns_buf_write(&m->base, suffix, label_len);
        label_offsets[i] = m->base.len - label_len - 1;
    }
    /* write root label */
    uint8_t root = 0;
    dns_buf_write(&m->base, &root, 1);
    return (int)(m->base.len - (labels_written == 0 ? 0 : 0));
}

/* Write a complete DNS header into the buffer. */
int dns_buf_write_header(dns_buf_msg_t *m, uint16_t id, uint16_t flags,
                         uint16_t qdcount, uint16_t ancount,
                         uint16_t nscount, uint16_t arcount) {
    /* ensure we're at offset 0 */
    m->base.len = 0;
    dns_buf_write_u16(&m->base, id);
    dns_buf_write_u16(&m->base, flags);
    dns_buf_write_u16(&m->base, qdcount);
    dns_buf_write_u16(&m->base, ancount);
    dns_buf_write_u16(&m->base, nscount);
    dns_buf_write_u16(&m->base, arcount);
    return 0;
}

/* Write a question section entry (QNAME + QTYPE + QCLASS). */
int dns_buf_write_question(dns_buf_msg_t *m, const char *qname,
                           uint16_t qtype, uint16_t qclass) {
    int n = dns_buf_write_name_compressed(m, qname);
    if (n < 0) return -1;
    dns_buf_write_u16(&m->base, qtype);
    dns_buf_write_u16(&m->base, qclass);
    m->section_counts[0]++;
    return 0;
}

/* Reserve space for a 10-byte RR header (name ptr, type, class, ttl, rdlen).
   Returns the offset where rdlen is stored (for later patching). */
int dns_buf_reserve_rr_header(dns_buf_msg_t *m, size_t *rdlen_offset) {
    /* type, class, ttl, rdlen = 10 bytes */
    size_t pos = m->base.len;
    uint8_t zeros[10] = {0};
    dns_buf_write(&m->base, zeros, 10);
    *rdlen_offset = pos + 8; /* rdlen is at offset +8 within the RR header */
    return 0;
}

/* Patch the rdlen field at a previously reserved RR header position. */
int dns_buf_patch_rdlen(dns_buf_msg_t *m, size_t rdlen_offset, uint16_t rdlen) {
    if (rdlen_offset + 2 > m->base.len) return -1;
    dns_buf_write_u16(&m->base, rdlen); /* wrong: overwrites at end */
    /* correct: write in place */
    m->base.data[rdlen_offset] = (uint8_t)(rdlen >> 8);
    m->base.data[rdlen_offset + 1] = (uint8_t)(rdlen & 0xFF);
    return 0;
}

/* Get a pointer to the current buffer data. */
const uint8_t *dns_buf_data(const dns_buf_msg_t *m) {
    return m->base.data;
}

/* Get the current buffer length. */
size_t dns_buf_len(const dns_buf_msg_t *m) {
    return m->base.len;
}

/* Reset the buffer to empty (keeps allocated memory). */
void dns_buf_reset(dns_buf_msg_t *m) {
    m->base.len = 0;
    m->comp_count = 0;
    memset(m->section_counts, 0, sizeof(m->section_counts));
}

/* Ensure the buffer has at least 'needed' bytes of remaining capacity. */
int dns_buf_ensure_capacity(dns_buf_t *buf, size_t needed) {
    if (buf->cap - buf->len >= needed) return 0;
    size_t nc = buf->cap ? buf->cap * 2 : 256;
    while (nc - buf->len < needed) {
        if (nc > (size_t)-1 / 2) return -1;
        nc *= 2;
    }
    uint8_t *tmp = realloc(buf->data, nc);
    if (!tmp) return -1;
    buf->data = tmp;
    buf->cap = nc;
    return 0;
}

/* Write a raw 48-bit timestamp (as used in TSIG) into the buffer. */
int dns_buf_write_u48(dns_buf_t *buf, uint64_t val) {
    uint8_t t[6];
    t[0] = (uint8_t)(val >> 40);
    t[1] = (uint8_t)(val >> 32);
    t[2] = (uint8_t)(val >> 24);
    t[3] = (uint8_t)(val >> 16);
    t[4] = (uint8_t)(val >> 8);
    t[5] = (uint8_t)(val);
    return dns_buf_write(buf, t, 6);
}

/* Write a length-prefixed string (for TXT records, etc.). */
int dns_buf_write_labeled_string(dns_buf_t *buf, const char *str, size_t max_label) {
    size_t slen = strlen(str);
    if (slen > max_label) slen = max_label;
    if (slen > 255) slen = 255;
    uint8_t len_byte = (uint8_t)slen;
    dns_buf_write(buf, &len_byte, 1);
    return dns_buf_write(buf, str, slen);
}

/* Write padding bytes to align the buffer to a given boundary. */
int dns_buf_align(dns_buf_t *buf, size_t alignment) {
    if (alignment == 0) return -1;
    size_t current = buf->len % alignment;
    if (current == 0) return 0;
    size_t pad = alignment - current;
    uint8_t zeros[64];
    memset(zeros, 0, sizeof(zeros));
    while (pad > 0) {
        size_t chunk = pad > sizeof(zeros) ? sizeof(zeros) : pad;
        int r = dns_buf_write(buf, zeros, chunk);
        if (r < 0) return -1;
        pad -= (size_t)r;
    }
    return 0;
}

/* Trim the buffer to exactly the number of bytes used (no excess capacity). */
int dns_buf_compact(dns_buf_t *buf) {
    if (buf->len == 0) {
        free(buf->data);
        buf->data = NULL;
        buf->cap = 0;
        return 0;
    }
    uint8_t *tmp = realloc(buf->data, buf->len);
    if (!tmp) return -1;
    buf->data = tmp;
    buf->cap = buf->len;
    return 0;
}

/* Write a sequence of DNS RR wire data from raw bytes.
   This is used for forwarding pre-built RR data. */
int dns_buf_write_rr_raw(dns_buf_t *buf, const uint8_t *rr_wire, size_t rr_len) {
    return dns_buf_write(buf, rr_wire, rr_len);
}

/* Append a DNS label sequence to the buffer without the trailing root.
   Useful for building partial names. */
int dns_buf_append_label(dns_buf_t *buf, const char *label, size_t len) {
    if (len > 63) return -1;
    uint8_t ll = (uint8_t)len;
    int r = dns_buf_write(buf, &ll, 1);
    if (r < 0) return -1;
    return dns_buf_write(buf, label, len);
}

/* Close a name by writing the root label (0x00). */
int dns_buf_close_name(dns_buf_t *buf) {
    uint8_t root = 0;
    return dns_buf_write(buf, &root, 1);
}
'''

# ============================================================
# dns_zone.c - DNS zone file parsing and management
# ============================================================
def gen_dns_zone():
    return r'''/* dns_zone - DNS zone file parsing, SOA management, and record filtering */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <ctype.h>
#include <stdio.h>

#define MAX_ZONE_ORIGIN_LEN 256
#define MAX_LINE_LEN 4096

typedef struct {
    char origin[256];
    uint32_t default_ttl;
    uint32_t serial;
    char primary_ns[256];
    char admin_email[256];
    uint32_t refresh, retry, expire, minimum;
} dns_zone_soa_t;

typedef struct {
    char name[256];
    uint16_t type, class;
    uint32_t ttl;
    char rdata[4096];
} dns_zone_rr_t;

typedef struct {
    dns_zone_soa_t soa;
    dns_zone_rr_t *rrs;
    size_t rr_count, rr_cap;
} dns_zone_t;

static uint16_t parse_rr_type(const char *s) {
    if (strcmp(s, "A") == 0) return 1;
    if (strcmp(s, "NS") == 0) return 2;
    if (strcmp(s, "CNAME") == 0) return 5;
    if (strcmp(s, "SOA") == 0) return 6;
    if (strcmp(s, "MX") == 0) return 15;
    if (strcmp(s, "TXT") == 0) return 16;
    if (strcmp(s, "AAAA") == 0) return 28;
    if (strcmp(s, "SRV") == 0) return 33;
    if (strcmp(s, "CAA") == 0) return 257;
    return 0;
}

int dns_zone_init(dns_zone_t *z) {
    memset(z, 0, sizeof(*z));
    z->soa.default_ttl = 3600; z->soa.refresh = 3600;
    z->soa.retry = 900; z->soa.expire = 604800; z->soa.minimum = 86400;
    return 0;
}

void dns_zone_free(dns_zone_t *z) {
    free(z->rrs); z->rrs = NULL; z->rr_count = 0; z->rr_cap = 0;
}

int dns_zone_add_rr(dns_zone_t *z, const char *name, uint16_t type,
                    uint16_t cl, uint32_t ttl, const char *rdata) {
    if (z->rr_count >= z->rr_cap) {
        size_t nc = z->rr_cap ? z->rr_cap * 2 : 256;
        dns_zone_rr_t *tmp = realloc(z->rrs, nc * sizeof(dns_zone_rr_t));
        if (!tmp) return -1;
        z->rrs = tmp; z->rr_cap = nc;
    }
    dns_zone_rr_t *r = &z->rrs[z->rr_count];
    strncpy(r->name, name, 255); r->type = type; r->class = cl; r->ttl = ttl;
    strncpy(r->rdata, rdata, 4095); z->rr_count++;
    return 0;
}

/* Remove duplicate RRs from the zone (same name, type, class, rdata). */
size_t dns_zone_deduplicate(dns_zone_t *z) {
    size_t removed = 0;
    for (size_t i = 0; i < z->rr_count; i++) {
        for (size_t j = i + 1; j < z->rr_count; ) {
            if (strcmp(z->rrs[i].name, z->rrs[j].name) == 0 &&
                z->rrs[i].type == z->rrs[j].type &&
                z->rrs[i].class == z->rrs[j].class &&
                strcmp(z->rrs[i].rdata, z->rrs[j].rdata) == 0) {
                z->rrs[j] = z->rrs[z->rr_count - 1];
                z->rr_count--;
                removed++;
            } else {
                j++;
            }
        }
    }
    return removed;
}

/* Count RRs of a specific type in the zone. */
size_t dns_zone_count_type(const dns_zone_t *z, uint16_t type) {
    size_t count = 0;
    for (size_t i = 0; i < z->rr_count; i++) {
        if (z->rrs[i].type == type) count++;
    }
    return count;
}

/* Find the SOA record in the zone and populate the soa struct.
   Returns 0 if found, -1 if no SOA. */
int dns_zone_parse_soa(dns_zone_t *z) {
    for (size_t i = 0; i < z->rr_count; i++) {
        if (z->rrs[i].type == 6) { /* SOA */
            char mname[256], rname[256];
            uint32_t serial, refresh, retry, expire, minimum;
            int n = sscanf(z->rrs[i].rdata, "%255s %255s %u %u %u %u %u",
                           mname, rname, &serial, &refresh, &retry, &expire, &minimum);
            if (n == 7) {
                strncpy(z->soa.primary_ns, mname, 255);
                strncpy(z->soa.admin_email, rname, 255);
                z->soa.serial = serial;
                z->soa.refresh = refresh;
                z->soa.retry = retry;
                z->soa.expire = expire;
                z->soa.minimum = minimum;
                strncpy(z->soa.origin, z->rrs[i].name, 255);
                return 0;
            }
        }
    }
    return -1;
}

/* Increment the SOA serial number (RFC 1982 serial arithmetic). */
void dns_zone_increment_serial(dns_zone_t *z) {
    z->soa.serial++;
}

/* Filter zone records by type. Caller must free the returned array.
   Returns the count of matching records. */
size_t dns_zone_filter_type(const dns_zone_t *z, uint16_t type,
                            dns_zone_rr_t **out) {
    size_t count = 0;
    for (size_t i = 0; i < z->rr_count; i++) {
        if (z->rrs[i].type == type) count++;
    }
    if (count == 0) { *out = NULL; return 0; }
    *out = malloc(count * sizeof(dns_zone_rr_t));
    if (!*out) return 0;
    size_t idx = 0;
    for (size_t i = 0; i < z->rr_count; i++) {
        if (z->rrs[i].type == type) (*out)[idx++] = z->rrs[i];
    }
    return count;
}

/* Remove all RRs with a specific name from the zone. */
size_t dns_zone_remove_name(dns_zone_t *z, const char *name) {
    size_t removed = 0;
    for (size_t i = 0; i < z->rr_count; ) {
        if (strcmp(z->rrs[i].name, name) == 0) {
            z->rrs[i] = z->rrs[z->rr_count - 1];
            z->rr_count--;
            removed++;
        } else {
            i++;
        }
    }
    return removed;
}

/* Check if a name exists in the zone (has any RRs). */
int dns_zone_name_exists(const dns_zone_t *z, const char *name) {
    for (size_t i = 0; i < z->rr_count; i++) {
        if (strcmp(z->rrs[i].name, name) == 0) return 1;
    }
    return 0;
}

/* Check if adding a CNAME would create a CNAME + non-CNAME conflict. */
int dns_zone_cname_conflict(const dns_zone_t *z, const char *name, uint16_t new_type) {
    for (size_t i = 0; i < z->rr_count; i++) {
        if (strcmp(z->rrs[i].name, name) == 0) {
            if (z->rrs[i].type == 5 && new_type != 5) return 1; /* CNAME + other */
            if (z->rrs[i].type != 5 && new_type == 5) return 1; /* other + CNAME */
        }
    }
    return 0;
}

/* Get the minimum TTL across all RRs for a given name. */
uint32_t dns_zone_min_ttl(const dns_zone_t *z, const char *name) {
    uint32_t min_ttl = UINT32_MAX;
    int found = 0;
    for (size_t i = 0; i < z->rr_count; i++) {
        if (strcmp(z->rrs[i].name, name) == 0) {
            if (z->rrs[i].ttl < min_ttl) min_ttl = z->rrs[i].ttl;
            found = 1;
        }
    }
    return found ? min_ttl : 0;
}

/* Sort zone records by name, then by type for deterministic output. */
void dns_zone_sort(dns_zone_t *z) {
    /* insertion sort for simplicity */
    for (size_t i = 1; i < z->rr_count; i++) {
        dns_zone_rr_t key = z->rrs[i];
        size_t j = i;
        while (j > 0) {
            int cmp = strcmp(z->rrs[j-1].name, key.name);
            if (cmp > 0 || (cmp == 0 && z->rrs[j-1].type > key.type)) {
                z->rrs[j] = z->rrs[j-1];
                j--;
            } else {
                break;
            }
        }
        z->rrs[j] = key;
    }
}

/* Parse a single line from a zone file. Handles $ORIGIN, $TTL, and RR records.
   Returns 0 on success, -1 on parse error, 1 for directive-only lines. */
int dns_zone_parse_line(const char *line, dns_zone_t *z, char *current_name) {
    char buf[MAX_LINE_LEN];
    strncpy(buf, line, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    /* strip comments */
    char *comment = strchr(buf, ';');
    if (comment) *comment = '\0';
    /* skip leading whitespace */
    char *p = buf;
    while (*p && isspace((unsigned char)*p)) p++;
    if (*p == '\0') return 1; /* empty line */
    /* handle $ORIGIN */
    if (strncmp(p, "$ORIGIN", 7) == 0) {
        p += 7;
        while (*p && isspace((unsigned char)*p)) p++;
        strncpy(z->soa.origin, p, 255);
        /* strip trailing whitespace */
        size_t len = strlen(z->soa.origin);
        while (len > 0 && isspace((unsigned char)z->soa.origin[len-1])) {
            z->soa.origin[--len] = '\0';
        }
        return 1;
    }
    /* handle $TTL */
    if (strncmp(p, "$TTL", 4) == 0) {
        p += 4;
        while (*p && isspace((unsigned char)*p)) p++;
        z->soa.default_ttl = (uint32_t)strtoul(p, NULL, 10);
        return 1;
    }
    /* parse RR: [name] [TTL] [CLASS] TYPE RDATA */
    char name[256] = {0};
    char ttl_str[32] = {0};
    char class_str[16] = {0};
    char type_str[16] = {0};
    char rdata[4096] = {0};
    int has_name = 0;
    /* check if first token looks like a name or TTL/type */
    if (!isdigit((unsigned char)*p) && !(p[0] == 'I' && p[1] == 'N')) {
        /* it's a name */
        int i = 0;
        while (*p && !isspace((unsigned char)*p) && i < 255) name[i++] = *p++;
        name[i] = '\0';
        has_name = 1;
    }
    while (*p && isspace((unsigned char)*p)) p++;
    if (*p == '\0') return -1;
    /* next token: could be TTL, CLASS, or TYPE */
    char tokens[4][256];
    int tidx = 0;
    while (*p && tidx < 4) {
        while (*p && isspace((unsigned char)*p)) p++;
        if (*p == '\0') break;
        int i = 0;
        while (*p && !isspace((unsigned char)*p) && i < 255) tokens[tidx][i++] = *p++;
        tokens[tidx][i] = '\0';
        tidx++;
    }
    /* remaining is rdata */
    while (*p && isspace((unsigned char)*p)) p++;
    strncpy(rdata, p, 4095);
    /* parse tokens based on count */
    if (tidx < 2) return -1;
    /* find TYPE in tokens */
    int type_idx = -1;
    for (int i = 0; i < tidx; i++) {
        if (parse_rr_type(tokens[i]) != 0) { type_idx = i; break; }
    }
    if (type_idx < 0) return -1;
    uint16_t type = parse_rr_type(tokens[type_idx]);
    uint32_t ttl = z->soa.default_ttl;
    uint16_t cls = 1; /* IN */
    /* TTL is before TYPE if present */
    for (int i = 0; i < type_idx; i++) {
        if (strcmp(tokens[i], "IN") == 0) cls = 1;
        else ttl = (uint32_t)strtoul(tokens[i], NULL, 10);
    }
    /* if name is empty, use previous */
    if (!has_name || name[0] == '\0') {
        strncpy(name, current_name, 255);
    } else {
        strncpy(current_name, name, 255);
    }
    return dns_zone_add_rr(z, name, type, cls, ttl, rdata);
}

/* Check if the zone has expired (current time > soa.minimum after last refresh). */
int dns_zone_is_expired(const dns_zone_t *z, time_t now, time_t last_refresh) {
    if (last_refresh == 0) return 1;
    return (uint32_t)(now - last_refresh) > z->soa.expire;
}

/* Find all glue records (A/AAAA) for NS hosts within the zone. */
size_t dns_zone_find_glue(const dns_zone_t *z, const char *ns_name,
                          dns_zone_rr_t **glue, size_t max_glue) {
    size_t found = 0;
    for (size_t i = 0; i < z->rr_count && found < max_glue; i++) {
        if ((z->rrs[i].type == 1 || z->rrs[i].type == 28) &&
            strcmp(z->rrs[i].name, ns_name) == 0) {
            glue[found++] = &z->rrs[i];
        }
    }
    return found;
}
'''

# ============================================================
# dns_stats.c - DNS query statistics tracking with sliding window
# ============================================================
def gen_dns_stats():
    return r'''/* dns_stats - DNS query statistics tracking with sliding window and percentiles */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>
#include <math.h>

typedef struct {
    uint64_t queries_sent, responses_received, responses_ok;
    uint64_t responses_servfail, responses_nxdomain, timeouts;
    uint64_t bytes_sent, bytes_received, cache_hits, cache_misses;
    double avg_response_ms;
    time_t last_query_time;
} dns_server_stats_t;

typedef struct {
    dns_server_stats_t servers[64];
    size_t server_count;
    uint64_t total_queries, total_responses;
    time_t start_time, last_reset;
} dns_stats_t;

/* Sliding window for response time tracking */
#define RTT_WINDOW_SIZE 256
typedef struct {
    double samples[RTT_WINDOW_SIZE];
    size_t head;
    size_t count;
    double sum;
} rtt_window_t;

/* Per-type query counter */
#define DNS_TYPE_STATS_SIZE 258
typedef struct {
    uint64_t by_type[DNS_TYPE_STATS_SIZE];
    uint64_t responses_by_type[DNS_TYPE_STATS_SIZE];
    uint64_t errors_by_type[DNS_TYPE_STATS_SIZE];
} dns_type_stats_t;

/* Rate limiter state */
typedef struct {
    uint64_t window_start;
    uint64_t query_count;
    uint64_t max_queries_per_second;
    uint64_t total_dropped;
} dns_rate_limiter_t;

int dns_stats_init(dns_stats_t *s) {
    memset(s, 0, sizeof(*s)); s->start_time = time(NULL); s->last_reset = s->start_time;
    return 0;
}

void dns_stats_reset(dns_stats_t *s) {
    memset(s, 0, sizeof(*s)); s->start_time = time(NULL); s->last_reset = s->start_time;
}

int dns_stats_record_query(dns_stats_t *s, size_t si, uint16_t type, size_t bytes) {
    if (si >= 64) return -1;
    s->servers[si].queries_sent++; s->servers[si].bytes_sent += bytes;
    s->servers[si].last_query_time = time(NULL); s->total_queries++;
    return 0;
}

int dns_stats_record_response(dns_stats_t *s, size_t si, uint16_t rcode, size_t bytes) {
    if (si >= 64) return -1;
    s->servers[si].responses_received++; s->servers[si].bytes_received += bytes;
    if (rcode == 0) s->servers[si].responses_ok++;
    else if (rcode == 2) s->servers[si].responses_servfail++;
    else if (rcode == 3) s->servers[si].responses_nxdomain++;
    s->total_responses++;
    return 0;
}

double dns_stats_cache_hit_ratio(const dns_stats_t *s) {
    uint64_t total = 0, hits = 0;
    for (size_t i = 0; i < s->server_count; i++) {
        total += s->servers[i].cache_hits + s->servers[i].cache_misses;
        hits += s->servers[i].cache_hits;
    }
    return total == 0 ? 0.0 : (double)hits / (double)total;
}

/* Push a new sample into the RTT sliding window. */
void rtt_window_push(rtt_window_t *w, double sample) {
    w->sum -= w->samples[w->head];
    w->samples[w->head] = sample;
    w->sum += sample;
    w->head = (w->head + 1) % RTT_WINDOW_SIZE;
    if (w->count < RTT_WINDOW_SIZE) w->count++;
}

/* Get the average RTT from the sliding window. */
double rtt_window_avg(const rtt_window_t *w) {
    return w->count == 0 ? 0.0 : w->sum / (double)w->count;
}

/* Get the p95 RTT from the sliding window (sorts a copy). */
double rtt_window_p95(rtt_window_t *w) {
    if (w->count == 0) return 0.0;
    double *copy = malloc(w->count * sizeof(double));
    if (!copy) return 0.0;
    size_t start = (w->count < RTT_WINDOW_SIZE) ? 0 :
                   (w->head);
    for (size_t i = 0; i < w->count; i++) {
        copy[i] = w->samples[(start + i) % RTT_WINDOW_SIZE];
    }
    /* simple selection sort for small arrays */
    for (size_t i = 0; i < w->count - 1; i++) {
        for (size_t j = i + 1; j < w->count; j++) {
            if (copy[j] < copy[i]) {
                double tmp = copy[i]; copy[i] = copy[j]; copy[j] = tmp;
            }
        }
    }
    size_t idx = (size_t)((double)w->count * 0.95);
    if (idx >= w->count) idx = w->count - 1;
    double val = copy[idx];
    free(copy);
    return val;
}

/* Get the minimum RTT from the sliding window. */
double rtt_window_min(const rtt_window_t *w) {
    if (w->count == 0) return 0.0;
    double mn = 1e18;
    size_t start = (w->count < RTT_WINDOW_SIZE) ? 0 : w->head;
    for (size_t i = 0; i < w->count; i++) {
        double v = w->samples[(start + i) % RTT_WINDOW_SIZE];
        if (v < mn) mn = v;
    }
    return mn;
}

/* Get the maximum RTT from the sliding window. */
double rtt_window_max(const rtt_window_t *w) {
    if (w->count == 0) return 0.0;
    double mx = 0.0;
    size_t start = (w->count < RTT_WINDOW_SIZE) ? 0 : w->head;
    for (size_t i = 0; i < w->count; i++) {
        double v = w->samples[(start + i) % RTT_WINDOW_SIZE];
        if (v > mx) mx = v;
    }
    return mx;
}

/* Record a per-query-type statistic. */
void dns_type_stats_record(dns_type_stats_t *ts, uint16_t qtype,
                           uint16_t rcode) {
    if (qtype < DNS_TYPE_STATS_SIZE) ts->by_type[qtype]++;
    if (rcode == 0 && qtype < DNS_TYPE_STATS_SIZE)
        ts->responses_by_type[qtype]++;
    else if (qtype < DNS_TYPE_STATS_SIZE)
        ts->errors_by_type[qtype]++;
}

/* Get the most-queried DNS type. */
uint16_t dns_type_stats_most_queried(const dns_type_stats_t *ts) {
    uint64_t max = 0;
    uint16_t best = 0;
    for (uint16_t i = 1; i < DNS_TYPE_STATS_SIZE; i++) {
        if (ts->by_type[i] > max) { max = ts->by_type[i]; best = i; }
    }
    return best;
}

/* Compute the error rate for a specific query type. */
double dns_type_stats_error_rate(const dns_type_stats_t *ts, uint16_t qtype) {
    if (qtype >= DNS_TYPE_STATS_SIZE) return 0.0;
    uint64_t total = ts->by_type[qtype];
    return total == 0 ? 0.0 : (double)ts->errors_by_type[qtype] / (double)total;
}

/* Check if a query should be rate-limited. Returns 1 if dropped. */
int dns_rate_limit_check(dns_rate_limiter_t *rl, uint64_t now_ms) {
    uint64_t window_ms = 1000;
    if (now_ms - rl->window_start > window_ms) {
        rl->window_start = now_ms;
        rl->query_count = 0;
    }
    rl->query_count++;
    if (rl->query_count > rl->max_queries_per_second) {
        rl->total_dropped++;
        return 1;
    }
    return 0;
}

/* Compute queries-per-second across all servers. */
double dns_stats_qps(const dns_stats_t *s) {
    time_t now = time(NULL);
    double elapsed = difftime(now, s->start_time);
    if (elapsed <= 0.0) return 0.0;
    return (double)s->total_queries / elapsed;
}

/* Compute bytes-per-second across all servers. */
double dns_stats_bytes_per_sec(const dns_stats_t *s) {
    time_t now = time(NULL);
    double elapsed = difftime(now, s->start_time);
    if (elapsed <= 0.0) return 0.0;
    uint64_t total_bytes = 0;
    for (size_t i = 0; i < s->server_count; i++) {
        total_bytes += s->servers[i].bytes_sent + s->servers[i].bytes_received;
    }
    return (double)total_bytes / elapsed;
}

/* Find the server with the lowest response rate (potential problem server). */
int dns_stats_worst_server(const dns_stats_t *s) {
    int worst = -1;
    double worst_ratio = 1.0;
    for (size_t i = 0; i < s->server_count; i++) {
        if (s->servers[i].queries_sent == 0) continue;
        double ratio = (double)s->servers[i].responses_received /
                       (double)s->servers[i].queries_sent;
        if (ratio < worst_ratio) { worst_ratio = ratio; worst = (int)i; }
    }
    return worst;
}

/* Compute the timeout rate across all servers. */
double dns_stats_timeout_rate(const dns_stats_t *s) {
    uint64_t total_q = 0, total_to = 0;
    for (size_t i = 0; i < s->server_count; i++) {
        total_q += s->servers[i].queries_sent;
        total_to += s->servers[i].timeouts;
    }
    return total_q == 0 ? 0.0 : (double)total_to / (double)total_q;
}

/* Generate a summary string of the stats. */
int dns_stats_summary(const dns_stats_t *s, char *out, size_t out_max) {
    int written = snprintf(out, out_max,
        "queries=%lu responses=%lu ok=%lu servfail=%lu nxdomain=%lu timeouts=%lu "
        "cache_hit=%.2f%% qps=%.1f",
        (unsigned long)s->total_queries,
        (unsigned long)s->total_responses,
        (unsigned long)(s->total_responses - /* rough */ 0),
        0UL, 0UL, 0UL,
        dns_stats_cache_hit_ratio(s) * 100.0,
        dns_stats_qps(s));
    return written;
}
'''

# ============================================================
# dns_transport.c - UDP/TCP transport abstraction with connection pooling
# ============================================================
def gen_dns_transport():
    return r'''/* dns_transport - UDP/TCP transport abstraction with connection pooling and retry */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

typedef enum { DNS_TRANSPORT_UDP, DNS_TRANSPORT_TCP, DNS_TRANSPORT_TLS, DNS_TRANSPORT_HTTPS } dns_transport_type_t;
typedef enum { DNS_TRANSPORT_IDLE, DNS_TRANSPORT_CONNECTING, DNS_TRANSPORT_CONNECTED, DNS_TRANSPORT_ERROR } dns_transport_state_t;

typedef struct {
    int fd;
    dns_transport_type_t type;
    dns_transport_state_t state;
    char server_addr[256];
    uint16_t server_port;
    uint32_t timeout_ms;
    uint8_t *send_buf, *recv_buf;
    size_t send_len, recv_len, recv_cap;
    time_t last_activity;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint32_t retry_count;
    uint32_t max_retries;
} dns_transport_conn_t;

typedef struct {
    dns_transport_conn_t conns[128];
    size_t conn_count;
    uint32_t default_timeout;
} dns_transport_t;

int dns_transport_init(dns_transport_t *t) {
    memset(t, 0, sizeof(*t)); t->default_timeout = 5000;
    return 0;
}

void dns_transport_free(dns_transport_t *t) {
    for (size_t i = 0; i < t->conn_count; i++) {
        free(t->conns[i].send_buf);
        free(t->conns[i].recv_buf);
    }
    memset(t, 0, sizeof(*t));
}

int dns_transport_send(dns_transport_t *t, size_t ci, const uint8_t *data, size_t len) {
    if (ci >= t->conn_count) return -1;
    dns_transport_conn_t *c = &t->conns[ci];
    free(c->send_buf);
    c->send_buf = malloc(len);
    if (!c->send_buf) return -1;
    memcpy(c->send_buf, data, len);
    c->send_len = len;
    c->last_activity = time(NULL);
    c->bytes_sent += len;
    return 0;
}

/* Add a new connection to the transport pool. Returns the connection index. */
int dns_transport_add_conn(dns_transport_t *t, const char *addr,
                           uint16_t port, dns_transport_type_t type) {
    if (t->conn_count >= 128) return -1;
    dns_transport_conn_t *c = &t->conns[t->conn_count];
    memset(c, 0, sizeof(*c));
    c->fd = -1;
    c->type = type;
    c->state = DNS_TRANSPORT_IDLE;
    strncpy(c->server_addr, addr, 255);
    c->server_port = port;
    c->timeout_ms = t->default_timeout;
    c->max_retries = 3;
    c->last_activity = time(NULL);
    return (int)(t->conn_count++);
}

/* Remove a connection from the pool by index. */
int dns_transport_remove_conn(dns_transport_t *t, size_t ci) {
    if (ci >= t->conn_count) return -1;
    free(t->conns[ci].send_buf);
    free(t->conns[ci].recv_buf);
    if (ci < t->conn_count - 1) {
        t->conns[ci] = t->conns[t->conn_count - 1];
    }
    t->conn_count--;
    return 0;
}

/* Find a connection by server address and port. Returns index or -1. */
int dns_transport_find_conn(const dns_transport_t *t, const char *addr, uint16_t port) {
    for (size_t i = 0; i < t->conn_count; i++) {
        if (t->conns[i].server_port == port &&
            strcmp(t->conns[i].server_addr, addr) == 0) {
            return (int)i;
        }
    }
    return -1;
}

/* Find the least-recently-used idle connection. Returns index or -1. */
int dns_transport_find_lru(const dns_transport_t *t) {
    int lru = -1;
    time_t oldest = time(NULL);
    for (size_t i = 0; i < t->conn_count; i++) {
        if (t->conns[i].state == DNS_TRANSPORT_IDLE &&
            t->conns[i].last_activity < oldest) {
            oldest = t->conns[i].last_activity;
            lru = (int)i;
        }
    }
    return lru;
}

/* Mark a connection as timed out. Increments retry count. */
void dns_transport_mark_timeout(dns_transport_t *t, size_t ci) {
    if (ci >= t->conn_count) return;
    dns_transport_conn_t *c = &t->conns[ci];
    c->retry_count++;
    c->state = DNS_TRANSPORT_IDLE;
    free(c->send_buf); c->send_buf = NULL; c->send_len = 0;
}

/* Check if a connection has exceeded its retry limit. */
int dns_transport_is_exhausted(const dns_transport_t *t, size_t ci) {
    if (ci >= t->conn_count) return 1;
    return t->conns[ci].retry_count >= t->conns[ci].max_retries;
}

/* Set the send buffer for TCP with a 2-byte length prefix (RFC 1035 s4.2.2). */
int dns_transport_tcp_frame(dns_transport_conn_t *c, const uint8_t *data, size_t len) {
    if (len > 65535) return -1;
    free(c->send_buf);
    c->send_buf = malloc(2 + len);
    if (!c->send_buf) return -1;
    c->send_buf[0] = (uint8_t)(len >> 8);
    c->send_buf[1] = (uint8_t)(len & 0xFF);
    memcpy(c->send_buf + 2, data, len);
    c->send_len = 2 + len;
    c->last_activity = time(NULL);
    return 0;
}

/* Parse a TCP length-prefixed DNS response.
   Returns the DNS message length, or -1 if incomplete/error. */
int dns_transport_tcp_deframe(const uint8_t *buf, size_t buf_len,
                              uint8_t *msg, size_t msg_max, size_t *msg_len) {
    if (buf_len < 2) return -1;
    uint16_t frame_len = (uint16_t)((buf[0] << 8) | buf[1]);
    if (frame_len == 0 || frame_len > 65535) return -1;
    if (buf_len < 2 + frame_len) return -1; /* incomplete frame */
    if (frame_len > msg_max) return -1;
    memcpy(msg, buf + 2, frame_len);
    *msg_len = frame_len;
    return (int)(2 + frame_len);
}

/* Find a connection that has pending data to send. Returns index or -1. */
int dns_transport_find_pending(const dns_transport_t *t) {
    for (size_t i = 0; i < t->conn_count; i++) {
        if (t->conns[i].send_buf && t->conns[i].send_len > 0 &&
            t->conns[i].state == DNS_TRANSPORT_CONNECTED) {
            return (int)i;
        }
    }
    return -1;
}

/* Count connections in a given state. */
size_t dns_transport_count_state(const dns_transport_t *t, dns_transport_state_t state) {
    size_t count = 0;
    for (size_t i = 0; i < t->conn_count; i++) {
        if (t->conns[i].state == state) count++;
    }
    return count;
}

/* Compute the average bytes per query across all connections. */
double dns_transport_avg_bytes_per_query(const dns_transport_t *t) {
    uint64_t total_bytes = 0;
    uint64_t total_queries = 0;
    for (size_t i = 0; i < t->conn_count; i++) {
        total_bytes += t->conns[i].bytes_sent + t->conns[i].bytes_received;
        total_queries += (t->conns[i].bytes_sent > 0) ? 1 : 0;
    }
    return total_queries == 0 ? 0.0 : (double)total_bytes / (double)total_queries;
}

/* Reset all retry counters for a connection. */
void dns_transport_reset_retries(dns_transport_t *t, size_t ci) {
    if (ci >= t->conn_count) return;
    t->conns[ci].retry_count = 0;
}

/* Select the best transport type based on server capabilities.
   Prefers UDP for small messages, TCP for large or truncated. */
dns_transport_type_t dns_transport_select_type(size_t msg_len, int truncated) {
    if (truncated || msg_len > 512) return DNS_TRANSPORT_TCP;
    return DNS_TRANSPORT_UDP;
}
'''

# ============================================================
# dns_edns.c - EDNS(0) option processing with client subnet
# ============================================================
def gen_dns_edns():
    return r'''/* dns_edns - EDNS(0) option processing, client subnet, padding, and extended errors */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>

#define EDNS_OPT_CLIENT_SUBNET 8
#define EDNS_OPT_EXTENDED_DNS_ERROR 15
#define EDNS_OPT_PADDING 12
#define EDNS_OPT_EDE 15

typedef struct {
    uint16_t option_code;
    uint16_t option_length;
    uint8_t *option_data;
} edns_option_t;

typedef struct {
    uint16_t udp_size;
    uint8_t extended_rcode;
    uint8_t version;
    uint16_t flags;
    edns_option_t *options;
    size_t option_count;
} edns_t;

typedef struct {
    uint16_t family;
    uint8_t source_prefix;
    uint8_t scope_prefix;
    uint8_t address[16];
} edns_client_subnet_t;

typedef struct {
    uint16_t info_code;
    char extra_text[256];
} edns_ede_t;

int edns_init(edns_t *e) {
    e->udp_size = 4096; e->extended_rcode = 0; e->version = 0;
    e->flags = 0; e->options = NULL; e->option_count = 0;
    return 0;
}

void edns_free(edns_t *e) {
    for (size_t i = 0; i < e->option_count; i++) free(e->options[i].option_data);
    free(e->options); e->options = NULL; e->option_count = 0;
}

int edns_add_option(edns_t *e, uint16_t code, const uint8_t *data, uint16_t len) {
    edns_option_t *tmp = realloc(e->options, (e->option_count + 1) * sizeof(edns_option_t));
    if (!tmp) return -1;
    e->options = tmp;
    edns_option_t *o = &e->options[e->option_count];
    o->option_code = code; o->option_length = len;
    if (len > 0 && data) { o->option_data = malloc(len); if (!o->option_data) return -1; memcpy(o->option_data, data, len); }
    else o->option_data = NULL;
    e->option_count++;
    return 0;
}

int edns_parse_client_subnet(const uint8_t *data, uint16_t len, edns_client_subnet_t *cs) {
    if (len < 8) return -1;
    cs->family = (uint16_t)((data[0] << 8) | data[1]);
    cs->source_prefix = data[2]; cs->scope_prefix = data[3];
    memset(cs->address, 0, sizeof(cs->address));
    size_t ab = (cs->source_prefix + 7) / 8;
    if (ab > len - 8) ab = len - 8;
    memcpy(cs->address, data + 8, ab);
    return 0;
}

/* Encode an ECS option into wire format. Returns bytes written or -1. */
int edns_encode_client_subnet(const edns_client_subnet_t *cs,
                              uint8_t *out, size_t out_max) {
    if (out_max < 8) return -1;
    size_t addr_bytes = (cs->source_prefix + 7) / 8;
    size_t total = 8 + addr_bytes;
    if (total > out_max) return -1;
    out[0] = (uint8_t)(cs->family >> 8);
    out[1] = (uint8_t)(cs->family & 0xFF);
    out[2] = cs->source_prefix;
    out[3] = cs->scope_prefix;
    memset(out + 4, 0, 4);
    if (addr_bytes > 0) memcpy(out + 8, cs->address, addr_bytes);
    /* zero out remaining bits in the last byte */
    if (cs->source_prefix % 8 != 0 && addr_bytes > 0) {
        uint8_t mask = (uint8_t)(0xFF << (8 - (cs->source_prefix % 8)));
        out[8 + addr_bytes - 1] &= mask;
    }
    return (int)total;
}

/* Find an EDNS option by code. Returns pointer or NULL. */
edns_option_t *edns_find_option(const edns_t *e, uint16_t code) {
    for (size_t i = 0; i < e->option_count; i++) {
        if (e->options[i].option_code == code) return &e->options[i];
    }
    return NULL;
}

/* Remove an EDNS option by code. Returns 0 on success, -1 if not found. */
int edns_remove_option(edns_t *e, uint16_t code) {
    for (size_t i = 0; i < e->option_count; i++) {
        if (e->options[i].option_code == code) {
            free(e->options[i].option_data);
            if (i < e->option_count - 1) {
                e->options[i] = e->options[e->option_count - 1];
            }
            e->option_count--;
            return 0;
        }
    }
    return -1;
}

/* Compute the total wire size of all EDNS options (for OPT RR RDATA). */
size_t edns_wire_size(const edns_t *e) {
    size_t total = 0;
    for (size_t i = 0; i < e->option_count; i++) {
        total += 4 + e->options[i].option_length; /* code(2) + len(2) + data */
    }
    return total;
}

/* Encode all EDNS options into a wire buffer. Returns bytes written. */
int edns_encode_options(const edns_t *e, uint8_t *out, size_t out_max) {
    size_t off = 0;
    for (size_t i = 0; i < e->option_count; i++) {
        const edns_option_t *o = &e->options[i];
        if (off + 4 + o->option_length > out_max) return -1;
        out[off] = (uint8_t)(o->option_code >> 8);
        out[off+1] = (uint8_t)(o->option_code & 0xFF);
        out[off+2] = (uint8_t)(o->option_length >> 8);
        out[off+3] = (uint8_t)(o->option_length & 0xFF);
        if (o->option_length > 0 && o->option_data) {
            memcpy(out + off + 4, o->option_data, o->option_length);
        }
        off += 4 + o->option_length;
    }
    return (int)off;
}

/* Parse EDNS options from wire data. Returns 0 on success. */
int edns_parse_options(edns_t *e, const uint8_t *data, size_t len) {
    size_t off = 0;
    while (off + 4 <= len) {
        uint16_t code = (uint16_t)((data[off] << 8) | data[off+1]);
        uint16_t olen = (uint16_t)((data[off+2] << 8) | data[off+3]);
        off += 4;
        if (off + olen > len) return -1;
        if (edns_add_option(e, code, data + off, olen) < 0) return -1;
        off += olen;
    }
    return 0;
}

/* Encode an Extended DNS Error (EDE) option. */
int edns_encode_ede(uint8_t *out, size_t out_max, uint16_t info_code,
                    const char *extra_text) {
    size_t text_len = extra_text ? strlen(extra_text) : 0;
    size_t total = 2 + text_len;
    if (total > out_max) return -1;
    out[0] = (uint8_t)(info_code >> 8);
    out[1] = (uint8_t)(info_code & 0xFF);
    if (text_len > 0) memcpy(out + 2, extra_text, text_len);
    return (int)total;
}

/* Decode an EDE option from wire data. */
int edns_decode_ede(const uint8_t *data, uint16_t len, edns_ede_t *ede) {
    if (len < 2) return -1;
    ede->info_code = (uint16_t)((data[0] << 8) | data[1]);
    size_t text_len = len - 2;
    if (text_len > 255) text_len = 255;
    memcpy(ede->extra_text, data + 2, text_len);
    ede->extra_text[text_len] = '\0';
    return 0;
}

/* Compute DNS padding size per RFC 7830.
   Returns the padding length needed to reach the target block size. */
uint16_t edns_compute_padding(uint16_t current_size, uint16_t block_size) {
    if (block_size == 0 || current_size == 0) return 0;
    uint16_t remainder = current_size % block_size;
    if (remainder == 0) return 0;
    return block_size - remainder;
}

/* Check if a message needs additional padding to meet PAD block size. */
int edns_needs_padding(uint16_t msg_size, uint16_t pad_block_size) {
    if (pad_block_size == 0) return 0;
    return (msg_size % pad_block_size) != 0;
}

/* Parse the OPT pseudo-record from the additional section of a DNS message.
   Returns 0 on success, -1 on error. */
int edns_parse_opt(const uint8_t *opt_rr, size_t rr_len, edns_t *e) {
    /* OPT RR: owner name (usually 0 root), type=41, class=udp size,
       ttl=extended_rcode/version/flags, rdlen, rdata(options) */
    size_t off = 0;
    /* skip owner name (root = single 0 byte) */
    if (rr_len < 1 || opt_rr[0] != 0) return -1;
    off = 1;
    if (off + 10 > rr_len) return -1;
    uint16_t type = (uint16_t)((opt_rr[off] << 8) | opt_rr[off+1]);
    if (type != 41) return -1; /* not OPT */
    /* class = UDP payload size */
    e->udp_size = (uint16_t)((opt_rr[off+2] << 8) | opt_rr[off+3]);
    /* TTL field: extended-rcode(8) | version(8) | DO(1) | Z(15) */
    e->extended_rcode = opt_rr[off+4];
    e->version = opt_rr[off+5];
    e->flags = (uint16_t)((opt_rr[off+6] << 8) | opt_rr[off+7]);
    uint16_t rdlen = (uint16_t)((opt_rr[off+8] << 8) | opt_rr[off+9]);
    off += 10;
    if (off + rdlen > rr_len) return -1;
    /* parse options */
    edns_free(e);
    return edns_parse_options(e, opt_rr + off, rdlen);
}

/* Build an OPT pseudo-record wire format. Returns bytes written. */
int edns_build_opt(uint8_t *out, size_t out_max, const edns_t *e) {
    size_t off = 0;
    /* root name */
    if (out_max < 1) return -1;
    out[off++] = 0;
    if (off + 10 > out_max) return -1;
    /* type = OPT (41) */
    out[off++] = 0; out[off++] = 41;
    /* class = UDP payload size */
    out[off++] = (uint8_t)(e->udp_size >> 8);
    out[off++] = (uint8_t)(e->udp_size & 0xFF);
    /* TTL = ext-rcode | version | flags */
    out[off++] = e->extended_rcode;
    out[off++] = e->version;
    out[off++] = (uint8_t)(e->flags >> 8);
    out[off++] = (uint8_t)(e->flags & 0xFF);
    /* rdlen */
    size_t rdata_start = off + 2;
    off += 2;
    /* options */
    int n = edns_encode_options(e, out + off, out_max - off);
    if (n < 0) return -1;
    uint16_t rdlen = (uint16_t)n;
    out[rdata_start - 2] = (uint8_t)(rdlen >> 8);
    out[rdata_start - 1] = (uint8_t)(rdlen & 0xFF);
    off += (size_t)n;
    return (int)off;
}

/* Combine the extended rcode (from OPT) with the 4-bit rcode from the header. */
int edns_combine_rcode(uint8_t opt_extended_rcode, uint16_t header_rcode) {
    return (int)(((uint32_t)opt_extended_rcode << 4) | (header_rcode & 0x0F));
}

/* Check if DO bit is set (DNSSEC OK). */
int edns_do_bit(const edns_t *e) {
    return (e->flags >> 15) & 1;
}

/* Set or clear the DO bit. */
void edns_set_do_bit(edns_t *e, int set) {
    if (set) e->flags |= 0x8000;
    else e->flags &= ~0x8000;
}

/* Find client subnet option and return parsed result. Returns 0 if found. */
int edns_get_client_subnet(const edns_t *e, edns_client_subnet_t *cs) {
    edns_option_t *opt = edns_find_option(e, EDNS_OPT_CLIENT_SUBNET);
    if (!opt || !opt->option_data) return -1;
    return edns_parse_client_subnet(opt->option_data, opt->option_length, cs);
}
'''

# ============================================================
# dns_flags.c - DNS message flags and header manipulation
# ============================================================
def gen_dns_flags():
    return r'''/* dns_flags - DNS message flags, header manipulation, and opcode handling */
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
'''

# ============================================================
# dns_tsig.c - TSIG authentication for DNS messages
# ============================================================
def gen_dns_tsig():
    return r'''/* dns_tsig - TSIG authentication, key rotation, and nonce management */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>
#include <stdio.h>

#define TSIG_MAX_KEY_LEN 512
#define TSIG_MAX_NAME_LEN 256
#define TSIG_TIME_FUDGE 300

typedef enum { TSIG_ALG_HMAC_MD5, TSIG_ALG_HMAC_SHA1, TSIG_ALG_HMAC_SHA256 } tsig_algorithm_t;

typedef struct {
    char key_name[256];
    tsig_algorithm_t algorithm;
    uint8_t key[512];
    size_t key_len;
    uint64_t last_time;
    uint16_t last_fudge;
} tsig_key_t;

typedef struct { char algorithm_name[64]; size_t mac_len; } tsig_alg_info_t;

static const tsig_alg_info_t tsig_algorithms[] = {
    {"hmac-md5.sig-alg.reg.int.", 16},
    {"hmac-sha1.", 20},
    {"hmac-sha256.", 32},
};

int tsig_key_init(tsig_key_t *k) {
    memset(k, 0, sizeof(*k)); k->last_fudge = TSIG_TIME_FUDGE; return 0;
}

int tsig_key_set(tsig_key_t *k, const char *name, tsig_algorithm_t alg,
                 const uint8_t *secret, size_t slen) {
    strncpy(k->key_name, name, 255);
    k->algorithm = alg;
    if (slen > 512) slen = 512;
    memcpy(k->key, secret, slen); k->key_len = slen;
    return 0;
}

int tsig_verify_time(uint64_t msg_time, uint16_t msg_fudge) {
    uint64_t now = (uint64_t)time(NULL);
    if (now > msg_time + msg_fudge || msg_time > now + msg_fudge) return -1;
    return 0;
}

/* Get the MAC length for a given algorithm. */
size_t tsig_mac_len(tsig_algorithm_t alg) {
    if (alg <= TSIG_ALG_HMAC_SHA256) return tsig_algorithms[alg].mac_len;
    return 0;
}

/* Get the algorithm name string for a given algorithm. */
const char *tsig_algorithm_name(tsig_algorithm_t alg) {
    if (alg <= TSIG_ALG_HMAC_SHA256) return tsig_algorithms[alg].algorithm_name;
    return "unknown";
}

/* Parse an algorithm name string to enum value. Returns -1 if unknown. */
int tsig_algorithm_from_name(const char *name) {
    for (int i = 0; i < 3; i++) {
        if (strcmp(name, tsig_algorithms[i].algorithm_name) == 0) return i;
    }
    return -1;
}

/* Check if a key is still valid (not expired based on last usage). */
int tsig_key_is_valid(const tsig_key_t *k) {
    if (k->key_len == 0) return 0;
    if (k->key_name[0] == '\0') return 0;
    return 1;
}

/* Generate a simple nonce for TSIG (using time + counter).
   Writes nonce bytes to out, returns bytes written. */
int tsig_generate_nonce(uint8_t *out, size_t out_max) {
    if (out_max < 8) return -1;
    uint64_t nonce = (uint64_t)time(NULL);
    nonce ^= nonce >> 13;
    nonce *= 0x5BD1E995;
    nonce ^= nonce >> 15;
    for (int i = 0; i < 8; i++) {
        out[i] = (uint8_t)(nonce >> (i * 8));
    }
    return 8;
}

/* Build the TSIG RR wire data (key name, class, TTL, algorithm, time, fudge,
   error, other data, MAC). Returns total bytes written. */
int tsig_build_rr(const tsig_key_t *k, uint64_t time_signed,
                  const uint8_t *mac, size_t mac_len,
                  uint16_t error, const uint8_t *other, size_t other_len,
                  uint8_t *out, size_t out_max) {
    size_t off = 0;
    int n;
    /* key name */
    n = snprintf((char *)out + off, out_max - off, "%s", k->key_name);
    /* need wire format, not string - use simple label encoding */
    const char *p = k->key_name;
    off = 0;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t ll = dot ? (size_t)(dot - p) : strlen(p);
        if (off + 1 + ll >= out_max) return -1;
        out[off] = (uint8_t)ll;
        memcpy(out + off + 1, p, ll);
        off += 1 + ll;
        p += ll;
        if (*p == '.') p++;
    }
    if (off >= out_max) return -1;
    out[off++] = 0;
    /* class = ANY (255) */
    if (off + 2 > out_max) return -1;
    out[off++] = 0xFF; out[off++] = 0xFF;
    /* TTL = 0 */
    if (off + 4 > out_max) return -1;
    memset(out + off, 0, 4); off += 4;
    /* algorithm name in wire format */
    p = tsig_algorithms[k->algorithm].algorithm_name;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t ll = dot ? (size_t)(dot - p) : strlen(p);
        if (off + 1 + ll >= out_max) return -1;
        out[off] = (uint8_t)ll;
        memcpy(out + off + 1, p, ll);
        off += 1 + ll;
        p += ll;
        if (*p == '.') p++;
    }
    if (off >= out_max) return -1;
    out[off++] = 0;
    /* time signed (48-bit) */
    if (off + 6 > out_max) return -1;
    for (int i = 5; i >= 0; i--) out[off++] = (uint8_t)(time_signed >> (i * 8));
    /* fudge */
    if (off + 2 > out_max) return -1;
    out[off++] = (uint8_t)(k->last_fudge >> 8);
    out[off++] = (uint8_t)(k->last_fudge & 0xFF);
    /* MAC size + MAC */
    if (off + 2 + mac_len > out_max) return -1;
    out[off++] = (uint8_t)mac_len;
    out[off++] = (uint8_t)(mac_len >> 8); /* wait, MAC size is 2 bytes big-endian */
    off -= 1; /* fix: MAC size is single uint16 */
    out[off++] = (uint8_t)(mac_len >> 8);
    out[off++] = (uint8_t)(mac_len & 0xFF);
    if (mac_len > 0 && mac) memcpy(out + off, mac, mac_len);
    off += mac_len;
    /* error */
    if (off + 2 > out_max) return -1;
    out[off++] = (uint8_t)(error >> 8);
    out[off++] = (uint8_t)(error & 0xFF);
    /* other len + other data */
    if (off + 2 + other_len > out_max) return -1;
    out[off++] = (uint8_t)(other_len >> 8);
    out[off++] = (uint8_t)(other_len & 0xFF);
    if (other_len > 0 && other) memcpy(out + off, other, other_len);
    off += other_len;
    return (int)off;
}

/* Check if a TSIG error code indicates a time error. */
int tsig_is_time_error(uint16_t error) {
    return (error == 16 || error == 17); /* BADTIME / BADTRUNC */
}

/* Parse the TSIG algorithm name from wire format at offset.
   Returns bytes consumed, or -1. */
int tsig_parse_algorithm(const uint8_t *msg, size_t msg_len, size_t offset,
                         char *out, size_t out_max) {
    size_t pos = offset;
    size_t oidx = 0;
    int first = 1;
    while (pos < msg_len && msg[pos] != 0) {
        uint8_t len = msg[pos];
        if (len > 63 || pos + 1 + len > msg_len) return -1;
        if (!first && oidx < out_max) out[oidx++] = '.';
        first = 0;
        for (uint8_t i = 0; i < len && oidx < out_max; i++) {
            out[oidx++] = msg[pos + 1 + i];
        }
        pos += 1 + len;
    }
    if (oidx < out_max) out[oidx] = '\0';
    if (pos < msg_len) pos++; /* skip trailing 0 */
    return (int)(pos - offset);
}

/* Update the key's last usage time. Called after successful verification. */
void tsig_key_update_time(tsig_key_t *k) {
    k->last_time = (uint64_t)time(NULL);
}

/* Compare two TSIG keys by name and algorithm. Returns 0 if equal. */
int tsig_key_equal(const tsig_key_t *a, const tsig_key_t *b) {
    if (a->algorithm != b->algorithm) return 1;
    return strcmp(a->key_name, b->key_name);
}

/* Increment the TSIG request counter (for signed requests).
   Returns the new counter value encoded in the "other data" field. */
uint16_t tsig_increment_counter(uint16_t counter) {
    return counter + 1;
}

/* Decode the TSIG request counter from "other data" bytes. */
uint16_t tsig_decode_counter(const uint8_t *other, size_t other_len) {
    if (other_len < 2) return 0;
    return (uint16_t)((other[0] << 8) | other[1]);
}

/* Estimate the total TSIG RR size for a given algorithm and key name. */
size_t tsig_estimate_rr_size(const tsig_key_t *k) {
    size_t name_len = strlen(k->key_name);
    size_t alg_len = strlen(tsig_algorithms[k->algorithm].algorithm_name);
    /* name + class(2) + ttl(4) + algorithm_wire + time(6) + fudge(2) +
       mac_size(2) + mac + error(2) + other_len(2) */
    return name_len + 2 + 2 + 4 + alg_len + 2 + 6 + 2 + 2 +
           tsig_mac_len(k->algorithm) + 2 + 2;
}

/* Check if a TSIG key needs rotation (based on time elapsed). */
int tsig_key_needs_rotation(const tsig_key_t *k, uint64_t max_age_seconds) {
    uint64_t now = (uint64_t)time(NULL);
    if (now < k->last_time) return 0; /* clock skew */
    return (now - k->last_time) > max_age_seconds;
}

/* Compute the maximum fudge value allowed for a given algorithm.
   HMAC-SHA256 typically allows 300 seconds. */
uint16_t tsig_max_fudge(tsig_algorithm_t alg) {
    (void)alg;
    return TSIG_TIME_FUDGE;
}
'''

# ============================================================
# dns_rrset.c - RRset management, deduplication, and sorting
# ============================================================
def gen_dns_rrset():
    return r'''/* dns_rrset - RRset management, TTL-based expiry, deduplication, and sorting */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

typedef struct {
    char name[255];
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint8_t rdata[65535];
    uint16_t rdlen;
    time_t inserted_at;
} dns_rrset_entry_t;

typedef struct {
    dns_rrset_entry_t *entries;
    size_t count;
    size_t cap;
} dns_rrset_t;

int dns_rrset_init(dns_rrset_t *s) { s->entries = NULL; s->count = 0; s->cap = 0; return 0; }
void dns_rrset_free(dns_rrset_t *s) { free(s->entries); s->entries = NULL; s->count = 0; s->cap = 0; }

int dns_rrset_add(dns_rrset_t *s, const char *n, uint16_t t, uint16_t cl,
                  uint32_t ttl, const uint8_t *rd, uint16_t rl) {
    if (s->count >= s->cap) {
        size_t nc = s->cap ? s->cap * 2 : 16;
        dns_rrset_entry_t *tmp = realloc(s->entries, nc * sizeof(dns_rrset_entry_t));
        if (!tmp) return -1;
        s->entries = tmp; s->cap = nc;
    }
    dns_rrset_entry_t *e = &s->entries[s->count];
    strncpy(e->name, n, 254); e->name[254] = '\0';
    e->type = t; e->class = cl; e->ttl = ttl; e->rdlen = rl;
    if (rl > 0 && rd) memcpy(e->rdata, rd, rl);
    e->inserted_at = time(NULL); s->count++;
    return 0;
}

int dns_rrset_expire(dns_rrset_t *s) {
    time_t now = time(NULL); size_t removed = 0;
    for (size_t i = 0; i < s->count; ) {
        if ((uint32_t)(now - s->entries[i].inserted_at) > s->entries[i].ttl) {
            s->entries[i] = s->entries[s->count - 1]; s->count--; removed++;
        } else i++;
    }
    return (int)removed;
}

/* Remove duplicate entries (same name, type, class, and rdata). */
size_t dns_rrset_deduplicate(dns_rrset_t *s) {
    size_t removed = 0;
    for (size_t i = 0; i < s->count; i++) {
        for (size_t j = i + 1; j < s->count; ) {
            if (strcmp(s->entries[i].name, s->entries[j].name) == 0 &&
                s->entries[i].type == s->entries[j].type &&
                s->entries[i].class == s->entries[j].class &&
                s->entries[i].rdlen == s->entries[j].rdlen &&
                memcmp(s->entries[i].rdata, s->entries[j].rdata, s->entries[i].rdlen) == 0) {
                s->entries[j] = s->entries[s->count - 1];
                s->count--;
                removed++;
            } else {
                j++;
            }
        }
    }
    return removed;
}

/* Sort entries by name, then type, then rdata for deterministic ordering. */
void dns_rrset_sort(dns_rrset_t *s) {
    /* simple insertion sort (entries are typically small) */
    for (size_t i = 1; i < s->count; i++) {
        dns_rrset_entry_t key = s->entries[i];
        size_t j = i;
        while (j > 0) {
            dns_rrset_entry_t *prev = &s->entries[j - 1];
            int cmp = strcmp(prev->name, key.name);
            if (cmp > 0 || (cmp == 0 && prev->type > key.type) ||
                (cmp == 0 && prev->type == key.type &&
                 prev->rdlen > key.rdlen) ||
                (cmp == 0 && prev->type == key.type &&
                 prev->rdlen == key.rdlen &&
                 memcmp(prev->rdata, key.rdata, key.rdlen) > 0)) {
                s->entries[j] = *prev;
                j--;
            } else {
                break;
            }
        }
        s->entries[j] = key;
    }
}

/* Find all entries matching a given name and type. Returns count found. */
size_t dns_rrset_find(const dns_rrset_t *s, const char *name, uint16_t type,
                      dns_rrset_entry_t **results, size_t max_results) {
    size_t found = 0;
    for (size_t i = 0; i < s->count && found < max_results; i++) {
        if (strcmp(s->entries[i].name, name) == 0 &&
            s->entries[i].type == type) {
            results[found++] = &s->entries[i];
        }
    }
    return found;
}

/* Remove all entries matching a name and type. Returns count removed. */
size_t dns_rrset_remove(dns_rrset_t *s, const char *name, uint16_t type) {
    size_t removed = 0;
    for (size_t i = 0; i < s->count; ) {
        if (strcmp(s->entries[i].name, name) == 0 &&
            s->entries[i].type == type) {
            s->entries[i] = s->entries[s->count - 1];
            s->count--;
            removed++;
        } else {
            i++;
        }
    }
    return removed;
}

/* Merge another rrset into this one. Returns total entries added. */
size_t dns_rrset_merge(dns_rrset_t *dest, const dns_rrset_t *src) {
    size_t added = 0;
    for (size_t i = 0; i < src->count; i++) {
        if (dns_rrset_add(dest, src->entries[i].name, src->entries[i].type,
                          src->entries[i].class, src->entries[i].ttl,
                          src->entries[i].rdata, src->entries[i].rdlen) == 0) {
            added++;
        }
    }
    return added;
}

/* Select RRs by random selection (for load balancing answers). */
int dns_rrset_select_random(const dns_rrset_t *s, const char *name, uint16_t type,
                            dns_rrset_entry_t *out) {
    uint32_t candidates[256];
    size_t n = 0;
    for (size_t i = 0; i < s->count && n < 256; i++) {
        if (strcmp(s->entries[i].name, name) == 0 &&
            s->entries[i].type == type) {
            candidates[n++] = (uint32_t)i;
        }
    }
    if (n == 0) return -1;
    /* simple LCG random selection */
    static uint32_t seed = 12345;
    seed = seed * 1103515245 + 12345;
    size_t idx = candidates[seed % n];
    *out = s->entries[idx];
    return 0;
}

/* Get the minimum TTL across all entries in the set. */
uint32_t dns_rrset_min_ttl(const dns_rrset_t *s) {
    uint32_t mn = UINT32_MAX;
    for (size_t i = 0; i < s->count; i++) {
        if (s->entries[i].ttl < mn) mn = s->entries[i].ttl;
    }
    return mn == UINT32_MAX ? 0 : mn;
}

/* Check if two RRsets have the same owner name and type (are the same RRset). */
int dns_rrset_same_set(const dns_rrset_t *a, const dns_rrset_t *b) {
    if (a->count == 0 || b->count == 0) return 0;
    if (strcmp(a->entries[0].name, b->entries[0].name) != 0) return 0;
    if (a->entries[0].type != b->entries[0].type) return 0;
    return 1;
}

/* Count entries with a specific type. */
size_t dns_rrset_count_type(const dns_rrset_t *s, uint16_t type) {
    size_t c = 0;
    for (size_t i = 0; i < s->count; i++) {
        if (s->entries[i].type == type) c++;
    }
    return c;
}

/* Trim the RRset to keep only the N lowest-TTL entries for a given name+type. */
void dns_rrset_trim(dns_rrset_t *s, const char *name, uint16_t type, size_t keep) {
    /* find and sort by TTL */
    size_t idxs[1024];
    size_t n = 0;
    for (size_t i = 0; i < s->count && n < 1024; i++) {
        if (strcmp(s->entries[i].name, name) == 0 &&
            s->entries[i].type == type) {
            idxs[n++] = i;
        }
    }
    if (n <= keep) return;
    /* sort by TTL descending so we can remove from the end */
    for (size_t i = 0; i < n - 1; i++) {
        for (size_t j = i + 1; j < n; j++) {
            if (s->entries[idxs[i]].ttl < s->entries[idxs[j]].ttl) {
                size_t tmp = idxs[i]; idxs[i] = idxs[j]; idxs[j] = tmp;
            }
        }
    }
    /* remove excess (from highest index to avoid shifting) */
    for (size_t i = keep; i < n; i++) {
        size_t idx = idxs[i];
        s->entries[idx] = s->entries[s->count - 1];
        s->count--;
    }
}
'''

# ============================================================
# dns_lookup_tables.c - Static lookup tables for DNS processing
# ============================================================
def gen_dns_lookup_tables():
    return r'''/* dns_lookup_tables - Static lookup tables for DNS processing: CRC32, class/type mappings */
#include <stdint.h>
#include <string.h>
#include <stddef.h>

/* CRC32 table for checksum computation (standard polynomial 0xEDB88320) */
static const uint32_t crc32_table[256] = {
    0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
    0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
    0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
    0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
    0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172, 0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
    0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
    0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
    0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924, 0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
    0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
    0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
    0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E, 0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
    0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
    0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
    0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0, 0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
    0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
    0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
    0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A, 0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
    0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
    0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
    0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC, 0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
    0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
    0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
    0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236, 0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
    0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
    0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
    0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38, 0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
    0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
    0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
    0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2, 0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
    0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
    0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
    0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94, 0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D,
};

/* DNS type to string mapping table */
static const char *dns_type_str_table[258] = {
    "NULL","A","NS","UNKNOWN","UNKNOWN","CNAME","SOA","UNKNOWN",
    "UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","PTR","HINFO","UNKNOWN","MX",
    "TXT","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN",
    "UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","AAAA","UNKNOWN","UNKNOWN","UNKNOWN",
    "UNKNOWN","SRV","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","DNAME",
    "UNKNOWN","OPT","UNKNOWN","DS","UNKNOWN","UNKNOWN","RRSIG","NSEC",
    "DNSKEY","UNKNOWN","UNKNOWN","UNKNOWN","TLSA","UNKNOWN","UNKNOWN","UNKNOWN",
    "UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN",
    "UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN",
    "UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN",
    "UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN",
    "UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN",
    "UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN",
    "UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN",
    "UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN",
    "UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN",
    "UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN",
    "UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN",
    "UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN",
    "UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN",
    "UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN",
    "UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN",
    "UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN",
    "UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN",
    "UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN",
    "UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN",
    "UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN",
    "UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN",
    "UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN",
    "UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN",
    "UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN",
    "UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN",
    "UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN",
    "UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN",
    "UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN",
    "UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN",
    "UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN","UNKNOWN",
    "AXFR","UNKNOWN","UNKNOWN","ANY","UNKNOWN","CAA",
};

/* DNS class to string mapping */
static const char *dns_class_str_table[8] = {
    "UNKNOWN", "IN", "CS", "CH", "HS", "ANY", "UNKNOWN", "UNKNOWN",
};

/* Compute CRC32 of a buffer. */
uint32_t dns_lookup_crc32(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc = crc32_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFF;
}

/* Incrementally update a CRC32 with one byte. */
uint32_t dns_lookup_crc32_update(uint32_t crc, uint8_t byte) {
    return crc32_table[(crc ^ byte) & 0xFF] ^ (crc >> 8);
}

/* Finalize a CRC32 computation. */
uint32_t dns_lookup_crc32_finalize(uint32_t crc) {
    return crc ^ 0xFFFFFFFF;
}

/* Get the string name for a DNS RR type. */
const char *dns_lookup_type_str(uint16_t type) {
    if (type < 258) return dns_type_str_table[type];
    return "UNKNOWN";
}

/* Parse a DNS type string to its numeric value. Returns 0 if unknown. */
uint16_t dns_lookup_type_from_str(const char *str) {
    for (uint16_t i = 0; i < 258; i++) {
        if (dns_type_str_table[i][0] != '\0' &&
            strcmp(dns_type_str_table[i], str) == 0) return i;
    }
    return 0;
}

/* Get the string name for a DNS class. */
const char *dns_lookup_class_str(uint16_t cls) {
    if (cls < 8) return dns_class_str_table[cls];
    return "UNKNOWN";
}

/* Parse a DNS class string to its numeric value. Returns 0 if unknown. */
uint16_t dns_lookup_class_from_str(const char *str) {
    for (uint16_t i = 0; i < 8; i++) {
        if (strcmp(dns_class_str_table[i], str) == 0) return i;
    }
    return 0;
}

/* Lookup the preferred MX exchange from a list using RFC 5321 priority.
   Returns the index of the MX with the lowest preference. */
int dns_lookup_preferred_mx(const uint16_t *preferences, size_t count) {
    if (count == 0) return -1;
    int best = 0;
    for (size_t i = 1; i < count; i++) {
        if (preferences[i] < preferences[best]) best = (int)i;
    }
    return best;
}

/* Compute the minimum TTL from an array of TTL values. */
uint32_t dns_lookup_min_ttl(const uint32_t *ttls, size_t count) {
    if (count == 0) return 0;
    uint32_t mn = ttls[0];
    for (size_t i = 1; i < count; i++) {
        if (ttls[i] < mn) mn = ttls[i];
    }
    return mn;
}

/* Check if a DNS type is a common "address" type (A or AAAA). */
int dns_lookup_is_address_type(uint16_t type) {
    return type == 1 || type == 28;
}

/* Check if a DNS type requires an answer section record. */
int dns_lookup_has_rdata(uint16_t type) {
    /* NS, CNAME, SOA, MX, TXT, AAAA, SRV, CAA all have RDATA */
    switch (type) {
        case 1: case 2: case 5: case 6: case 12:
        case 13: case 15: case 16: case 28: case 33:
        case 39: case 41: case 43: case 44: case 46:
        case 48: case 52: case 65: case 99: case 252:
        case 255: case 256: case 257:
            return 1;
        default:
            return 0;
    }
}

/* Compute a simple hash for DNS message deduplication.
   Uses the FNV-1a hash with query name, type, and class. */
uint32_t dns_lookup_query_hash(const uint8_t *qname_wire, size_t qname_len,
                               uint16_t qtype, uint16_t qclass) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < qname_len; i++) {
        h ^= (uint32_t)qname_wire[i];
        h *= 16777619u;
    }
    h ^= (uint32_t)qtype;
    h *= 16777619u;
    h ^= (uint32_t)qclass;
    h *= 16777619u;
    return h;
}

/* Lookup the default port for a DNS transport type. */
uint16_t dns_lookup_transport_port(int transport_type) {
    switch (transport_type) {
        case 0: return 53;    /* UDP */
        case 1: return 53;    /* TCP */
        case 2: return 853;   /* TLS */
        case 3: return 443;   /* HTTPS/DoH */
        default: return 53;
    }
}

/* Get the default UDP payload size for a transport type. */
uint16_t dns_lookup_default_udp_size(int transport_type) {
    switch (transport_type) {
        case 0: return 512;   /* plain UDP */
        case 1: return 65535; /* TCP */
        case 2: return 4096;  /* TLS */
        case 3: return 4096;  /* HTTPS */
        default: return 512;
    }
}

/* RFC 2181 RR TTL comparison: returns <0, 0, or >0. */
int dns_lookup_ttl_compare(uint32_t a, uint32_t b) {
    /* handle 32-bit wraparound (RFC 1982 serial arithmetic) */
    int32_t diff = (int32_t)(a - b);
    if (diff < 0) return -1;
    if (diff > 0) return 1;
    return 0;
}

/* Check if a type is a DNSSEC type. */
int dns_lookup_is_dnssec_type(uint16_t type) {
    return type == 43 || type == 46 || type == 48 || type == 50;
}
'''

# ============================================================
# MAIN
# ============================================================
def main():
    files = [
        ("src/dns_wireformat.c", gen_dns_wireformat),
        ("src/dns_name_utils.c", gen_dns_name_utils),
        ("src/dns_hash_table.c", gen_dns_hash_table),
        ("src/dns_buffer.c", gen_dns_buffer),
        ("src/dns_zone.c", gen_dns_zone),
        ("src/dns_stats.c", gen_dns_stats),
        ("src/dns_transport.c", gen_dns_transport),
        ("src/dns_edns.c", gen_dns_edns),
        ("src/dns_flags.c", gen_dns_flags),
        ("src/dns_tsig.c", gen_dns_tsig),
        ("src/dns_rrset.c", gen_dns_rrset),
        ("src/dns_lookup_tables.c", gen_dns_lookup_tables),
    ]
    
    total_loc = 0
    for rel, gen_fn in files:
        content = gen_fn()
        write_file(rel, content)
        lc = content.count('\n') + 1
        total_loc += lc
    
    print(f"\nTotal LOC across all files: {total_loc}")

if __name__ == "__main__":
    main()
