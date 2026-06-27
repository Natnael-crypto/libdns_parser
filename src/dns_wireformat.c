/* dns_wireformat - DNS wire format encoding/decoding utilities */
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
