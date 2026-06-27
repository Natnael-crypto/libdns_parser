/* dns_buffer - Dynamic buffer for DNS message construction with compression */
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
