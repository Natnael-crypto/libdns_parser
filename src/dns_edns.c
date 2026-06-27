/* dns_edns - EDNS(0) option processing, client subnet, padding, and extended errors */
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
