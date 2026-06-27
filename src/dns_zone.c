/* dns_zone - DNS zone file parsing, SOA management, and record filtering */
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
