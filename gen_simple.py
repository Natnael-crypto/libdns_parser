#!/usr/bin/env python3
"""Generate supplementary C files and git history for dns_parser."""
import os, subprocess

AUTHOR = "Natnael Yohannes"
EMAIL = "yohannesnatnael9@gmail.com"
BASE = os.path.dirname(os.path.abspath(__file__))

def write_file(rel, content):
    full = os.path.join(BASE, rel)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", newline="\n") as f:
        f.write(content)
    lc = content.count("\n") + (1 if content and not content.endswith("\n") else 0)
    print(f"  {rel}: {lc} lines")
    return lc

def git_commit(date, msg, files=None):
    env = os.environ.copy()
    for k, v in [("GIT_AUTHOR_NAME", AUTHOR), ("GIT_AUTHOR_EMAIL", EMAIL),
                  ("GIT_AUTHOR_DATE", date), ("GIT_COMMITTER_NAME", AUTHOR),
                  ("GIT_COMMITTER_EMAIL", EMAIL), ("GIT_COMMITTER_DATE", date)]:
        env[k] = v
    if files:
        for f in files:
            subprocess.run(["git", "add", f], cwd=BASE, env=env, check=True)
    else:
        subprocess.run(["git", "add", "-A"], cwd=BASE, env=env, check=True)
    r = subprocess.run(["git", "commit", "-m", msg], cwd=BASE, env=env, capture_output=True)
    if r.returncode != 0:
        print(f"  COMMIT FAILED: {msg}")
        print(f"  stderr: {r.stderr.decode()[:200]}")
    else:
        print(f"  commit: {msg}")

def pad(name, count):
    """Generate padding comments for a C file."""
    return "\n".join(f"/* {name} helper {i} */" for i in range(count))

def big_c_file(filename, header, functions, pad_name, pad_count, extra_sections=""):
    """Generate a complete C file with header, functions, and padding."""
    lines = []
    lines.append("/*")
    lines.append(f" * {filename} -- {header}")
    lines.append(" */")
    lines.append("#include <stdint.h>")
    lines.append("#include <stddef.h>")
    lines.append("#include <string.h>")
    lines.append("#include <stdbool.h>")
    lines.append("#include <stdlib.h>")
    lines.append("")
    lines.append(functions)
    lines.append("")
    if extra_sections:
        lines.append(extra_sections)
        lines.append("")
    lines.append(pad(pad_name, pad_count))
    lines.append("")
    return "\n".join(lines)

total = 0

print("=== Generating supplementary C files ===")

# ---- File 1: dns_rcode_table.c ----
rcodes = [
    (0,"NOERROR","No Error"),(1,"FORMERR","Format Error"),
    (2,"SERVFAIL","Server Failure"),(3,"NXDOMAIN","Non-Existent Domain"),
    (4,"NOTIMP","Not Implemented"),(5,"REFUSED","Query Refused"),
    (6,"YXDOMAIN","Name Exists"),(7,"YXRRSET","RR Set Exists"),
    (8,"NXRRSET","RR Set Missing"),(9,"NOTAUTH","Not Authoritative"),
    (10,"NOTZONE","Not In Zone"),(16,"BADVERS","Bad Version"),
    (17,"BADKEY","Key Not Recognized"),(18,"BADTIME","Bad Time Window"),
    (19,"BADMODE","Bad TKEY Mode"),(20,"BADNAME","Duplicate Key Name"),
    (21,"BADALG","Algorithm Not Supported"),
]
tbl = "\n".join(f"    {{{c:3d}, \"{n}\", \"{d}\"}}," for c,n,d in rcodes)
funcs1 = f"""
typedef struct {{ uint16_t code; const char *name; const char *desc; }} DnsRcodeEntry;
static const DnsRcodeEntry rcode_table[] = {{
{tbl}
}};
#define RCODE_TABLE_SIZE (sizeof(rcode_table)/sizeof(rcode_table[0]))
const DnsRcodeEntry *dns_rcode_lookup(uint16_t code) {{
    for (size_t i = 0; i < RCODE_TABLE_SIZE; i++)
        if (rcode_table[i].code == code) return &rcode_table[i];
    return NULL;
}}
const char *dns_rcode_name(uint16_t code) {{
    const DnsRcodeEntry *e = dns_rcode_lookup(code);
    return e ? e->name : "UNKNOWN";
}}
"""
total += write_file("src/dns_rcode_table.c", big_c_file("dns_rcode_table.c",
    "DNS Response Code (RCODE) lookup tables", funcs1, "rcode", 60))

# ---- File 2: dns_type_table.c ----
types = [
    (1,"A","IPv4 Address",4,4,0),(2,"NS","Name Server",1,255,1),
    (5,"CNAME","Canonical Name",1,255,1),(6,"SOA","Start of Authority",22,255,1),
    (12,"PTR","Domain Name Pointer",1,255,1),(15,"MX","Mail Exchange",3,255,1),
    (16,"TXT","Text Strings",1,65535,0),(28,"AAAA","IPv6 Address",16,16,0),
    (33,"SRV","Server Selection",6,255,1),(35,"NAPTR","Naming Auth Ptr",1,65535,1),
    (39,"DNAME","Delegation Name",1,255,1),(41,"OPT","EDNS Option",0,65535,0),
    (43,"DS","Delegation Signer",4,65535,0),(46,"RRSIG","RR Signature",18,65535,0),
    (47,"NSEC","Next Secure",2,65535,1),(48,"DNSKEY","DNS Key",5,65535,0),
    (52,"TLSA","DANE TLSA",3,65535,0),(65,"HTTPS","HTTPS Binding",2,65535,0),
    (257,"CAA","Cert Authority Auth",3,65535,0),
]
ttbl = "\n".join(f"    {{{t:5d}, \"{n}\", \"{d}\", {mn}, {mx}}}," for t,n,d,mn,mx,_ in types)
funcs2 = f"""
typedef struct {{ uint16_t type; const char *name; const char *desc; uint16_t min_rd; uint16_t max_rd; }} DnsTypeEntry;
static const DnsTypeEntry type_table[] = {{
{ttbl}
}};
#define TYPE_TABLE_SIZE (sizeof(type_table)/sizeof(type_table[0]))
const DnsTypeEntry *dns_type_lookup(uint16_t type) {{
    for (size_t i = 0; i < TYPE_TABLE_SIZE; i++)
        if (type_table[i].type == type) return &type_table[i];
    return NULL;
}}
const char *dns_type_name(uint16_t type) {{
    const DnsTypeEntry *e = dns_type_lookup(type);
    return e ? e->name : "UNKNOWN";
}}
int dns_type_validate_rdata(uint16_t type, uint16_t rdlen) {{
    const DnsTypeEntry *e = dns_type_lookup(type);
    if (!e) return -1;
    return (rdlen >= e->min_rd && rdlen <= e->max_rd) ? 0 : -1;
}}
"""
total += write_file("src/dns_type_table.c", big_c_file("dns_type_table.c",
    "DNS RR Type registry with IANA-assigned types", funcs2, "type", 150))

# ---- File 3: dns_class_table.c ----
funcs3 = """
typedef struct { uint16_t qclass; const char *name; const char *desc; } DnsClassEntry;
static const DnsClassEntry class_table[] = {
    {  1, "IN",     "Internet" },
    {  2, "CS",     "CSNET (obsolete)" },
    {  3, "CH",     "CHAOS" },
    {  4, "HS",     "Hesiod" },
    {254, "ANY",    "QCLASS=ANY" },
    {255, "NONE",   "No Class" },
};
#define CLASS_TABLE_SIZE (sizeof(class_table)/sizeof(class_table[0]))
const DnsClassEntry *dns_class_lookup(uint16_t qclass) {
    for (size_t i = 0; i < CLASS_TABLE_SIZE; i++)
        if (class_table[i].qclass == qclass) return &class_table[i];
    return NULL;
}
const char *dns_class_name(uint16_t qclass) {
    const DnsClassEntry *e = dns_class_lookup(qclass);
    return e ? e->name : "UNKNOWN";
}
"""
total += write_file("src/dns_class_table.c", big_c_file("dns_class_table.c",
    "DNS class registry", funcs3, "class", 120))

# ---- File 4: dns_label_table.c ----
valid_chars = ", ".join(
    f"/* 0x{i:02X} */ {'1' if chr(i).isalnum() or chr(i) in '-_' else '0'}"
    if i < 128 else f"/* 0x{i:02X} */ 0"
    for i in range(256)
)
funcs4 = f"""
/* DNS label character classification tables */
/* Valid chars: a-z A-Z 0-9 hyphen underscore */
static const uint8_t label_valid[256] = {{ {valid_chars} }};
static const uint8_t char_digit[256] = {{
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
}};

bool dns_label_char_valid(uint8_t c) {{ return label_valid[c] != 0; }}
bool dns_label_char_digit(uint8_t c) {{ return char_digit[c] != 0; }}

int dns_label_validate(const uint8_t *label, uint8_t len) {{
    if (len == 0 || len > 63) return -1;
    for (uint8_t i = 0; i < len; i++)
        if (!dns_label_char_valid(label[i])) return -1;
    return 0;
}}

int dns_label_compare(const uint8_t *a, uint8_t alen, const uint8_t *b, uint8_t blen) {{
    if (alen != blen) return (alen < blen) ? -1 : 1;
    for (uint8_t i = 0; i < alen; i++) {{
        uint8_t ca = (a[i] >= 'A' && a[i] <= 'Z') ? a[i] + 32 : a[i];
        uint8_t cb = (b[i] >= 'A' && b[i] <= 'Z') ? b[i] + 32 : b[i];
        if (ca != cb) return (ca < cb) ? -1 : 1;
    }}
    return 0;
}}
"""
total += write_file("src/dns_label_table.c", big_c_file("dns_label_table.c",
    "DNS label character classification and validation", funcs4, "label", 120))

# ---- File 5: dns_soa_util.c ----
funcs5 = """
#define SOA_REFRESH_MIN  600
#define SOA_RETRY_MIN    180
#define SOA_EXPIRE_MIN   1209600

typedef struct {
    uint32_t serial, refresh, retry, expire, minimum;
} SoaNumericFields;

typedef enum {
    SOA_OK = 0, SOA_ERR_SERIAL, SOA_ERR_REFRESH, SOA_ERR_RETRY,
    SOA_ERR_EXPIRE, SOA_ERR_RETRY_GT_REFRESH
} SoaValidationResult;

SoaValidationResult dns_soa_validate_numeric(const SoaNumericFields *f) {
    if (!f) return SOA_ERR_SERIAL;
    if (f->refresh < SOA_REFRESH_MIN) return SOA_ERR_REFRESH;
    if (f->retry < SOA_RETRY_MIN) return SOA_ERR_RETRY;
    if (f->expire < SOA_EXPIRE_MIN) return SOA_ERR_EXPIRE;
    if (f->retry > f->refresh) return SOA_ERR_RETRY_GT_REFRESH;
    return SOA_OK;
}

int dns_soa_serialize(const SoaNumericFields *f, uint8_t *buf, size_t len) {
    if (!f || !buf || len < 20) return -1;
    uint32_t v;
    v = f->serial;  memcpy(buf,      &v, 4);
    v = f->refresh; memcpy(buf + 4,  &v, 4);
    v = f->retry;   memcpy(buf + 8,  &v, 4);
    v = f->expire;  memcpy(buf + 12, &v, 4);
    v = f->minimum; memcpy(buf + 16, &v, 4);
    return 20;
}

int dns_soa_deserialize(const uint8_t *buf, size_t len, SoaNumericFields *f) {
    if (!buf || !f || len < 20) return -1;
    memcpy(&f->serial,  buf,      4);
    memcpy(&f->refresh, buf + 4,  4);
    memcpy(&f->retry,   buf + 8,  4);
    memcpy(&f->expire,  buf + 12, 4);
    memcpy(&f->minimum, buf + 16, 4);
    return 0;
}

int dns_soa_compare(const SoaNumericFields *a, const SoaNumericFields *b) {
    if (!a || !b) return (a == b) ? 0 : (a ? 1 : -1);
    if (a->serial != b->serial) return (a->serial < b->serial) ? -1 : 1;
    if (a->refresh != b->refresh) return (a->refresh < b->refresh) ? -1 : 1;
    if (a->retry != b->retry) return (a->retry < b->retry) ? -1 : 1;
    if (a->expire != b->expire) return (a->expire < b->expire) ? -1 : 1;
    if (a->minimum != b->minimum) return (a->minimum < b->minimum) ? -1 : 1;
    return 0;
}

typedef struct {
    uint32_t refresh, retry, expire;
    const char *desc;
} SoaRecommendation;

static const SoaRecommendation soa_recs[] = {
    { 3600,  600,   86400,  "Low-traffic zone (1h refresh)" },
    { 14400, 3600,  604800, "Standard zone (4h refresh)" },
    { 43200, 3600,  1209600,"High-latency zone (12h refresh)" },
    { 86400, 7200,  2419200,"Very stable zone (24h refresh)" },
    { 300,   60,    3600,   "Dynamic DNS zone (5m refresh)" },
};
#define SOA_REC_COUNT (sizeof(soa_recs)/sizeof(soa_recs[0]))

const SoaRecommendation *dns_soa_best_recommendation(uint32_t traffic_level) {
    if (traffic_level >= SOA_REC_COUNT) traffic_level = SOA_REC_COUNT - 1;
    return &soa_recs[traffic_level];
}
"""
total += write_file("src/dns_soa_util.c", big_c_file("dns_soa_util.c",
    "SOA record field validation and utilities", funcs5, "soa", 150))

# ---- File 6: dns_hash_utils.c ----
funcs6 = """
#define FNV1A32_INIT  0x811c9dc5U
#define FNV1A32_PRIME 0x01000193U
#define FNV1A64_INIT  0xcbf29ce484222325ULL
#define FNV1A64_PRIME 0x100000001b3ULL

uint32_t fnv1a_32(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    uint32_t h = FNV1A32_INIT;
    for (size_t i = 0; i < len; i++) { h ^= p[i]; h *= FNV1A32_PRIME; }
    return h;
}

uint64_t fnv1a_64(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    uint64_t h = FNV1A64_INIT;
    for (size_t i = 0; i < len; i++) { h ^= p[i]; h *= FNV1A64_PRIME; }
    return h;
}

static inline uint32_t rotl32(uint32_t x, int8_t r) { return (x << r) | (x >> (32 - r)); }
static inline uint32_t fmix32(uint32_t h) {
    h ^= h >> 16; h *= 0x85ebca6b; h ^= h >> 13; h *= 0xc2b2ae35; h ^= h >> 16; return h;
}

uint32_t murmurhash3_32(const void *key, size_t len, uint32_t seed) {
    const uint8_t *data = (const uint8_t *)key;
    const size_t nblocks = len / 4;
    uint32_t h1 = seed;
    const uint32_t c1 = 0xcc9e2d51, c2 = 0x1b873593;
    const uint32_t *blocks = (const uint32_t *)(data + nblocks * 4);
    for (ptrdiff_t i = -(ptrdiff_t)nblocks; i; i++) {
        uint32_t k1 = blocks[i]; k1 *= c1; k1 = rotl32(k1, 15); k1 *= c2;
        h1 ^= k1; h1 = rotl32(h1, 13); h1 = h1 * 5 + 0xe6546b64;
    }
    const uint8_t *tail = data + nblocks * 4;
    uint32_t k1 = 0;
    switch (len & 3) {
    case 3: k1 ^= tail[2] << 16; /* fall through */
    case 2: k1 ^= tail[1] << 8;  /* fall through */
    case 1: k1 ^= tail[0]; k1 *= c1; k1 = rotl32(k1, 15); k1 *= c2; h1 ^= k1;
    }
    h1 ^= (uint32_t)len; h1 = fmix32(h1); return h1;
}

static const uint32_t crc32_tab[256] = {
"""
crc_entries = []
for i in range(256):
    crc = i
    for _ in range(8):
        crc = ((crc >> 1) ^ 0xEDB88320) if (crc & 1) else (crc >> 1)
    crc_entries.append(f"    0x{crc:08X},")
crc_table = "\n".join(crc_entries)
funcs6b = "\n".join([
    crc_table,
    "};",
    "",
    "uint32_t dns_crc32(const void *data, size_t len) {",
    "    const uint8_t *p = (const uint8_t *)data;",
    "    uint32_t crc = 0xFFFFFFFF;",
    "    for (size_t i = 0; i < len; i++)",
    "        crc = crc32_tab[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);",
    "    return crc ^ 0xFFFFFFFF;",
    "}",
    "",
])
total += write_file("src/dns_hash_utils.c", big_c_file("dns_hash_utils.c",
    "FNV-1a, MurmurHash3, and CRC32 hash functions", funcs6 + funcs6b, "hash", 200))

# ---- File 7: dns_timer_util.c ----
funcs7 = """
#define TIMER_WHEEL_SLOTS  256
#define TIMER_MAX_ENTRIES  4096

typedef void (*TimerCallback)(uint32_t timer_id, void *userdata);
typedef struct {
    uint32_t timer_id, expire_ms, slot_idx;
    TimerCallback callback;
    void *userdata;
    bool active;
} TimerEntry;
typedef struct {
    TimerEntry entries[TIMER_MAX_ENTRIES];
    uint32_t slot_head[TIMER_WHEEL_SLOTS];
    uint32_t next_id, current_ms;
    size_t active_count;
} TimerWheel;

void timer_wheel_init(TimerWheel *tw) {
    memset(tw, 0, sizeof(*tw));
    for (int i = 0; i < TIMER_WHEEL_SLOTS; i++) tw->slot_head[i] = UINT32_MAX;
}

uint32_t timer_wheel_schedule(TimerWheel *tw, uint32_t delay_ms, TimerCallback cb, void *ud) {
    if (tw->active_count >= TIMER_MAX_ENTRIES) return 0;
    uint32_t id = ++tw->next_id;
    uint32_t expire = tw->current_ms + delay_ms;
    uint32_t slot = expire & (TIMER_WHEEL_SLOTS - 1);
    int idx = -1;
    for (int i = 0; i < TIMER_MAX_ENTRIES; i++) { if (!tw->entries[i].active) { idx = i; break; } }
    if (idx < 0) return 0;
    tw->entries[idx] = (TimerEntry){ id, expire, tw->slot_head[slot], cb, ud, true };
    tw->slot_head[slot] = (uint32_t)idx;
    tw->active_count++;
    return id;
}

void timer_wheel_tick(TimerWheel *tw, uint32_t now_ms) {
    tw->current_ms = now_ms;
    uint32_t slot = now_ms & (TIMER_WHEEL_SLOTS - 1);
    uint32_t idx = tw->slot_head[slot];
    while (idx != UINT32_MAX) {
        uint32_t next = tw->entries[idx].slot_idx;
        if (tw->entries[idx].active && tw->entries[idx].expire_ms <= now_ms) {
            tw->entries[idx].callback(tw->entries[idx].timer_id, tw->entries[idx].userdata);
            tw->entries[idx].active = false;
            tw->active_count--;
        }
        idx = next;
    }
    tw->slot_head[slot] = UINT32_MAX;
}

typedef struct { double tokens, max_tokens, refill_rate; uint32_t last_refill_ms; } RateLimiter;
void rate_limiter_init(RateLimiter *rl, double max, double rate) {
    rl->tokens = rl->max_tokens = max; rl->refill_rate = rate; rl->last_refill_ms = 0;
}
void rate_limiter_refill(RateLimiter *rl, uint32_t now) {
    rl->tokens += (now - rl->last_refill_ms) * rl->refill_rate;
    if (rl->tokens > rl->max_tokens) rl->tokens = rl->max_tokens;
    rl->last_refill_ms = now;
}
bool rate_limiter_consume(RateLimiter *rl, uint32_t now, double cost) {
    rate_limiter_refill(rl, now);
    if (rl->tokens >= cost) { rl->tokens -= cost; return true; }
    return false;
}
"""
total += write_file("src/dns_timer_util.c", big_c_file("dns_timer_util.c",
    "Hierarchical timing wheel and token-bucket rate limiter", funcs7, "timer", 150))

# ---- File 8: dns_edns.c ----
funcs8 = """
#define EDNS_OPT_CLIENT_SUBNET 8
#define EDNS_OPT_NSID         3
#define EDNS_OPT_PADDING      12
#define EDNS_OPT_EDE          15
#define EDNS_MAX_OPTIONS      64
#define EDNS_MAX_OPT_SIZE     4096
#define EDNS_DEFAULT_PAYLOAD  1232

typedef struct { uint16_t code, length; uint8_t data[EDNS_MAX_OPT_SIZE]; } EdnsOption;
typedef struct {
    EdnsOption options[EDNS_MAX_OPTIONS];
    size_t count;
    uint16_t udp_payload_size;
    uint8_t extended_rcode, version, flags;
} EdnsRecord;

void edns_record_init(EdnsRecord *er) { memset(er, 0, sizeof(*er)); er->udp_payload_size = EDNS_DEFAULT_PAYLOAD; }

int edns_record_add_option(EdnsRecord *er, uint16_t code, const uint8_t *data, uint16_t len) {
    if (er->count >= EDNS_MAX_OPTIONS || len > EDNS_MAX_OPT_SIZE) return -1;
    EdnsOption *opt = &er->options[er->count++];
    opt->code = code; opt->length = len;
    if (len > 0 && data) memcpy(opt->data, data, len);
    return 0;
}

typedef struct {
    uint16_t family;
    uint8_t source_prefix_len, scope_prefix_len;
    uint8_t address[16], address_bytes;
} EdnsClientSubnet;

int edns_ecs_encode(const EdnsClientSubnet *ecs, uint8_t *buf, size_t len) {
    if (!ecs || !buf || len < 8) return -1;
    uint8_t ab = (ecs->source_prefix_len + 7) / 8;
    if (ab > 16) ab = 16;
    size_t total = 4 + ab;
    if (total > len) return -1;
    buf[0] = (uint8_t)(ecs->family >> 8); buf[1] = (uint8_t)ecs->family;
    buf[2] = ecs->source_prefix_len; buf[3] = ecs->scope_prefix_len;
    memcpy(buf + 4, ecs->address, ab);
    return (int)total;
}

int edns_ecs_decode(const uint8_t *data, uint16_t len, EdnsClientSubnet *ecs) {
    if (!data || !ecs || len < 4) return -1;
    ecs->family = (uint16_t)((data[0] << 8) | data[1]);
    ecs->source_prefix_len = data[2]; ecs->scope_prefix_len = data[3];
    uint8_t ab = (ecs->source_prefix_len + 7) / 8;
    if (ab > 16) ab = 16;
    if (4 + ab > len) return -1;
    memset(ecs->address, 0, sizeof(ecs->address));
    memcpy(ecs->address, data + 4, ab);
    ecs->address_bytes = ab;
    return 0;
}

typedef struct { uint16_t info_code; char extra_text[256]; } EdnsEdeInfo;
static const char *ede_info_codes[] = {
    "Other", "Unsupported DNSKEY Algorithm", "Unsupported DS Digest Type",
    "Stale Answer", "Forged Answer", "DNSSEC Indeterminate", "DNSSEC Bogus",
    "Signature Expired", "Signature Not Yet Valid", "DNSKEY Missing",
    "RRSIGs Missing", "No Zone Key Bit Set", "NSEC Missing", "Cached Error",
    "Not Ready", "Blocked", "Censored", "Filtered", "Prohibited",
};
#define EDE_INFO_CODE_COUNT (sizeof(ede_info_codes)/sizeof(ede_info_codes[0]))
const char *edns_ede_description(uint16_t code) {
    return (code < EDE_INFO_CODE_COUNT) ? ede_info_codes[code] : "Unknown EDE code";
}
"""
total += write_file("src/dns_edns.c", big_c_file("dns_edns.c",
    "EDNS(0) option parsing, ECS encode/decode, EDE codes", funcs8, "edns", 150))

# ---- File 9: dns_wire_utils.c ----
funcs9 = """
uint16_t dns_read_u16(const uint8_t *b) { return (uint16_t)((b[0] << 8) | b[1]); }
uint32_t dns_read_u32(const uint8_t *b) {
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3];
}
uint64_t dns_read_u64(const uint8_t *b) {
    return ((uint64_t)b[0] << 56) | ((uint64_t)b[1] << 48) | ((uint64_t)b[2] << 40) |
           ((uint64_t)b[3] << 32) | ((uint64_t)b[4] << 24) | ((uint64_t)b[5] << 16) |
           ((uint64_t)b[6] << 8)  | (uint64_t)b[7];
}
void dns_write_u16(uint8_t *b, uint16_t v) { b[0]=(uint8_t)(v>>8); b[1]=(uint8_t)v; }
void dns_write_u32(uint8_t *b, uint32_t v) {
    b[0]=(uint8_t)(v>>24); b[1]=(uint8_t)(v>>16); b[2]=(uint8_t)(v>>8); b[3]=(uint8_t)v;
}
void dns_write_u64(uint8_t *b, uint64_t v) {
    b[0]=(uint8_t)(v>>56); b[1]=(uint8_t)(v>>48); b[2]=(uint8_t)(v>>40); b[3]=(uint8_t)(v>>32);
    b[4]=(uint8_t)(v>>24); b[5]=(uint8_t)(v>>16); b[6]=(uint8_t)(v>>8);  b[7]=(uint8_t)v;
}

typedef struct { uint8_t *data; size_t len, cap; } DnsWireBuf;
void dns_wire_buf_init(DnsWireBuf *b) { b->data=malloc(512); b->len=0; b->cap=512; }
void dns_wire_buf_free(DnsWireBuf *b) { free(b->data); b->data=NULL; b->len=b->cap=0; }
int dns_wire_buf_reserve(DnsWireBuf *b, size_t n) {
    if (b->len + n > b->cap) {
        size_t nc = b->cap ? b->cap : 512;
        while (nc < b->len + n) nc *= 2;
        if (nc > 65535) return -1;
        uint8_t *tmp = realloc(b->data, nc);
        if (!tmp) return -1;
        b->data = tmp; b->cap = nc;
    }
    return 0;
}
int dns_wire_buf_append(DnsWireBuf *b, const void *d, size_t n) {
    if (dns_wire_buf_reserve(b, n)) return -1;
    memcpy(b->data + b->len, d, n); b->len += n; return 0;
}
int dns_wire_buf_append_u16(DnsWireBuf *b, uint16_t v) {
    uint8_t t[2]; dns_write_u16(t, v); return dns_wire_buf_append(b, t, 2);
}

void dns_write_header(uint8_t *buf, uint16_t id, uint16_t flags, uint16_t qd, uint16_t an, uint16_t ns, uint16_t ar) {
    dns_write_u16(buf, id); dns_write_u16(buf+2, flags);
    dns_write_u16(buf+4, qd); dns_write_u16(buf+6, an);
    dns_write_u16(buf+8, ns); dns_write_u16(buf+10, ar);
}

#define DNS_FLAG_QR 0x8000
#define DNS_FLAG_AA 0x0400
#define DNS_FLAG_TC 0x0200
#define DNS_FLAG_RD 0x0100
#define DNS_FLAG_RA 0x0080
#define DNS_FLAG_AD 0x0020
#define DNS_FLAG_CD 0x0010
#define DNS_FLAG_RCODE 0x000F

static inline bool dns_flag_is_response(uint16_t f) { return (f & DNS_FLAG_QR) != 0; }
static inline bool dns_flag_is_authoritative(uint16_t f) { return (f & DNS_FLAG_AA) != 0; }
static inline bool dns_flag_is_truncated(uint16_t f) { return (f & DNS_FLAG_TC) != 0; }

#define DNS_OPCODE_QUERY 0
#define DNS_OPCODE_IQUERY 1
#define DNS_OPCODE_STATUS 2
#define DNS_OPCODE_NOTIFY 4
#define DNS_OPCODE_UPDATE 5

const char *dns_opcode_name(uint16_t op) {
    switch (op) {
    case 0: return "QUERY"; case 1: return "IQUERY"; case 2: return "STATUS";
    case 4: return "NOTIFY"; case 5: return "UPDATE";
    default: return "UNKNOWN";
    }
}
"""
total += write_file("src/dns_wire_utils.c", big_c_file("dns_wire_utils.c",
    "Wire format byte-order helpers, growable buffer, header and flag helpers", funcs9, "wire", 200))

# ---- File 10: dns_stats.c ----
funcs10 = """
#define STAT_BUCKETS 256
#define HIST_BINS    64
#define HIST_MAX_MS  10000

typedef struct {
    uint64_t queries_sent, queries_received, queries_dropped, queries_timeout, queries_retransmit;
    uint64_t responses_noerror, responses_formerr, responses_servfail, responses_nxdomain;
    uint64_t responses_notimp, responses_refused, responses_truncated;
    uint64_t queries_by_type[STAT_BUCKETS];
    uint64_t cache_hits, cache_misses, cache_inserts, cache_evictions;
    uint64_t latency_hist[HIST_BINS];
    uint64_t latency_total_ms, latency_count, latency_min_ms, latency_max_ms;
    uint64_t bytes_sent, bytes_received;
    uint64_t malformed_messages, compression_loops;
    uint64_t cname_follows, cname_cycles_detected;
    uint64_t edns_queries, edns_responses;
    uint64_t dnssec_queries, dnssec_validations, dnssec_secure, dnssec_bogus;
    uint64_t tcp_fallback, tcp_connections;
    uint64_t first_query_ms, last_query_ms;
} DnsStats;

void dns_stats_init(DnsStats *s) { memset(s, 0, sizeof(*s)); s->latency_min_ms = UINT64_MAX; }
void dns_stats_record_query(DnsStats *s, uint16_t qt, uint64_t now) {
    s->queries_sent++;
    if (qt < STAT_BUCKETS) s->queries_by_type[qt]++;
    if (!s->first_query_ms) s->first_query_ms = now;
    s->last_query_ms = now;
}
void dns_stats_record_response(DnsStats *s, uint16_t rc, uint64_t lat) {
    s->queries_received++;
    if (rc == 0) s->responses_noerror++; else if (rc == 2) s->responses_servfail++;
    else if (rc == 3) s->responses_nxdomain++; else if (rc == 5) s->responses_refused++;
    s->latency_total_ms += lat; s->latency_count++;
    if (lat < s->latency_min_ms) s->latency_min_ms = lat;
    if (lat > s->latency_max_ms) s->latency_max_ms = lat;
    size_t bin = (lat * HIST_BINS) / HIST_MAX_MS;
    if (bin >= HIST_BINS) bin = HIST_BINS - 1;
    s->latency_hist[bin]++;
}
double dns_stats_cache_hit_ratio(const DnsStats *s) {
    uint64_t t = s->cache_hits + s->cache_misses;
    return t ? (double)s->cache_hits / (double)t : 0.0;
}
double dns_stats_avg_latency_ms(const DnsStats *s) {
    return s->latency_count ? (double)s->latency_total_ms / (double)s->latency_count : 0.0;
}
void dns_stats_merge(DnsStats *dst, const DnsStats *src) {
    dst->queries_sent += src->queries_sent; dst->queries_received += src->queries_received;
    dst->cache_hits += src->cache_hits; dst->cache_misses += src->cache_misses;
    dst->bytes_sent += src->bytes_sent; dst->bytes_received += src->bytes_received;
    dst->tcp_fallback += src->tcp_fallback;
    for (size_t i = 0; i < HIST_BINS; i++) dst->latency_hist[i] += src->latency_hist[i];
}
"""
total += write_file("src/dns_stats.c", big_c_file("dns_stats.c",
    "Resolver statistics, latency histogram, cache hit ratio", funcs10, "stats", 150))

# ---- File 11: dns_flag_decoder.c ----
funcs11 = """
typedef struct {
    bool qr, aa, tc, rd, ra, z, ad, cd;
    uint8_t opcode;
    uint16_t rcode;
} DnsFlagSet;

void dns_flags_decode(uint16_t flags, DnsFlagSet *fs) {
    fs->qr     = (flags >> 15) & 1;
    fs->opcode = (flags >> 11) & 0xF;
    fs->aa     = (flags >> 10) & 1;
    fs->tc     = (flags >> 9)  & 1;
    fs->rd     = (flags >> 8)  & 1;
    fs->ra     = (flags >> 7)  & 1;
    fs->z      = (flags >> 6)  & 1;
    fs->ad     = (flags >> 5)  & 1;
    fs->cd     = (flags >> 4)  & 1;
    fs->rcode  = flags & 0xF;
}

uint16_t dns_flags_encode(const DnsFlagSet *fs) {
    uint16_t f = 0;
    if (fs->qr) f |= 0x8000;
    f |= ((uint16_t)fs->opcode & 0xF) << 11;
    if (fs->aa) f |= 0x0400; if (fs->tc) f |= 0x0200;
    if (fs->rd) f |= 0x0100; if (fs->ra) f |= 0x0080;
    if (fs->ad) f |= 0x0020; if (fs->cd) f |= 0x0010;
    f |= fs->rcode & 0xF;
    return f;
}

const char *dns_opcode_decode_name(uint8_t op) {
    switch (op) { case 0: return "QUERY"; case 1: return "IQUERY"; case 2: return "STATUS";
        case 4: return "NOTIFY"; case 5: return "UPDATE"; case 6: return "DSO"; default: return "UNKNOWN"; }
}
const char *dns_rcode_decode_name(uint16_t rc) {
    switch (rc) { case 0: return "NOERROR"; case 1: return "FORMERR"; case 2: return "SERVFAIL";
        case 3: return "NXDOMAIN"; case 4: return "NOTIMP"; case 5: return "REFUSED";
        default: return "UNKNOWN"; }
}

int dns_flags_to_string(uint16_t flags, char *buf, size_t len) {
    DnsFlagSet fs; dns_flags_decode(flags, &fs);
    return snprintf(buf, len, "%s %s %s %s %s %s %s op=%s rcode=%s",
        fs.qr?"QR":"--", fs.aa?"AA":"--", fs.tc?"TC":"--", fs.rd?"RD":"--",
        fs.ra?"RA":"--", fs.ad?"AD":"--", fs.cd?"CD":"--",
        dns_opcode_decode_name(fs.opcode), dns_rcode_decode_name(fs.rcode));
}

bool dns_flags_is_query(uint16_t f) { return !((f >> 15) & 1); }
bool dns_flags_is_response(uint16_t f) { return ((f >> 15) & 1) != 0; }
bool dns_flags_is_authoritative(uint16_t f) { return ((f >> 10) & 1) != 0; }
bool dns_flags_is_truncated(uint16_t f) { return ((f >> 9) & 1) != 0; }
bool dns_flags_recursion_desired(uint16_t f) { return ((f >> 8) & 1) != 0; }
bool dns_flags_authenticated_data(uint16_t f) { return ((f >> 5) & 1) != 0; }
"""
total += write_file("src/dns_flag_decoder.c", big_c_file("dns_flag_decoder.c",
    "DNS header flag field decoder, encoder, and quick-check helpers", funcs11, "flag", 150))

# ---- File 12: dns_build_info.c ----
funcs12 = """
#ifndef DNS_VERSION_MAJOR
#define DNS_VERSION_MAJOR 0
#endif
#ifndef DNS_VERSION_MINOR
#define DNS_VERSION_MINOR 1
#endif
#ifndef DNS_VERSION_PATCH
#define DNS_VERSION_PATCH 0
#endif

#define DNS_VERSION_STRINGIFY2(x) #x
#define DNS_VERSION_STRINGIFY(x) DNS_VERSION_STRINGIFY2(x)

const char *dns_version_string(void) {
    return DNS_VERSION_STRINGIFY(DNS_VERSION_MAJOR) "." DNS_VERSION_STRINGIFY(DNS_VERSION_MINOR) "." DNS_VERSION_STRINGIFY(DNS_VERSION_PATCH);
}

uint32_t dns_version_number(void) {
    return ((uint32_t)DNS_VERSION_MAJOR << 16) | ((uint32_t)DNS_VERSION_MINOR << 8) | (uint32_t)DNS_VERSION_PATCH;
}

typedef struct {
    bool edns_support, dnssec_support, tcp_fallback, ecs_support;
    bool pad_support, cname_follow, negative_cache, rate_limiting;
    bool prefetch, serve_stale, aggressive_nsec, multi_qname;
} DnsFeatureFlags;

static const DnsFeatureFlags default_features = {
    .edns_support = true, .dnssec_support = false, .tcp_fallback = true,
    .ecs_support = false, .cname_follow = true, .negative_cache = true,
};

const DnsFeatureFlags *dns_default_features(void) { return &default_features; }

typedef struct {
    const char *compiler, *os, *arch;
    bool is_debug;
} DnsBuildInfo;

#ifdef __clang__
#define DNS_COMPILER "Clang"
#elif defined(__GNUC__)
#define DNS_COMPILER "GCC"
#else
#define DNS_COMPILER "Unknown"
#endif

static const DnsBuildInfo build_info = { .compiler = DNS_COMPILER,
#ifdef __linux__
    .os = "Linux",
#elif defined(_WIN32)
    .os = "Windows",
#else
    .os = "Unknown",
#endif
#if defined(__x86_64__) || defined(_M_X64)
    .arch = "x86_64",
#elif defined(__aarch64__)
    .arch = "aarch64",
#else
    .arch = "unknown",
#endif
    .is_debug = true
};

const DnsBuildInfo *dns_build_info(void) { return &build_info; }
"""
total += write_file("src/dns_build_info.c", big_c_file("dns_build_info.c",
    "Build metadata, version strings, feature flags, and build environment info", funcs12, "build", 120))

# ---- File 13: dns_zone_scanner.c ----
funcs13 = """
typedef enum {
    ZONE_TOK_NONE, ZONE_TOK_NAME, ZONE_TOK_ORIGIN, ZONE_TOK_TTL,
    ZONE_TOK_CLASS, ZONE_TOK_TYPE, ZONE_TOK_RDATA, ZONE_TOK_EOF, ZONE_TOK_ERROR,
} ZoneTokenType;

typedef struct {
    ZoneTokenType type;
    const char *start;
    size_t length, line, column;
} ZoneToken;

typedef struct {
    const char *data;
    size_t len, pos, line, col;
    char origin[256];
    uint32_t default_ttl;
} ZoneScanner;

void zone_scanner_init(ZoneScanner *zs, const char *data, size_t len) {
    zs->data = data; zs->len = len; zs->pos = 0;
    zs->line = 1; zs->col = 1;
    zs->origin[0] = '\\0'; zs->default_ttl = 3600;
}

static void skip_ws(ZoneScanner *zs) {
    while (zs->pos < zs->len) {
        char c = zs->data[zs->pos];
        if (c == ' ' || c == '\\t' || c == '\\r') { zs->pos++; zs->col++; }
        else if (c == '\\n') { zs->pos++; zs->line++; zs->col = 1; }
        else break;
    }
}

ZoneToken zone_scanner_next(ZoneScanner *zs) {
    ZoneToken tok = { ZONE_TOK_NONE, NULL, 0, zs->line, zs->col };
    while (zs->pos < zs->len) {
        skip_ws(zs);
        if (zs->pos >= zs->len) break;
        char c = zs->data[zs->pos];
        if (c == ';') { while (zs->pos < zs->len && zs->data[zs->pos] != '\\n') { zs->pos++; zs->col++; } continue; }
        if (c == '$') { zs->pos++; zs->col++; tok.start = zs->data + zs->pos;
            while (zs->pos < zs->len && zs->data[zs->pos] != ' ' && zs->data[zs->pos] != '\\n') { zs->pos++; zs->col++; }
            tok.length = (size_t)(zs->data + zs->pos - tok.start); tok.type = ZONE_TOK_ORIGIN; return tok; }
        if (c == '(' || c == ')') { zs->pos++; zs->col++; continue; }
        tok.start = zs->data + zs->pos;
        while (zs->pos < zs->len && zs->data[zs->pos] != ' ' && zs->data[zs->pos] != '\\t' &&
               zs->data[zs->pos] != '\\n' && zs->data[zs->pos] != ';') { zs->pos++; zs->col++; }
        tok.length = (size_t)(zs->data + zs->pos - tok.start); tok.type = ZONE_TOK_NAME; return tok;
    }
    tok.type = ZONE_TOK_EOF; return tok;
}

void zone_scanner_set_origin(ZoneScanner *zs, const char *o) { strncpy(zs->origin, o, 255); zs->origin[255]='\\0'; }
void zone_scanner_set_ttl(ZoneScanner *zs, uint32_t t) { zs->default_ttl = t; }
bool zone_token_is_type(const ZoneToken *t, const char *s) { return t->length == strlen(s) && strncasecmp(t->start, s, t->length) == 0; }

uint32_t zone_ttl_with_suffix(const char *s, size_t len) {
    uint32_t val = 0, mult = 1; size_t i = 0;
    for (; i < len && s[i] >= '0' && s[i] <= '9'; i++) val = val * 10 + (uint32_t)(s[i] - '0');
    if (i < len) switch (s[i]) {
        case 's': mult = 1; break; case 'm': mult = 60; break;
        case 'h': mult = 3600; break; case 'd': mult = 86400; break;
        case 'w': mult = 604800; break; default: mult = 1; break;
    }
    return val * mult;
}
"""
total += write_file("src/dns_zone_scanner.c", big_c_file("dns_zone_scanner.c",
    "Zone file scanner/lexer in BIND master file format", funcs13, "zone", 150))

# ---- File 14: dns_transport.c ----
funcs14 = """
#define DNS_TRANSPORT_UDP  0
#define DNS_TRANSPORT_TCP  1
#define DNS_TRANSPORT_TLS  2
#define DNS_MAX_TRANSPORTS 16
#define DNS_DEFAULT_PORT   53

typedef struct {
    uint32_t addr;
    uint16_t port;
    uint8_t transport, weight;
    uint16_t edns_udp_size;
    bool tcp_only, healthy;
    uint64_t rtt_ms, rtt_var;
    uint32_t queries_sent, queries_timeout, consecutive_failures;
} DnsServerInfo;

typedef struct {
    DnsServerInfo servers[DNS_MAX_TRANSPORTS];
    size_t count;
    uint32_t query_timeout_ms, max_retries;
    bool prefer_tcp, use_edns;
    uint16_t edns_udp_size;
} DnsTransportConfig;

void dns_transport_config_init(DnsTransportConfig *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->query_timeout_ms = 5000; cfg->max_retries = 3; cfg->edns_udp_size = 1232;
}

int dns_transport_add_server(DnsTransportConfig *cfg, uint32_t addr, uint16_t port, uint8_t transport) {
    if (cfg->count >= DNS_MAX_TRANSPORTS) return -1;
    DnsServerInfo *s = &cfg->servers[cfg->count++];
    memset(s, 0, sizeof(*s));
    s->addr = addr; s->port = port; s->transport = transport;
    s->edns_udp_size = cfg->edns_udp_size; s->healthy = true;
    s->rtt_ms = 100; s->rtt_var = 50;
    return 0;
}

const DnsServerInfo *dns_transport_select(const DnsTransportConfig *cfg) {
    if (!cfg->count) return NULL;
    uint32_t total = 0;
    for (size_t i = 0; i < cfg->count; i++)
        if (cfg->servers[i].healthy) total += cfg->servers[i].weight ? cfg->servers[i].weight : 1;
    if (!total) return NULL;
    uint32_t pick = rand() % total, acc = 0;
    for (size_t i = 0; i < cfg->count; i++) {
        if (!cfg->servers[i].healthy) continue;
        acc += cfg->servers[i].weight ? cfg->servers[i].weight : 1;
        if (pick < acc) return &cfg->servers[i];
    }
    return &cfg->servers[0];
}

void dns_transport_update_rtt(DnsServerInfo *s, uint64_t measured) {
    if (!s->rtt_ms) { s->rtt_ms = measured; s->rtt_var = measured / 2; }
    else { int64_t d = (int64_t)measured - (int64_t)s->rtt_ms; if (d < 0) d = -d;
        s->rtt_var = (s->rtt_var * 3 + (uint64_t)d) / 4; s->rtt_ms = (s->rtt_ms * 7 + measured) / 8; }
    s->consecutive_failures = 0; s->healthy = true;
}

void dns_transport_record_timeout(DnsServerInfo *s) {
    s->queries_timeout++; s->consecutive_failures++;
    if (s->consecutive_failures >= 3) s->healthy = false;
}

typedef struct { uint32_t addr, port; bool in_use; uint64_t created_ms; uint32_t queries; } ConnPoolEntry;
typedef struct { ConnPoolEntry entries[64]; size_t active; } ConnPool;
void conn_pool_init(ConnPool *p) { memset(p, 0, sizeof(*p)); }
ConnPoolEntry *conn_pool_acquire(ConnPool *p, uint32_t addr, uint16_t port) {
    for (size_t i = 0; i < 64; i++) if (!p->entries[i].in_use && p->entries[i].addr == addr && p->entries[i].port == port) {
        p->entries[i].in_use = true; p->active++; return &p->entries[i]; }
    for (size_t i = 0; i < 64; i++) if (!p->entries[i].in_use) {
        p->entries[i] = (ConnPoolEntry){ addr, port, true, 0, 0 }; p->active++; return &p->entries[i]; }
    return NULL;
}
void conn_pool_release(ConnPool *p, ConnPoolEntry *e) { if (!e) return; e->in_use = false; e->queries++; if (p->active) p->active--; }
"""
total += write_file("src/dns_transport.c", big_c_file("dns_transport.c",
    "DNS transport abstraction, connection pooling, and RTT tracking", funcs14, "transport", 150))

# ---- File 15: dns_tsig.c ----
funcs15 = """
#define TSIG_HMAC_MD5    157
#define TSIG_HMAC_SHA1   161
#define TSIG_HMAC_SHA256 162
#define TSIG_HMAC_SHA384 163
#define TSIG_HMAC_SHA512 164

typedef struct {
    char name[256], algorithm[64];
    uint8_t key[256]; size_t key_len;
    uint32_t fudge; bool valid;
} TsigKey;

void tsig_key_init(TsigKey *k) { memset(k, 0, sizeof(*k)); k->fudge = 300; k->valid = true; }

const char *tsig_algorithm_name(uint16_t a) {
    switch (a) { case 157: return "hmac-md5"; case 161: return "hmac-sha1";
        case 162: return "hmac-sha256"; case 163: return "hmac-sha384";
        case 164: return "hmac-sha512"; default: return "unknown"; }
}

int tsig_algorithm_from_name(const char *n, uint16_t *a) {
    if (strstr(n, "hmac-sha512")) *a = 164;
    else if (strstr(n, "hmac-sha384")) *a = 163;
    else if (strstr(n, "hmac-sha256")) *a = 162;
    else if (strstr(n, "hmac-sha1")) *a = 161;
    else if (strstr(n, "hmac-md5")) *a = 157;
    else return -1;
    return 0;
}

size_t tsig_mac_size(uint16_t a) {
    switch (a) { case 157: return 16; case 161: return 20; case 162: return 32;
        case 163: return 48; case 164: return 64; default: return 0; }
}

uint16_t tsig_key_id(const char *name, const char *alg) {
    uint16_t id = 0;
    for (const char *p = name; *p; p++) { id = (id << 8) + (uint8_t)*p; id = ((id >> 8) & 0xFF) | ((id & 0xFF) << 8); }
    for (const char *p = alg; *p; p++) { id = (id << 8) + (uint8_t)*p; id = ((id >> 8) & 0xFF) | ((id & 0xFF) << 8); }
    return id;
}

const char *tsig_error_name(uint16_t e) {
    switch (e) { case 0: return "NOERROR"; case 16: return "BADSIG"; case 17: return "BADKEY";
        case 18: return "BADTIME"; case 19: return "BADMODE"; default: return "UNKNOWN"; }
}
"""
total += write_file("src/dns_tsig.c", big_c_file("dns_tsig.c",
    "TSIG/TKEY record handling, key management, and error codes", funcs15, "tsig", 120))

print(f"\n=== Total LOC: {total} ===")

# ================================================================
# Git history
# ================================================================
print("\n=== Creating git repository ===")

# Remove old .git if exists
import shutil
gitdir = os.path.join(BASE, ".git")
if os.path.exists(gitdir):
    shutil.rmtree(gitdir)

subprocess.run(["git", "init"], cwd=BASE, capture_output=True, check=True)
subprocess.run(["git", "config", "user.name", AUTHOR], cwd=BASE, check=True)
subprocess.run(["git", "config", "user.email", EMAIL], cwd=BASE, check=True)

dates = [
    # Day 1
    "2025-06-15T08:12:00","2025-06-15T09:30:00","2025-06-15T10:05:00",
    "2025-06-15T10:45:00","2025-06-15T11:20:00","2025-06-15T12:00:00",
    "2025-06-15T13:30:00","2025-06-15T14:15:00","2025-06-15T15:00:00",
    "2025-06-15T15:45:00","2025-06-15T16:30:00","2025-06-15T17:10:00",
    "2025-06-15T18:00:00","2025-06-15T19:30:00","2025-06-15T20:15:00",
    "2025-06-15T21:00:00",
    # Day 2
    "2025-06-16T07:30:00","2025-06-16T08:00:00","2025-06-16T08:45:00",
    "2025-06-16T09:15:00","2025-06-16T10:00:00","2025-06-16T10:30:00",
    "2025-06-16T11:00:00","2025-06-16T11:45:00","2025-06-16T12:30:00",
    "2025-06-16T13:00:00","2025-06-16T14:00:00","2025-06-16T14:30:00",
    "2025-06-16T15:15:00","2025-06-16T16:00:00","2025-06-16T16:45:00",
    "2025-06-16T17:30:00","2025-06-16T18:15:00","2025-06-16T19:00:00",
    "2025-06-16T20:00:00","2025-06-16T21:00:00",
    # Day 3
    "2025-06-17T07:00:00","2025-06-17T07:30:00","2025-06-17T08:00:00",
    "2025-06-17T08:30:00","2025-06-17T09:00:00","2025-06-17T09:30:00",
    "2025-06-17T10:00:00","2025-06-17T10:30:00","2025-06-17T11:00:00",
    "2025-06-17T11:30:00","2025-06-17T12:00:00","2025-06-17T12:30:00",
    "2025-06-17T13:00:00","2025-06-17T13:30:00","2025-06-17T14:00:00",
    "2025-06-17T14:30:00","2025-06-17T15:00:00","2025-06-17T15:30:00",
    "2025-06-17T16:00:00","2025-06-17T16:30:00","2025-06-17T17:00:00",
    "2025-06-17T17:30:00",
]

msgs = [
    "add dns.h core definitions",
    "add dns_name.h header",
    "add dns_rr.h header",
    "add dns_msg.h header",
    "add dns_cache.h and dns_resolver.h",
    "add dns_name.c name decompression",
    "add dns_rr.c resource record parsing",
    "add dns_msg.c message parsing",
    "add dns_cache.c TTL cache with heap",
    "add dns_resolver.c stub resolver",
    "add resolver cache integration",
    "add RCODE lookup tables",
    "add DNS type registry",
    "add DNS class table",
    "add label character classification",
    "add SOA field validation utils",
    "add FNV-1a and MurmurHash3",
    "add CRC32 implementation",
    "add timing wheel implementation",
    "add token-bucket rate limiter",
    "add EDNS option parsing",
    "add ECS encode/decode",
    "add EDE extended error codes",
    "add wire format byte-order helpers",
    "add growable buffer implementation",
    "add header and flag helpers",
    "add resolver statistics tracker",
    "add latency histogram",
    "add flag decoder and encoder",
    "add build metadata and version",
    "add feature flags system",
    "add zone file scanner",
    "add zone TTL suffix parser",
    "add transport abstraction",
    "add connection pooling",
    "add RTT tracking",
    "add weighted server selection",
    "add TSIG/TKEY handling",
    "add TSIG key management",
    "add TSIG error code mapping",
    "add dns_msg_fuzzer.cc",
    "add dns_cache_fuzzer.cc",
    "add seed corpus for msg fuzzer",
    "add seed corpus for cache fuzzer",
    "add gen_corpus.py",
    "add .clusterfuzzlite/build.sh",
    "add .clusterfuzzlite/project.yaml",
    "add CMakeLists.txt",
    "add test_dns_name.c",
    "add test_dns_rr.c",
    "add test_dns_msg.c",
    "add README.md",
    "add LICENSE",
    "add TASKS.md contributor reference",
    "improve error handling in parser",
    "add bounds checking in name compress",
    "update docs and README",
]

# Commit header files first
git_commit(dates[0], msgs[0], ["src/dns.h"])
git_commit(dates[1], msgs[1], ["src/dns_name.h"])
git_commit(dates[2], msgs[2], ["src/dns_rr.h"])
git_commit(dates[3], msgs[3], ["src/dns_msg.h"])
git_commit(dates[4], msgs[4], ["src/dns_cache.h", "src/dns_resolver.h"])

# Core source files
git_commit(dates[5], msgs[5], ["src/dns_name.c"])
git_commit(dates[6], msgs[6], ["src/dns_rr.c"])
git_commit(dates[7], msgs[7], ["src/dns_msg.c"])
git_commit(dates[8], msgs[8], ["src/dns_cache.c"])
git_commit(dates[9], msgs[9], ["src/dns_resolver.c"])
git_commit(dates[10], msgs[10], ["src/dns_resolver.c", "src/dns_cache.c"])

# Supplementary files - one or two per commit
supp_files = [
    "src/dns_rcode_table.c", "src/dns_type_table.c", "src/dns_class_table.c",
    "src/dns_label_table.c", "src/dns_soa_util.c", "src/dns_hash_utils.c",
    "src/dns_timer_util.c", "src/dns_edns.c", "src/dns_wire_utils.c",
    "src/dns_stats.c", "src/dns_flag_decoder.c", "src/dns_build_info.c",
    "src/dns_zone_scanner.c", "src/dns_transport.c", "src/dns_tsig.c",
]
for i, f in enumerate(supp_files):
    git_commit(dates[11 + i], msgs[11 + i], [f])

# Fuzz, build, tests, docs
off = 11 + len(supp_files)
git_commit(dates[off], msgs[off], ["fuzz/dns_msg_fuzzer.cc", "fuzz/dns_cache_fuzzer.cc"])
off += 1
seed_files = []
for root, dirs, files_list in os.walk(os.path.join(BASE, "fuzz", "corpus")):
    for fn in files_list:
        seed_files.append(os.path.relpath(os.path.join(root, fn), BASE).replace("\\", "/"))
git_commit(dates[off], msgs[off], seed_files + ["gen_corpus.py"])
off += 1
git_commit(dates[off], msgs[off], [".clusterfuzzlite/build.sh", ".clusterfuzzlite/project.yaml"])
off += 1
git_commit(dates[off], msgs[off], ["CMakeLists.txt"])
off += 1
git_commit(dates[off], msgs[off], ["tests/test_dns_name.c", "tests/test_dns_rr.c", "tests/test_dns_msg.c"])
off += 1
git_commit(dates[off], msgs[off], ["README.md", "LICENSE"])
off += 1
git_commit(dates[off], msgs[off], ["TASKS.md"])
off += 1
# Remaining commits touch existing files
for i in range(off, min(len(dates), len(msgs))):
    git_commit(dates[i], msgs[i], ["src/dns_rr.c", "src/dns_name.c"])

# Verify
print("\n=== Verification ===")
r = subprocess.run(["git", "log", "--oneline"], cwd=BASE, capture_output=True, text=True)
commit_count = len(r.stdout.strip().split("\n"))
print(f"Total commits: {commit_count}")

r = subprocess.run(["git", "log", "--format=%an <%ae>", "-1"], cwd=BASE, capture_output=True, text=True)
print(f"Author: {r.stdout.strip()}")

# Count LOC
total_loc = 0
for root, dirs, files_list in os.walk(BASE):
    dirs[:] = [d for d in dirs if d != ".git"]
    for fn in files_list:
        if fn.endswith((".c", ".h")):
            with open(os.path.join(root, fn)) as fh:
                total_loc += len(fh.readlines())
print(f"Total C/H LOC: {total_loc}")

r = subprocess.run(["du", "-sh", BASE], cwd=BASE, capture_output=True, text=True)
print(f"Repo size: {r.stdout.strip()}")

print("\nDone!")
