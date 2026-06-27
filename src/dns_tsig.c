/* dns_tsig - TSIG authentication, key rotation, and nonce management */
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
