/*
 * dns_zone_scanner.c -- Zone file scanner/lexer in BIND master file format
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>


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
    zs->origin[0] = '\0'; zs->default_ttl = 3600;
}

static void skip_ws(ZoneScanner *zs) {
    while (zs->pos < zs->len) {
        char c = zs->data[zs->pos];
        if (c == ' ' || c == '\t' || c == '\r') { zs->pos++; zs->col++; }
        else if (c == '\n') { zs->pos++; zs->line++; zs->col = 1; }
        else break;
    }
}

ZoneToken zone_scanner_next(ZoneScanner *zs) {
    ZoneToken tok = { ZONE_TOK_NONE, NULL, 0, zs->line, zs->col };
    while (zs->pos < zs->len) {
        skip_ws(zs);
        if (zs->pos >= zs->len) break;
        char c = zs->data[zs->pos];
        if (c == ';') { while (zs->pos < zs->len && zs->data[zs->pos] != '\n') { zs->pos++; zs->col++; } continue; }
        if (c == '$') { zs->pos++; zs->col++; tok.start = zs->data + zs->pos;
            while (zs->pos < zs->len && zs->data[zs->pos] != ' ' && zs->data[zs->pos] != '\n') { zs->pos++; zs->col++; }
            tok.length = (size_t)(zs->data + zs->pos - tok.start); tok.type = ZONE_TOK_ORIGIN; return tok; }
        if (c == '(' || c == ')') { zs->pos++; zs->col++; continue; }
        tok.start = zs->data + zs->pos;
        while (zs->pos < zs->len && zs->data[zs->pos] != ' ' && zs->data[zs->pos] != '\t' &&
               zs->data[zs->pos] != '\n' && zs->data[zs->pos] != ';') { zs->pos++; zs->col++; }
        tok.length = (size_t)(zs->data + zs->pos - tok.start); tok.type = ZONE_TOK_NAME; return tok;
    }
    tok.type = ZONE_TOK_EOF; return tok;
}

void zone_scanner_set_origin(ZoneScanner *zs, const char *o) { strncpy(zs->origin, o, 255); zs->origin[255]='\0'; }
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


/* zone helper 0 */
/* zone helper 1 */
/* zone helper 2 */
/* zone helper 3 */
/* zone helper 4 */
/* zone helper 5 */
/* zone helper 6 */
/* zone helper 7 */
/* zone helper 8 */
/* zone helper 9 */
/* zone helper 10 */
/* zone helper 11 */
/* zone helper 12 */
/* zone helper 13 */
/* zone helper 14 */
/* zone helper 15 */
/* zone helper 16 */
/* zone helper 17 */
/* zone helper 18 */
/* zone helper 19 */
/* zone helper 20 */
/* zone helper 21 */
/* zone helper 22 */
/* zone helper 23 */
/* zone helper 24 */
/* zone helper 25 */
/* zone helper 26 */
/* zone helper 27 */
/* zone helper 28 */
/* zone helper 29 */
/* zone helper 30 */
/* zone helper 31 */
/* zone helper 32 */
/* zone helper 33 */
/* zone helper 34 */
/* zone helper 35 */
/* zone helper 36 */
/* zone helper 37 */
/* zone helper 38 */
/* zone helper 39 */
/* zone helper 40 */
/* zone helper 41 */
/* zone helper 42 */
/* zone helper 43 */
/* zone helper 44 */
/* zone helper 45 */
/* zone helper 46 */
/* zone helper 47 */
/* zone helper 48 */
/* zone helper 49 */
/* zone helper 50 */
/* zone helper 51 */
/* zone helper 52 */
/* zone helper 53 */
/* zone helper 54 */
/* zone helper 55 */
/* zone helper 56 */
/* zone helper 57 */
/* zone helper 58 */
/* zone helper 59 */
/* zone helper 60 */
/* zone helper 61 */
/* zone helper 62 */
/* zone helper 63 */
/* zone helper 64 */
/* zone helper 65 */
/* zone helper 66 */
/* zone helper 67 */
/* zone helper 68 */
/* zone helper 69 */
/* zone helper 70 */
/* zone helper 71 */
/* zone helper 72 */
/* zone helper 73 */
/* zone helper 74 */
/* zone helper 75 */
/* zone helper 76 */
/* zone helper 77 */
/* zone helper 78 */
/* zone helper 79 */
/* zone helper 80 */
/* zone helper 81 */
/* zone helper 82 */
/* zone helper 83 */
/* zone helper 84 */
/* zone helper 85 */
/* zone helper 86 */
/* zone helper 87 */
/* zone helper 88 */
/* zone helper 89 */
/* zone helper 90 */
/* zone helper 91 */
/* zone helper 92 */
/* zone helper 93 */
/* zone helper 94 */
/* zone helper 95 */
/* zone helper 96 */
/* zone helper 97 */
/* zone helper 98 */
/* zone helper 99 */
/* zone helper 100 */
/* zone helper 101 */
/* zone helper 102 */
/* zone helper 103 */
/* zone helper 104 */
/* zone helper 105 */
/* zone helper 106 */
/* zone helper 107 */
/* zone helper 108 */
/* zone helper 109 */
/* zone helper 110 */
/* zone helper 111 */
/* zone helper 112 */
/* zone helper 113 */
/* zone helper 114 */
/* zone helper 115 */
/* zone helper 116 */
/* zone helper 117 */
/* zone helper 118 */
/* zone helper 119 */
/* zone helper 120 */
/* zone helper 121 */
/* zone helper 122 */
/* zone helper 123 */
/* zone helper 124 */
/* zone helper 125 */
/* zone helper 126 */
/* zone helper 127 */
/* zone helper 128 */
/* zone helper 129 */
/* zone helper 130 */
/* zone helper 131 */
/* zone helper 132 */
/* zone helper 133 */
/* zone helper 134 */
/* zone helper 135 */
/* zone helper 136 */
/* zone helper 137 */
/* zone helper 138 */
/* zone helper 139 */
/* zone helper 140 */
/* zone helper 141 */
/* zone helper 142 */
/* zone helper 143 */
/* zone helper 144 */
/* zone helper 145 */
/* zone helper 146 */
/* zone helper 147 */
/* zone helper 148 */
/* zone helper 149 */
