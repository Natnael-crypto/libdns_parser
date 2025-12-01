/*
 * dns_label_table.c -- DNS label character classification and validation
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>


/* DNS label character classification tables */
/* Valid chars: a-z A-Z 0-9 hyphen underscore */
static const uint8_t label_valid[256] = { /* 0x00 */ 0, /* 0x01 */ 0, /* 0x02 */ 0, /* 0x03 */ 0, /* 0x04 */ 0, /* 0x05 */ 0, /* 0x06 */ 0, /* 0x07 */ 0, /* 0x08 */ 0, /* 0x09 */ 0, /* 0x0A */ 0, /* 0x0B */ 0, /* 0x0C */ 0, /* 0x0D */ 0, /* 0x0E */ 0, /* 0x0F */ 0, /* 0x10 */ 0, /* 0x11 */ 0, /* 0x12 */ 0, /* 0x13 */ 0, /* 0x14 */ 0, /* 0x15 */ 0, /* 0x16 */ 0, /* 0x17 */ 0, /* 0x18 */ 0, /* 0x19 */ 0, /* 0x1A */ 0, /* 0x1B */ 0, /* 0x1C */ 0, /* 0x1D */ 0, /* 0x1E */ 0, /* 0x1F */ 0, /* 0x20 */ 0, /* 0x21 */ 0, /* 0x22 */ 0, /* 0x23 */ 0, /* 0x24 */ 0, /* 0x25 */ 0, /* 0x26 */ 0, /* 0x27 */ 0, /* 0x28 */ 0, /* 0x29 */ 0, /* 0x2A */ 0, /* 0x2B */ 0, /* 0x2C */ 0, /* 0x2D */ 1, /* 0x2E */ 0, /* 0x2F */ 0, /* 0x30 */ 1, /* 0x31 */ 1, /* 0x32 */ 1, /* 0x33 */ 1, /* 0x34 */ 1, /* 0x35 */ 1, /* 0x36 */ 1, /* 0x37 */ 1, /* 0x38 */ 1, /* 0x39 */ 1, /* 0x3A */ 0, /* 0x3B */ 0, /* 0x3C */ 0, /* 0x3D */ 0, /* 0x3E */ 0, /* 0x3F */ 0, /* 0x40 */ 0, /* 0x41 */ 1, /* 0x42 */ 1, /* 0x43 */ 1, /* 0x44 */ 1, /* 0x45 */ 1, /* 0x46 */ 1, /* 0x47 */ 1, /* 0x48 */ 1, /* 0x49 */ 1, /* 0x4A */ 1, /* 0x4B */ 1, /* 0x4C */ 1, /* 0x4D */ 1, /* 0x4E */ 1, /* 0x4F */ 1, /* 0x50 */ 1, /* 0x51 */ 1, /* 0x52 */ 1, /* 0x53 */ 1, /* 0x54 */ 1, /* 0x55 */ 1, /* 0x56 */ 1, /* 0x57 */ 1, /* 0x58 */ 1, /* 0x59 */ 1, /* 0x5A */ 1, /* 0x5B */ 0, /* 0x5C */ 0, /* 0x5D */ 0, /* 0x5E */ 0, /* 0x5F */ 1, /* 0x60 */ 0, /* 0x61 */ 1, /* 0x62 */ 1, /* 0x63 */ 1, /* 0x64 */ 1, /* 0x65 */ 1, /* 0x66 */ 1, /* 0x67 */ 1, /* 0x68 */ 1, /* 0x69 */ 1, /* 0x6A */ 1, /* 0x6B */ 1, /* 0x6C */ 1, /* 0x6D */ 1, /* 0x6E */ 1, /* 0x6F */ 1, /* 0x70 */ 1, /* 0x71 */ 1, /* 0x72 */ 1, /* 0x73 */ 1, /* 0x74 */ 1, /* 0x75 */ 1, /* 0x76 */ 1, /* 0x77 */ 1, /* 0x78 */ 1, /* 0x79 */ 1, /* 0x7A */ 1, /* 0x7B */ 0, /* 0x7C */ 0, /* 0x7D */ 0, /* 0x7E */ 0, /* 0x7F */ 0, /* 0x80 */ 0, /* 0x81 */ 0, /* 0x82 */ 0, /* 0x83 */ 0, /* 0x84 */ 0, /* 0x85 */ 0, /* 0x86 */ 0, /* 0x87 */ 0, /* 0x88 */ 0, /* 0x89 */ 0, /* 0x8A */ 0, /* 0x8B */ 0, /* 0x8C */ 0, /* 0x8D */ 0, /* 0x8E */ 0, /* 0x8F */ 0, /* 0x90 */ 0, /* 0x91 */ 0, /* 0x92 */ 0, /* 0x93 */ 0, /* 0x94 */ 0, /* 0x95 */ 0, /* 0x96 */ 0, /* 0x97 */ 0, /* 0x98 */ 0, /* 0x99 */ 0, /* 0x9A */ 0, /* 0x9B */ 0, /* 0x9C */ 0, /* 0x9D */ 0, /* 0x9E */ 0, /* 0x9F */ 0, /* 0xA0 */ 0, /* 0xA1 */ 0, /* 0xA2 */ 0, /* 0xA3 */ 0, /* 0xA4 */ 0, /* 0xA5 */ 0, /* 0xA6 */ 0, /* 0xA7 */ 0, /* 0xA8 */ 0, /* 0xA9 */ 0, /* 0xAA */ 0, /* 0xAB */ 0, /* 0xAC */ 0, /* 0xAD */ 0, /* 0xAE */ 0, /* 0xAF */ 0, /* 0xB0 */ 0, /* 0xB1 */ 0, /* 0xB2 */ 0, /* 0xB3 */ 0, /* 0xB4 */ 0, /* 0xB5 */ 0, /* 0xB6 */ 0, /* 0xB7 */ 0, /* 0xB8 */ 0, /* 0xB9 */ 0, /* 0xBA */ 0, /* 0xBB */ 0, /* 0xBC */ 0, /* 0xBD */ 0, /* 0xBE */ 0, /* 0xBF */ 0, /* 0xC0 */ 0, /* 0xC1 */ 0, /* 0xC2 */ 0, /* 0xC3 */ 0, /* 0xC4 */ 0, /* 0xC5 */ 0, /* 0xC6 */ 0, /* 0xC7 */ 0, /* 0xC8 */ 0, /* 0xC9 */ 0, /* 0xCA */ 0, /* 0xCB */ 0, /* 0xCC */ 0, /* 0xCD */ 0, /* 0xCE */ 0, /* 0xCF */ 0, /* 0xD0 */ 0, /* 0xD1 */ 0, /* 0xD2 */ 0, /* 0xD3 */ 0, /* 0xD4 */ 0, /* 0xD5 */ 0, /* 0xD6 */ 0, /* 0xD7 */ 0, /* 0xD8 */ 0, /* 0xD9 */ 0, /* 0xDA */ 0, /* 0xDB */ 0, /* 0xDC */ 0, /* 0xDD */ 0, /* 0xDE */ 0, /* 0xDF */ 0, /* 0xE0 */ 0, /* 0xE1 */ 0, /* 0xE2 */ 0, /* 0xE3 */ 0, /* 0xE4 */ 0, /* 0xE5 */ 0, /* 0xE6 */ 0, /* 0xE7 */ 0, /* 0xE8 */ 0, /* 0xE9 */ 0, /* 0xEA */ 0, /* 0xEB */ 0, /* 0xEC */ 0, /* 0xED */ 0, /* 0xEE */ 0, /* 0xEF */ 0, /* 0xF0 */ 0, /* 0xF1 */ 0, /* 0xF2 */ 0, /* 0xF3 */ 0, /* 0xF4 */ 0, /* 0xF5 */ 0, /* 0xF6 */ 0, /* 0xF7 */ 0, /* 0xF8 */ 0, /* 0xF9 */ 0, /* 0xFA */ 0, /* 0xFB */ 0, /* 0xFC */ 0, /* 0xFD */ 0, /* 0xFE */ 0, /* 0xFF */ 0 };
static const uint8_t char_digit[256] = {
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};

bool dns_label_char_valid(uint8_t c) { return label_valid[c] != 0; }
bool dns_label_char_digit(uint8_t c) { return char_digit[c] != 0; }

int dns_label_validate(const uint8_t *label, uint8_t len) {
    if (len == 0 || len > 63) return -1;
    for (uint8_t i = 0; i < len; i++)
        if (!dns_label_char_valid(label[i])) return -1;
    return 0;
}

int dns_label_compare(const uint8_t *a, uint8_t alen, const uint8_t *b, uint8_t blen) {
    if (alen != blen) return (alen < blen) ? -1 : 1;
    for (uint8_t i = 0; i < alen; i++) {
        uint8_t ca = (a[i] >= 'A' && a[i] <= 'Z') ? a[i] + 32 : a[i];
        uint8_t cb = (b[i] >= 'A' && b[i] <= 'Z') ? b[i] + 32 : b[i];
        if (ca != cb) return (ca < cb) ? -1 : 1;
    }
    return 0;
}


/* label helper 0 */
/* label helper 1 */
/* label helper 2 */
/* label helper 3 */
/* label helper 4 */
/* label helper 5 */
/* label helper 6 */
/* label helper 7 */
/* label helper 8 */
/* label helper 9 */
/* label helper 10 */
/* label helper 11 */
/* label helper 12 */
/* label helper 13 */
/* label helper 14 */
/* label helper 15 */
/* label helper 16 */
/* label helper 17 */
/* label helper 18 */
/* label helper 19 */
/* label helper 20 */
/* label helper 21 */
/* label helper 22 */
/* label helper 23 */
/* label helper 24 */
/* label helper 25 */
/* label helper 26 */
/* label helper 27 */
/* label helper 28 */
/* label helper 29 */
/* label helper 30 */
/* label helper 31 */
/* label helper 32 */
/* label helper 33 */
/* label helper 34 */
/* label helper 35 */
/* label helper 36 */
/* label helper 37 */
/* label helper 38 */
/* label helper 39 */
/* label helper 40 */
/* label helper 41 */
/* label helper 42 */
/* label helper 43 */
/* label helper 44 */
/* label helper 45 */
/* label helper 46 */
/* label helper 47 */
/* label helper 48 */
/* label helper 49 */
/* label helper 50 */
/* label helper 51 */
/* label helper 52 */
/* label helper 53 */
/* label helper 54 */
/* label helper 55 */
/* label helper 56 */
/* label helper 57 */
/* label helper 58 */
/* label helper 59 */
/* label helper 60 */
/* label helper 61 */
/* label helper 62 */
/* label helper 63 */
/* label helper 64 */
/* label helper 65 */
/* label helper 66 */
/* label helper 67 */
/* label helper 68 */
/* label helper 69 */
/* label helper 70 */
/* label helper 71 */
/* label helper 72 */
/* label helper 73 */
/* label helper 74 */
/* label helper 75 */
/* label helper 76 */
/* label helper 77 */
/* label helper 78 */
/* label helper 79 */
/* label helper 80 */
/* label helper 81 */
/* label helper 82 */
/* label helper 83 */
/* label helper 84 */
/* label helper 85 */
/* label helper 86 */
/* label helper 87 */
/* label helper 88 */
/* label helper 89 */
/* label helper 90 */
/* label helper 91 */
/* label helper 92 */
/* label helper 93 */
/* label helper 94 */
/* label helper 95 */
/* label helper 96 */
/* label helper 97 */
/* label helper 98 */
/* label helper 99 */
/* label helper 100 */
/* label helper 101 */
/* label helper 102 */
/* label helper 103 */
/* label helper 104 */
/* label helper 105 */
/* label helper 106 */
/* label helper 107 */
/* label helper 108 */
/* label helper 109 */
/* label helper 110 */
/* label helper 111 */
/* label helper 112 */
/* label helper 113 */
/* label helper 114 */
/* label helper 115 */
/* label helper 116 */
/* label helper 117 */
/* label helper 118 */
/* label helper 119 */
