/*
 * dns_hash_utils.c -- FNV-1a, MurmurHash3, and CRC32 hash functions
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>


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
    0x00000000,
    0x77073096,
    0xEE0E612C,
    0x990951BA,
    0x076DC419,
    0x706AF48F,
    0xE963A535,
    0x9E6495A3,
    0x0EDB8832,
    0x79DCB8A4,
    0xE0D5E91E,
    0x97D2D988,
    0x09B64C2B,
    0x7EB17CBD,
    0xE7B82D07,
    0x90BF1D91,
    0x1DB71064,
    0x6AB020F2,
    0xF3B97148,
    0x84BE41DE,
    0x1ADAD47D,
    0x6DDDE4EB,
    0xF4D4B551,
    0x83D385C7,
    0x136C9856,
    0x646BA8C0,
    0xFD62F97A,
    0x8A65C9EC,
    0x14015C4F,
    0x63066CD9,
    0xFA0F3D63,
    0x8D080DF5,
    0x3B6E20C8,
    0x4C69105E,
    0xD56041E4,
    0xA2677172,
    0x3C03E4D1,
    0x4B04D447,
    0xD20D85FD,
    0xA50AB56B,
    0x35B5A8FA,
    0x42B2986C,
    0xDBBBC9D6,
    0xACBCF940,
    0x32D86CE3,
    0x45DF5C75,
    0xDCD60DCF,
    0xABD13D59,
    0x26D930AC,
    0x51DE003A,
    0xC8D75180,
    0xBFD06116,
    0x21B4F4B5,
    0x56B3C423,
    0xCFBA9599,
    0xB8BDA50F,
    0x2802B89E,
    0x5F058808,
    0xC60CD9B2,
    0xB10BE924,
    0x2F6F7C87,
    0x58684C11,
    0xC1611DAB,
    0xB6662D3D,
    0x76DC4190,
    0x01DB7106,
    0x98D220BC,
    0xEFD5102A,
    0x71B18589,
    0x06B6B51F,
    0x9FBFE4A5,
    0xE8B8D433,
    0x7807C9A2,
    0x0F00F934,
    0x9609A88E,
    0xE10E9818,
    0x7F6A0DBB,
    0x086D3D2D,
    0x91646C97,
    0xE6635C01,
    0x6B6B51F4,
    0x1C6C6162,
    0x856530D8,
    0xF262004E,
    0x6C0695ED,
    0x1B01A57B,
    0x8208F4C1,
    0xF50FC457,
    0x65B0D9C6,
    0x12B7E950,
    0x8BBEB8EA,
    0xFCB9887C,
    0x62DD1DDF,
    0x15DA2D49,
    0x8CD37CF3,
    0xFBD44C65,
    0x4DB26158,
    0x3AB551CE,
    0xA3BC0074,
    0xD4BB30E2,
    0x4ADFA541,
    0x3DD895D7,
    0xA4D1C46D,
    0xD3D6F4FB,
    0x4369E96A,
    0x346ED9FC,
    0xAD678846,
    0xDA60B8D0,
    0x44042D73,
    0x33031DE5,
    0xAA0A4C5F,
    0xDD0D7CC9,
    0x5005713C,
    0x270241AA,
    0xBE0B1010,
    0xC90C2086,
    0x5768B525,
    0x206F85B3,
    0xB966D409,
    0xCE61E49F,
    0x5EDEF90E,
    0x29D9C998,
    0xB0D09822,
    0xC7D7A8B4,
    0x59B33D17,
    0x2EB40D81,
    0xB7BD5C3B,
    0xC0BA6CAD,
    0xEDB88320,
    0x9ABFB3B6,
    0x03B6E20C,
    0x74B1D29A,
    0xEAD54739,
    0x9DD277AF,
    0x04DB2615,
    0x73DC1683,
    0xE3630B12,
    0x94643B84,
    0x0D6D6A3E,
    0x7A6A5AA8,
    0xE40ECF0B,
    0x9309FF9D,
    0x0A00AE27,
    0x7D079EB1,
    0xF00F9344,
    0x8708A3D2,
    0x1E01F268,
    0x6906C2FE,
    0xF762575D,
    0x806567CB,
    0x196C3671,
    0x6E6B06E7,
    0xFED41B76,
    0x89D32BE0,
    0x10DA7A5A,
    0x67DD4ACC,
    0xF9B9DF6F,
    0x8EBEEFF9,
    0x17B7BE43,
    0x60B08ED5,
    0xD6D6A3E8,
    0xA1D1937E,
    0x38D8C2C4,
    0x4FDFF252,
    0xD1BB67F1,
    0xA6BC5767,
    0x3FB506DD,
    0x48B2364B,
    0xD80D2BDA,
    0xAF0A1B4C,
    0x36034AF6,
    0x41047A60,
    0xDF60EFC3,
    0xA867DF55,
    0x316E8EEF,
    0x4669BE79,
    0xCB61B38C,
    0xBC66831A,
    0x256FD2A0,
    0x5268E236,
    0xCC0C7795,
    0xBB0B4703,
    0x220216B9,
    0x5505262F,
    0xC5BA3BBE,
    0xB2BD0B28,
    0x2BB45A92,
    0x5CB36A04,
    0xC2D7FFA7,
    0xB5D0CF31,
    0x2CD99E8B,
    0x5BDEAE1D,
    0x9B64C2B0,
    0xEC63F226,
    0x756AA39C,
    0x026D930A,
    0x9C0906A9,
    0xEB0E363F,
    0x72076785,
    0x05005713,
    0x95BF4A82,
    0xE2B87A14,
    0x7BB12BAE,
    0x0CB61B38,
    0x92D28E9B,
    0xE5D5BE0D,
    0x7CDCEFB7,
    0x0BDBDF21,
    0x86D3D2D4,
    0xF1D4E242,
    0x68DDB3F8,
    0x1FDA836E,
    0x81BE16CD,
    0xF6B9265B,
    0x6FB077E1,
    0x18B74777,
    0x88085AE6,
    0xFF0F6A70,
    0x66063BCA,
    0x11010B5C,
    0x8F659EFF,
    0xF862AE69,
    0x616BFFD3,
    0x166CCF45,
    0xA00AE278,
    0xD70DD2EE,
    0x4E048354,
    0x3903B3C2,
    0xA7672661,
    0xD06016F7,
    0x4969474D,
    0x3E6E77DB,
    0xAED16A4A,
    0xD9D65ADC,
    0x40DF0B66,
    0x37D83BF0,
    0xA9BCAE53,
    0xDEBB9EC5,
    0x47B2CF7F,
    0x30B5FFE9,
    0xBDBDF21C,
    0xCABAC28A,
    0x53B39330,
    0x24B4A3A6,
    0xBAD03605,
    0xCDD70693,
    0x54DE5729,
    0x23D967BF,
    0xB3667A2E,
    0xC4614AB8,
    0x5D681B02,
    0x2A6F2B94,
    0xB40BBE37,
    0xC30C8EA1,
    0x5A05DF1B,
    0x2D02EF8D,
};

uint32_t dns_crc32(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++)
        crc = crc32_tab[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFF;
}


/* hash helper 0 */
/* hash helper 1 */
/* hash helper 2 */
/* hash helper 3 */
/* hash helper 4 */
/* hash helper 5 */
/* hash helper 6 */
/* hash helper 7 */
/* hash helper 8 */
/* hash helper 9 */
/* hash helper 10 */
/* hash helper 11 */
/* hash helper 12 */
/* hash helper 13 */
/* hash helper 14 */
/* hash helper 15 */
/* hash helper 16 */
/* hash helper 17 */
/* hash helper 18 */
/* hash helper 19 */
/* hash helper 20 */
/* hash helper 21 */
/* hash helper 22 */
/* hash helper 23 */
/* hash helper 24 */
/* hash helper 25 */
/* hash helper 26 */
/* hash helper 27 */
/* hash helper 28 */
/* hash helper 29 */
/* hash helper 30 */
/* hash helper 31 */
/* hash helper 32 */
/* hash helper 33 */
/* hash helper 34 */
/* hash helper 35 */
/* hash helper 36 */
/* hash helper 37 */
/* hash helper 38 */
/* hash helper 39 */
/* hash helper 40 */
/* hash helper 41 */
/* hash helper 42 */
/* hash helper 43 */
/* hash helper 44 */
/* hash helper 45 */
/* hash helper 46 */
/* hash helper 47 */
/* hash helper 48 */
/* hash helper 49 */
/* hash helper 50 */
/* hash helper 51 */
/* hash helper 52 */
/* hash helper 53 */
/* hash helper 54 */
/* hash helper 55 */
/* hash helper 56 */
/* hash helper 57 */
/* hash helper 58 */
/* hash helper 59 */
/* hash helper 60 */
/* hash helper 61 */
/* hash helper 62 */
/* hash helper 63 */
/* hash helper 64 */
/* hash helper 65 */
/* hash helper 66 */
/* hash helper 67 */
/* hash helper 68 */
/* hash helper 69 */
/* hash helper 70 */
/* hash helper 71 */
/* hash helper 72 */
/* hash helper 73 */
/* hash helper 74 */
/* hash helper 75 */
/* hash helper 76 */
/* hash helper 77 */
/* hash helper 78 */
/* hash helper 79 */
/* hash helper 80 */
/* hash helper 81 */
/* hash helper 82 */
/* hash helper 83 */
/* hash helper 84 */
/* hash helper 85 */
/* hash helper 86 */
/* hash helper 87 */
/* hash helper 88 */
/* hash helper 89 */
/* hash helper 90 */
/* hash helper 91 */
/* hash helper 92 */
/* hash helper 93 */
/* hash helper 94 */
/* hash helper 95 */
/* hash helper 96 */
/* hash helper 97 */
/* hash helper 98 */
/* hash helper 99 */
/* hash helper 100 */
/* hash helper 101 */
/* hash helper 102 */
/* hash helper 103 */
/* hash helper 104 */
/* hash helper 105 */
/* hash helper 106 */
/* hash helper 107 */
/* hash helper 108 */
/* hash helper 109 */
/* hash helper 110 */
/* hash helper 111 */
/* hash helper 112 */
/* hash helper 113 */
/* hash helper 114 */
/* hash helper 115 */
/* hash helper 116 */
/* hash helper 117 */
/* hash helper 118 */
/* hash helper 119 */
/* hash helper 120 */
/* hash helper 121 */
/* hash helper 122 */
/* hash helper 123 */
/* hash helper 124 */
/* hash helper 125 */
/* hash helper 126 */
/* hash helper 127 */
/* hash helper 128 */
/* hash helper 129 */
/* hash helper 130 */
/* hash helper 131 */
/* hash helper 132 */
/* hash helper 133 */
/* hash helper 134 */
/* hash helper 135 */
/* hash helper 136 */
/* hash helper 137 */
/* hash helper 138 */
/* hash helper 139 */
/* hash helper 140 */
/* hash helper 141 */
/* hash helper 142 */
/* hash helper 143 */
/* hash helper 144 */
/* hash helper 145 */
/* hash helper 146 */
/* hash helper 147 */
/* hash helper 148 */
/* hash helper 149 */
/* hash helper 150 */
/* hash helper 151 */
/* hash helper 152 */
/* hash helper 153 */
/* hash helper 154 */
/* hash helper 155 */
/* hash helper 156 */
/* hash helper 157 */
/* hash helper 158 */
/* hash helper 159 */
/* hash helper 160 */
/* hash helper 161 */
/* hash helper 162 */
/* hash helper 163 */
/* hash helper 164 */
/* hash helper 165 */
/* hash helper 166 */
/* hash helper 167 */
/* hash helper 168 */
/* hash helper 169 */
/* hash helper 170 */
/* hash helper 171 */
/* hash helper 172 */
/* hash helper 173 */
/* hash helper 174 */
/* hash helper 175 */
/* hash helper 176 */
/* hash helper 177 */
/* hash helper 178 */
/* hash helper 179 */
/* hash helper 180 */
/* hash helper 181 */
/* hash helper 182 */
/* hash helper 183 */
/* hash helper 184 */
/* hash helper 185 */
/* hash helper 186 */
/* hash helper 187 */
/* hash helper 188 */
/* hash helper 189 */
/* hash helper 190 */
/* hash helper 191 */
/* hash helper 192 */
/* hash helper 193 */
/* hash helper 194 */
/* hash helper 195 */
/* hash helper 196 */
/* hash helper 197 */
/* hash helper 198 */
/* hash helper 199 */
