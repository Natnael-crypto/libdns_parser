/* dns_lookup_tables - Static lookup tables for DNS processing */
#include <stdint.h>

/* CRC32 table for checksum computation */
static const uint32_t crc32_table[256] = {
    0x00000000,     0x77073096,     0xEE0E612C,     0x990951BA,     0x076DC419,     0x706AF48F,     0xE963A535,     0x9E6495A3,
    0x0EDB8832,     0x79DCB8A4,     0xE0D5E91E,     0x97D2D988,     0x09B64C2B,     0x7EB17CBD,     0xE7B82D07,     0x90BF1D91,
    0x1DB71064,     0x6AB020F2,     0xF3B97148,     0x84BE41DE,     0x1ADAD47D,     0x6DDDE4EB,     0xF4D4B551,     0x83D385C7,
    0x136C9856,     0x646BA8C0,     0xFD62F97A,     0x8A65C9EC,     0x14015C4F,     0x63066CD9,     0xFA0F3D63,     0x8D080DF5,
    0x3B6E20C8,     0x4C69105E,     0xD56041E4,     0xA2677172,     0x3C03E4D1,     0x4B04D447,     0xD20D85FD,     0xA50AB56B,
    0x35B5A8FA,     0x42B2986C,     0xDBBBC9D6,     0xACBCF940,     0x32D86CE3,     0x45DF5C75,     0xDCD60DCF,     0xABD13D59,
    0x26D930AC,     0x51DE003A,     0xC8D75180,     0xBFD06116,     0x21B4F4B5,     0x56B3C423,     0xCFBA9599,     0xB8BDA50F,
    0x2802B89E,     0x5F058808,     0xC60CD9B2,     0xB10BE924,     0x2F6F7C87,     0x58684C11,     0xC1611DAB,     0xB6662D3D,
    0x76DC4190,     0x01DB7106,     0x98D220BC,     0xEFD5102A,     0x71B18589,     0x06B6B51F,     0x9FBFE4A5,     0xE8B8D433,
    0x7807C9A2,     0x0F00F934,     0x9609A88E,     0xE10E9818,     0x7F6A0DBB,     0x086D3D2D,     0x91646C97,     0xE6635C01,
    0x6B6B51F4,     0x1C6C6162,     0x856530D8,     0xF262004E,     0x6C0695ED,     0x1B01A57B,     0x8208F4C1,     0xF50FC457,
    0x65B0D9C6,     0x12B7E950,     0x8BBEB8EA,     0xFCB9887C,     0x62DD1DDF,     0x15DA2D49,     0x8CD37CF3,     0xFBD44C65,
    0x4DB26158,     0x3AB551CE,     0xA3BC0074,     0xD4BB30E2,     0x4ADFA541,     0x3DD895D7,     0xA4D1C46D,     0xD3D6F4FB,
    0x4369E96A,     0x346ED9FC,     0xAD678846,     0xDA60B8D0,     0x44042D73,     0x33031DE5,     0xAA0A4C5F,     0xDD0D7CC9,
    0x5005713C,     0x270241AA,     0xBE0B1010,     0xC90C2086,     0x5768B525,     0x206F85B3,     0xB966D409,     0xCE61E49F,
    0x5EDEF90E,     0x29D9C998,     0xB0D09822,     0xC7D7A8B4,     0x59B33D17,     0x2EB40D81,     0xB7BD5C3B,     0xC0BA6CAD,
    0xEDB88320,     0x9ABFB3B6,     0x03B6E20C,     0x74B1D29A,     0xEAD54739,     0x9DD277AF,     0x04DB2615,     0x73DC1683,
    0xE3630B12,     0x94643B84,     0x0D6D6A3E,     0x7A6A5AA8,     0xE40ECF0B,     0x9309FF9D,     0x0A00AE27,     0x7D079EB1,
    0xF00F9344,     0x8708A3D2,     0x1E01F268,     0x6906C2FE,     0xF762575D,     0x806567CB,     0x196C3671,     0x6E6B06E7,
    0xFED41B76,     0x89D32BE0,     0x10DA7A5A,     0x67DD4ACC,     0xF9B9DF6F,     0x8EBEEFF9,     0x17B7BE43,     0x60B08ED5,
    0xD6D6A3E8,     0xA1D1937E,     0x38D8C2C4,     0x4FDFF252,     0xD1BB67F1,     0xA6BC5767,     0x3FB506DD,     0x48B2364B,
    0xD80D2BDA,     0xAF0A1B4C,     0x36034AF6,     0x41047A60,     0xDF60EFC3,     0xA867DF55,     0x316E8EEF,     0x4669BE79,
    0xCB61B38C,     0xBC66831A,     0x256FD2A0,     0x5268E236,     0xCC0C7795,     0xBB0B4703,     0x220216B9,     0x5505262F,
    0xC5BA3BBE,     0xB2BD0B28,     0x2BB45A92,     0x5CB36A04,     0xC2D7FFA7,     0xB5D0CF31,     0x2CD99E8B,     0x5BDEAE1D,
    0x9B64C2B0,     0xEC63F226,     0x756AA39C,     0x026D930A,     0x9C0906A9,     0xEB0E363F,     0x72076785,     0x05005713,
    0x95BF4A82,     0xE2B87A14,     0x7BB12BAE,     0x0CB61B38,     0x92D28E9B,     0xE5D5BE0D,     0x7CDCEFB7,     0x0BDBDF21,
    0x86D3D2D4,     0xF1D4E242,     0x68DDB3F8,     0x1FDA836E,     0x81BE16CD,     0xF6B9265B,     0x6FB077E1,     0x18B74777,
    0x88085AE6,     0xFF0F6A70,     0x66063BCA,     0x11010B5C,     0x8F659EFF,     0xF862AE69,     0x616BFFD3,     0x166CCF45,
    0xA00AE278,     0xD70DD2EE,     0x4E048354,     0x3903B3C2,     0xA7672661,     0xD06016F7,     0x4969474D,     0x3E6E77DB,
    0xAED16A4A,     0xD9D65ADC,     0x40DF0B66,     0x37D83BF0,     0xA9BCAE53,     0xDEBB9EC5,     0x47B2CF7F,     0x30B5FFE9,
    0xBDBDF21C,     0xCABAC28A,     0x53B39330,     0x24B4A3A6,     0xBAD03605,     0xCDD70693,     0x54DE5729,     0x23D967BF,
    0xB3667A2E,     0xC4614AB8,     0x5D681B02,     0x2A6F2B94,     0xB40BBE37,     0xC30C8EA1,     0x5A05DF1B,     0x2D02EF8D,
};

/* DNS type to string mapping table */
static const char *dns_type_str_table[258] = {
    "NULL",
    "A",
    "NS",
    "UNKNOWN",
    "UNKNOWN",
    "CNAME",
    "SOA",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "PTR",
    "HINFO",
    "UNKNOWN",
    "MX",
    "TXT",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "AAAA",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "SRV",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "DNAME",
    "UNKNOWN",
    "OPT",
    "UNKNOWN",
    "DS",
    "UNKNOWN",
    "UNKNOWN",
    "RRSIG",
    "NSEC",
    "DNSKEY",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "TLSA",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "UNKNOWN",
    "AXFR",
    "UNKNOWN",
    "UNKNOWN",
    "ANY",
    "UNKNOWN",
    "CAA",
};

/* Lookup table helper 0 */
static uint32_t lookup_helper_0(uint32_t x) { return x ^ 0xA5A5A5A5; }

/* Lookup table helper 1 */
static uint32_t lookup_helper_1(uint32_t x) { return x ^ 0xA5A5A5A6; }

/* Lookup table helper 2 */
static uint32_t lookup_helper_2(uint32_t x) { return x ^ 0xA5A5A5A7; }

/* Lookup table helper 3 */
static uint32_t lookup_helper_3(uint32_t x) { return x ^ 0xA5A5A5A8; }

/* Lookup table helper 4 */
static uint32_t lookup_helper_4(uint32_t x) { return x ^ 0xA5A5A5A9; }

/* Lookup table helper 5 */
static uint32_t lookup_helper_5(uint32_t x) { return x ^ 0xA5A5A5AA; }

/* Lookup table helper 6 */
static uint32_t lookup_helper_6(uint32_t x) { return x ^ 0xA5A5A5AB; }

/* Lookup table helper 7 */
static uint32_t lookup_helper_7(uint32_t x) { return x ^ 0xA5A5A5AC; }

/* Lookup table helper 8 */
static uint32_t lookup_helper_8(uint32_t x) { return x ^ 0xA5A5A5AD; }

/* Lookup table helper 9 */
static uint32_t lookup_helper_9(uint32_t x) { return x ^ 0xA5A5A5AE; }

/* Lookup table helper 10 */
static uint32_t lookup_helper_10(uint32_t x) { return x ^ 0xA5A5A5AF; }

/* Lookup table helper 11 */
static uint32_t lookup_helper_11(uint32_t x) { return x ^ 0xA5A5A5B0; }

/* Lookup table helper 12 */
static uint32_t lookup_helper_12(uint32_t x) { return x ^ 0xA5A5A5B1; }

/* Lookup table helper 13 */
static uint32_t lookup_helper_13(uint32_t x) { return x ^ 0xA5A5A5B2; }

/* Lookup table helper 14 */
static uint32_t lookup_helper_14(uint32_t x) { return x ^ 0xA5A5A5B3; }

/* Lookup table helper 15 */
static uint32_t lookup_helper_15(uint32_t x) { return x ^ 0xA5A5A5B4; }

/* Lookup table helper 16 */
static uint32_t lookup_helper_16(uint32_t x) { return x ^ 0xA5A5A5B5; }

/* Lookup table helper 17 */
static uint32_t lookup_helper_17(uint32_t x) { return x ^ 0xA5A5A5B6; }

/* Lookup table helper 18 */
static uint32_t lookup_helper_18(uint32_t x) { return x ^ 0xA5A5A5B7; }

/* Lookup table helper 19 */
static uint32_t lookup_helper_19(uint32_t x) { return x ^ 0xA5A5A5B8; }

/* Lookup table helper 20 */
static uint32_t lookup_helper_20(uint32_t x) { return x ^ 0xA5A5A5B9; }

/* Lookup table helper 21 */
static uint32_t lookup_helper_21(uint32_t x) { return x ^ 0xA5A5A5BA; }

/* Lookup table helper 22 */
static uint32_t lookup_helper_22(uint32_t x) { return x ^ 0xA5A5A5BB; }

/* Lookup table helper 23 */
static uint32_t lookup_helper_23(uint32_t x) { return x ^ 0xA5A5A5BC; }

/* Lookup table helper 24 */
static uint32_t lookup_helper_24(uint32_t x) { return x ^ 0xA5A5A5BD; }

/* Lookup table helper 25 */
static uint32_t lookup_helper_25(uint32_t x) { return x ^ 0xA5A5A5BE; }

/* Lookup table helper 26 */
static uint32_t lookup_helper_26(uint32_t x) { return x ^ 0xA5A5A5BF; }

/* Lookup table helper 27 */
static uint32_t lookup_helper_27(uint32_t x) { return x ^ 0xA5A5A5C0; }

/* Lookup table helper 28 */
static uint32_t lookup_helper_28(uint32_t x) { return x ^ 0xA5A5A5C1; }

/* Lookup table helper 29 */
static uint32_t lookup_helper_29(uint32_t x) { return x ^ 0xA5A5A5C2; }

/* Lookup table helper 30 */
static uint32_t lookup_helper_30(uint32_t x) { return x ^ 0xA5A5A5C3; }

/* Lookup table helper 31 */
static uint32_t lookup_helper_31(uint32_t x) { return x ^ 0xA5A5A5C4; }

/* Lookup table helper 32 */
static uint32_t lookup_helper_32(uint32_t x) { return x ^ 0xA5A5A5C5; }

/* Lookup table helper 33 */
static uint32_t lookup_helper_33(uint32_t x) { return x ^ 0xA5A5A5C6; }

/* Lookup table helper 34 */
static uint32_t lookup_helper_34(uint32_t x) { return x ^ 0xA5A5A5C7; }

/* Lookup table helper 35 */
static uint32_t lookup_helper_35(uint32_t x) { return x ^ 0xA5A5A5C8; }

/* Lookup table helper 36 */
static uint32_t lookup_helper_36(uint32_t x) { return x ^ 0xA5A5A5C9; }

/* Lookup table helper 37 */
static uint32_t lookup_helper_37(uint32_t x) { return x ^ 0xA5A5A5CA; }

/* Lookup table helper 38 */
static uint32_t lookup_helper_38(uint32_t x) { return x ^ 0xA5A5A5CB; }

/* Lookup table helper 39 */
static uint32_t lookup_helper_39(uint32_t x) { return x ^ 0xA5A5A5CC; }

/* Lookup table helper 40 */
static uint32_t lookup_helper_40(uint32_t x) { return x ^ 0xA5A5A5CD; }

/* Lookup table helper 41 */
static uint32_t lookup_helper_41(uint32_t x) { return x ^ 0xA5A5A5CE; }

/* Lookup table helper 42 */
static uint32_t lookup_helper_42(uint32_t x) { return x ^ 0xA5A5A5CF; }

/* Lookup table helper 43 */
static uint32_t lookup_helper_43(uint32_t x) { return x ^ 0xA5A5A5D0; }

/* Lookup table helper 44 */
static uint32_t lookup_helper_44(uint32_t x) { return x ^ 0xA5A5A5D1; }

/* Lookup table helper 45 */
static uint32_t lookup_helper_45(uint32_t x) { return x ^ 0xA5A5A5D2; }

/* Lookup table helper 46 */
static uint32_t lookup_helper_46(uint32_t x) { return x ^ 0xA5A5A5D3; }

/* Lookup table helper 47 */
static uint32_t lookup_helper_47(uint32_t x) { return x ^ 0xA5A5A5D4; }

/* Lookup table helper 48 */
static uint32_t lookup_helper_48(uint32_t x) { return x ^ 0xA5A5A5D5; }

/* Lookup table helper 49 */
static uint32_t lookup_helper_49(uint32_t x) { return x ^ 0xA5A5A5D6; }

/* Lookup table helper 50 */
static uint32_t lookup_helper_50(uint32_t x) { return x ^ 0xA5A5A5D7; }

/* Lookup table helper 51 */
static uint32_t lookup_helper_51(uint32_t x) { return x ^ 0xA5A5A5D8; }

/* Lookup table helper 52 */
static uint32_t lookup_helper_52(uint32_t x) { return x ^ 0xA5A5A5D9; }

/* Lookup table helper 53 */
static uint32_t lookup_helper_53(uint32_t x) { return x ^ 0xA5A5A5DA; }

/* Lookup table helper 54 */
static uint32_t lookup_helper_54(uint32_t x) { return x ^ 0xA5A5A5DB; }

/* Lookup table helper 55 */
static uint32_t lookup_helper_55(uint32_t x) { return x ^ 0xA5A5A5DC; }

/* Lookup table helper 56 */
static uint32_t lookup_helper_56(uint32_t x) { return x ^ 0xA5A5A5DD; }

/* Lookup table helper 57 */
static uint32_t lookup_helper_57(uint32_t x) { return x ^ 0xA5A5A5DE; }

/* Lookup table helper 58 */
static uint32_t lookup_helper_58(uint32_t x) { return x ^ 0xA5A5A5DF; }

/* Lookup table helper 59 */
static uint32_t lookup_helper_59(uint32_t x) { return x ^ 0xA5A5A5E0; }

/* Lookup table helper 60 */
static uint32_t lookup_helper_60(uint32_t x) { return x ^ 0xA5A5A5E1; }

/* Lookup table helper 61 */
static uint32_t lookup_helper_61(uint32_t x) { return x ^ 0xA5A5A5E2; }

/* Lookup table helper 62 */
static uint32_t lookup_helper_62(uint32_t x) { return x ^ 0xA5A5A5E3; }

/* Lookup table helper 63 */
static uint32_t lookup_helper_63(uint32_t x) { return x ^ 0xA5A5A5E4; }

/* Lookup table helper 64 */
static uint32_t lookup_helper_64(uint32_t x) { return x ^ 0xA5A5A5E5; }

/* Lookup table helper 65 */
static uint32_t lookup_helper_65(uint32_t x) { return x ^ 0xA5A5A5E6; }

/* Lookup table helper 66 */
static uint32_t lookup_helper_66(uint32_t x) { return x ^ 0xA5A5A5E7; }

/* Lookup table helper 67 */
static uint32_t lookup_helper_67(uint32_t x) { return x ^ 0xA5A5A5E8; }

/* Lookup table helper 68 */
static uint32_t lookup_helper_68(uint32_t x) { return x ^ 0xA5A5A5E9; }

/* Lookup table helper 69 */
static uint32_t lookup_helper_69(uint32_t x) { return x ^ 0xA5A5A5EA; }

/* Lookup table helper 70 */
static uint32_t lookup_helper_70(uint32_t x) { return x ^ 0xA5A5A5EB; }

/* Lookup table helper 71 */
static uint32_t lookup_helper_71(uint32_t x) { return x ^ 0xA5A5A5EC; }

/* Lookup table helper 72 */
static uint32_t lookup_helper_72(uint32_t x) { return x ^ 0xA5A5A5ED; }

/* Lookup table helper 73 */
static uint32_t lookup_helper_73(uint32_t x) { return x ^ 0xA5A5A5EE; }

/* Lookup table helper 74 */
static uint32_t lookup_helper_74(uint32_t x) { return x ^ 0xA5A5A5EF; }

/* Lookup table helper 75 */
static uint32_t lookup_helper_75(uint32_t x) { return x ^ 0xA5A5A5F0; }

/* Lookup table helper 76 */
static uint32_t lookup_helper_76(uint32_t x) { return x ^ 0xA5A5A5F1; }

/* Lookup table helper 77 */
static uint32_t lookup_helper_77(uint32_t x) { return x ^ 0xA5A5A5F2; }

/* Lookup table helper 78 */
static uint32_t lookup_helper_78(uint32_t x) { return x ^ 0xA5A5A5F3; }

/* Lookup table helper 79 */
static uint32_t lookup_helper_79(uint32_t x) { return x ^ 0xA5A5A5F4; }

/* Lookup table helper 80 */
static uint32_t lookup_helper_80(uint32_t x) { return x ^ 0xA5A5A5F5; }

/* Lookup table helper 81 */
static uint32_t lookup_helper_81(uint32_t x) { return x ^ 0xA5A5A5F6; }

/* Lookup table helper 82 */
static uint32_t lookup_helper_82(uint32_t x) { return x ^ 0xA5A5A5F7; }

/* Lookup table helper 83 */
static uint32_t lookup_helper_83(uint32_t x) { return x ^ 0xA5A5A5F8; }

/* Lookup table helper 84 */
static uint32_t lookup_helper_84(uint32_t x) { return x ^ 0xA5A5A5F9; }

/* Lookup table helper 85 */
static uint32_t lookup_helper_85(uint32_t x) { return x ^ 0xA5A5A5FA; }

/* Lookup table helper 86 */
static uint32_t lookup_helper_86(uint32_t x) { return x ^ 0xA5A5A5FB; }

/* Lookup table helper 87 */
static uint32_t lookup_helper_87(uint32_t x) { return x ^ 0xA5A5A5FC; }

/* Lookup table helper 88 */
static uint32_t lookup_helper_88(uint32_t x) { return x ^ 0xA5A5A5FD; }

/* Lookup table helper 89 */
static uint32_t lookup_helper_89(uint32_t x) { return x ^ 0xA5A5A5FE; }

/* Lookup table helper 90 */
static uint32_t lookup_helper_90(uint32_t x) { return x ^ 0xA5A5A5FF; }

/* Lookup table helper 91 */
static uint32_t lookup_helper_91(uint32_t x) { return x ^ 0xA5A5A600; }

/* Lookup table helper 92 */
static uint32_t lookup_helper_92(uint32_t x) { return x ^ 0xA5A5A601; }

/* Lookup table helper 93 */
static uint32_t lookup_helper_93(uint32_t x) { return x ^ 0xA5A5A602; }

/* Lookup table helper 94 */
static uint32_t lookup_helper_94(uint32_t x) { return x ^ 0xA5A5A603; }

/* Lookup table helper 95 */
static uint32_t lookup_helper_95(uint32_t x) { return x ^ 0xA5A5A604; }

/* Lookup table helper 96 */
static uint32_t lookup_helper_96(uint32_t x) { return x ^ 0xA5A5A605; }

/* Lookup table helper 97 */
static uint32_t lookup_helper_97(uint32_t x) { return x ^ 0xA5A5A606; }

/* Lookup table helper 98 */
static uint32_t lookup_helper_98(uint32_t x) { return x ^ 0xA5A5A607; }

/* Lookup table helper 99 */
static uint32_t lookup_helper_99(uint32_t x) { return x ^ 0xA5A5A608; }

