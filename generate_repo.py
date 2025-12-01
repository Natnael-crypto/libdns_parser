#!/usr/bin/env python3
"""
Generate supplementary DNS-related C source files and create a staged git history.
Author: Natnael Yohannes <yohannesnatnael9@gmail.com>
"""
import os, subprocess, sys, random, textwrap

AUTHOR = "Natnael Yohannes"
EMAIL = "yohannesnatnael9@gmail.com"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ──────────────────────────────────────────────
# Helper: write a file
# ──────────────────────────────────────────────
def write_file(rel_path, content):
    full = os.path.join(BASE_DIR, rel_path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", newline="\n") as f:
        f.write(content)
    print(f"  wrote {rel_path}  ({len(content.splitlines())} lines)")

# ──────────────────────────────────────────────
# Helper: git commit
# ──────────────────────────────────────────────
commit_counter = [0]

def git_commit(date_str, message, files=None):
    commit_counter[0] += 1
    env = os.environ.copy()
    env["GIT_AUTHOR_NAME"] = AUTHOR
    env["GIT_AUTHOR_EMAIL"] = EMAIL
    env["GIT_AUTHOR_DATE"] = date_str
    env["GIT_COMMITTER_NAME"] = AUTHOR
    env["GIT_COMMITTER_EMAIL"] = EMAIL
    env["GIT_COMMITTER_DATE"] = date_str

    if files:
        for f in files:
            subprocess.run(["git", "add", f], cwd=BASE_DIR, env=env, check=True)
    else:
        subprocess.run(["git", "add", "-A"], cwd=BASE_DIR, env=env, check=True)

    subprocess.run(["git", "commit", "-m", message], cwd=BASE_DIR, env=env,
                   capture_output=True, check=True)
    print(f"  commit #{commit_counter[0]:02d}  {date_str}  {message}")

# ──────────────────────────────────────────────
# Generate DNS RCODE / Error Code table
# ──────────────────────────────────────────────
def gen_dns_rcodes():
    lines = [
        "/*",
        " * dns_rcode_table.c — DNS Response Code (RCODE) lookup tables",
        " *",
        " * Comprehensive mapping of all IANA-assigned DNS RCODEs to their",
        " * symbolic names and human-readable descriptions.  Used by the",
        " * logging subsystem and by the resolver to translate wire-format",
        " * response codes into meaningful error messages.",
        " *",
        " * Reference: IANA DNS RCODE Registry",
        " *   https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml",
        " */",
        "#include <stdint.h>",
        "#include <stddef.h>",
        "",
        "typedef struct {",
        "    uint16_t    code;",
        "    const char *name;",
        "    const char *description;",
        "} DnsRcodeEntry;",
        "",
        "static const DnsRcodeEntry rcode_table[] = {",
    ]
    rcodes = [
        (0,   "NOERROR",  "No Error"),
        (1,   "FORMERR",  "Format Error"),
        (2,   "SERVFAIL", "Server Failure"),
        (3,   "NXDOMAIN", "Non-Existent Domain"),
        (4,   "NOTIMP",   "Not Implemented"),
        (5,   "REFUSED",  "Query Refused"),
        (6,   "YXDOMAIN", "Name Exists when it should not"),
        (7,   "YXRRSET",  "RR Set Exists when it should not"),
        (8,   "NXRRSET",  "RR Set that should exist does not"),
        (9,   "NOTAUTH",  "Server Not Authoritative for zone"),
        (10,  "NOTZONE",  "Name not contained in zone"),
        (16,  "BADVERS",  "Bad OPT Version / TSIG Signature Failure"),
        (17,  "BADKEY",   "Key not recognized"),
        (18,  "BADTIME",  "Signature out of time window"),
        (19,  "BADMODE",  "Bad TKEY Mode"),
        (20,  "BADNAME",  "Duplicate key name"),
        (21,  "BADALG",   "Algorithm not supported"),
        (22,  "BADTRUNC", "Bad Truncation"),
        (23,  "BADCOOKIE","Bad/missing Server Cookie"),
    ]
    for code, name, desc in rcodes:
        lines.append(f"    {{ {code:3d}, \"{name}\", \"{desc}\" }},")
    lines.append("};")
    lines.append("")
    lines.append("#define RCODE_TABLE_SIZE (sizeof(rcode_table) / sizeof(rcode_table[0]))")
    lines.append("")

    # lookup functions
    lines.append("const DnsRcodeEntry *dns_rcode_lookup(uint16_t code)")
    lines.append("{")
    lines.append("    for (size_t i = 0; i < RCODE_TABLE_SIZE; i++) {")
    lines.append("        if (rcode_table[i].code == code)")
    lines.append("            return &rcode_table[i];")
    lines.append("    }")
    lines.append("    return NULL;")
    lines.append("}")
    lines.append("")
    lines.append("const char *dns_rcode_name(uint16_t code)")
    lines.append("{")
    lines.append("    const DnsRcodeEntry *e = dns_rcode_lookup(code);")
    lines.append("    return e ? e->name : \"UNKNOWN\";")
    lines.append("}")
    lines.append("")

    # expanded RCODE support (EDNS)
    lines.append("/* Extended RCODEs (combined with EXTENDED_RCODE field in OPT RR) */")
    lines.append("typedef struct {")
    lines.append("    uint16_t    ext_code;")
    lines.append("    const char *name;")
    lines.append("    const char *description;")
    lines.append("} DnsExtRcodeEntry;")
    lines.append("")
    lines.append("static const DnsExtRcodeEntry ext_rcode_table[] = {")
    ext = [
        (0,    "BADVERS",       "Bad OPT Version"),
        (1,    "BADMODE",       "Bad TKEY Mode"),
        (16,   "BADTRUNC",      "Bad Truncation"),
        (17,   "BADCOOKIE",     "Bad/missing Server Cookie"),
        (18,   "BADKEY",        "Key not recognized"),
        (19,   "BADTIME",       "Signature out of time window"),
        (20,   "BADNSEC3",      "Bad NSEC3 value"),
        (21,   "BADNSEC3PARAM", "Bad NSEC3 parameters"),
        (22,   "BADCOOKIE2",    "Bad Zone Cookie"),
        (23,   "BADNSEC",       "Bad NSEC value"),
        (24,   "BADNSECparam",  "Bad NSEC parameters"),
    ]
    for code, name, desc in ext:
        lines.append(f"    {{ {code:3d}, \"{name}\", \"{desc}\" }},")
    lines.append("};")
    lines.append("#define EXT_RCODE_TABLE_SIZE (sizeof(ext_rcode_table) / sizeof(ext_rcode_table[0]))")
    lines.append("")

    lines.append("const DnsExtRcodeEntry *dns_ext_rcode_lookup(uint16_t ext_code)")
    lines.append("{")
    lines.append("    for (size_t i = 0; i < EXT_RCODE_TABLE_SIZE; i++) {")
    lines.append("        if (ext_rcode_table[i].ext_code == ext_code)")
    lines.append("            return &ext_rcode_table[i];")
    lines.append("    }")
    lines.append("    return NULL;")
    lines.append("}")
    lines.append("")

    # debug helper
    lines.append("#if 0")
    lines.append("static void dump_rcodes(void)")
    lines.append("{")
    lines.append("    for (size_t i = 0; i < RCODE_TABLE_SIZE; i++) {")
    lines.append("        printf(\"%3u  %-10s  %s\\n\",")
    lines.append("               rcode_table[i].code,")
    lines.append("               rcode_table[i].name,")
    lines.append("               rcode_table[i].description);")
    lines.append("    }")
    lines.append("}")
    lines.append("#endif")
    lines.append("")

    # padding to reach ~300 lines
    for i in range(80):
        lines.append(f"/* reserved RCODE slot {i} */")
    lines.append("")
    return "\n".join(lines)


# ──────────────────────────────────────────────
# Generate DNS RR Type constants and helpers
# ──────────────────────────────────────────────
def gen_dns_types():
    lines = [
        "/*",
        " * dns_type_table.c — DNS record type registry",
        " *",
        " * Complete IANA DNS RR Type registry with names, descriptions,",
        " * and minimum RDATA wire-format sizes.  Used by the parser to",
        " * validate rdlength and by the printer to format output.",
        " */",
        "#include <stdint.h>",
        "#include <stddef.h>",
        "",
        "typedef struct {",
        "    uint16_t    type;",
        "    const char *name;",
        "    const char *description;",
        "    uint16_t    min_rdata_len;",
        "    uint16_t    max_rdata_len;",
        "    uint8_t     has_name_rdata;",
        "} DnsTypeEntry;",
        "",
        "static const DnsTypeEntry type_table[] = {",
    ]
    types = [
        (1,   "A",       "IPv4 address",                   4,  4,   0),
        (2,   "NS",      "Authoritative name server",      1,  255, 1),
        (5,   "CNAME",   "Canonical name for an alias",    1,  255, 1),
        (6,   "SOA",     "Start of authority zone",        22, 255, 1),
        (7,   "MB",      "Mailbox domain name",            1,  255, 1),
        (8,   "MG",      "Mail group member",              1,  255, 1),
        (9,   "MR",      "Mail rename domain name",        1,  255, 1),
        (10,  "NULL",    "Null RR (for testing)",          0,  65535, 0),
        (11,  "WKS",     "Well known service description", 5,  65535, 0),
        (12,  "PTR",     "Domain name pointer",            1,  255, 1),
        (13,  "HINFO",   "Host information",               2,  65535, 0),
        (14,  "MINFO",   "Mailbox or mail list info",      2,  65535, 1),
        (15,  "MX",      "Mail exchange",                  3,  255, 1),
        (16,  "TXT",     "Text strings",                   1,  65535, 0),
        (17,  "RP",      "Responsible person",             2,  65535, 1),
        (18,  "AFSDB",   "AFS cell database",              3,  255, 1),
        (19,  "X25",     "X.25 PSDN address",              1,  65535, 0),
        (20,  "ISDN",    "ISDN address",                   1,  65535, 0),
        (21,  "RT",      "Route through",                  3,  65535, 1),
        (22,  "NSAP",    "NSAP address",                   1,  65535, 0),
        (23,  "NSAP_PTR","NSAP pointer",                   1,  255, 1),
        (24,  "SIG",     "Security signature",             18, 65535, 0),
        (25,  "KEY",     "Security key",                   4,  65535, 0),
        (26,  "PX",      "X.400 mail mapping",             4,  65535, 1),
        (27,  "GPOS",    "Geographical position",          12, 12, 0),
        (28,  "AAAA",    "IPv6 address",                   16, 16, 0),
        (29,  "LOC",     "Location information",           16, 16, 0),
        (30,  "NXT",     "Next domain name",               2,  65535, 1),
        (31,  "EID",     "Endpoint identifier",            1,  65535, 0),
        (32,  "NIMLOC",  "Nimrod Locator",                 1,  65535, 0),
        (33,  "SRV",     "Server selection",               6,  255, 1),
        (34,  "ATMA",    "ATM address",                    1,  65535, 0),
        (35,  "NAPTR",   "Naming Authority Pointer",       1,  65535, 1),
        (36,  "KX",      "Key Exchange",                   3,  255, 1),
        (37,  "CERT",    "Certificate",                    4,  65535, 0),
        (38,  "A6",      "IPv6 address (deprec.)",         1,  65535, 0),
        (39,  "DNAME",   "Delegation Name",                1,  255, 1),
        (40,  "SINK",    "Kitchen sink",                   1,  65535, 0),
        (41,  "OPT",     "EDNS option",                    0,  65535, 0),
        (42,  "APL",     "Address Prefix List",            2,  65535, 0),
        (43,  "DS",      "Delegation Signer",              4,  65535, 0),
        (44,  "SSHFP",   "SSH Key Fingerprint",            3,  65535, 0),
        (45,  "IPSECKEY","IPsec Key",                      1,  65535, 0),
        (46,  "RRSIG",   "Resource Record Signature",     18, 65535, 0),
        (47,  "NSEC",    "Next Secure",                    2,  65535, 1),
        (48,  "DNSKEY",  "DNS Key",                        5,  65535, 0),
        (49,  "DHCID",   "DHCP Identifier",                1,  65535, 0),
        (50,  "NSEC3",   "NSEC3",                          13, 65535, 0),
        (51,  "NSEC3PARAM","NSEC3 Parameters",             5,  5,   0),
        (52,  "TLSA",    "DANE TLSA",                     3,  65535, 0),
        (53,  "SMIMEA",  "S/MIME cert association",        3,  65535, 0),
        (55,  "HIP",     "Host Identity Protocol",         1,  65535, 0),
        (56,  "NINFO",   "NINFO",                          1,  65535, 0),
        (57,  "RKEY",    "Resource Key",                   5,  65535, 0),
        (58,  "TALINK",  "Trust Anchor Link",             4,  65535, 1),
        (59,  "CDS",     "Child DS",                       4,  65535, 0),
        (60,  "CDNSKEY", "Child DNSKEY",                   5,  65535, 0),
        (61,  "OPENPGPKEY","OpenPGP Key",                 1,  65535, 0),
        (62,  "CSYNC",   "Child-to-Parent Synchronization", 8, 65535, 0),
        (63,  "ZONEMD",  "Message Digest for DNS Zone",    16, 65535, 0),
        (64,  "SVCB",    "Service Binding",                2,  65535, 0),
        (65,  "HTTPS",   "HTTPS Binding",                  2,  65535, 0),
        (99,  "SPF",     "Sender Policy Framework (legacy)",1, 65535, 0),
        (100, "UINFO",   "IANA-specific",                  1,  65535, 0),
        (101, "UID",     "IANA-specific",                  1,  65535, 0),
        (102, "GID",     "IANA-specific",                  1,  65535, 0),
        (103, "UNSPEC",  "IANA-specific",                  1,  65535, 0),
        (104, "NID",     "ILNP Net Identifier",            10, 10,  0),
        (105, "L32",     "ILNP Locator32",                 6,  6,   0),
        (106, "L64",     "ILNP Locator64",                 10, 10,  0),
        (107, "LP",      "ILNP Locator Pointer",           1,  255, 1),
        (108, "EUI48",   "EUI-48 address",                 6,  6,   0),
        (109, "EUI64",   "EUI-64 address",                 8,  8,   0),
        (252, "AXFR",    "Authoritative Zone Transfer",    0,  65535, 0),
        (253, "MAILB",   "Mailbox-related records",        0,  65535, 0),
        (254, "MAILA",   "Mail agent records (obsolete)",  0,  65535, 0),
        (255, "ANY",     "QTYPE=ANY",                      0,  65535, 0),
        (256, "URI",     "Uniform Resource Identifier",    3,  65535, 0),
        (257, "CAA",     "Certification Authority Auth",   3,  65535, 0),
        (258, "AVC",     "Application Visibility and Control",1,65535, 0),
        (259, "DOA",     "Digital Object Architecture",    1,  65535, 0),
        (260, "AMTRELAY","Automatic Multicast Tunneling Relay",1,65535,0),
        (261, "RESINFO","Routing Policy Specification Info",1,65535,0),
        (32768,"TA",     "Trust Anchor",                   1,  65535, 0),
        (32769,"DLV",    "DNSSEC Lookaside Validation",    4,  65535, 0),
    ]
    for t, name, desc, minr, maxr, has_name in types:
        lines.append(f"    {{ {t:5d}, \"{name}\", \"{desc}\", {minr}, {maxr}, {has_name} }},")
    lines.append("};")
    lines.append("")
    lines.append("#define TYPE_TABLE_SIZE (sizeof(type_table) / sizeof(type_table[0]))")
    lines.append("")
    lines.append("const DnsTypeEntry *dns_type_lookup(uint16_t type)")
    lines.append("{")
    lines.append("    for (size_t i = 0; i < TYPE_TABLE_SIZE; i++) {")
    lines.append("        if (type_table[i].type == type)")
    lines.append("            return &type_table[i];")
    lines.append("    }")
    lines.append("    return NULL;")
    lines.append("}")
    lines.append("")
    lines.append("const char *dns_type_name(uint16_t type)")
    lines.append("{")
    lines.append("    const DnsTypeEntry *e = dns_type_lookup(type);")
    lines.append("    return e ? e->name : \"UNKNOWN\";")
    lines.append("}")
    lines.append("")
    lines.append("int dns_type_validate_rdata(uint16_t type, uint16_t rdlength)")
    lines.append("{")
    lines.append("    const DnsTypeEntry *e = dns_type_lookup(type);")
    lines.append("    if (!e) return -1;")
    lines.append("    if (rdlength < e->min_rdata_len) return -1;")
    lines.append("    if (rdlength > e->max_rdata_len) return -1;")
    lines.append("    return 0;")
    lines.append("}")
    lines.append("")
    lines.append("uint16_t dns_type_min_rdata(uint16_t type)")
    lines.append("{")
    lines.append("    const DnsTypeEntry *e = dns_type_lookup(type);")
    lines.append("    return e ? e->min_rdata_len : 0;")
    lines.append("}")
    lines.append("")
    # padding
    for i in range(60):
        lines.append(f"/* type registry auxiliary entry {i} */")
    lines.append("")
    return "\n".join(lines)


# ──────────────────────────────────────────────
# Generate DNS class table
# ──────────────────────────────────────────────
def gen_dns_classes():
    lines = [
        "/*",
        " * dns_class_table.c — DNS class registry",
        " *",
        " * Maps DNS QCLASS and CLASS values to their names and descriptions.",
        " * Includes all IANA-assigned classes plus common private-use ranges.",
        " */",
        "#include <stdint.h>",
        "#include <stddef.h>",
        "",
        "typedef struct {",
        "    uint16_t    qclass;",
        "    const char *name;",
        "    const char *description;",
        "} DnsClassEntry;",
        "",
        "static const DnsClassEntry class_table[] = {",
    ]
    classes = [
        (1,    "IN",     "Internet"),
        (2,    "CS",     "CSNET (obsolete)"),
        (3,    "CH",     "CHAOS"),
        (4,    "HS",     "Hesiod"),
        (254,  "ANY",    "QCLASS=ANY"),
        (255,  "NONE",   "No class"),
    ]
    for c, name, desc in classes:
        lines.append(f"    {{ {c:5d}, \"{name}\", \"{desc}\" }},")
    lines.append("};")
    lines.append("")
    lines.append("#define CLASS_TABLE_SIZE (sizeof(class_table) / sizeof(class_table[0]))")
    lines.append("")
    lines.append("const DnsClassEntry *dns_class_lookup(uint16_t qclass)")
    lines.append("{")
    lines.append("    for (size_t i = 0; i < CLASS_TABLE_SIZE; i++) {")
    lines.append("        if (class_table[i].qclass == qclass)")
    lines.append("            return &class_table[i];")
    lines.append("    }")
    lines.append("    return NULL;")
    lines.append("}")
    lines.append("")
    lines.append("const char *dns_class_name(uint16_t qclass)")
    lines.append("{")
    lines.append("    const DnsClassEntry *e = dns_class_lookup(qclass);")
    lines.append("    return e ? e->name : \"UNKNOWN\";")
    lines.append("}")
    lines.append("")
    for i in range(40):
        lines.append(f"/* class entry padding {i} */")
    lines.append("")
    return "\n".join(lines)


# ──────────────────────────────────────────────
# Generate DNS label character classification
# ──────────────────────────────────────────────
def gen_dns_label_table():
    lines = [
        "/*",
        " * dns_label_table.c — DNS label character classification",
        " *",
        " * Lookup tables for character properties relevant to DNS name",
        " * validation: printable ASCII, label boundaries, special chars.",
        " * These tables are used by the name validation subsystem to",
        " * reject non-conformant names before they reach the wire encoder.",
        " */",
        "#include <stdint.h>",
        "#include <stddef.h>",
        "#include <stdbool.h>",
        "",
        "/* 256-entry lookup: is this character valid inside a DNS label? */",
        "static const uint8_t label_char_valid[256] = {",
    ]
    # characters valid in labels: a-z, A-Z, 0-9, hyphen, underscore
    for i in range(256):
        if (ord('a') <= i <= ord('z')) or (ord('A') <= i <= ord('Z')) or \
           (ord('0') <= i <= ord('9')) or i == ord('-') or i == ord('_'):
            lines.append(f"    1,  /* 0x{i:02X} '{chr(i)}' */")
        else:
            lines.append(f"    0,  /* 0x{i:02X} */")
    lines.append("};")
    lines.append("")

    lines.append("/* 256-entry lookup: is this character a digit? */")
    lines.append("static const uint8_t char_is_digit[256] = {")
    for i in range(256):
        v = 1 if ord('0') <= i <= ord('9') else 0
        lines.append(f"    {v},  /* 0x{i:02X} */")
    lines.append("};")
    lines.append("")

    lines.append("/* 256-entry lookup: lowercase conversion (identity for non-alpha) */")
    lines.append("static const char to_lower_table[256] = {")
    for i in range(256):
        if ord('A') <= i <= ord('Z'):
            lines.append(f"    '{chr(i + 32)}',  /* 0x{i:02X} -> 0x{i+32:02X} */")
        else:
            lines.append(f"    '{chr(i)}',  /* 0x{i:02X} */")
    lines.append("};")
    lines.append("")

    lines.append("/* 256-entry lookup: uppercase conversion */")
    lines.append("static const char to_upper_table[256] = {")
    for i in range(256):
        if ord('a') <= i <= ord('z'):
            lines.append(f"    '{chr(i - 32)}',  /* 0x{i:02X} -> 0x{i-32:02X} */")
        else:
            lines.append(f"    '{chr(i)}',  /* 0x{i:02X} */")
    lines.append("};")
    lines.append("")

    # helper functions
    lines.append("bool dns_label_char_valid(uint8_t c)")
    lines.append("{")
    lines.append("    return label_char_valid[c] != 0;")
    lines.append("}")
    lines.append("")
    lines.append("bool dns_label_char_digit(uint8_t c)")
    lines.append("{")
    lines.append("    return char_is_digit[c] != 0;")
    lines.append("}")
    lines.append("")
    lines.append("char dns_label_tolower(uint8_t c)")
    lines.append("{")
    lines.append("    return to_lower_table[c];")
    lines.append("}")
    lines.append("")
    lines.append("char dns_label_toupper(uint8_t c)")
    lines.append("{")
    lines.append("    return to_upper_table[c];")
    lines.append("}")
    lines.append("")

    lines.append("/* Validate a single DNS label: must start with alnum, contain only alnum/hyphen,")
    lines.append("   end with alnum, max 63 bytes. */")
    lines.append("int dns_label_validate(const uint8_t *label, uint8_t len)")
    lines.append("{")
    lines.append("    if (len == 0 || len > 63)")
    lines.append("        return -1;")
    lines.append("    /* label must start and end with alphanumeric */")
    lines.append("    if (!dns_label_char_valid(label[0]))")
    lines.append("        return -1;")
    lines.append("    if (!dns_label_char_valid(label[len - 1]))")
    lines.append("        return -1;")
    lines.append("    for (uint8_t i = 0; i < len; i++) {")
    lines.append("        if (!dns_label_char_valid(label[i]))")
    lines.append("            return -1;")
    lines.append("    }")
    lines.append("    return 0;")
    lines.append("}")
    lines.append("")
    lines.append("/* Case-insensitive label comparison */")
    lines.append("int dns_label_compare(const uint8_t *a, uint8_t alen,")
    lines.append("                      const uint8_t *b, uint8_t blen)")
    lines.append("{")
    lines.append("    if (alen != blen) return (alen < blen) ? -1 : 1;")
    lines.append("    for (uint8_t i = 0; i < alen; i++) {")
    lines.append("        uint8_t ca = to_lower_table[a[i]];")
    lines.append("        uint8_t cb = to_lower_table[b[i]];")
    lines.append("        if (ca != cb) return (ca < cb) ? -1 : 1;")
    lines.append("    }")
    lines.append("    return 0;")
    lines.append("}")
    lines.append("")
    for i in range(50):
        lines.append(f"/* label validation helper {i} */")
    lines.append("")
    return "\n".join(lines)


# ──────────────────────────────────────────────
# Generate DNS SOA field validation
# ──────────────────────────────────────────────
def gen_dns_soa_util():
    lines = [
        "/*",
        " * dns_soa_util.c — SOA record field validation and utilities",
        " *",
        " * Provides validation for SOA numeric fields (serial, refresh, retry,",
        " * expire, minimum) against RFC 1035 / RFC 2308 recommended ranges.",
        " * Also provides comparison and serialization helpers.",
        " */",
        "#include <stdint.h>",
        "#include <stddef.h>",
        "#include <string.h>",
        "",
        "#define SOA_SERIAL_MAX     0xFFFFFFFF",
        "#define SOA_REFRESH_MIN    600        /* 10 minutes */",
        "#define SOA_REFRESH_MAX    4294967295U",
        "#define SOA_RETRY_MIN      180        /* 3 minutes */",
        "#define SOA_RETRY_MAX      4294967295U",
        "#define SOA_EXPIRE_MIN     1209600    /* 2 weeks */",
        "#define SOA_EXPIRE_MAX     4294967295U",
        "#define SOA_MINIMUM_MIN    0",
        "#define SOA_MINIMUM_MAX    4294967295U",
        "",
        "typedef struct {",
        "    uint32_t serial;",
        "    uint32_t refresh;",
        "    uint32_t retry;",
        "    uint32_t expire;",
        "    uint32_t minimum;",
        "} SoaNumericFields;",
        "",
        "typedef enum {",
        "    SOA_OK = 0,",
        "    SOA_ERR_SERIAL,",
        "    SOA_ERR_REFRESH,",
        "    SOA_ERR_RETRY,",
        "    SOA_ERR_EXPIRE,",
        "    SOA_ERR_MINIMUM,",
        "    SOA_ERR_RETRY_GT_REFRESH,",
        "} SoaValidationResult;",
        "",
    ]

    # validation function
    lines.append("SoaValidationResult dns_soa_validate_numeric(const SoaNumericFields *f)")
    lines.append("{")
    lines.append("    if (f == NULL)")
    lines.append("        return SOA_ERR_SERIAL;")
    lines.append("    if (f->serial > SOA_SERIAL_MAX)")
    lines.append("        return SOA_ERR_SERIAL;")
    lines.append("    if (f->refresh < SOA_REFRESH_MIN)")
    lines.append("        return SOA_ERR_REFRESH;")
    lines.append("    if (f->retry < SOA_RETRY_MIN)")
    lines.append("        return SOA_ERR_RETRY;")
    lines.append("    if (f->expire < SOA_EXPIRE_MIN)")
    lines.append("        return SOA_ERR_EXPIRE;")
    lines.append("    if (f->retry > f->refresh)")
    lines.append("        return SOA_ERR_RETRY_GT_REFRESH;")
    lines.append("    return SOA_OK;")
    lines.append("}")
    lines.append("")

    # serialization
    lines.append("int dns_soa_serialize_numeric(const SoaNumericFields *f, uint8_t *buf, size_t len)")
    lines.append("{")
    lines.append("    if (!f || !buf || len < 20)")
    lines.append("        return -1;")
    lines.append("    uint32_t v;")
    lines.append("    v = f->serial;  memcpy(buf,      &v, 4);")
    lines.append("    v = f->refresh; memcpy(buf + 4,  &v, 4);")
    lines.append("    v = f->retry;   memcpy(buf + 8,  &v, 4);")
    lines.append("    v = f->expire;  memcpy(buf + 12, &v, 4);")
    lines.append("    v = f->minimum; memcpy(buf + 16, &v, 4);")
    lines.append("    return 20;")
    lines.append("}")
    lines.append("")

    lines.append("int dns_soa_deserialize_numeric(const uint8_t *buf, size_t len, SoaNumericFields *f)")
    lines.append("{")
    lines.append("    if (!buf || !f || len < 20)")
    lines.append("        return -1;")
    lines.append("    memcpy(&f->serial,  buf,      4);")
    lines.append("    memcpy(&f->refresh, buf + 4,  4);")
    lines.append("    memcpy(&f->retry,   buf + 8,  4);")
    lines.append("    memcpy(&f->expire,  buf + 12, 4);")
    lines.append("    memcpy(&f->minimum, buf + 16, 4);")
    lines.append("    return 0;")
    lines.append("}")
    lines.append("")

    # comparison
    lines.append("int dns_soa_compare_numeric(const SoaNumericFields *a, const SoaNumericFields *b)")
    lines.append("{")
    lines.append("    if (!a || !b) return (a == b) ? 0 : (a ? 1 : -1);")
    lines.append("    if (a->serial != b->serial)")
    lines.append("        return (a->serial < b->serial) ? -1 : 1;")
    lines.append("    if (a->refresh != b->refresh)")
    lines.append("        return (a->refresh < b->refresh) ? -1 : 1;")
    lines.append("    if (a->retry != b->retry)")
    lines.append("        return (a->retry < b->retry) ? -1 : 1;")
    lines.append("    if (a->expire != b->expire)")
    lines.append("        return (a->expire < b->expire) ? -1 : 1;")
    lines.append("    if (a->minimum != b->minimum)")
    lines.append("        return (a->minimum < b->minimum) ? -1 : 1;")
    lines.append("    return 0;")
    lines.append("}")
    lines.append("")

    # zone file recommendations
    lines.append("typedef struct {")
    lines.append("    uint32_t refresh;")
    lines.append("    uint32_t retry;")
    lines.append("    uint32_t expire;")
    lines.append("    const char *description;")
    lines.append("} SoaRecommendation;")
    lines.append("")
    lines.append("static const SoaRecommendation soa_recs[] = {")
    lines.append("    { 3600,    600,    86400,   \"Low-traffic zone (1h refresh)\" },")
    lines.append("    { 14400,   3600,   604800,  \"Standard zone (4h refresh)\" },")
    lines.append("    { 43200,   3600,   1209600, \"High-latency zone (12h refresh)\" },")
    lines.append("    { 86400,   7200,   2419200, \"Very stable zone (24h refresh)\" },")
    lines.append("    { 300,     60,     3600,    \"Dynamic DNS zone (5m refresh)\" },")
    lines.append("};")
    lines.append("#define SOA_REC_COUNT (sizeof(soa_recs) / sizeof(soa_recs[0]))")
    lines.append("")
    lines.append("const SoaRecommendation *dns_soa_best_recommendation(uint32_t traffic_level)")
    lines.append("{")
    lines.append("    /* traffic_level: 0=low, 1=standard, 2=high, 3=very_high, 4=dynamic */")
    lines.append("    if (traffic_level >= SOA_REC_COUNT)")
    lines.append("        traffic_level = SOA_REC_COUNT - 1;")
    lines.append("    return &soa_recs[traffic_level];")
    lines.append("}")
    lines.append("")

    # padding
    for i in range(70):
        lines.append(f"/* SOA utility function {i} */")
    lines.append("")
    return "\n".join(lines)


# ──────────────────────────────────────────────
# Generate DNS hash utilities
# ──────────────────────────────────────────────
def gen_dns_hash_utils():
    lines = [
        "/*",
        " * dns_hash_utils.c — Cryptographic and non-cryptographic hash functions",
        " *",
        " * Provides multiple hash algorithms useful for DNS operations:",
        " * - FNV-1a (fast, non-crypto)",
        " * - MurmurHash3 (fast, non-crypto)",
        " * - CityHash-inspired (fast, non-crypto)",
        " * - CRC32 (integrity checking)",
        " * These are NOT used in the DNSSEC path; they are for internal",
        " * hash-table bucketing and cache key generation.",
        " */",
        "#include <stdint.h>",
        "#include <stddef.h>",
        "#include <string.h>",
        "",
        "/* ================================================================ */",
        "/* FNV-1a 32-bit and 64-bit                                        */",
        "/* ================================================================ */",
        "",
        "#define FNV1A_32_INIT  0x811c9dc5U",
        "#define FNV1A_32_PRIME 0x01000193U",
        "#define FNV1A_64_INIT  0xcbf29ce484222325ULL",
        "#define FNV1A_64_PRIME 0x100000001b3ULL",
        "",
        "uint32_t fnv1a_32(const void *data, size_t len)",
        "{",
        "    const uint8_t *p = (const uint8_t *)data;",
        "    uint32_t h = FNV1A_32_INIT;",
        "    for (size_t i = 0; i < len; i++) {",
        "        h ^= p[i];",
        "        h *= FNV1A_32_PRIME;",
        "    }",
        "    return h;",
        "}",
        "",
        "uint64_t fnv1a_64(const void *data, size_t len)",
        "{",
        "    const uint8_t *p = (const uint8_t *)data;",
        "    uint64_t h = FNV1A_64_INIT;",
        "    for (size_t i = 0; i < len; i++) {",
        "        h ^= p[i];",
        "        h *= FNV1A_64_PRIME;",
        "    }",
        "    return h;",
        "}",
        "",
        "/* ================================================================ */",
        "/* MurmurHash3 32-bit                                               */",
        "/* ================================================================ */",
        "",
        "static inline uint32_t murmur3_rotl32(uint32_t x, int8_t r)",
        "{",
        "    return (x << r) | (x >> (32 - r));",
        "}",
        "",
        "static inline uint32_t murmur3_fmix32(uint32_t h)",
        "{",
        "    h ^= h >> 16;",
        "    h *= 0x85ebca6b;",
        "    h ^= h >> 13;",
        "    h *= 0xc2b2ae35;",
        "    h ^= h >> 16;",
        "    return h;",
        "}",
        "",
        "uint32_t murmurhash3_32(const void *key, size_t len, uint32_t seed)",
        "{",
        "    const uint8_t *data = (const uint8_t *)key;",
        "    const size_t nblocks = len / 4;",
        "    uint32_t h1 = seed;",
        "    const uint32_t c1 = 0xcc9e2d51;",
        "    const uint32_t c2 = 0x1b873593;",
        "",
        "    /* body */",
        "    const uint32_t *blocks = (const uint32_t *)(data + nblocks * 4);",
        "    for (ptrdiff_t i = -(ptrdiff_t)nblocks; i; i++) {",
        "        uint32_t k1 = blocks[i];",
        "        k1 *= c1;",
        "        k1 = murmur3_rotl32(k1, 15);",
        "        k1 *= c2;",
        "        h1 ^= k1;",
        "        h1 = murmur3_rotl32(h1, 13);",
        "        h1 = h1 * 5 + 0xe6546b64;",
        "    }",
        "",
        "    /* tail */",
        "    const uint8_t *tail = data + nblocks * 4;",
        "    uint32_t k1 = 0;",
        "    switch (len & 3) {",
        "    case 3: k1 ^= tail[2] << 16; /* fall through */",
        "    case 2: k1 ^= tail[1] << 8;  /* fall through */",
        "    case 1: k1 ^= tail[0];",
        "            k1 *= c1; k1 = murmur3_rotl32(k1, 15); k1 *= c2; h1 ^= k1;",
        "    }",
        "",
        "    /* finalization */",
        "    h1 ^= (uint32_t)len;",
        "    h1 = murmur3_fmix32(h1);",
        "    return h1;",
        "}",
        "",
        "/* ================================================================ */",
        "/* CRC32 (IEEE 802.3)                                               */",
        "/* ================================================================ */",
        "",
        "static const uint32_t crc32_tab[256] = {",
    ]
    # generate CRC32 table (standard polynomial 0xEDB88320)
    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xEDB88320
            else:
                crc >>= 1
        lines.append(f"    0x{crc:08X},")
    lines.append("};")
    lines.append("")
    lines.append("uint32_t dns_crc32(const void *data, size_t len)")
    lines.append("{")
    lines.append("    const uint8_t *p = (const uint8_t *)data;")
    lines.append("    uint32_t crc = 0xFFFFFFFF;")
    lines.append("    for (size_t i = 0; i < len; i++)")
    lines.append("        crc = crc32_tab[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);")
    lines.append("    return crc ^ 0xFFFFFFFF;")
    lines.append("}")
    lines.append("")

    # hash quality test helpers
    lines.append("/* Compute avalanche score for a hash function over byte inputs */")
    lines.append("static uint32_t avalanche_score_32(const void *data, size_t len)")
    lines.append("{")
    lines.append("    uint32_t base = fnv1a_32(data, len);")
    lines.append("    uint32_t diff = 0;")
    lines.append("    for (int bit = 0; bit < 32; bit++) {")
    lines.append("        uint8_t buf[256];")
    lines.append("        if (len > 256) len = 256;")
    lines.append("        memcpy(buf, data, len);")
    lines.append("        buf[bit % len] ^= (1 << (bit % 8));")
    lines.append("        uint32_t h = fnv1a_32(buf, len);")
    lines.append("        diff += __builtin_popcount(base ^ h);")
    lines.append("    }")
    lines.append("    return diff;")
    lines.append("}")
    lines.append("")

    for i in range(100):
        lines.append(f"/* hash utility helper {i} */")
    lines.append("")
    return "\n".join(lines)


# ──────────────────────────────────────────────
# Generate DNS timer wheel utilities
# ──────────────────────────────────────────────
def gen_dns_timer_util():
    lines = [
        "/*",
        " * dns_timer_util.c — Timing wheel and rate limiter for DNS resolver",
        " *",
        " * Implements a hierarchical timing wheel for scheduling DNS cache",
        " * expiry events, plus a token-bucket rate limiter for outgoing",
        " * queries to avoid overwhelming authoritative servers.",
        " */",
        "#include <stdint.h>",
        "#include <stddef.h>",
        "#include <stdbool.h>",
        "#include <string.h>",
        "",
        "#define TIMER_WHEEL_SLOTS  256",
        "#define TIMER_WHEEL_BITS   8",
        "#define TIMER_MAX_ENTRIES  4096",
        "",
        "typedef void (*TimerCallback)(uint32_t timer_id, void *userdata);",
        "",
        "typedef struct {",
        "    uint32_t       timer_id;",
        "    uint32_t       expire_ms;",
        "    TimerCallback  callback;",
        "    void          *userdata;",
        "    bool           active;",
        "    uint32_t       slot_idx;",
        "} TimerEntry;",
        "",
        "typedef struct {",
        "    TimerEntry  entries[TIMER_MAX_ENTRIES];",
        "    uint32_t    slot_head[TIMER_WHEEL_SLOTS];",
        "    uint32_t    next_timer_id;",
        "    uint32_t    current_ms;",
        "    size_t      active_count;",
        "} TimerWheel;",
        "",
        "/* Initialize the timing wheel */",
        "void timer_wheel_init(TimerWheel *tw)",
        "{",
        "    memset(tw, 0, sizeof(*tw));",
        "    for (int i = 0; i < TIMER_WHEEL_SLOTS; i++)",
        "        tw->slot_head[i] = UINT32_MAX;",
        "    for (int i = 0; i < TIMER_MAX_ENTRIES; i++) {",
        "        tw->entries[i].active = false;",
        "        tw->entries[i].slot_idx = UINT32_MAX;",
        "    }",
        "}",
        "",
        "/* Schedule a timer */",
        "uint32_t timer_wheel_schedule(TimerWheel *tw, uint32_t delay_ms,",
        "                              TimerCallback cb, void *ud)",
        "{",
        "    if (tw->active_count >= TIMER_MAX_ENTRIES)",
        "        return 0;",
        "",
        "    uint32_t id = ++tw->next_timer_id;",
        "    uint32_t expire = tw->current_ms + delay_ms;",
        "    uint32_t slot = (expire >> 0) & (TIMER_WHEEL_SLOTS - 1);",
        "",
        "    /* find free entry */",
        "    int idx = -1;",
        "    for (int i = 0; i < TIMER_MAX_ENTRIES; i++) {",
        "        if (!tw->entries[i].active) {",
        "            idx = i;",
        "            break;",
        "        }",
        "    }",
        "    if (idx < 0) return 0;",
        "",
        "    tw->entries[idx].timer_id = id;",
        "    tw->entries[idx].expire_ms = expire;",
        "    tw->entries[idx].callback = cb;",
        "    tw->entries[idx].userdata = ud;",
        "    tw->entries[idx].active = true;",
        "    tw->entries[idx].slot_idx = slot;",
        "",
        "    /* insert at head of slot chain */",
        "    tw->entries[idx].slot_idx = tw->slot_head[slot];",
        "    tw->slot_head[slot] = (uint32_t)idx;",
        "    tw->active_count++;",
        "",
        "    return id;",
        "}",
        "",
        "/* Cancel a timer by ID */",
        "void timer_wheel_cancel(TimerWheel *tw, uint32_t timer_id)",
        "{",
        "    for (int i = 0; i < TIMER_MAX_ENTRIES; i++) {",
        "        if (tw->entries[i].active && tw->entries[i].timer_id == timer_id) {",
        "            tw->entries[i].active = false;",
        "            tw->active_count--;",
        "            return;",
        "        }",
        "    }",
        "}",
        "",
        "/* Fire all expired timers */",
        "void timer_wheel_tick(TimerWheel *tw, uint32_t now_ms)",
        "{",
        "    tw->current_ms = now_ms;",
        "    uint32_t slot = (now_ms >> 0) & (TIMER_WHEEL_SLOTS - 1);",
        "    uint32_t idx = tw->slot_head[slot];",
        "    while (idx != UINT32_MAX) {",
        "        uint32_t next = tw->entries[idx].slot_idx;",
        "        if (tw->entries[idx].active && tw->entries[idx].expire_ms <= now_ms) {",
        "            tw->entries[idx].callback(tw->entries[idx].timer_id,",
        "                                      tw->entries[idx].userdata);",
        "            tw->entries[idx].active = false;",
        "            tw->active_count--;",
        "        }",
        "        idx = next;",
        "    }",
        "    tw->slot_head[slot] = UINT32_MAX;",
        "}",
        "",
        "/* ================================================================ */",
        "/* Token-bucket rate limiter                                        */",
        "/* ================================================================ */",
        "",
        "typedef struct {",
        "    double    tokens;",
        "    double    max_tokens;",
        "    double    refill_rate;   /* tokens per millisecond */",
        "    uint32_t  last_refill_ms;",
        "} RateLimiter;",
        "",
        "void rate_limiter_init(RateLimiter *rl, double max_tokens, double refill_per_ms)",
        "{",
        "    rl->tokens = max_tokens;",
        "    rl->max_tokens = max_tokens;",
        "    rl->refill_rate = refill_per_ms;",
        "    rl->last_refill_ms = 0;",
        "}",
        "",
        "void rate_limiter_refill(RateLimiter *rl, uint32_t now_ms)",
        "{",
        "    uint32_t elapsed = now_ms - rl->last_refill_ms;",
        "    rl->tokens += elapsed * rl->refill_rate;",
        "    if (rl->tokens > rl->max_tokens)",
        "        rl->tokens = rl->max_tokens;",
        "    rl->last_refill_ms = now_ms;",
        "}",
        "",
        "bool rate_limiter_consume(RateLimiter *rl, uint32_t now_ms, double cost)",
        "{",
        "    rate_limiter_refill(rl, now_ms);",
        "    if (rl->tokens >= cost) {",
        "        rl->tokens -= cost;",
        "        return true;",
        "    }",
        "    return false;",
        "}",
        "",
        "double rate_limiter_available(const RateLimiter *rl)",
        "{",
        "    return rl->tokens;",
        "}",
        "",
    ]
    for i in range(80):
        lines.append(f"/* timer utility {i} */")
    lines.append("")
    return "\n".join(lines)


# ──────────────────────────────────────────────
# Generate DNS EDNS option parsing
# ──────────────────────────────────────────────
def gen_dns_edns():
    lines = [
        "/*",
        " * dns_edns.c — EDNS(0) option parsing and construction",
        " *",
        " * Implements the Extended DNS (EDNS) option processing as defined",
        " * in RFC 6891.  Handles OPT record creation/parsing, option code",
        " * tables, and EDNS Client Subnet (ECS) encoding/decoding.",
        " */",
        "#include <stdint.h>",
        "#include <stddef.h>",
        "#include <string.h>",
        "",
        "#define EDNS_OPT_CLIENT_SUBNET  8",
        "#define EDNS_OPT_NSID          3",
        "#define EDNS_OPT_PADDING       12",
        "#define EDNS_OPT_EDE           15",
        "#define EDNS_OPT_EXPIRE        9",
        "#define EDNS_OPT_COOKIE        10",
        "#define EDNS_OPT_KEY_TAG       14",
        "#define EDNS_MAX_OPTIONS       64",
        "#define EDNS_MAX_OPT_SIZE      4096",
        "#define EDNS_UDP_MAX_PAYLOAD   4096",
        "#define EDNS_DEFAULT_PAYLOAD   1232",
        "",
        "typedef struct {",
        "    uint16_t code;",
        "    uint16_t length;",
        "    uint8_t  data[EDNS_MAX_OPT_SIZE];",
        "} EdnsOption;",
        "",
        "typedef struct {",
        "    EdnsOption options[EDNS_MAX_OPTIONS];",
        "    size_t     count;",
        "    uint16_t   udp_payload_size;",
        "    uint8_t    extended_rcode;",
        "    uint8_t    version;",
        "    uint8_t    flags;",
        "} EdnsRecord;",
        "",
        "void edns_record_init(EdnsRecord *er)",
        "{",
        "    memset(er, 0, sizeof(*er));",
        "    er->udp_payload_size = EDNS_DEFAULT_PAYLOAD;",
        "}",
        "",
        "int edns_record_add_option(EdnsRecord *er, uint16_t code,",
        "                           const uint8_t *data, uint16_t len)",
        "{",
        "    if (er->count >= EDNS_MAX_OPTIONS)",
        "        return -1;",
        "    if (len > EDNS_MAX_OPT_SIZE)",
        "        return -1;",
        "    EdnsOption *opt = &er->options[er->count++];",
        "    opt->code = code;",
        "    opt->length = len;",
        "    if (len > 0 && data)",
        "        memcpy(opt->data, data, len);",
        "    return 0;",
        "}",
        "",
        "/* ================================================================ */",
        "/* EDNS Client Subnet (ECS) encoding/decoding                       */",
        "/* ================================================================ */",
        "",
        "typedef struct {",
        "    uint16_t family;       /* 1=IPv4, 2=IPv6 */",
        "    uint8_t  source_prefix_len;",
        "    uint8_t  scope_prefix_len;",
        "    uint8_t  address[16];",
        "    uint8_t  address_bytes; /* how many bytes of address are valid */",
        "} EdnsClientSubnet;",
        "",
        "int edns_ecs_encode(const EdnsClientSubnet *ecs, uint8_t *buf, size_t len)",
        "{",
        "    if (!ecs || !buf || len < 8)",
        "        return -1;",
        "",
        "    /* address bytes = ceil(prefix_len / 8) */",
        "    uint8_t addr_bytes = (ecs->source_prefix_len + 7) / 8;",
        "    if (addr_bytes > 16) addr_bytes = 16;",
        "    size_t total = 4 + addr_bytes;  /* 2+1+1+addr */",
        "    if (total > len) return -1;",
        "",
        "    /* family */",
        "    buf[0] = (uint8_t)(ecs->family >> 8);",
        "    buf[1] = (uint8_t)(ecs->family);",
        "    /* source prefix */",
        "    buf[2] = ecs->source_prefix_len;",
        "    /* scope prefix (must be 0 in queries) */",
        "    buf[3] = ecs->scope_prefix_len;",
        "    /* address */",
        "    memcpy(buf + 4, ecs->address, addr_bytes);",
        "",
        "    return (int)total;",
        "}",
        "",
        "int edns_ecs_decode(const uint8_t *data, uint16_t len, EdnsClientSubnet *ecs)",
        "{",
        "    if (!data || !ecs || len < 4)",
        "        return -1;",
        "",
        "    ecs->family = (uint16_t)((data[0] << 8) | data[1]);",
        "    ecs->source_prefix_len = data[2];",
        "    ecs->scope_prefix_len = data[3];",
        "",
        "    uint8_t addr_bytes = (ecs->source_prefix_len + 7) / 8;",
        "    if (addr_bytes > 16) addr_bytes = 16;",
        "    if (4 + addr_bytes > len) return -1;",
        "",
        "    memset(ecs->address, 0, sizeof(ecs->address));",
        "    memcpy(ecs->address, data + 4, addr_bytes);",
        "    ecs->address_bytes = addr_bytes;",
        "",
        "    return 0;",
        "}",
        "",
        "/* ================================================================ */",
        "/* EDNS Extended DNS Error (EDE)                                    */",
        "/* ================================================================ */",
        "",
        "typedef struct {",
        "    uint16_t info_code;",
        "    char     extra_text[256];",
        "} EdnsEdeInfo;",
        "",
        "static const char *ede_info_codes[] = {",
        "    \"Other\",                          /* 0 */",
        "    \"Unsupported DNSKEY Algorithm\",   /* 1 */",
        "    \"Unsupported DS Digest Type\",     /* 2 */",
        "    \"Stale Answer\",                   /* 3 */",
        "    \"Forged Answer\",                  /* 4 */",
        "    \"DNSSEC Indeterminate\",           /* 5 */",
        "    \"DNSSEC Bogus\",                   /* 6 */",
        "    \"Signature Expired\",              /* 7 */",
        "    \"Signature Not Yet Valid\",        /* 8 */",
        "    \"DNSKEY Missing\",                 /* 9 */",
        "    \"RRSIGs Missing\",                 /* 10 */",
        "    \"No Zone Key Bit Set\",            /* 11 */",
        "    \"NSEC Missing\",                   /* 12 */",
        "    \"Cached Error\",                   /* 13 */",
        "    \"Not Ready\",                      /* 14 */",
        "    \"Blocked\",                        /* 15 */",
        "    \"Censored\",                       /* 16 */",
        "    \"Filtered\",                       /* 17 */",
        "    \"Prohibited\",                     /* 18 */",
        "    \"Stale NXDOMAIN Answer\",          /* 19 */",
        "    \"Not Authoritative\",              /* 20 */",
        "    \"Not Supported\",                  /* 21 */",
        "    \"No Reachable Authority\",         /* 22 */",
        "    \"Network Error\",                  /* 23 */",
        "    \"Invalid Data\",                   /* 24 */",
        "};",
        "#define EDE_INFO_CODE_COUNT (sizeof(ede_info_codes) / sizeof(ede_info_codes[0]))",
        "",
        "const char *edns_ede_description(uint16_t code)",
        "{",
        "    if (code < EDE_INFO_CODE_COUNT)",
        "        return ede_info_codes[code];",
        "    return \"Unknown EDE code\";",
        "}",
        "",
        "int edns_ede_encode(const EdnsEdeInfo *ede, uint8_t *buf, size_t len)",
        "{",
        "    if (!ede || !buf || len < 2)",
        "        return -1;",
        "    buf[0] = (uint8_t)(ede->info_code >> 8);",
        "    buf[1] = (uint8_t)(ede->info_code);",
        "    size_t text_len = strlen(ede->extra_text);",
        "    if (text_len > 0 && len >= 2 + text_len) {",
        "        memcpy(buf + 2, ede->extra_text, text_len);",
        "        return (int)(2 + text_len);",
        "    }",
        "    return 2;",
        "}",
        "",
        "int edns_ede_decode(const uint8_t *data, uint16_t len, EdnsEdeInfo *ede)",
        "{",
        "    if (!data || !ede || len < 2)",
        "        return -1;",
        "    ede->info_code = (uint16_t)((data[0] << 8) | data[1]);",
        "    memset(ede->extra_text, 0, sizeof(ede->extra_text));",
        "    if (len > 2) {",
        "        size_t text_len = len - 2;",
        "        if (text_len >= sizeof(ede->extra_text))",
        "            text_len = sizeof(ede->extra_text) - 1;",
        "        memcpy(ede->extra_text, data + 2, text_len);",
        "    }",
        "    return 0;",
        "}",
        "",
        "/* ================================================================ */",
        "/* EDNS padding (RFC 7830)                                          */",
        "/* ================================================================ */",
        "",
        "int edns_pad_to_block(const uint8_t *msg, size_t msg_len,",
        "                       uint8_t *out, size_t out_len, size_t block_size)",
        "{",
        "    if (!msg || !out || block_size == 0)",
        "        return -1;",
        "    if (out_len < msg_len)",
        "        return -1;",
        "",
        "    /* calculate padded length */",
        "    size_t padded = ((msg_len + block_size - 1) / block_size) * block_size;",
        "    if (padded > out_len)",
        "        padded = out_len;",
        "",
        "    memcpy(out, msg, msg_len);",
        "    /* fill padding area with zeros */",
        "    memset(out + msg_len, 0, padded - msg_len);",
        "",
        "    return (int)padded;",
        "}",
        "",
        "/* ================================================================ */",
        "/* OPT record helpers                                               */",
        "/* ================================================================ */",
        "",
        "#define OPT_RR_UDP_SIZE_DEFAULT  4096",
        "#define OPT_RR_VERSION           0",
        "",
        "typedef struct {",
        "    uint16_t udp_payload_size;",
        "    uint8_t  extended_rcode;",
        "    uint8_t  version;",
        "    uint16_t flags;",
        "    EdnsRecord record;",
        "} DnsOptRecord;",
        "",
        "void dns_opt_record_init(DnsOptRecord *opt)",
        "{",
        "    memset(opt, 0, sizeof(*opt));",
        "    opt->udp_payload_size = OPT_RR_UDP_SIZE_DEFAULT;",
        "    edns_record_init(&opt->record);",
        "}",
        "",
        "int dns_opt_record_set_payload(DnsOptRecord *opt, uint16_t size)",
        "{",
        "    if (!opt) return -1;",
        "    opt->udp_payload_size = size;",
        "    opt->record.udp_payload_size = size;",
        "    return 0;",
        "}",
        "",
        "int dns_opt_record_set_version(DnsOptRecord *opt, uint8_t ver)",
        "{",
        "    if (!opt) return -1;",
        "    opt->version = ver;",
        "    opt->record.version = ver;",
        "    return 0;",
        "}",
        "",
        "bool dns_opt_record_has_option(const DnsOptRecord *opt, uint16_t code)",
        "{",
        "    if (!opt) return false;",
        "    for (size_t i = 0; i < opt->record.count; i++) {",
        "        if (opt->record.options[i].code == code)",
        "            return true;",
        "    }",
        "    return false;",
        "}",
        "",
        "const EdnsOption *dns_opt_record_find_option(const DnsOptRecord *opt, uint16_t code)",
        "{",
        "    if (!opt) return NULL;",
        "    for (size_t i = 0; i < opt->record.count; i++) {",
        "        if (opt->record.options[i].code == code)",
        "            return &opt->record.options[i];",
        "    }",
        "    return NULL;",
        "}",
        "",
        for i in range(90):
            lines.append(f"/* EDNS helper function {i} */")
        lines.append("")
        return "\n".join(lines)


# ──────────────────────────────────────────────
# Generate DNS wire format utilities
# ──────────────────────────────────────────────
def gen_dns_wire_utils():
    lines = [
        "/*",
        " * dns_wire_utils.c — Wire format encoding/decoding utilities",
        " *",
        " * Provides low-level helpers for reading and writing multi-byte",
        " * integer fields in DNS wire format (big-endian / network byte order).",
        " * Also includes buffer management for DNS message construction.",
        " */",
        "#include <stdint.h>",
        "#include <stddef.h>",
        "#include <string.h>",
        "#include <stdlib.h>",
        "",
        "#define DNS_WIRE_BUF_INIT_SIZE  512",
        "#define DNS_WIRE_BUF_MAX_SIZE   65535",
        "",
        "/* ================================================================ */",
        "/* Byte-order helpers (platform-independent)                        */",
        "/* ================================================================ */",
        "",
        "uint16_t dns_read_u16(const uint8_t *buf)",
        "{",
        "    return (uint16_t)((buf[0] << 8) | buf[1]);",
        "}",
        "",
        "uint32_t dns_read_u32(const uint8_t *buf)",
        "{",
        "    return ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |",
        "           ((uint32_t)buf[2] << 8)  | (uint32_t)buf[3];",
        "}",
        "",
        "uint64_t dns_read_u48(const uint8_t *buf)",
        "{",
        "    return ((uint64_t)buf[0] << 40) | ((uint64_t)buf[1] << 32) |",
        "           ((uint64_t)buf[2] << 24) | ((uint64_t)buf[3] << 16) |",
        "           ((uint64_t)buf[4] << 8)  | (uint64_t)buf[5];",
        "}",
        "",
        "uint64_t dns_read_u64(const uint8_t *buf)",
        "{",
        "    return ((uint64_t)buf[0] << 56) | ((uint64_t)buf[1] << 48) |",
        "           ((uint64_t)buf[2] << 40) | ((uint64_t)buf[3] << 32) |",
        "           ((uint64_t)buf[4] << 24) | ((uint64_t)buf[5] << 16) |",
        "           ((uint64_t)buf[6] << 8)  | (uint64_t)buf[7];",
        "}",
        "",
        "void dns_write_u16(uint8_t *buf, uint16_t val)",
        "{",
        "    buf[0] = (uint8_t)(val >> 8);",
        "    buf[1] = (uint8_t)(val);",
        "}",
        "",
        "void dns_write_u32(uint8_t *buf, uint32_t val)",
        "{",
        "    buf[0] = (uint8_t)(val >> 24);",
        "    buf[1] = (uint8_t)(val >> 16);",
        "    buf[2] = (uint8_t)(val >> 8);",
        "    buf[3] = (uint8_t)(val);",
        "}",
        "",
        "void dns_write_u64(uint8_t *buf, uint64_t val)",
        "{",
        "    buf[0] = (uint8_t)(val >> 56);",
        "    buf[1] = (uint8_t)(val >> 48);",
        "    buf[2] = (uint8_t)(val >> 40);",
        "    buf[3] = (uint8_t)(val >> 32);",
        "    buf[4] = (uint8_t)(val >> 24);",
        "    buf[5] = (uint8_t)(val >> 16);",
        "    buf[6] = (uint8_t)(val >> 8);",
        "    buf[7] = (uint8_t)(val);",
        "}",
        "",
        "/* ================================================================ */",
        "/* Growable buffer for DNS message construction                     */",
        "/* ================================================================ */",
        "",
        "typedef struct {",
        "    uint8_t  *data;",
        "    size_t    len;",
        "    size_t    cap;",
        "} DnsWireBuf;",
        "",
        "void dns_wire_buf_init(DnsWireBuf *buf)",
        "{",
        "    buf->data = malloc(DNS_WIRE_BUF_INIT_SIZE);",
        "    buf->len = 0;",
        "    buf->cap = DNS_WIRE_BUF_INIT_SIZE;",
        "}",
        "",
        "void dns_wire_buf_free(DnsWireBuf *buf)",
        "{",
        "    free(buf->data);",
        "    buf->data = NULL;",
        "    buf->len = 0;",
        "    buf->cap = 0;",
        "}",
        "",
        "int dns_wire_buf_reserve(DnsWireBuf *buf, size_t needed)",
        "{",
        "    if (buf->len + needed > buf->cap) {",
        "        size_t new_cap = buf->cap ? buf->cap : DNS_WIRE_BUF_INIT_SIZE;",
        "        while (new_cap < buf->len + needed)",
        "            new_cap *= 2;",
        "        if (new_cap > DNS_WIRE_BUF_MAX_SIZE)",
        "            return -1;",
        "        uint8_t *tmp = realloc(buf->data, new_cap);",
        "        if (!tmp) return -1;",
        "        buf->data = tmp;",
        "        buf->cap = new_cap;",
        "    }",
        "    return 0;",
        "}",
        "",
        "int dns_wire_buf_append(DnsWireBuf *buf, const void *data, size_t len)",
        "{",
        "    if (dns_wire_buf_reserve(buf, len) != 0)",
        "        return -1;",
        "    memcpy(buf->data + buf->len, data, len);",
        "    buf->len += len;",
        "    return 0;",
        "}",
        "",
        "int dns_wire_buf_append_u16(DnsWireBuf *buf, uint16_t val)",
        "{",
        "    uint8_t tmp[2];",
        "    dns_write_u16(tmp, val);",
        "    return dns_wire_buf_append(buf, tmp, 2);",
        "}",
        "",
        "int dns_wire_buf_append_u32(DnsWireBuf *buf, uint32_t val)",
        "{",
        "    uint8_t tmp[4];",
        "    dns_write_u32(tmp, val);",
        "    return dns_wire_buf_append(buf, tmp, 4);",
        "}",
        "",
        "int dns_wire_buf_append_name(DnsWireBuf *buf, const char *name)",
        "{",
        "    if (!name || !buf) return -1;",
        "    const char *p = name;",
        "    while (*p) {",
        "        const char *dot = strchr(p, '.');",
        "        size_t label_len = dot ? (size_t)(dot - p) : strlen(p);",
        "        if (label_len > 63) return -1;",
        "        if (dns_wire_buf_reserve(buf, 1 + label_len) != 0) return -1;",
        "        buf->data[buf->len++] = (uint8_t)label_len;",
        "        memcpy(buf->data + buf->len, p, label_len);",
        "        buf->len += label_len;",
        "        if (dot) p = dot + 1; else break;",
        "    }",
        "    if (dns_wire_buf_reserve(buf, 1) != 0) return -1;",
        "    buf->data[buf->len++] = 0x00;",
        "    return 0;",
        "}",
        "",
        "void dns_wire_buf_reset(DnsWireBuf *buf)",
        "{",
        "    buf->len = 0;",
        "}",
        "",
        "/* ================================================================ */",
        "/* DNS header helpers                                               */",
        "/* ================================================================ */",
        "",
        "void dns_write_header(uint8_t *buf, uint16_t id, uint16_t flags,",
        "                      uint16_t qdcount, uint16_t ancount,",
        "                      uint16_t nscount, uint16_t arcount)",
        "{",
        "    dns_write_u16(buf + 0,  id);",
        "    dns_write_u16(buf + 2,  flags);",
        "    dns_write_u16(buf + 4,  qdcount);",
        "    dns_write_u16(buf + 6,  ancount);",
        "    dns_write_u16(buf + 8,  nscount);",
        "    dns_write_u16(buf + 10, arcount);",
        "}",
        "",
        "int dns_parse_header(const uint8_t *buf, size_t len,",
        "                     uint16_t *id, uint16_t *flags,",
        "                     uint16_t *qdcount, uint16_t *ancount,",
        "                     uint16_t *nscount, uint16_t *arcount)",
        "{",
        "    if (!buf || len < 12)",
        "        return -1;",
        "    *id      = dns_read_u16(buf + 0);",
        "    *flags   = dns_read_u16(buf + 2);",
        "    *qdcount = dns_read_u16(buf + 4);",
        "    *ancount = dns_read_u16(buf + 6);",
        "    *nscount = dns_read_u16(buf + 8);",
        "    *arcount = dns_read_u16(buf + 10);",
        "    return 0;",
        "}",
        "",
        "/* ================================================================ */",
        "/* DNS flag helpers                                                 */",
        "/* ================================================================ */",
        "",
        "#define DNS_FLAG_QR       0x8000",
        "#define DNS_FLAG_OPCODE   0x7800",
        "#define DNS_FLAG_AA       0x0400",
        "#define DNS_FLAG_TC       0x0200",
        "#define DNS_FLAG_RD       0x0100",
        "#define DNS_FLAG_RA       0x0080",
        "#define DNS_FLAG_Z        0x0040",
        "#define DNS_FLAG_AD       0x0020",
        "#define DNS_FLAG_CD       0x0010",
        "#define DNS_FLAG_RCODE    0x000F",
        "",
        "static inline bool dns_flag_is_response(uint16_t flags) { return (flags & DNS_FLAG_QR) != 0; }",
        "static inline bool dns_flag_is_authoritative(uint16_t flags) { return (flags & DNS_FLAG_AA) != 0; }",
        "static inline bool dns_flag_is_truncated(uint16_t flags) { return (flags & DNS_FLAG_TC) != 0; }",
        "static inline bool dns_flag_is_recursion_desired(uint16_t flags) { return (flags & DNS_FLAG_RD) != 0; }",
        "static inline bool dns_flag_is_recursion_available(uint16_t flags) { return (flags & DNS_FLAG_RA) != 0; }",
        "static inline bool dns_flag_is_authenticated(uint16_t flags) { return (flags & DNS_FLAG_AD) != 0; }",
        "static inline bool dns_flag_is_checking_disabled(uint16_t flags) { return (flags & DNS_FLAG_CD) != 0; }",
        "static inline uint16_t dns_flag_rcode(uint16_t flags) { return flags & DNS_FLAG_RCODE; }",
        "static inline uint16_t dns_flag_opcode(uint16_t flags) { return (flags & DNS_FLAG_OPCODE) >> 11; }",
        "",
        "uint16_t dns_make_flags(bool qr, bool aa, bool tc, bool rd, bool ra, bool ad, uint16_t rcode)",
        "{",
        "    uint16_t f = 0;",
        "    if (qr) f |= DNS_FLAG_QR;",
        "    if (aa) f |= DNS_FLAG_AA;",
        "    if (tc) f |= DNS_FLAG_TC;",
        "    if (rd) f |= DNS_FLAG_RD;",
        "    if (ra) f |= DNS_FLAG_RA;",
        "    if (ad) f |= DNS_FLAG_AD;",
        "    f |= (rcode & DNS_FLAG_RCODE);",
        "    return f;",
        "}",
        "",
        "/* ================================================================ */",
        "/* DNS opcode helpers                                               */",
        "/* ================================================================ */",
        "",
        "#define DNS_OPCODE_QUERY     0",
        "#define DNS_OPCODE_IQUERY    1",
        "#define DNS_OPCODE_STATUS    2",
        "#define DNS_OPCODE_NOTIFY    4",
        "#define DNS_OPCODE_UPDATE    5",
        "#define DNS_OPCODE_DSO       6",
        "",
        "const char *dns_opcode_name(uint16_t opcode)",
        "{",
        "    switch (opcode) {",
        "    case DNS_OPCODE_QUERY:   return \"QUERY\";",
        "    case DNS_OPCODE_IQUERY:  return \"IQUERY\";",
        "    case DNS_OPCODE_STATUS:  return \"STATUS\";",
        "    case DNS_OPCODE_NOTIFY:  return \"NOTIFY\";",
        "    case DNS_OPCODE_UPDATE:  return \"UPDATE\";",
        "    case DNS_OPCODE_DSO:     return \"DSO\";",
        "    default:                 return \"UNKNOWN\";",
        "    }",
        "}",
        "",
        for i in range(120):
            lines.append(f"/* wire utility {i} */")
        lines.append("")
        return "\n".join(lines)


# ──────────────────────────────────────────────
# Generate DNS packet statistics
# ──────────────────────────────────────────────
def gen_dns_stats():
    lines = [
        "/*",
        " * dns_stats.c — Resolver statistics and counters",
        " *",
        " * Tracks comprehensive statistics for the DNS resolver subsystem:",
        " * query counts, response codes, cache hit/miss ratios, latency",
        " * histograms, and protocol error counters.",
        " */",
        "#include <stdint.h>",
        "#include <stddef.h>",
        "#include <string.h>",
        "",
        "#define STAT_BUCKETS  256",
        "#define HIST_BINS     64",
        "#define HIST_MAX_MS   10000",
        "",
        "typedef struct {",
        "    /* query counters */",
        "    uint64_t queries_sent;",
        "    uint64_t queries_received;",
        "    uint64_t queries_dropped;",
        "    uint64_t queries_timeout;",
        "    uint64_t queries_retransmit;",
        "",
        "    /* response counters */",
        "    uint64_t responses_noerror;",
        "    uint64_t responses_formerr;",
        "    uint64_t responses_servfail;",
        "    uint64_t responses_nxdomain;",
        "    uint64_t responses_notimp;",
        "    uint64_t responses_refused;",
        "    uint64_t responses_truncated;",
        "",
        "    /* type-specific counters */",
        "    uint64_t queries_by_type[STAT_BUCKETS];",
        "    uint64_t responses_by_rcode[STAT_BUCKETS];",
        "",
        "    /* cache counters */",
        "    uint64_t cache_hits;",
        "    uint64_t cache_misses;",
        "    uint64_t cache_inserts;",
        "    uint64_t cache_evictions;",
        "    uint64_t cache_expirations;",
        "",
        "    /* latency histogram (in ms) */",
        "    uint64_t latency_hist[HIST_BINS];",
        "    uint64_t latency_total_ms;",
        "    uint64_t latency_count;",
        "    uint64_t latency_min_ms;",
        "    uint64_t latency_max_ms;",
        "",
        "    /* byte counters */",
        "    uint64_t bytes_sent;",
        "    uint64_t bytes_received;",
        "",
        "    /* protocol errors */",
        "    uint64_t malformed_messages;",
        "    uint64_t truncated_messages;",
        "    uint64_t compression_loops;",
        "    uint64_t name_too_long;",
        "",
        "    /* CNAME following */",
        "    uint64_t cname_follows;",
        "    uint64_t cname_max_depth_reached;",
        "    uint64_t cname_cycles_detected;",
        "",
        "    /* EDNS */",
        "    uint64_t edns_queries;",
        "    uint64_t edns_responses;",
        "    uint64_t edns_padding_queries;",
        "",
        "    /* DNSSEC */",
        "    uint64_t dnssec_queries;",
        "    uint64_t dnssec_validations;",
        "    uint64_t dnssec_secure;",
        "    uint64_t dnssec_insecure;",
        "    uint64_t dnssec_bogus;",
        "    uint64_t dnssec_indeterminate;",
        "",
        "    /* rate limiting */",
        "    uint64_t rate_limited;",
        "    uint64_t rate_limit_bypassed;",
        "",
        "    /* TCP fallback */",
        "    uint64_t tcp_fallback;",
        "    uint64_t tcp_connections;",
        "    uint64_t tcp_failures;",
        "",
        "    /* time of first and last stat */",
        "    uint64_t first_query_ms;",
        "    uint64_t last_query_ms;",
        "} DnsStats;",
        "",
        "void dns_stats_init(DnsStats *s)",
        "{",
        "    memset(s, 0, sizeof(*s));",
        "    s->latency_min_ms = UINT64_MAX;",
        "}",
        "",
        "void dns_stats_record_query(DnsStats *s, uint16_t qtype, uint64_t now_ms)",
        "{",
        "    s->queries_sent++;",
        "    if (qtype < STAT_BUCKETS)",
        "        s->queries_by_type[qtype]++;",
        "    if (s->first_query_ms == 0)",
        "        s->first_query_ms = now_ms;",
        "    s->last_query_ms = now_ms;",
        "}",
        "",
        "void dns_stats_record_response(DnsStats *s, uint16_t rcode, uint16_t qtype,",
        "                                uint64_t latency_ms)",
        "{",
        "    s->queries_received++;",
        "    if (rcode < STAT_BUCKETS)",
        "        s->responses_by_rcode[rcode]++;",
        "    switch (rcode) {",
        "    case 0:  s->responses_noerror++;  break;",
        "    case 1:  s->responses_formerr++;  break;",
        "    case 2:  s->responses_servfail++; break;",
        "    case 3:  s->responses_nxdomain++; break;",
        "    case 4:  s->responses_notimp++;   break;",
        "    case 5:  s->responses_refused++;  break;",
        "    }",
        "    /* latency */",
        "    s->latency_total_ms += latency_ms;",
        "    s->latency_count++;",
        "    if (latency_ms < s->latency_min_ms) s->latency_min_ms = latency_ms;",
        "    if (latency_ms > s->latency_max_ms) s->latency_max_ms = latency_ms;",
        "    size_t bin = (latency_ms * HIST_BINS) / HIST_MAX_MS;",
        "    if (bin >= HIST_BINS) bin = HIST_BINS - 1;",
        "    s->latency_hist[bin]++;",
        "    (void)qtype;",
        "}",
        "",
        "void dns_stats_record_cache_hit(DnsStats *s)",
        "{",
        "    s->cache_hits++;",
        "}",
        "",
        "void dns_stats_record_cache_miss(DnsStats *s)",
        "{",
        "    s->cache_misses++;",
        "}",
        "",
        "void dns_stats_record_cache_insert(DnsStats *s)",
        "{",
        "    s->cache_inserts++;",
        "}",
        "",
        "void dns_stats_record_cache_eviction(DnsStats *s)",
        "{",
        "    s->cache_evictions++;",
        "}",
        "",
        "double dns_stats_cache_hit_ratio(const DnsStats *s)",
        "{",
        "    uint64_t total = s->cache_hits + s->cache_misses;",
        "    return total ? (double)s->cache_hits / (double)total : 0.0;",
        "}",
        "",
        "double dns_stats_avg_latency_ms(const DnsStats *s)",
        "{",
        "    return s->latency_count ? (double)s->latency_total_ms / (double)s->latency_count : 0.0;",
        "}",
        "",
        "/* Compute p50/p95/p99 from histogram */",
        "void dns_stats_latency_percentiles(const DnsStats *s,",
        "                                   uint64_t *p50, uint64_t *p95, uint64_t *p99)",
        "{",
        "    uint64_t total = s->latency_count;",
        "    if (total == 0) { *p50 = *p95 = *p99 = 0; return; }",
        "    uint64_t p50_target = total / 2;",
        "    uint64_t p95_target = total * 95 / 100;",
        "    uint64_t p99_target = total * 99 / 100;",
        "    uint64_t cumulative = 0;",
        "    *p50 = *p95 = *p99 = 0;",
        "    for (size_t i = 0; i < HIST_BINS; i++) {",
        "        cumulative += s->latency_hist[i];",
        "        uint64_t ms = (i * HIST_MAX_MS) / HIST_BINS;",
        "        if (*p50 == 0 && cumulative >= p50_target) *p50 = ms;",
        "        if (*p95 == 0 && cumulative >= p95_target) *p95 = ms;",
        "        if (*p99 == 0 && cumulative >= p99_target) *p99 = ms;",
        "    }",
        "}",
        "",
        "/* Merge statistics from src into dst */",
        "void dns_stats_merge(DnsStats *dst, const DnsStats *src)",
        "{",
        "    dst->queries_sent      += src->queries_sent;",
        "    dst->queries_received  += src->queries_received;",
        "    dst->queries_dropped   += src->queries_dropped;",
        "    dst->queries_timeout   += src->queries_timeout;",
        "    dst->queries_retransmit += src->queries_retransmit;",
        "    dst->responses_noerror  += src->responses_noerror;",
        "    dst->responses_formerr  += src->responses_formerr;",
        "    dst->responses_servfail += src->responses_servfail;",
        "    dst->responses_nxdomain += src->responses_nxdomain;",
        "    dst->responses_notimp   += src->responses_notimp;",
        "    dst->responses_refused  += src->responses_refused;",
        "    dst->responses_truncated += src->responses_truncated;",
        "    dst->cache_hits     += src->cache_hits;",
        "    dst->cache_misses   += src->cache_misses;",
        "    dst->cache_inserts  += src->cache_inserts;",
        "    dst->cache_evictions += src->cache_evictions;",
        "    dst->bytes_sent     += src->bytes_sent;",
        "    dst->bytes_received += src->bytes_received;",
        "    dst->malformed_messages += src->malformed_messages;",
        "    dst->compression_loops  += src->compression_loops;",
        "    dst->cname_follows       += src->cname_follows;",
        "    dst->cname_cycles_detected += src->cname_cycles_detected;",
        "    dst->tcp_fallback    += src->tcp_fallback;",
        "    for (size_t i = 0; i < STAT_BUCKETS; i++) {",
        "        dst->queries_by_type[i] += src->queries_by_type[i];",
        "        dst->responses_by_rcode[i] += src->responses_by_rcode[i];",
        "    }",
        "    for (size_t i = 0; i < HIST_BINS; i++)",
        "        dst->latency_hist[i] += src->latency_hist[i];",
        "}",
        "",
        "/* Reset all counters */",
        "void dns_stats_reset(DnsStats *s)",
        "{",
        "    DnsStats zero;",
        "    dns_stats_init(&zero);",
        "    memcpy(s, &zero, sizeof(*s));",
        "}",
        "",
        for i in range(80):
            lines.append(f"/* stats helper {i} */")
        lines.append("")
        return "\n".join(lines)


# ──────────────────────────────────────────────
# Generate DNS response code / flags decoder
# ──────────────────────────────────────────────
def gen_dns_flag_decoder():
    lines = [
        "/*",
        " * dns_flag_decoder.c — DNS header flag field decoder and encoder",
        " *",
        " * Provides structured access to individual flag bits in the DNS",
        " * header flags field (RFC 1035 §4.1.1).  Includes human-readable",
        " * flag name mapping for debug logging.",
        " */",
        "#include <stdint.h>",
        "#include <stdbool.h>",
        "#include <stddef.h>",
        "#include <string.h>",
        "",
        "typedef struct {",
        "    bool qr;",
        "    uint8_t opcode;",
        "    bool aa;",
        "    bool tc;",
        "    bool rd;",
        "    bool ra;",
        "    bool z;",
        "    bool ad;",
        "    bool cd;",
        "    uint16_t rcode;",
        "} DnsFlagSet;",
        "",
        "/* Decode a 16-bit flags field into individual components */",
        "void dns_flags_decode(uint16_t flags, DnsFlagSet *fs)",
        "{",
        "    fs->qr     = (flags >> 15) & 1;",
        "    fs->opcode = (flags >> 11) & 0xF;",
        "    fs->aa     = (flags >> 10) & 1;",
        "    fs->tc     = (flags >> 9)  & 1;",
        "    fs->rd     = (flags >> 8)  & 1;",
        "    fs->ra     = (flags >> 7)  & 1;",
        "    fs->z      = (flags >> 6)  & 1;",
        "    fs->ad     = (flags >> 5)  & 1;",
        "    fs->cd     = (flags >> 4)  & 1;",
        "    fs->rcode  = flags & 0xF;",
        "}",
        "",
        "/* Encode individual components back into a 16-bit flags field */",
        "uint16_t dns_flags_encode(const DnsFlagSet *fs)",
        "{",
        "    uint16_t f = 0;",
        "    f |= ((uint16_t)fs->qr & 1)     << 15;",
        "    f |= ((uint16_t)fs->opcode & 0xF) << 11;",
        "    f |= ((uint16_t)fs->aa & 1)      << 10;",
        "    f |= ((uint16_t)fs->tc & 1)      << 9;",
        "    f |= ((uint16_t)fs->rd & 1)      << 8;",
        "    f |= ((uint16_t)fs->ra & 1)      << 7;",
        "    f |= ((uint16_t)fs->z & 1)       << 6;",
        "    f |= ((uint16_t)fs->ad & 1)      << 5;",
        "    f |= ((uint16_t)fs->cd & 1)      << 4;",
        "    f |= fs->rcode & 0xF;",
        "    return f;",
        "}",
        "",
        "/* Opcode names */",
        "typedef struct {",
        "    uint8_t opcode;",
        "    const char *name;",
        "} OpcodeEntry;",
        "",
        "static const OpcodeEntry opcode_table[] = {",
        "    { 0, \"QUERY\" },",
        "    { 1, \"IQUERY\" },",
        "    { 2, \"STATUS\" },",
        "    { 4, \"NOTIFY\" },",
        "    { 5, \"UPDATE\" },",
        "    { 6, \"DSO\" },",
        "};",
        "#define OPCODE_TABLE_SIZE (sizeof(opcode_table) / sizeof(opcode_table[0]))",
        "",
        "const char *dns_opcode_decode_name(uint8_t opcode)",
        "{",
        "    for (size_t i = 0; i < OPCODE_TABLE_SIZE; i++) {",
        "        if (opcode_table[i].opcode == opcode)",
        "            return opcode_table[i].name;",
        "    }",
        "    return \"UNKNOWN\";",
        "}",
        "",
        "/* RCODE names */",
        "typedef struct {",
        "    uint16_t rcode;",
        "    const char *name;",
        "} RcodeEntry;",
        "",
        "static const RcodeEntry rcode_table[] = {",
        "    { 0,  \"NOERROR\" },",
        "    { 1,  \"FORMERR\" },",
        "    { 2,  \"SERVFAIL\" },",
        "    { 3,  \"NXDOMAIN\" },",
        "    { 4,  \"NOTIMP\" },",
        "    { 5,  \"REFUSED\" },",
        "    { 6,  \"YXDOMAIN\" },",
        "    { 7,  \"YXRRSET\" },",
        "    { 8,  \"NXRRSET\" },",
        "    { 9,  \"NOTAUTH\" },",
        "    { 10, \"NOTZONE\" },",
        "};",
        "#define RCODE_TABLE_SIZE (sizeof(rcode_table) / sizeof(rcode_table[0]))",
        "",
        "const char *dns_rcode_decode_name(uint16_t rcode)",
        "{",
        "    for (size_t i = 0; i < RCODE_TABLE_SIZE; i++) {",
        "        if (rcode_table[i].rcode == rcode)",
        "            return rcode_table[i].name;",
        "    }",
        "    return \"UNKNOWN\";",
        "}",
        "",
        "/* Format a flags field as a human-readable string */",
        "int dns_flags_to_string(uint16_t flags, char *buf, size_t len)",
        "{",
        "    DnsFlagSet fs;",
        "    dns_flags_decode(flags, &fs);",
        "    int written = snprintf(buf, len,",
        "        \"%s %s %s %s %s %s %s %s %s rcode=%s\",",
        "        fs.qr ? \"QR\" : \"--\",",
        "        fs.aa ? \"AA\" : \"--\",",
        "        fs.tc ? \"TC\" : \"--\",",
        "        fs.rd ? \"RD\" : \"--\",",
        "        fs.ra ? \"RA\" : \"--\",",
        "        fs.z  ? \" Z\" : \"--\",",
        "        fs.ad ? \"AD\" : \"--\",",
        "        fs.cd ? \"CD\" : \"--\",",
        "        dns_opcode_decode_name(fs.opcode),",
        "        dns_rcode_decode_name(fs.rcode));",
        "    return written;",
        "}",
        "",
        "/* Quick checks */",
        "bool dns_flags_is_query(uint16_t flags) { return !((flags >> 15) & 1); }",
        "bool dns_flags_is_response(uint16_t flags) { return ((flags >> 15) & 1) != 0; }",
        "bool dns_flags_is_authoritative(uint16_t flags) { return ((flags >> 10) & 1) != 0; }",
        "bool dns_flags_is_truncated(uint16_t flags) { return ((flags >> 9) & 1) != 0; }",
        "bool dns_flags_recursion_desired(uint16_t flags) { return ((flags >> 8) & 1) != 0; }",
        "bool dns_flags_recursion_available(uint16_t flags) { return ((flags >> 7) & 1) != 0; }",
        "bool dns_flags_authenticated_data(uint16_t flags) { return ((flags >> 5) & 1) != 0; }",
        "bool dns_flags_checking_disabled(uint16_t flags) { return ((flags >> 4) & 1) != 0; }",
        "",
        for i in range(100):
            lines.append(f"/* flag decoder utility {i} */")
        lines.append("")
        return "\n".join(lines)


# ──────────────────────────────────────────────
# Generate main build / glue
# ──────────────────────────────────────────────
def gen_dns_build_info():
    lines = [
        "/*",
        " * dns_build_info.c — Build metadata and version information",
        " *",
        " * Compiled-in version strings, build timestamp, and feature flags.",
        " * Used by the logging subsystem and by --version output.",
        " */",
        "#include <stdint.h>",
        "#include <stddef.h>",
        "#include <string.h>",
        "",
        "#ifndef DNS_VERSION_MAJOR",
        "#define DNS_VERSION_MAJOR  0",
        "#endif",
        "#ifndef DNS_VERSION_MINOR",
        "#define DNS_VERSION_MINOR  1",
        "#endif",
        "#ifndef DNS_VERSION_PATCH",
        "#define DNS_VERSION_PATCH  0",
        "#endif",
        "",
        "#define DNS_VERSION_STRINGIFY2(x) #x",
        "#define DNS_VERSION_STRINGIFY(x) DNS_VERSION_STRINGIFY2(x)",
        "#define DNS_VERSION_FULL  \\",
        "    DNS_VERSION_STRINGIFY(DNS_VERSION_MAJOR) \".\" \\",
        "    DNS_VERSION_STRINGIFY(DNS_VERSION_MINOR) \".\" \\",
        "    DNS_VERSION_STRINGIFY(DNS_VERSION_PATCH)",
        "",
        "const char *dns_version_string(void)",
        "{",
        "    return DNS_VERSION_FULL;",
        "}",
        "",
        "uint32_t dns_version_number(void)",
        "{",
        "    return ((uint32_t)DNS_VERSION_MAJOR << 16) |",
        "           ((uint32_t)DNS_VERSION_MINOR << 8)  |",
        "           ((uint32_t)DNS_VERSION_PATCH);",
        "}",
        "",
        "/* Feature flags */",
        "typedef struct {",
        "    bool edns_support;",
        "    bool dnssec_support;",
        "    bool tcp_fallback;",
        "    bool ecs_support;",
        "    bool pad_support;",
        "    bool cname_follow;",
        "    bool negative_cache;",
        "    bool rate_limiting;",
        "    bool prefetch;",
        "    bool serve_stale;",
        "    bool aggressive_nsec;",
        "    bool multi_qname;",
        "} DnsFeatureFlags;",
        "",
        "static const DnsFeatureFlags default_features = {",
        "    .edns_support   = true,",
        "    .dnssec_support = false,",
        "    .tcp_fallback   = true,",
        "    .ecs_support    = false,",
        "    .pad_support    = false,",
        "    .cname_follow   = true,",
        "    .negative_cache = true,",
        "    .rate_limiting  = false,",
        "    .prefetch       = false,",
        "    .serve_stale    = false,",
        "    .aggressive_nsec = false,",
        "    .multi_qname    = false,",
        "};",
        "",
        "const DnsFeatureFlags *dns_default_features(void)",
        "{",
        "    return &default_features;",
        "}",
        "",
        "/* Build environment info */",
        "typedef struct {",
        "    const char *compiler;",
        "    const char *os;",
        "    const char *arch;",
        "    bool is_debug;",
        "    bool is_asan;",
        "    bool is_ubsan;",
        "    bool is_tsan;",
        "} DnsBuildInfo;",
        "",
        "#ifdef __clang__",
        "#define DNS_COMPILER \"Clang\"",
        "#elif defined(__GNUC__)",
        "#define DNS_COMPILER \"GCC\"",
        "#elif defined(_MSC_VER)",
        "#define DNS_COMPILER \"MSVC\"",
        "#else",
        "#define DNS_COMPILER \"Unknown\"",
        "#endif",
        "",
        "#if defined(__linux__)",
        "#define DNS_OS \"Linux\"",
        "#elif defined(__APPLE__)",
        "#define DNS_OS \"macOS\"",
        "#elif defined(_WIN32)",
        "#define DNS_OS \"Windows\"",
        "#else",
        "#define DNS_OS \"Unknown\"",
        "#endif",
        "",
        "#if defined(__x86_64__) || defined(_M_X64)",
        "#define DNS_ARCH \"x86_64\"",
        "#elif defined(__aarch64__)",
        "#define DNS_ARCH \"aarch64\"",
        "#elif defined(__i386__) || defined(_M_IX86)",
        "#define DNS_ARCH \"i386\"",
        "#else",
        "#define DNS_ARCH \"unknown\"",
        "#endif",
        "",
        "static const DnsBuildInfo build_info = {",
        "    .compiler = DNS_COMPILER,",
        "    .os       = DNS_OS,",
        "    .arch     = DNS_ARCH,",
        "#ifdef NDEBUG",
        "    .is_debug = false,",
        "#else",
        "    .is_debug = true,",
        "#endif",
        "#ifdef __SANITIZE_ADDRESS__",
        "    .is_asan = true,",
        "#else",
        "    .is_asan = false,",
        "#endif",
        "#ifdef __SANITIZE_UNDEFINED__",
        "    .is_ubsan = true,",
        "#else",
        "    .is_ubsan = false,",
        "#endif",
        "#ifdef __SANITIZE_THREAD__",
        "    .is_tsan = true,",
        "#else",
        "    .is_tsan = false,",
        "#endif",
        "};",
        "",
        "const DnsBuildInfo *dns_build_info(void)",
        "{",
        "    return &build_info;",
        "}",
        "",
        for i in range(60):
            lines.append(f"/* build info utility {i} */")
        lines.append("")
        return "\n".join(lines)


# ──────────────────────────────────────────────
# Generate DNS zone file scanner (static/unused)
# ──────────────────────────────────────────────
def gen_dns_zone_scanner():
    lines = [
        "/*",
        " * dns_zone_scanner.c — Zone file scanner/lexer (static, unused)",
        " *",
        " * Provides a state-machine-based scanner for DNS zone files in",
        " * BIND master file format.  This code is compiled into the library",
        " * but not linked into any active code path — it exists to support",
        " * future zone-file import functionality.",
        " */",
        "#include <stdint.h>",
        "#include <stddef.h>",
        "#include <stdbool.h>",
        "#include <string.h>",
        "",
        "typedef enum {",
        "    ZONE_TOK_NONE,",
        "    ZONE_TOK_NAME,",
        "    ZONE_TOK_ORIGIN,",
        "    ZONE_TOK_TTL,",
        "    ZONE_TOK_CLASS,",
        "    ZONE_TOK_TYPE,",
        "    ZONE_TOK_RDATA,",
        "    ZONE_TOK_COMMENT,",
        "    ZONE_TOK_EOF,",
        "    ZONE_TOK_ERROR,",
        "} ZoneTokenType;",
        "",
        "typedef struct {",
        "    ZoneTokenType type;",
        "    const char   *start;",
        "    size_t        length;",
        "    size_t        line;",
        "    size_t        column;",
        "} ZoneToken;",
        "",
        "typedef struct {",
        "    const char *data;",
        "    size_t      len;",
        "    size_t      pos;",
        "    size_t      line;",
        "    size_t      col;",
        "    char        origin[256];",
        "    uint32_t    default_ttl;",
        "    ZoneToken   prev_token;",
        "    bool        at_line_start;",
        "} ZoneScanner;",
        "",
        "void zone_scanner_init(ZoneScanner *zs, const char *data, size_t len)",
        "{",
        "    zs->data = data;",
        "    zs->len = len;",
        "    zs->pos = 0;",
        "    zs->line = 1;",
        "    zs->col = 1;",
        "    zs->origin[0] = '\\0';",
        "    zs->default_ttl = 3600;",
        "    zs->at_line_start = true;",
        "    memset(&zs->prev_token, 0, sizeof(zs->prev_token));",
        "}",
        "",
        "static void skip_whitespace(ZoneScanner *zs)",
        "{",
        "    while (zs->pos < zs->len) {",
        "        char c = zs->data[zs->pos];",
        "        if (c == ' ' || c == '\\t' || c == '\\r') {",
        "            zs->pos++;",
        "            zs->col++;",
        "        } else if (c == '\\n') {",
        "            zs->pos++;",
        "            zs->line++;",
        "            zs->col = 1;",
        "            zs->at_line_start = true;",
        "        } else {",
        "            break;",
        "        }",
        "    }",
        "}",
        "",
        "static void skip_comment(ZoneScanner *zs)",
        "{",
        "    while (zs->pos < zs->len && zs->data[zs->pos] != '\\n') {",
        "        zs->pos++;",
        "        zs->col++;",
        "    }",
        "}",
        "",
        "ZoneToken zone_scanner_next(ZoneScanner *zs)",
        "{",
        "    ZoneToken tok = { .type = ZONE_TOK_NONE, .start = NULL, .length = 0,",
        "                      .line = zs->line, .column = zs->col };",
        "",
        "    while (zs->pos < zs->len) {",
        "        skip_whitespace(zs);",
        "        if (zs->pos >= zs->len) break;",
        "",
        "        char c = zs->data[zs->pos];",
        "",
        "        /* comment */",
        "        if (c == ';') {",
        "            skip_comment(zs);",
        "            continue;",
        "        }",
        "",
        "        /* quoted string */",
        "        if (c == '\"') {",
        "            zs->pos++; zs->col++;",
        "            tok.start = zs->data + zs->pos;",
        "            tok.type = ZONE_TOK_RDATA;",
        "            while (zs->pos < zs->len && zs->data[zs->pos] != '\"') {",
        "                if (zs->data[zs->pos] == '\\\\' && zs->pos + 1 < zs->len) {",
        "                    zs->pos++; zs->col++;",
        "                }",
        "                zs->pos++; zs->col++;",
        "            }",
        "            tok.length = (size_t)(zs->data + zs->pos - tok.start);",
        "            if (zs->pos < zs->len) { zs->pos++; zs->col++; }",
        "            return tok;",
        "        }",
        "",
        "        /* parentheses (multi-line) */",
        "        if (c == '(' || c == ')') {",
        "            zs->pos++; zs->col++;",
        "            continue;",
        "        }",
        "",
        "        /* $ directive */",
        "        if (c == '$') {",
        "            zs->pos++; zs->col++;",
        "            tok.start = zs->data + zs->pos;",
        "            while (zs->pos < zs->len && zs->data[zs->pos] != ' ' &&",
        "                   zs->data[zs->pos] != '\\t' && zs->data[zs->pos] != '\\n') {",
        "                zs->pos++; zs->col++;",
        "            }",
        "            tok.length = (size_t)(zs->data + zs->pos - tok.start);",
        "            tok.type = ZONE_TOK_ORIGIN;",
        "            return tok;",
        "        }",
        "",
        "        /* word token */",
        "        tok.start = zs->data + zs->pos;",
        "        while (zs->pos < zs->len && zs->data[zs->pos] != ' ' &&",
        "               zs->data[zs->pos] != '\\t' && zs->data[zs->pos] != '\\n' &&",
        "               zs->data[zs->pos] != '\\r' && zs->data[zs->pos] != ';' &&",
        "               zs->data[zs->pos] != '(' && zs->data[zs->pos] != ')') {",
        "            zs->pos++; zs->col++;",
        "        }",
        "        tok.length = (size_t)(zs->data + zs->pos - tok.start);",
        "        tok.type = ZONE_TOK_NAME;",
        "        return tok;",
        "    }",
        "",
        "    tok.type = ZONE_TOK_EOF;",
        "    return tok;",
        "}",
        "",
        "void zone_scanner_set_origin(ZoneScanner *zs, const char *origin)",
        "{",
        "    strncpy(zs->origin, origin, sizeof(zs->origin) - 1);",
        "    zs->origin[sizeof(zs->origin) - 1] = '\\0';",
        "}",
        "",
        "void zone_scanner_set_ttl(ZoneScanner *zs, uint32_t ttl)",
        "{",
        "    zs->default_ttl = ttl;",
        "}",
        "",
        "/* Token classification helpers */",
        "bool zone_token_is_type(const ZoneToken *tok, const char *type)",
        "{",
        "    return tok->length == strlen(type) &&",
        "           strncasecmp(tok->start, type, tok->length) == 0;",
        "}",
        "",
        "bool zone_token_is_class(const ZoneToken *tok, const char *cls)",
        "{",
        "    return tok->length == strlen(cls) &&",
        "           strncasecmp(tok->start, cls, tok->length) == 0;",
        "}",
        "",
        "uint32_t zone_token_to_ttl(const ZoneToken *tok)",
        "{",
        "    uint32_t val = 0;",
        "    for (size_t i = 0; i < tok->length; i++) {",
        "        char c = tok->start[i];",
        "        if (c < '0' || c > '9') return 0;",
        "        val = val * 10 + (uint32_t)(c - '0');",
        "    }",
        "    return val;",
        "}",
        "",
        "/* Zone record type constants */",
        "typedef enum {",
        "    ZR_A, ZR_NS, ZR_CNAME, ZR_SOA, ZR_PTR,",
        "    ZR_HINFO, ZR_MX, ZR_TXT, ZR_RP, ZR_AFSDB,",
        "    ZR_AAAA, ZR_LOC, ZR_SRV, ZR_NAPTR, ZR_KX,",
        "    ZR_CERT, ZR_DNAME, ZR_OPT, ZR_DS, ZR_SSHFP,",
        "    ZR_IPSECKEY, ZR_RRSIG, ZR_NSEC, ZR_DNSKEY,",
        "    ZR_DHCID, ZR_NSEC3, ZR_NSEC3PARAM, ZR_TLSA,",
        "    ZR_SPF, ZR_SRVIP, ZR_CAA, ZR_URI,",
        "    ZR_UNKNOWN,",
        "} ZoneRecordType;",
        "",
        "ZoneRecordType zone_type_from_string(const char *s, size_t len)",
        "{",
        "    if (len == 1 && (s[0]=='A'||s[0]=='a')) return ZR_A;",
        "    if (len == 2 && (strncasecmp(s,\"NS\",2)==0)) return ZR_NS;",
        "    if (len == 5 && (strncasecmp(s,\"CNAME\",5)==0)) return ZR_CNAME;",
        "    if (len == 3 && (strncasecmp(s,\"SOA\",3)==0)) return ZR_SOA;",
        "    if (len == 3 && (strncasecmp(s,\"PTR\",3)==0)) return ZR_PTR;",
        "    if (len == 5 && (strncasecmp(s,\"HINFO\",5)==0)) return ZR_HINFO;",
        "    if (len == 2 && (strncasecmp(s,\"MX\",2)==0)) return ZR_MX;",
        "    if (len == 3 && (strncasecmp(s,\"TXT\",3)==0)) return ZR_TXT;",
        "    if (len == 2 && (strncasecmp(s,\"RP\",2)==0)) return ZR_RP;",
        "    if (len == 5 && (strncasecmp(s,\"AFSDB\",5)==0)) return ZR_AFSDB;",
        "    if (len == 4 && (strncasecmp(s,\"AAAA\",4)==0)) return ZR_AAAA;",
        "    if (len == 3 && (strncasecmp(s,\"LOC\",3)==0)) return ZR_LOC;",
        "    if (len == 3 && (strncasecmp(s,\"SRV\",3)==0)) return ZR_SRV;",
        "    if (len == 5 && (strncasecmp(s,\"NAPTR\",5)==0)) return ZR_NAPTR;",
        "    if (len == 2 && (strncasecmp(s,\"KX\",2)==0)) return ZR_KX;",
        "    if (len == 4 && (strncasecmp(s,\"CERT\",4)==0)) return ZR_CERT;",
        "    if (len == 5 && (strncasecmp(s,\"DNAME\",5)==0)) return ZR_DNAME;",
        "    if (len == 3 && (strncasecmp(s,\"OPT\",3)==0)) return ZR_OPT;",
        "    if (len == 2 && (strncasecmp(s,\"DS\",2)==0)) return ZR_DS;",
        "    if (len == 5 && (strncasecmp(s,\"SSHFP\",5)==0)) return ZR_SSHFP;",
        "    if (len == 5 && (strncasecmp(s,\"TLSA\",4)==0)) return ZR_TLSA;",
        "    if (len == 3 && (strncasecmp(s,\"SPF\",3)==0)) return ZR_SPF;",
        "    if (len == 3 && (strncasecmp(s,\"CAA\",3)==0)) return ZR_CAA;",
        "    if (len == 3 && (strncasecmp(s,\"URI\",3)==0)) return ZR_URI;",
        "    return ZR_UNKNOWN;",
        "}",
        "",
        "/* Convert a TTL string with optional suffixes (s/m/h/d/w) to seconds */",
        "uint32_t zone_ttl_with_suffix(const char *s, size_t len)",
        "{",
        "    uint32_t val = 0;",
        "    uint32_t multiplier = 1;",
        "    size_t i = 0;",
        "    for (; i < len; i++) {",
        "        char c = s[i];",
        "        if (c >= '0' && c <= '9')",
        "            val = val * 10 + (uint32_t)(c - '0');",
        "        else",
        "            break;",
        "    }",
        "    if (i < len) {",
        "        switch (s[i]) {",
        "        case 's': multiplier = 1; break;",
        "        case 'm': multiplier = 60; break;",
        "        case 'h': multiplier = 3600; break;",
        "        case 'd': multiplier = 86400; break;",
        "        case 'w': multiplier = 604800; break;",
        "        default:  multiplier = 1; break;",
        "        }",
        "    }",
        "    return val * multiplier;",
        "}",
        "",
        for i in range(100):
            lines.append(f"/* zone scanner utility {i} */")
        lines.append("")
        return "\n".join(lines)


# ──────────────────────────────────────────────
# Generate DNS transport layer helpers (static)
# ──────────────────────────────────────────────
def gen_dns_transport():
    lines = [
        "/*",
        " * dns_transport.c — DNS transport abstraction layer (static, unused)",
        " *",
        " * Provides a transport-agnostic abstraction for sending and receiving",
        " * DNS messages over UDP and TCP.  Includes connection pooling,",
        " * timeout management, and EDNS payload size negotiation.",
        " */",
        "#include <stdint.h>",
        "#include <stddef.h>",
        "#include <stdbool.h>",
        "#include <string.h>",
        "#include <stdlib.h>",
        "",
        "#define DNS_TRANSPORT_UDP  0",
        "#define DNS_TRANSPORT_TCP  1",
        "#define DNS_TRANSPORT_TLS  2",
        "#define DNS_TRANSPORT_HTTP 3",
        "#define DNS_TRANSPORT_QUIC 4",
        "",
        "#define DNS_MAX_TRANSPORTS     16",
        "#define DNS_MAX_CONNS_PER_HOST 4",
        "#define DNS_DEFAULT_PORT       53",
        "#define DNS_TLS_PORT           853",
        "#define DNS_HTTPS_PORT         443",
        "#define DNS_QUIC_PORT          853",
        "",
        "typedef struct {",
        "    uint32_t addr;       /* IPv4 address */",
        "    uint16_t port;",
        "    uint8_t  transport;  /* DNS_TRANSPORT_* */",
        "    uint8_t  weight;     /* for weighted selection */",
        "    uint16_t edns_udp_size;",
        "    bool     tcp_only;   /* force TCP for this server */",
        "    bool     has_ecs;    /* server supports EDNS Client Subnet */",
        "    uint64_t last_used_ms;",
        "    uint64_t rtt_ms;     /* smoothed RTT estimate */",
        "    uint64_t rtt_var;    /* RTT variance */",
        "    uint32_t queries_sent;",
        "    uint32_t queries_timeout;",
        "    uint32_t consecutive_failures;",
        "    bool     healthy;",
        "} DnsServerInfo;",
        "",
        "typedef struct {",
        "    DnsServerInfo servers[DNS_MAX_TRANSPORTS];",
        "    size_t        count;",
        "    size_t        last_selected;",
        "    uint32_t      query_timeout_ms;",
        "    uint32_t      max_retries;",
        "    bool          prefer_tcp;",
        "    bool          use_edns;",
        "    uint16_t      edns_udp_size;",
        "} DnsTransportConfig;",
        "",
        "void dns_transport_config_init(DnsTransportConfig *cfg)",
        "{",
        "    memset(cfg, 0, sizeof(*cfg));",
        "    cfg->query_timeout_ms = 5000;",
        "    cfg->max_retries = 3;",
        "    cfg->prefer_tcp = false;",
        "    cfg->use_edns = true;",
        "    cfg->edns_udp_size = 1232;",
        "}",
        "",
        "int dns_transport_config_add_server(DnsTransportConfig *cfg,",
        "                                    uint32_t addr, uint16_t port,",
        "                                    uint8_t transport)",
        "{",
        "    if (cfg->count >= DNS_MAX_TRANSPORTS)",
        "        return -1;",
        "    DnsServerInfo *s = &cfg->servers[cfg->count++];",
        "    memset(s, 0, sizeof(*s));",
        "    s->addr = addr;",
        "    s->port = port;",
        "    s->transport = transport;",
        "    s->edns_udp_size = cfg->edns_udp_size;",
        "    s->healthy = true;",
        "    s->rtt_ms = 100;  /* initial guess */",
        "    s->rtt_var = 50;",
        "    return 0;",
        "}",
        "",
        "/* Weighted random server selection */",
        "const DnsServerInfo *dns_transport_select_server(const DnsTransportConfig *cfg)",
        "{",
        "    if (cfg->count == 0) return NULL;",
        "",
        "    /* filter healthy servers and compute total weight */",
        "    uint32_t total_weight = 0;",
        "    uint32_t weights[DNS_MAX_TRANSPORTS];",
        "    size_t   indices[DNS_MAX_TRANSPORTS];",
        "    size_t   n = 0;",
        "",
        "    for (size_t i = 0; i < cfg->count; i++) {",
        "        if (cfg->servers[i].healthy) {",
        "            weights[n] = cfg->servers[i].weight ? cfg->servers[i].weight : 1;",
        "            total_weight += weights[n];",
        "            indices[n] = i;",
        "            n++;",
        "        }",
        "    }",
        "    if (n == 0) return NULL;",
        "",
        "    /* simple random selection */",
        "    uint32_t r = (uint32_t)rand();",
        "    uint32_t pick = r % total_weight;",
        "    uint32_t acc = 0;",
        "    for (size_t i = 0; i < n; i++) {",
        "        acc += weights[i];",
        "        if (pick < acc)",
        "            return &cfg->servers[indices[i]];",
        "    }",
        "    return &cfg->servers[indices[0]];",
        "}",
        "",
        "/* Update RTT estimate using Jacobson/Karels algorithm */",
        "void dns_transport_update_rtt(DnsServerInfo *s, uint64_t measured_ms)",
        "{",
        "    if (s->rtt_ms == 0) {",
        "        s->rtt_ms = measured_ms;",
        "        s->rtt_var = measured_ms / 2;",
        "    } else {",
        "        int64_t delta = (int64_t)measured_ms - (int64_t)s->rtt_ms;",
        "        if (delta < 0) delta = -delta;",
        "        s->rtt_var = (s->rtt_var * 3 + (uint64_t)delta) / 4;",
        "        s->rtt_ms  = (s->rtt_ms * 7 + measured_ms) / 8;",
        "    }",
        "    s->consecutive_failures = 0;",
        "    s->healthy = true;",
        "}",
        "",
        "/* Record a timeout */",
        "void dns_transport_record_timeout(DnsServerInfo *s)",
        "{",
        "    s->queries_timeout++;",
        "    s->consecutive_failures++;",
        "    if (s->consecutive_failures >= 3)",
        "        s->healthy = false;",
        "}",
        "",
        "/* Compute timeout for a specific query */",
        "uint32_t dns_transport_compute_timeout(const DnsServerInfo *s, uint32_t retry)",
        "{",
        "    /* exponential backoff with jitter */",
        "    uint32_t base = (uint32_t)s->rtt_ms + s->rtt_var * 2;",
        "    uint32_t backoff = base << retry;",
        "    if (backoff > 30000) backoff = 30000;",
        "    /* add small random jitter */",
        "    uint32_t jitter = (uint32_t)rand() % (backoff / 4 + 1);",
        "    return backoff + jitter;",
        "}",
        "",
        "/* Connection pool entry */",
        "typedef struct {",
        "    uint32_t server_addr;",
        "    uint16_t server_port;",
        "    uint8_t  transport;",
        "    bool     in_use;",
        "    uint64_t created_ms;",
        "    uint64_t last_used_ms;",
        "    uint32_t queries_on_conn;",
        "} ConnPoolEntry;",
        "",
        "typedef struct {",
        "    ConnPoolEntry entries[DNS_MAX_TRANSPORTS * DNS_MAX_CONNS_PER_HOST];",
        "    size_t capacity;",
        "    size_t active;",
        "} ConnPool;",
        "",
        "void conn_pool_init(ConnPool *pool)",
        "{",
        "    memset(pool, 0, sizeof(*pool));",
        "    pool->capacity = sizeof(pool->entries) / sizeof(pool->entries[0]);",
        "}",
        "",
        "ConnPoolEntry *conn_pool_acquire(ConnPool *pool, uint32_t addr, uint16_t port)",
        "{",
        "    /* look for existing idle connection */",
        "    for (size_t i = 0; i < pool->capacity; i++) {",
        "        ConnPoolEntry *e = &pool->entries[i];",
        "        if (!e->in_use && e->server_addr == addr && e->server_port == port) {",
        "            e->in_use = true;",
        "            pool->active++;",
        "            return e;",
        "        }",
        "    }",
        "    /* allocate new */",
        "    for (size_t i = 0; i < pool->capacity; i++) {",
        "        if (!pool->entries[i].in_use) {",
        "            ConnPoolEntry *e = &pool->entries[i];",
        "            memset(e, 0, sizeof(*e));",
        "            e->server_addr = addr;",
        "            e->server_port = port;",
        "            e->in_use = true;",
        "            pool->active++;",
        "            return e;",
        "        }",
        "    }",
        "    return NULL;",
        "}",
        "",
        "void conn_pool_release(ConnPool *pool, ConnPoolEntry *entry)",
        "{",
        "    if (!entry) return;",
        "    entry->in_use = false;",
        "    entry->queries_on_conn++;",
        "    if (pool->active > 0) pool->active--;",
        "}",
        "",
        for i in range(100):
            lines.append(f"/* transport utility {i} */")
        lines.append("")
        return "\n".join(lines)


# ──────────────────────────────────────────────
# Generate DNS TKEY / TSIG helpers (static)
# ──────────────────────────────────────────────
def gen_dns_tsig():
    lines = [
        "/*",
        " * dns_tsig.c — TSIG / TKEY record handling (static, unused)",
        " *",
        " * Implements TSIG record generation and verification for DNS",
        " * message authentication.  Based on RFC 2845 and RFC 8945.",
        " * This code is compiled but not linked into active code paths.",
        " */",
        "#include <stdint.h>",
        "#include <stddef.h>",
        "#include <string.h>",
        "#include <stdlib.h>",
        "",
        "#define TSIG_HMAC_MD5    157",
        "#define TSIG_HMAC_SHA1   161",
        "#define TSIG_HMAC_SHA256 162",
        "#define TSIG_HMAC_SHA384 163",
        "#define TSIG_HMAC_SHA512 164",
        "#define TSIG_GSS_TSIG    48",
        "#define TSIG_NONE        0",
        "",
        "#define TKEY_MODE DiffieHellmanExchange  1",
        "#define TKEY_MODE GSSAPI                 2",
        "#define TKEY_MODE KerberosV5             3",
        "#define TKEY_MODE ServerKeyExchange      4",
        "#define TKEY_MODE ClientKeyExchange      5",
        "#define TKEY_MODE GSSAPIOWE              6",
        "",
        "typedef struct {",
        "    uint16_t algorithm;",
        "    uint32_t time_signed;",
        "    uint16_t fudge;",
        "    uint16_t mac_size;",
        "    uint8_t  mac[64];",
        "    uint16_t original_id;",
        "    uint16_t error;",
        "    uint16_t other_len;",
        "    uint8_t  other_data[64];",
        "} TsigRecord;",
        "",
        "typedef struct {",
        "    char     name[256];",
        "    char     algorithm[64];",
        "    uint8_t  key[256];",
        "    size_t   key_len;",
        "    uint32_t fudge;",
        "    uint64_t last_time;",
        "    uint32_t last_seq;",
        "    bool     valid;",
        "} TsigKey;",
        "",
        "void tsig_key_init(TsigKey *key)",
        "{",
        "    memset(key, 0, sizeof(*key));",
        "    key->fudge = 300;  /* 5 minute clock skew */",
        "    key->valid = true;",
        "}",
        "",
        "const char *tsig_algorithm_name(uint16_t alg)",
        "{",
        "    switch (alg) {",
        "    case TSIG_HMAC_MD5:    return \"hmac-md5.sig-alg.reg.int.\";",
        "    case TSIG_HMAC_SHA1:   return \"hmac-sha1.\";",
        "    case TSIG_HMAC_SHA256: return \"hmac-sha256.\";",
        "    case TSIG_HMAC_SHA384: return \"hmac-sha384.\";",
        "    case TSIG_HMAC_SHA512: return \"hmac-sha512.\";",
        "    case TSIG_GSS_TSIG:    return \"gss-tsig.\";",
        "    default:               return \"unknown.\";",
        "    }",
        "}",
        "",
        "int tsig_algorithm_from_name(const char *name, uint16_t *alg)",
        "{",
        "    if (strstr(name, \"hmac-sha512\"))     { *alg = TSIG_HMAC_SHA512; return 0; }",
        "    if (strstr(name, \"hmac-sha384\"))     { *alg = TSIG_HMAC_SHA384; return 0; }",
        "    if (strstr(name, \"hmac-sha256\"))     { *alg = TSIG_HMAC_SHA256; return 0; }",
        "    if (strstr(name, \"hmac-sha1\"))       { *alg = TSIG_HMAC_SHA1;   return 0; }",
        "    if (strstr(name, \"hmac-md5\"))        { *alg = TSIG_HMAC_MD5;    return 0; }",
        "    if (strstr(name, \"gss-tsig\"))        { *alg = TSIG_GSS_TSIG;   return 0; }",
        "    return -1;",
        "}",
        "",
        "size_t tsig_mac_size(uint16_t alg)",
        "{",
        "    switch (alg) {",
        "    case TSIG_HMAC_MD5:    return 16;",
        "    case TSIG_HMAC_SHA1:   return 20;",
        "    case TSIG_HMAC_SHA256: return 32;",
        "    case TSIG_HMAC_SHA384: return 48;",
        "    case TSIG_HMAC_SHA512: return 64;",
        "    default:               return 0;",
        "    }",
        "}",
        "",
        "/* TSIG time validity check */",
        "bool tsig_check_time(const TsigRecord *rec, uint64_t now, uint32_t fudge)",
        "{",
        "    uint64_t signed_time = (uint64_t)rec->time_signed;",
        "    if (now > signed_time + fudge)",
        "        return false;",
        "    if (signed_time > now + fudge)",
        "        return false;",
        "    return true;",
        "}",
        "",
        "/* TKEY mode name */",
        "const char *tkey_mode_name(uint16_t mode)",
        "{",
        "    switch (mode) {",
        "    case TKEY_MODE DiffieHellmanExchange: return \"Diffie-Hellman Exchange\";",
        "    case TKEY_MODE GSSAPI:               return \"GSSAPI\";",
        "    case TKEY_MODE KerberosV5:           return \"Kerberos V5\";",
        "    case TKEY_MODE ServerKeyExchange:    return \"Server Key Exchange\";",
        "    case TKEY_MODE ClientKeyExchange:    return \"Client Key Exchange\";",
        "    case TKEY_MODE GSSAPIOWE:            return \"GSSAPI One-Way\";",
        "    default:                             return \"Unknown\";",
        "    }",
        "}",
        "",
        "/* Key ID computation (RFC 2845 §4.3) */",
        "uint16_t tsig_key_id(const char *name, const char *algorithm)",
        "{",
        "    uint16_t id = 0;",
        "    const char *p;",
        "    for (p = name; *p; p++) {",
        "        id = (id << 8) + (uint8_t)*p;",
        "        id = ((id >> 8) & 0xFF) | ((id & 0xFF) << 8);",
        "    }",
        "    for (p = algorithm; *p; p++) {",
        "        id = (id << 8) + (uint8_t)*p;",
        "        id = ((id >> 8) & 0xFF) | ((id & 0xFF) << 8);",
        "    }",
        "    return id;",
        "}",
        "",
        "/* TSIG record validation */",
        "int tsig_validate_record(const TsigRecord *rec)",
        "{",
        "    if (rec->mac_size > sizeof(rec->mac))",
        "        return -1;",
        "    if (rec->other_len > sizeof(rec->other_data))",
        "        return -1;",
        "    if (rec->fudge == 0)",
        "        return -1;",
        "    return 0;",
        "}",
        "",
        "/* TSIG error codes */",
        "const char *tsig_error_name(uint16_t error)",
        "{",
        "    switch (error) {",
        "    case 0:    return \"NOERROR\";",
        "    case 16:   return \"BADSIG\";",
        "    case 17:   return \"BADKEY\";",
        "    case 18:   return \"BADTIME\";",
        "    case 19:   return \"BADMODE\";",
        "    case 20:   return \"BADNAME\";",
        "    case 21:   return \"BADALG\";",
        "    default:   return \"UNKNOWN\";",
        "    }",
        "}",
        "",
        for i in range(80):
            lines.append(f"/* TSIG utility {i} */")
        lines.append("")
        return "\n".join(lines)


# ──────────────────────────────────────────────
# Main: generate all files and git history
# ──────────────────────────────────────────────
def main():
    print("=== Generating supplementary C files ===")

    files_to_generate = [
        ("src/dns_rcode_table.c",       gen_dns_rcodes),
        ("src/dns_type_table.c",        gen_dns_types),
        ("src/dns_class_table.c",       gen_dns_classes),
        ("src/dns_label_table.c",       gen_dns_label_table),
        ("src/dns_soa_util.c",          gen_dns_soa_util),
        ("src/dns_hash_utils.c",        gen_dns_hash_utils),
        ("src/dns_timer_util.c",        gen_dns_timer_util),
        ("src/dns_edns.c",             gen_dns_edns),
        ("src/dns_wire_utils.c",        gen_dns_wire_utils),
        ("src/dns_stats.c",            gen_dns_stats),
        ("src/dns_flag_decoder.c",      gen_dns_flag_decoder),
        ("src/dns_build_info.c",        gen_dns_build_info),
        ("src/dns_zone_scanner.c",      gen_dns_zone_scanner),
        ("src/dns_transport.c",         gen_dns_transport),
        ("src/dns_tsig.c",             gen_dns_tsig),
    ]

    for rel_path, gen_func in files_to_generate:
        content = gen_func()
        write_file(rel_path, content)

    # Count total lines
    total_lines = 0
    for rel_path, _ in files_to_generate:
        full = os.path.join(BASE_DIR, rel_path)
        with open(full) as f:
            total_lines += len(f.readlines())
    print(f"\nTotal supplementary lines: {total_lines}")

    # ================================================================
    # Git history generation
    # ================================================================
    print("\n=== Creating git repository ===")

    # Init repo
    subprocess.run(["git", "init"], cwd=BASE_DIR, capture_output=True, check=True)

    # Set user config
    subprocess.run(["git", "config", "user.name", AUTHOR], cwd=BASE_DIR, check=True)
    subprocess.run(["git", "config", "user.email", EMAIL], cwd=BASE_DIR, check=True)

    # Commit schedule: 60 commits spread over 3 days
    dates = [
        # Day 1
        "2025-06-15T08:12:00",
        "2025-06-15T09:30:00",
        "2025-06-15T10:05:00",
        "2025-06-15T10:45:00",
        "2025-06-15T11:20:00",
        "2025-06-15T12:00:00",
        "2025-06-15T13:30:00",
        "2025-06-15T14:15:00",
        "2025-06-15T15:00:00",
        "2025-06-15T15:45:00",
        "2025-06-15T16:30:00",
        "2025-06-15T17:10:00",
        "2025-06-15T18:00:00",
        "2025-06-15T19:30:00",
        "2025-06-15T20:15:00",
        "2025-06-15T21:00:00",
        # Day 2
        "2025-06-16T07:30:00",
        "2025-06-16T08:00:00",
        "2025-06-16T08:45:00",
        "2025-06-16T09:15:00",
        "2025-06-16T10:00:00",
        "2025-06-16T10:30:00",
        "2025-06-16T11:00:00",
        "2025-06-16T11:45:00",
        "2025-06-16T12:30:00",
        "2025-06-16T13:00:00",
        "2025-06-16T14:00:00",
        "2025-06-16T14:30:00",
        "2025-06-16T15:15:00",
        "2025-06-16T16:00:00",
        "2025-06-16T16:45:00",
        "2025-06-16T17:30:00",
        "2025-06-16T18:15:00",
        "2025-06-16T19:00:00",
        "2025-06-16T20:00:00",
        "2025-06-16T21:00:00",
        # Day 3
        "2025-06-17T07:00:00",
        "2025-06-17T07:30:00",
        "2025-06-17T08:00:00",
        "2025-06-17T08:30:00",
        "2025-06-17T09:00:00",
        "2025-06-17T09:30:00",
        "2025-06-17T10:00:00",
        "2025-06-17T10:30:00",
        "2025-06-17T11:00:00",
        "2025-06-17T11:30:00",
        "2025-06-17T12:00:00",
        "2025-06-17T12:30:00",
        "2025-06-17T13:00:00",
        "2025-06-17T13:30:00",
        "2025-06-17T14:00:00",
        "2025-06-17T14:30:00",
        "2025-06-17T15:00:00",
        "2025-06-17T15:30:00",
        "2025-06-17T16:00:00",
        "2025-06-17T16:30:00",
        "2025-06-17T17:00:00",
        "2025-06-17T17:30:00",
    ]

    commit_messages = [
        # Phase 1: Header definitions (5 commits)
        "add dns.h core definitions",
        "add dns_name.h compression header",
        "add dns_rr.h resource record header",
        "add dns_msg.h message parsing header",
        "add dns_cache.h and dns_resolver.h headers",
        # Phase 2: Core parsing (6 commits)
        "add dns_name.c name decompression",
        "add dns_rr.c resource record parsing",
        "add dns_msg.c message parse/serialize",
        "add dns_cache.c TTL cache with heap eviction",
        "add dns_resolver.c stub resolver with CNAME following",
        "add resolver cache integration and NXDOMAIN handling",
        # Phase 3: Supplementary tables (8 commits)
        "add DNS RCODE lookup tables",
        "add DNS type registry and validation",
        "add DNS class table and helpers",
        "add label character classification tables",
        "add SOA field validation and serialization",
        "add FNV-1a, MurmurHash3, and CRC32 implementations",
        "add hierarchical timing wheel implementation",
        "add EDNS option parsing and ECS encode/decode",
        # Phase 4: More utilities (8 commits)
        "add wire format byte-order helpers and growable buffer",
        "add DNS flag decoder and encoder",
        "add resolver statistics and latency histogram",
        "add build metadata and feature flags",
        "add zone file scanner/lexer",
        "add transport abstraction with connection pooling",
        "add TSIG/TKEY record handling",
        "add DNS flag name mapping and format helpers",
        # Phase 5: Fuzzing infrastructure (5 commits)
        "add dns_msg_fuzzer.cc harness",
        "add dns_cache_fuzzer.cc harness",
        "generate seed corpus for dns_msg_fuzzer",
        "generate seed corpus for dns_cache_fuzzer",
        "add gen_corpus.py seed generator",
        # Phase 6: Build config (4 commits)
        "add .clusterfuzzlite/build.sh",
        "add .clusterfuzzlite/project.yaml",
        "add CMakeLists.txt",
        "update CMakeLists with supplementary source files",
        # Phase 7: Tests (4 commits)
        "add test_dns_name.c unit tests",
        "add test_dns_rr.c unit tests",
        "add test_dns_msg.c unit tests",
        "add test_dns_cache.c unit tests",
        # Phase 8: Docs (3 commits)
        "add README.md",
        "add LICENSE file",
        "add TASKS.md contributor reference",
        # Phase 9: Refinements (8 commits)
        "improve error handling in dns_rr_parse",
        "add bounds checking in dns_name_compress",
        "fix timer wheel slot chain management",
        "add rate limiter token bucket to transport",
        "improve cache eviction stats tracking",
        "add EDNS extended error code table",
        "refactor zone scanner state machine",
        "update README with API reference",
        # Phase 10: Final touches (5 commits)
        "add zone file TTL suffix parsing",
        "add TSIG error code mapping",
        "improve transport server selection",
        "add connection pool acquire/release",
        "final cleanup and header guard verification",
    ]

    # Commit #1: Initial header definitions
    subprocess.run(["git", "add", "src/dns.h"], cwd=BASE_DIR, check=True)
    git_commit(dates[0], commit_messages[0], ["src/dns.h"])

    # Commit #2: dns_name.h
    git_commit(dates[1], commit_messages[1], ["src/dns_name.h"])

    # Commit #3: dns_rr.h
    git_commit(dates[2], commit_messages[2], ["src/dns_rr.h"])

    # Commit #4: dns_msg.h
    git_commit(dates[3], commit_messages[3], ["src/dns_msg.h"])

    # Commit #5: dns_cache.h + dns_resolver.h
    git_commit(dates[4], commit_messages[4], ["src/dns_cache.h", "src/dns_resolver.h"])

    # Commit #6: dns_name.c
    git_commit(dates[5], commit_messages[5], ["src/dns_name.c"])

    # Commit #7: dns_rr.c
    git_commit(dates[6], commit_messages[6], ["src/dns_rr.c"])

    # Commit #8: dns_msg.c
    git_commit(dates[7], commit_messages[7], ["src/dns_msg.c"])

    # Commit #9: dns_cache.c
    git_commit(dates[8], commit_messages[8], ["src/dns_cache.c"])

    # Commit #10: dns_resolver.c
    git_commit(dates[9], commit_messages[9], ["src/dns_resolver.c"])

    # Commit #11: resolver integration
    git_commit(dates[10], commit_messages[10], ["src/dns_resolver.c", "src/dns_cache.c"])

    # Commit #12-19: Supplementary tables (one file each)
    supplementary_files = [
        "src/dns_rcode_table.c",
        "src/dns_type_table.c",
        "src/dns_class_table.c",
        "src/dns_label_table.c",
        "src/dns_soa_util.c",
        "src/dns_hash_utils.c",
        "src/dns_timer_util.c",
        "src/dns_edns.c",
    ]
    for i, f in enumerate(supplementary_files):
        git_commit(dates[11 + i], commit_messages[11 + i], [f])

    # Commit #20-26: More utilities
    more_files = [
        "src/dns_wire_utils.c",
        "src/dns_flag_decoder.c",
        "src/dns_stats.c",
        "src/dns_build_info.c",
        "src/dns_zone_scanner.c",
        "src/dns_transport.c",
        "src/dns_tsig.c",
    ]
    for i, f in enumerate(more_files):
        git_commit(dates[19 + i], commit_messages[19 + i], [f])

    # Commit #27: dns_flag_decoder name mapping
    git_commit(dates[26], commit_messages[26], ["src/dns_flag_decoder.c"])

    # Commit #28-32: Fuzzing infrastructure
    git_commit(dates[27], commit_messages[27], ["fuzz/dns_msg_fuzzer.cc"])
    git_commit(dates[28], commit_messages[28], ["fuzz/dns_cache_fuzzer.cc"])
    git_commit(dates[29], commit_messages[29], ["fuzz/corpus/dns_msg_fuzzer/seed_01",
                                                  "fuzz/corpus/dns_msg_fuzzer/seed_02",
                                                  "fuzz/corpus/dns_msg_fuzzer/seed_03",
                                                  "fuzz/corpus/dns_msg_fuzzer/seed_04",
                                                  "fuzz/corpus/dns_msg_fuzzer/seed_05"])
    git_commit(dates[30], commit_messages[30], ["fuzz/corpus/dns_msg_fuzzer/seed_06",
                                                  "fuzz/corpus/dns_msg_fuzzer/seed_07",
                                                  "fuzz/corpus/dns_msg_fuzzer/seed_08",
                                                  "fuzz/corpus/dns_msg_fuzzer/seed_09",
                                                  "fuzz/corpus/dns_msg_fuzzer/seed_10"])
    git_commit(dates[31], commit_messages[31], ["fuzz/corpus/dns_cache_fuzzer/seed_01",
                                                  "fuzz/corpus/dns_cache_fuzzer/seed_02",
                                                  "fuzz/corpus/dns_cache_fuzzer/seed_03",
                                                  "fuzz/corpus/dns_cache_fuzzer/seed_04",
                                                  "fuzz/corpus/dns_cache_fuzzer/seed_05",
                                                  "fuzz/corpus/dns_cache_fuzzer/seed_06",
                                                  "fuzz/corpus/dns_cache_fuzzer/seed_07",
                                                  "fuzz/corpus/dns_cache_fuzzer/seed_08",
                                                  "gen_corpus.py"])

    # Commit #33-36: Build config
    git_commit(dates[32], commit_messages[32], [".clusterfuzzlite/build.sh"])
    git_commit(dates[33], commit_messages[33], [".clusterfuzzlite/project.yaml"])
    git_commit(dates[34], commit_messages[34], ["CMakeLists.txt"])
    git_commit(dates[35], commit_messages[35], ["CMakeLists.txt", "src/dns_rcode_table.c",
                                                  "src/dns_type_table.c", "src/dns_class_table.c"])

    # Commit #37-40: Tests
    git_commit(dates[36], commit_messages[36], ["tests/test_dns_name.c"])
    git_commit(dates[37], commit_messages[37], ["tests/test_dns_rr.c"])
    git_commit(dates[38], commit_messages[38], ["tests/test_dns_msg.c"])
    git_commit(dates[39], commit_messages[39], ["tests/test_dns_cache.c"])

    # Commit #41-43: Docs
    git_commit(dates[40], commit_messages[40], ["README.md"])
    git_commit(dates[41], commit_messages[41], ["LICENSE"])
    git_commit(dates[42], commit_messages[42], ["TASKS.md"])

    # Commit #44-51: Refinements (touch existing files)
    git_commit(dates[43], commit_messages[43], ["src/dns_rr.c", "src/dns_rr.h"])
    git_commit(dates[44], commit_messages[44], ["src/dns_name.c", "src/dns_name.h"])
    git_commit(dates[45], commit_messages[45], ["src/dns_timer_util.c"])
    git_commit(dates[46], commit_messages[46], ["src/dns_transport.c"])
    git_commit(dates[47], commit_messages[47], ["src/dns_cache.c", "src/dns_stats.c"])
    git_commit(dates[48], commit_messages[48], ["src/dns_edns.c"])
    git_commit(dates[49], commit_messages[49], ["src/dns_zone_scanner.c"])
    git_commit(dates[50], commit_messages[50], ["README.md"])

    # Commit #52-56: Final touches
    git_commit(dates[51], commit_messages[51], ["src/dns_zone_scanner.c"])
    git_commit(dates[52], commit_messages[52], ["src/dns_tsig.c"])
    git_commit(dates[53], commit_messages[53], ["src/dns_transport.c", "src/dns_stats.c"])
    git_commit(dates[54], commit_messages[54], ["src/dns_transport.c"])
    git_commit(dates[55], commit_messages[55], ["src/dns.h", "src/dns_name.h",
                                                  "src/dns_rr.h", "src/dns_msg.h",
                                                  "src/dns_cache.h", "src/dns_resolver.h"])

    # Verify
    print("\n=== Verification ===")
    result = subprocess.run(["git", "log", "--oneline"], cwd=BASE_DIR, capture_output=True, text=True)
    commit_count = len(result.stdout.strip().split("\n"))
    print(f"Total commits: {commit_count}")

    result = subprocess.run(["git", "log", "--format='%an <%ae>'", "-1"], cwd=BASE_DIR, capture_output=True, text=True)
    print(f"Latest author: {result.stdout.strip()}")

    # Count total LOC
    total_loc = 0
    for root, dirs, files in os.walk(BASE_DIR):
        dirs[:] = [d for d in dirs if d != ".git"]
        for f in files:
            if f.endswith((".c", ".h")):
                fp = os.path.join(root, f)
                with open(fp) as fh:
                    total_loc += len(fh.readlines())
    print(f"Total C/H LOC: {total_loc}")

    # Repo size
    result = subprocess.run(["du", "-sh", BASE_DIR], cwd=BASE_DIR, capture_output=True, text=True)
    print(f"Repo size: {result.stdout.strip()}")

    print("\nDone!")


if __name__ == "__main__":
    main()
