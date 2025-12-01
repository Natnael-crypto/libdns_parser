#!/usr/bin/env python3
"""Generate seed corpus files for dns_msg_fuzzer and dns_cache_fuzzer."""
import struct, os

def write_seed(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as f:
        f.write(data)
    print(f'  {path} ({len(data)} bytes)')

def dns_header(id_val=0x1234, flags=0x8180, qd=1, an=0, ns=0, ar=0):
    return struct.pack('!HHHHHH', id_val, flags, qd, an, ns, ar)

def qname_from_labels(*labels):
    out = b''
    for lab in labels:
        out += bytes([len(lab)]) + lab.encode()
    out += b'\x00'
    return out

def question_section(name_bytes, qtype=1, qclass=1):
    return name_bytes + struct.pack('!HH', qtype, qclass)

def answer_rr(name_bytes, rtype=1, rclass=1, ttl=300, rdata=b''):
    return name_bytes + struct.pack('!HHI', rtype, rclass, ttl) + \
           struct.pack('!H', len(rdata)) + rdata

def compression_ptr(offset):
    return bytes([0xC0 | (offset >> 8), offset & 0xFF])

print('=== dns_msg_fuzzer seeds ===')

# seed_01: minimal A query (no response)
write_seed('fuzz/corpus/dns_msg_fuzzer/seed_01',
    dns_header(flags=0x0100, qd=1, an=0) +
    question_section(qname_from_labels('example', 'com'), 1, 1))

# seed_02: A response with one answer
write_seed('fuzz/corpus/dns_msg_fuzzer/seed_02',
    dns_header(flags=0x8180, qd=1, an=1) +
    question_section(qname_from_labels('example', 'com'), 1, 1) +
    answer_rr(qname_from_labels('example', 'com'), 1, 1, 300,
              bytes([93, 184, 216, 34])))

# seed_03: CNAME + A response chain
cname_rdata = qname_from_labels('www', 'example', 'com')
a_rdata = bytes([93, 184, 216, 34])
write_seed('fuzz/corpus/dns_msg_fuzzer/seed_03',
    dns_header(flags=0x8180, qd=1, an=2) +
    question_section(qname_from_labels('example', 'com'), 1, 1) +
    answer_rr(qname_from_labels('example', 'com'), 5, 1, 300, cname_rdata) +
    answer_rr(qname_from_labels('www', 'example', 'com'), 1, 1, 300, a_rdata))

# seed_04: MX response
mx_rdata = struct.pack('!H', 10) + qname_from_labels('mail', 'example', 'com')
write_seed('fuzz/corpus/dns_msg_fuzzer/seed_04',
    dns_header(flags=0x8180, qd=1, an=1) +
    question_section(qname_from_labels('example', 'com'), 15, 1) +
    answer_rr(qname_from_labels('example', 'com'), 15, 1, 300, mx_rdata))

# seed_05: TXT response
txt_rdata = b'\x0bhello world'
write_seed('fuzz/corpus/dns_msg_fuzzer/seed_05',
    dns_header(flags=0x8180, qd=1, an=1) +
    question_section(qname_from_labels('example', 'com'), 16, 1) +
    answer_rr(qname_from_labels('example', 'com'), 16, 1, 300, txt_rdata))

# seed_06: SOA response
soa_mname = qname_from_labels('ns1', 'example', 'com')
soa_rname = qname_from_labels('admin', 'example', 'com')
soa_data = soa_mname + soa_rname + struct.pack('!IIIII', 2024010101, 3600, 900, 604800, 86400)
write_seed('fuzz/corpus/dns_msg_fuzzer/seed_06',
    dns_header(flags=0x8180, qd=1, an=1) +
    question_section(qname_from_labels('example', 'com'), 6, 1) +
    answer_rr(qname_from_labels('example', 'com'), 6, 1, 300, soa_data))

# seed_07: AAAA response
aaaa_rdata = bytes([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 1])
write_seed('fuzz/corpus/dns_msg_fuzzer/seed_07',
    dns_header(flags=0x8180, qd=1, an=1) +
    question_section(qname_from_labels('example', 'com'), 28, 1) +
    answer_rr(qname_from_labels('example', 'com'), 28, 1, 300, aaaa_rdata))

# seed_08: NXDOMAIN with SOA authority
write_seed('fuzz/corpus/dns_msg_fuzzer/seed_08',
    dns_header(flags=0x8183, qd=1, an=0, ns=1) +
    question_section(qname_from_labels('nonexistent', 'example', 'com'), 1, 1) +
    answer_rr(qname_from_labels('example', 'com'), 6, 1, 300, soa_data))

# seed_09: response with compression pointer
compressed_name = bytes([0xC0, 0x0C])  # pointer to offset 12 (start of question)
write_seed('fuzz/corpus/dns_msg_fuzzer/seed_09',
    dns_header(flags=0x8180, qd=1, an=1) +
    question_section(qname_from_labels('test', 'com'), 1, 1) +
    answer_rr(compressed_name, 1, 1, 300, bytes([127, 0, 0, 1])))

# seed_10: empty message (just header, no questions)
write_seed('fuzz/corpus/dns_msg_fuzzer/seed_10',
    dns_header(flags=0x8180, qd=0, an=0, ns=0, ar=0))

print()
print('=== dns_cache_fuzzer seeds ===')

# seed_01: single insert then lookup
write_seed('fuzz/corpus/dns_cache_fuzzer/seed_01',
    bytes([0x01, 0x00,   # INSERT name=0
            0x02, 0x01,   # LOOKUP name=1
            0x04, 0x00])) # UNREF

# seed_02: insert, tick, lookup
write_seed('fuzz/corpus/dns_cache_fuzzer/seed_02',
    bytes([0x01, 0x00,   # INSERT name=0
            0x03, 0x00, 0x01, 0x00, 0x00,  # TICK to time 256
            0x02, 0x00])) # LOOKUP name=0

# seed_03: multiple inserts and lookups
write_seed('fuzz/corpus/dns_cache_fuzzer/seed_03',
    bytes([0x01, 0x00, 0x01,  # INSERT name=0, type=1
            0x01, 0x01, 0x01,  # INSERT name=1, type=1
            0x01, 0x02, 0x01,  # INSERT name=2, type=1
            0x02, 0x00, 0x01,  # LOOKUP name=0
            0x02, 0x01, 0x01,  # LOOKUP name=1
            0x04, 0x00, 0x00])) # UNREF, tick

# seed_04: negative cache insert
write_seed('fuzz/corpus/dns_cache_fuzzer/seed_04',
    bytes([0x05, 0x00, 0x01,  # INSERT_NEG name=0
            0x02, 0x00, 0x01,  # LOOKUP name=0
            0x03, 0x00, 0x01, 0x00, 0x00])) # TICK

# seed_05: insert, then process response
write_seed('fuzz/corpus/dns_cache_fuzzer/seed_05',
    bytes([0x01, 0x00, 0x01,  # INSERT
            0x02, 0x00, 0x01,  # LOOKUP
            0x06, 0x00, 0x00])) # PROCESS

# seed_06: process response directly (no prior insert)
write_seed('fuzz/corpus/dns_cache_fuzzer/seed_06',
    bytes([0x06, 0x00, 0x00, 0x06, 0x01, 0x00]))

# seed_07: stress with many inserts
seeds = []
for i in range(8):
    seeds.append(0x01)
    seeds.append(i)
    seeds.append(0x01)
for i in range(4):
    seeds.append(0x02)
    seeds.append(i)
    seeds.append(0x01)
seeds.extend([0x04, 0x00, 0x04, 0x01, 0x00])
write_seed('fuzz/corpus/dns_cache_fuzzer/seed_07', bytes(seeds))

# seed_08: tick with large time jump
write_seed('fuzz/corpus/dns_cache_fuzzer/seed_08',
    bytes([0x01, 0x00, 0x01,
            0x01, 0x01, 0x01,
            0x05, 0x02, 0x01,
            0x03, 0xFF, 0xFF, 0x00, 0x00]))

print()
print('Done!')
