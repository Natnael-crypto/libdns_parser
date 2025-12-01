# dns_parser

A lightweight C library for parsing, serializing, and resolving DNS messages in wire format (RFC 1035). Provides structured access to DNS headers, questions, and all standard resource record types including A, AAAA, CNAME, NS, MX, TXT, and SOA. Includes a simple cache with TTL-based eviction and a stub resolver with CNAME chain following.

## Building

```bash
mkdir build && cd build
cmake ..
make
```

## Running Tests

```bash
cd build
ctest --output-on-failure
```

Or run individual test binaries:

```bash
./test_dns_name
./test_dns_rr
./test_dns_msg
```

## API Reference

### Core Types

| Type | Description |
|------|-------------|
| `DnsHeader` | 12-byte DNS message header |
| `DnsQuestion` | DNS question entry (name, type, class) |
| `DnsRR` | Resource record (linked list node) |
| `DnsMsg` | Parsed DNS message with all sections |
| `SoaData` | Decoded SOA record data |
| `MxData` | Decoded MX record data |

### Message Parsing

```c
int dns_msg_parse(const uint8_t *buf, size_t len, DnsMsg *msg);
void dns_msg_free(DnsMsg *msg);
int dns_msg_serialize(const DnsMsg *msg, uint8_t *buf, size_t buf_len);
```

### Name Handling

```c
int dns_name_expand(const uint8_t *msg, size_t msg_len, size_t offset,
                    char *out, size_t out_len);
int dns_name_compress(const char *name, uint8_t *buf, size_t buf_len);
```

### Resource Records

```c
int dns_rr_parse(const uint8_t *buf, size_t len, size_t *off, DnsRR *rr);
void dns_rr_free(DnsRR *rr);
void dns_rr_chain_free(DnsRR *head);
```

### Cache

```c
DnsCache *dns_cache_create(size_t max_entries);
void dns_cache_destroy(DnsCache *cache);
int dns_cache_insert(DnsCache *cache, const char *name, uint16_t qtype,
                     DnsRR *records, uint32_t ttl, uint32_t current_time);
CacheEntry *dns_cache_lookup(DnsCache *cache, const char *name, uint16_t qtype);
void dns_cache_tick(DnsCache *cache, uint32_t new_time);
```

### Resolver

```c
Resolver *resolver_create(DnsCache *cache);
void resolver_destroy(Resolver *r);
int resolver_query(Resolver *r, const char *name, uint16_t qtype, uint32_t query_id);
int resolver_process_response(Resolver *r, DnsMsg *msg);
DnsRR *resolver_follow_cname(Resolver *r, DnsMsg *msg, const char *name, int depth);
```

## Known Limitations

- Does not support DNSSEC validation or EDNS(0) extension options.
- The cache uses a fixed-size hash table which may not perform well under high key-collision scenarios.
