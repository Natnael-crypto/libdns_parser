# TASKS.md — Contributor Reference (DO NOT COMMIT)

## TASK 1 — Heap Buffer Overflow in dns_name_expand

### Task Description (submit this to the platform — max 80 words)
A heap buffer overflow occurs in `dns_name_expand` in `dns_name.c` when a crafted DNS message contains a compression pointer that points backward, causing the output buffer `out` to be written past its bounds. The pointer depth check is performed after increment rather than before, allowing extra iterations that advance the write cursor beyond `out_len` before the truncation check triggers.

### How to Trigger It (for creating the PoC)
1. Construct a DNS message where a compression pointer at offset N points to offset N-2 (two bytes before itself)
2. The pointer creates a backward jump, and the label at the new position has a large `len` value
3. The `out_written` counter advances past `out_len` before the check fires
4. Result: ASan fires `heap-buffer-overflow` on the `memcpy` into `out`

### PoC Input (hex bytes for binary, text for text formats)
```
00 00 81 80 00 01 00 00 00 00 00 00
07 65 78 61 6d 70 6c 65 03 63 6f 6d 00
00 01 00 01
C0 0A
```

### The Patch (do NOT commit this — apply only after PoC is accepted)
File: `src/dns_name.c`
Function: `dns_name_expand()`

BEFORE:
```c
if (ptr_depth++ > DNS_MAX_PTRS) {
    return DNS_ERR_LOOP;
}
```

AFTER:
```c
if (ptr_depth >= DNS_MAX_PTRS) {
    return DNS_ERR_LOOP;
}
ptr_depth++;
```

Explanation: The depth check must happen before the increment so that the limit is enforced on the Nth pointer follow, not after.

---

## TASK 2 — Use-After-Free via Cache TTL Eviction During Resolver Access

### Task Description (submit this to the platform — max 80 words)
A use-after-free occurs in `resolver_process_response` in `dns_resolver.c` when the resolver holds a borrowed reference to a cache entry that has been evicted and freed by a concurrent `dns_cache_tick` call. The function reads the `evicted` field of the cache reference without first verifying that the entry is still valid, causing a read from freed memory.

### How to Trigger It (for creating the PoC)
1. Call `dns_cache_lookup` to get a cache entry (sets `refs=1`)
2. Simulate a timeout retry by calling `dns_cache_unref` (drops `refs` to 0)
3. Call `dns_cache_tick` with a time past the entry's expiry (frees the entry since `refs==0`)
4. Call `resolver_process_response` which reads `r->cache_ref->evicted`
5. Result: ASan fires `heap-use-after-free`

### PoC Input (hex bytes for binary, text for text formats)
Sequence of operations encoded as binary:
```
01 00 01          # insert cache entry name=0, type=A
02 00 01          # lookup (gets ref)
04 00             # unref (drops ref to 0)
03 FF FF 00 00    # tick far into future (evicts entry, frees it)
02 00 01          # process response using stale cache_ref
```

### The Patch (do NOT commit this — apply only after PoC is accepted)
File: `src/dns_resolver.c`
Function: `resolver_process_response()`

BEFORE:
```c
if (r->cache_ref != NULL) {
    if (r->cache_ref->evicted) {
        dns_cache_unref(r->cache, r->cache_ref);
        r->cache_ref = NULL;
    }
}
```

AFTER:
```c
if (r->cache_ref != NULL) {
    if (r->cache_ref->refs <= 0 || r->cache_ref->evicted) {
        r->cache_ref = NULL;
    }
}
```

Explanation: Check the refcount before accessing the entry, and avoid calling unref on an entry that may already be freed.

---

## TASK 3 — Integer Overflow in TXT Record RDATA Concatenation

### Task Description (submit this to the platform — max 80 words)
An integer overflow occurs in `dns_rr_parse_txt` in `dns_rr.c` when a TXT record with a large `rdlength` contains many length-prefixed string segments. The running `total` accumulator can overflow, causing `realloc` to allocate a buffer smaller than expected. The subsequent `memcpy` writes past the undersized allocation. Additionally the final `rdlength` field is truncated to 16 bits.

### How to Trigger It (for creating the PoC)
1. Set the RR's `rdlength` to 65535 (0xFFFF)
2. Fill the RDATA with alternating 0xFF length bytes and data bytes
3. The `total += slen` loop runs ~256 times, accumulating enough to overflow on 32-bit or produce a mismatched allocation
4. Result: ASan fires `heap-buffer-overflow` on `memcpy` into `concat`

### PoC Input (hex bytes for binary, text for text formats)
```
00 C0 00 01 00 01 00 00 00 00 00 FF
FF 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00
(repeat: 0xFF length byte followed by 255 zero bytes, until RDATA fills 65535 bytes)
```

### The Patch (do NOT commit this — apply only after PoC is accepted)
File: `src/dns_rr.c`
Function: `dns_rr_parse_txt()`

BEFORE:
```c
total += slen;
if (i + slen > rdlength) break;
concat = realloc(concat, total + 1);
```

AFTER:
```c
if (total + slen < total) { free(concat); return DNS_ERR_NOMEM; }
total += slen;
if (i + slen > rdlength) break;
uint8_t *tmp = realloc(concat, total + 1);
if (!tmp) { free(concat); return DNS_ERR_NOMEM; }
concat = tmp;
```

Explanation: Check for size_t overflow before accumulating `total`, and handle realloc failure without leaking memory.

---

## TASK 4 — Double-Free in dns_msg_free Error Path

### Task Description (submit this to the platform — max 80 words)
A double-free occurs in `dns_msg_parse` and `dns_msg_free` in `dns_msg.c` when the answer section fails to parse midway. The `parse_section` function frees its own chain on error, but the caller also stores a pointer to the partially-freed chain in `msg->answers` and then calls `dns_msg_free`, which attempts to free the same chain again.

### How to Trigger It (for creating the PoC)
1. Construct a DNS message with a valid question section
2. Set `ANCOUNT` to 2
3. Make the first answer RR parse successfully (e.g., valid A record)
4. Make the second answer RR malformed (e.g., rdlength exceeds buffer)
5. `parse_section` frees the chain, then `dns_msg_free` frees it again
6. Result: ASan fires `double-free` in `dns_rr_chain_free`

### PoC Input (hex bytes for binary, text for text formats)
```
12 34 81 80 00 01 00 02 00 00 00 00
07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 00 01 00 01
C0 0C 00 01 00 01 00 00 01 2C 00 04 5D B8 D8 22
C0 0C 00 01 00 01 00 00 01 2C 00 FF
```

### The Patch (do NOT commit this — apply only after PoC is accepted)
File: `src/dns_msg.c`
Function: `parse_section()`

BEFORE:
```c
if (rc != 0) {
    free(rr);
    dns_rr_chain_free(head);
    return rc;
}
```

AFTER:
```c
if (rc != 0) {
    free(rr);
    dns_rr_chain_free(head);
    *out = NULL;
    return rc;
}
```

Explanation: Set `*out = NULL` before returning so the caller's `msg->answers` pointer is NULL, preventing double-free in `dns_msg_free`.

---

## TASK 5 — Stack Exhaustion via Mutual CNAME Pointer Following

### Task Description (submit this to the platform — max 80 words)
A stack exhaustion occurs in `resolver_follow_cname` in `dns_resolver.c` when a DNS response contains CNAME records forming a cycle (A CNAME B, B CNAME A). The recursive function accepts a `depth` parameter but never checks it against a maximum, causing infinite recursion until the stack overflows.

### How to Trigger It (for creating the PoC)
1. Construct a DNS response with two answer RRs:
   - RR1: name="a.example.com", type=CNAME, rdata="b.example.com"
   - RR2: name="b.example.com", type=CNAME, rdata="a.example.com"
2. Call `resolver_follow_cname(r, msg, "a.example.com", 0)`
3. Infinite recursion between the two CNAME entries
4. Result: Stack overflow / SIGSEGV

### PoC Input (hex bytes for binary, text for text formats)
```
12 34 81 80 00 01 00 02 00 00 00 00
01 61 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 00 01 00 01
C0 0C 00 05 00 01 00 00 01 2C 00 0F 01 62 C0 0D
01 62 C0 0D 00 05 00 01 00 00 01 2C 00 0F 01 61 C0 0D
```

### The Patch (do NOT commit this — apply only after PoC is accepted)
File: `src/dns_resolver.c`
Function: `resolver_follow_cname()`

BEFORE:
```c
DnsRR *resolver_follow_cname(Resolver *r, DnsMsg *msg, const char *name, int depth)
{
    for (DnsRR *rr = msg->answers; rr; rr = rr->next) {
        if (rr->rtype == DNS_T_CNAME && strcasecmp(rr->name, name) == 0) {
            char *target = (char *)rr->rdata;
            return resolver_follow_cname(r, msg, target, depth + 1);
        }
```

AFTER:
```c
DnsRR *resolver_follow_cname(Resolver *r, DnsMsg *msg, const char *name, int depth)
{
    if (depth >= RESOLVER_MAX_CNAME_DEPTH)
        return NULL;
    for (DnsRR *rr = msg->answers; rr; rr = rr->next) {
        if (rr->rtype == DNS_T_CNAME && strcasecmp(rr->name, name) == 0) {
            char *target = (char *)rr->rdata;
            return resolver_follow_cname(r, msg, target, depth + 1);
        }
```

Explanation: Add a depth limit check at the top of the function to prevent infinite recursion through CNAME cycles.

---

## TASK 6 — Heap Buffer Overflow in SOA Record RDATA Parsing

### Task Description (submit this to the platform — max 80 words)
A heap buffer overflow occurs in `dns_rr_parse_soa` in `dns_rr.c` when parsing an SOA record. The `dns_name_expand` return value (bytes consumed by mname) is discarded, so `off` is never advanced. The subsequent rdata fields are read from an incorrect offset that may point past the message buffer boundary.

### How to Trigger It (for creating the PoC)
1. Construct a DNS message with an SOA record answer
2. The SOA RDATA contains mname followed by rname and 5 uint32_t fields
3. Since `off` is not advanced past mname, the rname and numeric fields are read from the wrong position
4. Result: ASan fires `heap-buffer-overflow` on the `memcpy` reading past `rdata`

### PoC Input (hex bytes for binary, text for text formats)
```
12 34 81 80 00 01 00 01 00 00 00 00
07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 00 06 00 01
C0 0C 00 06 00 01 00 00 01 2C 00 2B
03 6E 73 31 C0 0C 05 61 64 6D 69 6E C0 0C
00 00 00 01 00 00 0E 10 00 00 03 84
00 00 00 3C 00 00 01 2C 00 00 01 00
```

### The Patch (do NOT commit this — apply only after PoC is accepted)
File: `src/dns_rr.c`
Function: `dns_rr_parse_soa()`

BEFORE:
```c
dns_name_expand(msg, msg_len, off, soa->mname, DNS_MAX_NAME);
dns_name_expand(msg, msg_len, off, soa->rname, DNS_MAX_NAME);
```

AFTER:
```c
int mname_len = dns_name_expand(msg, msg_len, off, soa->mname, DNS_MAX_NAME);
if (mname_len < 0) { free(soa); return mname_len; }
off += (size_t)mname_len;
int rname_len = dns_name_expand(msg, msg_len, off, soa->rname, DNS_MAX_NAME);
if (rname_len < 0) { free(soa); return rname_len; }
off += (size_t)rname_len;
```

Explanation: Capture the return value of `dns_name_expand` and advance `off` by the number of bytes consumed by each name expansion.

---

## TASK 7 — Use-After-Free in Cache Heap Rebalance During Eviction

### Task Description (submit this to the platform — max 80 words)
A use-after-free occurs in `dns_cache_tick` in `dns_cache.c` during heap rebalancing. After `cache_heap_remove` replaces the root entry, the removed entry may have already been freed if its refcount reached zero inside the removal path. The function then writes to the freed entry's `evicted` field without checking whether the entry is still valid.

### How to Trigger It (for creating the PoC)
1. Insert multiple cache entries with short TTLs and `refs=0`
2. Insert a second entry that causes a heap rebalance cascade during removal
3. Advance the clock past all entry expiry times
4. `cache_heap_remove` triggers the cascade that frees the root entry
5. `dns_cache_tick` writes `entry->evicted = true` to freed memory
6. Result: ASan fires `heap-use-after-free`

### PoC Input (hex bytes for binary, text for text formats)
```
01 00 01          # INSERT name=0, type=A (short TTL)
01 01 01          # INSERT name=1, type=A (short TTL)
01 02 01          # INSERT name=2, type=A (short TTL)
03 FF FF 00 00    # TICK far into future (evicts all, triggers cascade)
```

### The Patch (do NOT commit this — apply only after PoC is accepted)
File: `src/dns_cache.c`
Function: `dns_cache_tick()`

BEFORE:
```c
CacheEntry *entry = cache->heap[0];
cache_heap_remove(cache, 0);
entry->evicted = true;
if (entry->refs == 0) {
    cache_entry_free(entry);
}
```

AFTER:
```c
CacheEntry *entry = cache->heap[0];
cache_heap_remove(cache, 0);
if (entry->refs > 0) {
    entry->evicted = true;
} else {
    cache_entry_free(entry);
}
```

Explanation: Only access the entry's fields if it still has outstanding references; otherwise free it immediately without touching its memory.

---

## TASK 8 — OOB Read in MX Record Preference Parsing

### Task Description (submit this to the platform — max 80 words)
An out-of-bounds read occurs in `dns_rr_parse_mx` in `dns_rr.c` when an MX record has an undersized RDATA field (rdlength of 0 or 1). The function reads 2 bytes for the preference field without first checking that `rdlength >= 2`, causing a read past the allocated RDATA buffer.

### How to Trigger It (for creating the PoC)
1. Construct a DNS message with an MX record answer where `rdlength = 0`
2. `dns_rr_parse` passes `rdata` pointing at an empty area
3. `memcpy(&pref, rdata, 2)` reads 2 bytes past the rdata allocation
4. Result: ASan fires `heap-buffer-overflow` (read)

### PoC Input (hex bytes for binary, text for text formats)
```
12 34 81 80 00 01 00 01 00 00 00 00
07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 00 0F 00 01
C0 0C 00 0F 00 01 00 00 01 2C 00 00
```

### The Patch (do NOT commit this — apply only after PoC is accepted)
File: `src/dns_rr.c`
Function: `dns_rr_parse_mx()`

BEFORE:
```c
uint16_t pref;
memcpy(&pref, rdata, 2);
```

AFTER:
```c
if (rdlength < 2) return DNS_ERR_PARSE;
uint16_t pref;
memcpy(&pref, rdata, 2);
```

Explanation: Validate that the RDATA buffer contains at least 2 bytes before reading the preference field.

---

## TASK 9 — Integer Truncation in Cache Hash Causing Silent Collision Corruption

### Task Description (submit this to the platform — max 80 words)
An integer truncation in `dns_cache.c` causes entries to be inserted and looked up in different hash buckets. `dns_cache_insert` truncates the hash to `uint8_t` (8 bits) while `dns_cache_lookup` uses the full `uint32_t` hash modulo `DNS_CACHE_BUCKETS`. When the hash values differ after these operations, entries alias across buckets, leading to UAF when one bucket frees an entry referenced by another.

### How to Trigger It (for creating the PoC)
1. Find two names where `dns_name_hash(name1) & 0xFF != dns_name_hash(name1) % 256`
2. Insert entry for name1 (goes to bucket `hash & 0xFF`)
3. Look up entry for name1 (searches bucket `hash % 256` — different bucket)
4. The lookup finds a stale entry from a different chain, or an aliased entry gets double-freed
5. Result: ASan fires `heap-use-after-free`

### PoC Input (hex bytes for binary, text for text formats)
```
01 00 01          # INSERT name=0, type=A
01 01 01          # INSERT name=1, type=A (different bucket in lookup)
02 00 01          # LOOKUP name=0 (different bucket than insert)
04 00             # UNREF
03 FF FF 00 00    # TICK (may free aliased entries)
```

### The Patch (do NOT commit this — apply only after PoC is accepted)
File: `src/dns_cache.c`
Function: `dns_cache_insert()` and `dns_cache_lookup()`

BEFORE (insert):
```c
uint8_t bucket = (uint8_t)(dns_name_hash(name, qtype));
```

AFTER (insert):
```c
uint32_t bucket = dns_name_hash(name, qtype) % DNS_CACHE_BUCKETS;
```

Explanation: Use the same bucket computation in both insert and lookup to ensure entries are always found where they were placed.

---

## TASK 10 — Null Pointer Dereference in Resolver NXDOMAIN Handling

### Task Description (submit this to the platform — max 80 words)
A null pointer dereference occurs in `resolver_handle_nxdomain` in `dns_resolver.c` when processing an NXDOMAIN response that has no SOA record in the authority section. The function searches for an SOA record but does not check whether one was found before dereferencing the pointer to extract the negative TTL.

### How to Trigger It (for creating the PoC)
1. Construct a DNS response with `rcode=3` (NXDOMAIN)
2. Set `NSCOUNT=0` (empty authority section, no SOA)
3. Call `resolver_handle_nxdomain` or route through `resolver_process_response`
4. `soa` remains NULL, then `soa->rdata` is dereferenced
5. Result: ASan fires `null-dereference` / SIGSEGV

### PoC Input (hex bytes for binary, text for text formats)
```
12 34 81 83 00 01 00 00 00 00 00 00
07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 00 01 00 01
```

### The Patch (do NOT commit this — apply only after PoC is accepted)
File: `src/dns_resolver.c`
Function: `resolver_handle_nxdomain()`

BEFORE:
```c
SoaData *sd = (SoaData *)soa->rdata;
uint32_t neg_ttl = ntohl(sd->minimum);
```

AFTER:
```c
uint32_t neg_ttl = 3600; /* default negative TTL */
if (soa) {
    SoaData *sd = (SoaData *)soa->rdata;
    neg_ttl = ntohl(sd->minimum);
}
```

Explanation: Check that an SOA record was actually found before dereferencing it, falling back to a default negative TTL if none exists.
