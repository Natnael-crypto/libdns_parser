#ifndef DNS_PARSER_DNS_NAME_H
#define DNS_PARSER_DNS_NAME_H

#include "dns.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Expand a DNS name from wire format at msg[offset] into out.
 * Handles compression pointers (0xC0 prefix).
 * Returns number of bytes consumed from the message on success,
 * or a negative DNS_ERR_* code on failure.
 */
int dns_name_expand(const uint8_t *msg, size_t msg_len, size_t offset,
                    char *out, size_t out_len);

/*
 * Write a DNS name in wire format into buf.
 * Names are dot-separated labels: "\x03www\x06google\x03com\x00"
 * Returns number of bytes written, or -1 on overflow.
 */
int dns_name_compress(const char *name, uint8_t *buf, size_t buf_len);

#ifdef __cplusplus
}
#endif

#endif /* DNS_PARSER_DNS_NAME_H */
