#ifndef DNS_PARSER_DNS_MSG_H
#define DNS_PARSER_DNS_MSG_H

#include "dns.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Parse a raw DNS message buffer into a DnsMsg struct.
 * Returns DNS_OK or DNS_ERR_*. On error, msg is partially filled
 * and caller should call dns_msg_free(). */
int dns_msg_parse(const uint8_t *buf, size_t len, DnsMsg *msg);

/* Free a parsed DNS message and all owned memory */
void dns_msg_free(DnsMsg *msg);

/* Serialize a DnsMsg into a wire-format buffer.
 * Returns bytes written or -1 on error. */
int dns_msg_serialize(const DnsMsg *msg, uint8_t *buf, size_t buf_len);

#ifdef __cplusplus
}
#endif

#endif /* DNS_PARSER_DNS_MSG_H */
