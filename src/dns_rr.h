#ifndef DNS_PARSER_DNS_RR_H
#define DNS_PARSER_DNS_RR_H

#include "dns.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Parse one resource record starting at *off in buf.
 * Advances *off past the parsed RR.
 * Populates rr (caller-allocated).
 * Returns DNS_OK or DNS_ERR_*. */
int dns_rr_parse(const uint8_t *buf, size_t len, size_t *off, DnsRR *rr);

/* Free an RR and its rdata */
void dns_rr_free(DnsRR *rr);

/* Free a linked list of RRs */
void dns_rr_chain_free(DnsRR *head);

/* Type-specific parsers (called internally by dns_rr_parse) */
int dns_rr_parse_txt(const uint8_t *rdata, uint16_t rdlength, DnsRR *rr);
int dns_rr_parse_soa(const uint8_t *msg, size_t msg_len,
                     const uint8_t *rdata, uint16_t rdlength, DnsRR *rr);
int dns_rr_parse_mx(const uint8_t *msg, size_t msg_len,
                    const uint8_t *rdata, uint16_t rdlength, DnsRR *rr);

#ifdef __cplusplus
}
#endif

#endif /* DNS_PARSER_DNS_RR_H */
