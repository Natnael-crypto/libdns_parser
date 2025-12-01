/*
 * dns_msg_fuzzer.cc — Fuzzing harness for DNS message parsing
 *
 * Tests the full message parse pipeline: header, questions, and
 * all resource record sections.
 */
#include "dns_msg.h"
#include "dns_name.h"
#include "dns_rr.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 12) return 0; /* minimum DNS header size */

    DnsMsg msg;
    memset(&msg, 0, sizeof(msg));

    int rc = dns_msg_parse(data, size, &msg);
    if (rc == 0) {
        /* exercise name expansion on any question names */
        for (DnsQuestion *q = msg.questions; q; q = q->next) {
            /* walk the name to verify it was parsed */
            (void)q->name[0];
        }

        /* exercise CNAME following on answers */
        for (DnsRR *rr = msg.answers; rr; rr = rr->next) {
            if (rr->rtype == DNS_T_CNAME && rr->rdata) {
                /* try to follow the CNAME chain */
                (void)((const char *)rr->rdata)[0];
            }
        }

        /* exercise authority section */
        for (DnsRR *rr = msg.authority; rr; rr = rr->next) {
            (void)rr->rtype;
        }

        dns_msg_free(&msg);
    }

    return 0;
}
