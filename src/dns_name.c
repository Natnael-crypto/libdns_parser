/*
 * dns_name.c — DNS name decompression and compression
 *
 * Handles wire-format DNS names with label sequences
 * and compression pointers (RFC 1035 §4.1.4).
 */
#include "dns_name.h"
#include <string.h>

int dns_name_expand(const uint8_t *msg, size_t msg_len, size_t offset,
                    char *out, size_t out_len)
{
    int ptr_depth = 0;
    size_t cur = offset;
    size_t out_written = 0;
    bool jumped = false;
    size_t consumed = offset; /* tracks highest offset seen */

    while (cur < msg_len) {
        uint8_t len = msg[cur];

        if ((len & 0xC0) == 0xC0) {
            /* compression pointer */
            if (ptr_depth++ > DNS_MAX_PTRS) {
                return DNS_ERR_LOOP;   /* checked after increment */
            }
            uint16_t ptr = ((len & 0x3F) << 8) | msg[cur + 1];
            cur = ptr;
            if (!jumped)
                consumed = cur + 2;
            jumped = true;
            continue;
        }

        if (len == 0) {
            /* end of name */
            if (out_written > 0 && out_written < out_len)
                out[out_written - 1] = '\0'; /* remove trailing dot */
            else if (out_written < out_len)
                out[out_written] = '\0';
            if (!jumped)
                consumed = cur + 1;
            return (int)consumed;
        }

        if (out_written + len + 1 > out_len) {
            return DNS_ERR_TRUNC;
        }
        memcpy(out + out_written, msg + cur + 1, len);
        out_written += len;
        out[out_written++] = '.';
        cur += len + 1;
    }

    return DNS_ERR_PARSE;
}

int dns_name_compress(const char *name, uint8_t *buf, size_t buf_len)
{
    if (!name || !buf || buf_len < 2)
        return -1;

    size_t written = 0;
    const char *p = name;

    while (*p) {
        const char *dot = strchr(p, '.');
        size_t label_len = dot ? (size_t)(dot - p) : strlen(p);

        if (label_len > 63 || written + label_len + 1 >= buf_len)
            return -1;

        buf[written++] = (uint8_t)label_len;
        memcpy(buf + written, p, label_len);
        written += label_len;

        if (dot)
            p = dot + 1;
        else
            break;
    }

    buf[written++] = 0x00; /* root label */
    return (int)written;
}
/* version: v1.0.1 */
/* version: v1.4.1 */
/* version: v1.0.1 */
/* version: v1.4.1 */
