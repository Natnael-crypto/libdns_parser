/* dns_transport - UDP/TCP transport abstraction with connection pooling and retry */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

typedef enum { DNS_TRANSPORT_UDP, DNS_TRANSPORT_TCP, DNS_TRANSPORT_TLS, DNS_TRANSPORT_HTTPS } dns_transport_type_t;
typedef enum { DNS_TRANSPORT_IDLE, DNS_TRANSPORT_CONNECTING, DNS_TRANSPORT_CONNECTED, DNS_TRANSPORT_ERROR } dns_transport_state_t;

typedef struct {
    int fd;
    dns_transport_type_t type;
    dns_transport_state_t state;
    char server_addr[256];
    uint16_t server_port;
    uint32_t timeout_ms;
    uint8_t *send_buf, *recv_buf;
    size_t send_len, recv_len, recv_cap;
    time_t last_activity;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint32_t retry_count;
    uint32_t max_retries;
} dns_transport_conn_t;

typedef struct {
    dns_transport_conn_t conns[128];
    size_t conn_count;
    uint32_t default_timeout;
} dns_transport_t;

int dns_transport_init(dns_transport_t *t) {
    memset(t, 0, sizeof(*t)); t->default_timeout = 5000;
    return 0;
}

void dns_transport_free(dns_transport_t *t) {
    for (size_t i = 0; i < t->conn_count; i++) {
        free(t->conns[i].send_buf);
        free(t->conns[i].recv_buf);
    }
    memset(t, 0, sizeof(*t));
}

int dns_transport_send(dns_transport_t *t, size_t ci, const uint8_t *data, size_t len) {
    if (ci >= t->conn_count) return -1;
    dns_transport_conn_t *c = &t->conns[ci];
    free(c->send_buf);
    c->send_buf = malloc(len);
    if (!c->send_buf) return -1;
    memcpy(c->send_buf, data, len);
    c->send_len = len;
    c->last_activity = time(NULL);
    c->bytes_sent += len;
    return 0;
}

/* Add a new connection to the transport pool. Returns the connection index. */
int dns_transport_add_conn(dns_transport_t *t, const char *addr,
                           uint16_t port, dns_transport_type_t type) {
    if (t->conn_count >= 128) return -1;
    dns_transport_conn_t *c = &t->conns[t->conn_count];
    memset(c, 0, sizeof(*c));
    c->fd = -1;
    c->type = type;
    c->state = DNS_TRANSPORT_IDLE;
    strncpy(c->server_addr, addr, 255);
    c->server_port = port;
    c->timeout_ms = t->default_timeout;
    c->max_retries = 3;
    c->last_activity = time(NULL);
    return (int)(t->conn_count++);
}

/* Remove a connection from the pool by index. */
int dns_transport_remove_conn(dns_transport_t *t, size_t ci) {
    if (ci >= t->conn_count) return -1;
    free(t->conns[ci].send_buf);
    free(t->conns[ci].recv_buf);
    if (ci < t->conn_count - 1) {
        t->conns[ci] = t->conns[t->conn_count - 1];
    }
    t->conn_count--;
    return 0;
}

/* Find a connection by server address and port. Returns index or -1. */
int dns_transport_find_conn(const dns_transport_t *t, const char *addr, uint16_t port) {
    for (size_t i = 0; i < t->conn_count; i++) {
        if (t->conns[i].server_port == port &&
            strcmp(t->conns[i].server_addr, addr) == 0) {
            return (int)i;
        }
    }
    return -1;
}

/* Find the least-recently-used idle connection. Returns index or -1. */
int dns_transport_find_lru(const dns_transport_t *t) {
    int lru = -1;
    time_t oldest = time(NULL);
    for (size_t i = 0; i < t->conn_count; i++) {
        if (t->conns[i].state == DNS_TRANSPORT_IDLE &&
            t->conns[i].last_activity < oldest) {
            oldest = t->conns[i].last_activity;
            lru = (int)i;
        }
    }
    return lru;
}

/* Mark a connection as timed out. Increments retry count. */
void dns_transport_mark_timeout(dns_transport_t *t, size_t ci) {
    if (ci >= t->conn_count) return;
    dns_transport_conn_t *c = &t->conns[ci];
    c->retry_count++;
    c->state = DNS_TRANSPORT_IDLE;
    free(c->send_buf); c->send_buf = NULL; c->send_len = 0;
}

/* Check if a connection has exceeded its retry limit. */
int dns_transport_is_exhausted(const dns_transport_t *t, size_t ci) {
    if (ci >= t->conn_count) return 1;
    return t->conns[ci].retry_count >= t->conns[ci].max_retries;
}

/* Set the send buffer for TCP with a 2-byte length prefix (RFC 1035 s4.2.2). */
int dns_transport_tcp_frame(dns_transport_conn_t *c, const uint8_t *data, size_t len) {
    if (len > 65535) return -1;
    free(c->send_buf);
    c->send_buf = malloc(2 + len);
    if (!c->send_buf) return -1;
    c->send_buf[0] = (uint8_t)(len >> 8);
    c->send_buf[1] = (uint8_t)(len & 0xFF);
    memcpy(c->send_buf + 2, data, len);
    c->send_len = 2 + len;
    c->last_activity = time(NULL);
    return 0;
}

/* Parse a TCP length-prefixed DNS response.
   Returns the DNS message length, or -1 if incomplete/error. */
int dns_transport_tcp_deframe(const uint8_t *buf, size_t buf_len,
                              uint8_t *msg, size_t msg_max, size_t *msg_len) {
    if (buf_len < 2) return -1;
    uint16_t frame_len = (uint16_t)((buf[0] << 8) | buf[1]);
    if (frame_len == 0 || frame_len > 65535) return -1;
    if (buf_len < 2 + frame_len) return -1; /* incomplete frame */
    if (frame_len > msg_max) return -1;
    memcpy(msg, buf + 2, frame_len);
    *msg_len = frame_len;
    return (int)(2 + frame_len);
}

/* Find a connection that has pending data to send. Returns index or -1. */
int dns_transport_find_pending(const dns_transport_t *t) {
    for (size_t i = 0; i < t->conn_count; i++) {
        if (t->conns[i].send_buf && t->conns[i].send_len > 0 &&
            t->conns[i].state == DNS_TRANSPORT_CONNECTED) {
            return (int)i;
        }
    }
    return -1;
}

/* Count connections in a given state. */
size_t dns_transport_count_state(const dns_transport_t *t, dns_transport_state_t state) {
    size_t count = 0;
    for (size_t i = 0; i < t->conn_count; i++) {
        if (t->conns[i].state == state) count++;
    }
    return count;
}

/* Compute the average bytes per query across all connections. */
double dns_transport_avg_bytes_per_query(const dns_transport_t *t) {
    uint64_t total_bytes = 0;
    uint64_t total_queries = 0;
    for (size_t i = 0; i < t->conn_count; i++) {
        total_bytes += t->conns[i].bytes_sent + t->conns[i].bytes_received;
        total_queries += t->conns[i].bytes_sent > 0 ? 1 : 0;
    }
    return total_queries == 0 ? 0.0 : (double)total_bytes / (double)total_queries;
}

/* Reset all retry counters for a connection. */
void dns_transport_reset_retries(dns_transport_t *t, size_t ci) {
    if (ci >= t->conn_count) return;
    t->conns[ci].retry_count = 0;
}

/* Select the best transport type based on server capabilities.
   Prefers UDP for small messages, TCP for large or truncated. */
dns_transport_type_t dns_transport_select_type(size_t msg_len, int truncated) {
    if (truncated || msg_len > 512) return DNS_TRANSPORT_TCP;
    return DNS_TRANSPORT_UDP;
}
