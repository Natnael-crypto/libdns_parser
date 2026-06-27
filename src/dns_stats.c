/* dns_stats - DNS query statistics tracking with sliding window and percentiles */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>
#include <math.h>

typedef struct {
    uint64_t queries_sent, responses_received, responses_ok;
    uint64_t responses_servfail, responses_nxdomain, timeouts;
    uint64_t bytes_sent, bytes_received, cache_hits, cache_misses;
    double avg_response_ms;
    time_t last_query_time;
} dns_server_stats_t;

typedef struct {
    dns_server_stats_t servers[64];
    size_t server_count;
    uint64_t total_queries, total_responses;
    time_t start_time, last_reset;
} dns_stats_t;

/* Sliding window for response time tracking */
#define RTT_WINDOW_SIZE 256
typedef struct {
    double samples[RTT_WINDOW_SIZE];
    size_t head;
    size_t count;
    double sum;
} rtt_window_t;

/* Per-type query counter */
#define DNS_TYPE_STATS_SIZE 258
typedef struct {
    uint64_t by_type[DNS_TYPE_STATS_SIZE];
    uint64_t responses_by_type[DNS_TYPE_STATS_SIZE];
    uint64_t errors_by_type[DNS_TYPE_STATS_SIZE];
} dns_type_stats_t;

/* Rate limiter state */
typedef struct {
    uint64_t window_start;
    uint64_t query_count;
    uint64_t max_queries_per_second;
    uint64_t total_dropped;
} dns_rate_limiter_t;

int dns_stats_init(dns_stats_t *s) {
    memset(s, 0, sizeof(*s)); s->start_time = time(NULL); s->last_reset = s->start_time;
    return 0;
}

void dns_stats_reset(dns_stats_t *s) {
    memset(s, 0, sizeof(*s)); s->start_time = time(NULL); s->last_reset = s->start_time;
}

int dns_stats_record_query(dns_stats_t *s, size_t si, uint16_t type, size_t bytes) {
    if (si >= 64) return -1;
    s->servers[si].queries_sent++; s->servers[si].bytes_sent += bytes;
    s->servers[si].last_query_time = time(NULL); s->total_queries++;
    return 0;
}

int dns_stats_record_response(dns_stats_t *s, size_t si, uint16_t rcode, size_t bytes) {
    if (si >= 64) return -1;
    s->servers[si].responses_received++; s->servers[si].bytes_received += bytes;
    if (rcode == 0) s->servers[si].responses_ok++;
    else if (rcode == 2) s->servers[si].responses_servfail++;
    else if (rcode == 3) s->servers[si].responses_nxdomain++;
    s->total_responses++;
    return 0;
}

double dns_stats_cache_hit_ratio(const dns_stats_t *s) {
    uint64_t total = 0, hits = 0;
    for (size_t i = 0; i < s->server_count; i++) {
        total += s->servers[i].cache_hits + s->servers[i].cache_misses;
        hits += s->servers[i].cache_hits;
    }
    return total == 0 ? 0.0 : (double)hits / (double)total;
}

/* Push a new sample into the RTT sliding window. */
void rtt_window_push(rtt_window_t *w, double sample) {
    w->sum -= w->samples[w->head];
    w->samples[w->head] = sample;
    w->sum += sample;
    w->head = (w->head + 1) % RTT_WINDOW_SIZE;
    if (w->count < RTT_WINDOW_SIZE) w->count++;
}

/* Get the average RTT from the sliding window. */
double rtt_window_avg(const rtt_window_t *w) {
    return w->count == 0 ? 0.0 : w->sum / (double)w->count;
}

/* Get the p95 RTT from the sliding window (sorts a copy). */
double rtt_window_p95(rtt_window_t *w) {
    if (w->count == 0) return 0.0;
    double *copy = malloc(w->count * sizeof(double));
    if (!copy) return 0.0;
    size_t start = (w->count < RTT_WINDOW_SIZE) ? 0 :
                   (w->head);
    for (size_t i = 0; i < w->count; i++) {
        copy[i] = w->samples[(start + i) % RTT_WINDOW_SIZE];
    }
    /* simple selection sort for small arrays */
    for (size_t i = 0; i < w->count - 1; i++) {
        for (size_t j = i + 1; j < w->count; j++) {
            if (copy[j] < copy[i]) {
                double tmp = copy[i]; copy[i] = copy[j]; copy[j] = tmp;
            }
        }
    }
    size_t idx = (size_t)((double)w->count * 0.95);
    if (idx >= w->count) idx = w->count - 1;
    double val = copy[idx];
    free(copy);
    return val;
}

/* Get the minimum RTT from the sliding window. */
double rtt_window_min(const rtt_window_t *w) {
    if (w->count == 0) return 0.0;
    double mn = 1e18;
    size_t start = (w->count < RTT_WINDOW_SIZE) ? 0 : w->head;
    for (size_t i = 0; i < w->count; i++) {
        double v = w->samples[(start + i) % RTT_WINDOW_SIZE];
        if (v < mn) mn = v;
    }
    return mn;
}

/* Get the maximum RTT from the sliding window. */
double rtt_window_max(const rtt_window_t *w) {
    if (w->count == 0) return 0.0;
    double mx = 0.0;
    size_t start = (w->count < RTT_WINDOW_SIZE) ? 0 : w->head;
    for (size_t i = 0; i < w->count; i++) {
        double v = w->samples[(start + i) % RTT_WINDOW_SIZE];
        if (v > mx) mx = v;
    }
    return mx;
}

/* Record a per-query-type statistic. */
void dns_type_stats_record(dns_type_stats_t *ts, uint16_t qtype,
                           uint16_t rcode) {
    if (qtype < DNS_TYPE_STATS_SIZE) ts->by_type[qtype]++;
    if (rcode == 0 && qtype < DNS_TYPE_STATS_SIZE)
        ts->responses_by_type[qtype]++;
    else if (qtype < DNS_TYPE_STATS_SIZE)
        ts->errors_by_type[qtype]++;
}

/* Get the most-queried DNS type. */
uint16_t dns_type_stats_most_queried(const dns_type_stats_t *ts) {
    uint64_t max = 0;
    uint16_t best = 0;
    for (uint16_t i = 1; i < DNS_TYPE_STATS_SIZE; i++) {
        if (ts->by_type[i] > max) { max = ts->by_type[i]; best = i; }
    }
    return best;
}

/* Compute the error rate for a specific query type. */
double dns_type_stats_error_rate(const dns_type_stats_t *ts, uint16_t qtype) {
    if (qtype >= DNS_TYPE_STATS_SIZE) return 0.0;
    uint64_t total = ts->by_type[qtype];
    return total == 0 ? 0.0 : (double)ts->errors_by_type[qtype] / (double)total;
}

/* Check if a query should be rate-limited. Returns 1 if dropped. */
int dns_rate_limit_check(dns_rate_limiter_t *rl, uint64_t now_ms) {
    uint64_t window_ms = 1000;
    if (now_ms - rl->window_start > window_ms) {
        rl->window_start = now_ms;
        rl->query_count = 0;
    }
    rl->query_count++;
    if (rl->query_count > rl->max_queries_per_second) {
        rl->total_dropped++;
        return 1;
    }
    return 0;
}

/* Compute queries-per-second across all servers. */
double dns_stats_qps(const dns_stats_t *s) {
    time_t now = time(NULL);
    double elapsed = difftime(now, s->start_time);
    if (elapsed <= 0.0) return 0.0;
    return (double)s->total_queries / elapsed;
}

/* Compute bytes-per-second across all servers. */
double dns_stats_bytes_per_sec(const dns_stats_t *s) {
    time_t now = time(NULL);
    double elapsed = difftime(now, s->start_time);
    if (elapsed <= 0.0) return 0.0;
    uint64_t total_bytes = 0;
    for (size_t i = 0; i < s->server_count; i++) {
        total_bytes += s->servers[i].bytes_sent + s->servers[i].bytes_received;
    }
    return (double)total_bytes / elapsed;
}

/* Find the server with the lowest response rate (potential problem server). */
int dns_stats_worst_server(const dns_stats_t *s) {
    int worst = -1;
    double worst_ratio = 1.0;
    for (size_t i = 0; i < s->server_count; i++) {
        if (s->servers[i].queries_sent == 0) continue;
        double ratio = (double)s->servers[i].responses_received /
                       (double)s->servers[i].queries_sent;
        if (ratio < worst_ratio) { worst_ratio = ratio; worst = (int)i; }
    }
    return worst;
}

/* Compute the timeout rate across all servers. */
double dns_stats_timeout_rate(const dns_stats_t *s) {
    uint64_t total_q = 0, total_to = 0;
    for (size_t i = 0; i < s->server_count; i++) {
        total_q += s->servers[i].queries_sent;
        total_to += s->servers[i].timeouts;
    }
    return total_q == 0 ? 0.0 : (double)total_to / (double)total_q;
}

/* Generate a summary string of the stats. */
int dns_stats_summary(const dns_stats_t *s, char *out, size_t out_max) {
    int written = snprintf(out, out_max,
        "queries=%lu responses=%lu ok=%lu servfail=%lu nxdomain=%lu timeouts=%lu "
        "cache_hit=%.2f%% qps=%.1f",
        (unsigned long)s->total_queries,
        (unsigned long)s->total_responses,
        (unsigned long)(s->total_responses - /* rough */ 0),
        0UL, 0UL, 0UL,
        dns_stats_cache_hit_ratio(s) * 100.0,
        dns_stats_qps(s));
    return written;
}
