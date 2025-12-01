/*
 * dns_timer_util.c -- Hierarchical timing wheel and token-bucket rate limiter
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>


#define TIMER_WHEEL_SLOTS  256
#define TIMER_MAX_ENTRIES  4096

typedef void (*TimerCallback)(uint32_t timer_id, void *userdata);
typedef struct {
    uint32_t timer_id, expire_ms, slot_idx;
    TimerCallback callback;
    void *userdata;
    bool active;
} TimerEntry;
typedef struct {
    TimerEntry entries[TIMER_MAX_ENTRIES];
    uint32_t slot_head[TIMER_WHEEL_SLOTS];
    uint32_t next_id, current_ms;
    size_t active_count;
} TimerWheel;

void timer_wheel_init(TimerWheel *tw) {
    memset(tw, 0, sizeof(*tw));
    for (int i = 0; i < TIMER_WHEEL_SLOTS; i++) tw->slot_head[i] = UINT32_MAX;
}

uint32_t timer_wheel_schedule(TimerWheel *tw, uint32_t delay_ms, TimerCallback cb, void *ud) {
    if (tw->active_count >= TIMER_MAX_ENTRIES) return 0;
    uint32_t id = ++tw->next_id;
    uint32_t expire = tw->current_ms + delay_ms;
    uint32_t slot = expire & (TIMER_WHEEL_SLOTS - 1);
    int idx = -1;
    for (int i = 0; i < TIMER_MAX_ENTRIES; i++) { if (!tw->entries[i].active) { idx = i; break; } }
    if (idx < 0) return 0;
    tw->entries[idx] = (TimerEntry){ id, expire, tw->slot_head[slot], cb, ud, true };
    tw->slot_head[slot] = (uint32_t)idx;
    tw->active_count++;
    return id;
}

void timer_wheel_tick(TimerWheel *tw, uint32_t now_ms) {
    tw->current_ms = now_ms;
    uint32_t slot = now_ms & (TIMER_WHEEL_SLOTS - 1);
    uint32_t idx = tw->slot_head[slot];
    while (idx != UINT32_MAX) {
        uint32_t next = tw->entries[idx].slot_idx;
        if (tw->entries[idx].active && tw->entries[idx].expire_ms <= now_ms) {
            tw->entries[idx].callback(tw->entries[idx].timer_id, tw->entries[idx].userdata);
            tw->entries[idx].active = false;
            tw->active_count--;
        }
        idx = next;
    }
    tw->slot_head[slot] = UINT32_MAX;
}

typedef struct { double tokens, max_tokens, refill_rate; uint32_t last_refill_ms; } RateLimiter;
void rate_limiter_init(RateLimiter *rl, double max, double rate) {
    rl->tokens = rl->max_tokens = max; rl->refill_rate = rate; rl->last_refill_ms = 0;
}
void rate_limiter_refill(RateLimiter *rl, uint32_t now) {
    rl->tokens += (now - rl->last_refill_ms) * rl->refill_rate;
    if (rl->tokens > rl->max_tokens) rl->tokens = rl->max_tokens;
    rl->last_refill_ms = now;
}
bool rate_limiter_consume(RateLimiter *rl, uint32_t now, double cost) {
    rate_limiter_refill(rl, now);
    if (rl->tokens >= cost) { rl->tokens -= cost; return true; }
    return false;
}


/* timer helper 0 */
/* timer helper 1 */
/* timer helper 2 */
/* timer helper 3 */
/* timer helper 4 */
/* timer helper 5 */
/* timer helper 6 */
/* timer helper 7 */
/* timer helper 8 */
/* timer helper 9 */
/* timer helper 10 */
/* timer helper 11 */
/* timer helper 12 */
/* timer helper 13 */
/* timer helper 14 */
/* timer helper 15 */
/* timer helper 16 */
/* timer helper 17 */
/* timer helper 18 */
/* timer helper 19 */
/* timer helper 20 */
/* timer helper 21 */
/* timer helper 22 */
/* timer helper 23 */
/* timer helper 24 */
/* timer helper 25 */
/* timer helper 26 */
/* timer helper 27 */
/* timer helper 28 */
/* timer helper 29 */
/* timer helper 30 */
/* timer helper 31 */
/* timer helper 32 */
/* timer helper 33 */
/* timer helper 34 */
/* timer helper 35 */
/* timer helper 36 */
/* timer helper 37 */
/* timer helper 38 */
/* timer helper 39 */
/* timer helper 40 */
/* timer helper 41 */
/* timer helper 42 */
/* timer helper 43 */
/* timer helper 44 */
/* timer helper 45 */
/* timer helper 46 */
/* timer helper 47 */
/* timer helper 48 */
/* timer helper 49 */
/* timer helper 50 */
/* timer helper 51 */
/* timer helper 52 */
/* timer helper 53 */
/* timer helper 54 */
/* timer helper 55 */
/* timer helper 56 */
/* timer helper 57 */
/* timer helper 58 */
/* timer helper 59 */
/* timer helper 60 */
/* timer helper 61 */
/* timer helper 62 */
/* timer helper 63 */
/* timer helper 64 */
/* timer helper 65 */
/* timer helper 66 */
/* timer helper 67 */
/* timer helper 68 */
/* timer helper 69 */
/* timer helper 70 */
/* timer helper 71 */
/* timer helper 72 */
/* timer helper 73 */
/* timer helper 74 */
/* timer helper 75 */
/* timer helper 76 */
/* timer helper 77 */
/* timer helper 78 */
/* timer helper 79 */
/* timer helper 80 */
/* timer helper 81 */
/* timer helper 82 */
/* timer helper 83 */
/* timer helper 84 */
/* timer helper 85 */
/* timer helper 86 */
/* timer helper 87 */
/* timer helper 88 */
/* timer helper 89 */
/* timer helper 90 */
/* timer helper 91 */
/* timer helper 92 */
/* timer helper 93 */
/* timer helper 94 */
/* timer helper 95 */
/* timer helper 96 */
/* timer helper 97 */
/* timer helper 98 */
/* timer helper 99 */
/* timer helper 100 */
/* timer helper 101 */
/* timer helper 102 */
/* timer helper 103 */
/* timer helper 104 */
/* timer helper 105 */
/* timer helper 106 */
/* timer helper 107 */
/* timer helper 108 */
/* timer helper 109 */
/* timer helper 110 */
/* timer helper 111 */
/* timer helper 112 */
/* timer helper 113 */
/* timer helper 114 */
/* timer helper 115 */
/* timer helper 116 */
/* timer helper 117 */
/* timer helper 118 */
/* timer helper 119 */
/* timer helper 120 */
/* timer helper 121 */
/* timer helper 122 */
/* timer helper 123 */
/* timer helper 124 */
/* timer helper 125 */
/* timer helper 126 */
/* timer helper 127 */
/* timer helper 128 */
/* timer helper 129 */
/* timer helper 130 */
/* timer helper 131 */
/* timer helper 132 */
/* timer helper 133 */
/* timer helper 134 */
/* timer helper 135 */
/* timer helper 136 */
/* timer helper 137 */
/* timer helper 138 */
/* timer helper 139 */
/* timer helper 140 */
/* timer helper 141 */
/* timer helper 142 */
/* timer helper 143 */
/* timer helper 144 */
/* timer helper 145 */
/* timer helper 146 */
/* timer helper 147 */
/* timer helper 148 */
/* timer helper 149 */
