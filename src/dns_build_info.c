/*
 * dns_build_info.c -- Build metadata, version strings, feature flags, and build environment info
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>


#ifndef DNS_VERSION_MAJOR
#define DNS_VERSION_MAJOR 0
#endif
#ifndef DNS_VERSION_MINOR
#define DNS_VERSION_MINOR 1
#endif
#ifndef DNS_VERSION_PATCH
#define DNS_VERSION_PATCH 0
#endif

#define DNS_VERSION_STRINGIFY2(x) #x
#define DNS_VERSION_STRINGIFY(x) DNS_VERSION_STRINGIFY2(x)

const char *dns_version_string(void) {
    return DNS_VERSION_STRINGIFY(DNS_VERSION_MAJOR) "." DNS_VERSION_STRINGIFY(DNS_VERSION_MINOR) "." DNS_VERSION_STRINGIFY(DNS_VERSION_PATCH);
}

uint32_t dns_version_number(void) {
    return ((uint32_t)DNS_VERSION_MAJOR << 16) | ((uint32_t)DNS_VERSION_MINOR << 8) | (uint32_t)DNS_VERSION_PATCH;
}

typedef struct {
    bool edns_support, dnssec_support, tcp_fallback, ecs_support;
    bool pad_support, cname_follow, negative_cache, rate_limiting;
    bool prefetch, serve_stale, aggressive_nsec, multi_qname;
} DnsFeatureFlags;

static const DnsFeatureFlags default_features = {
    .edns_support = true, .dnssec_support = false, .tcp_fallback = true,
    .ecs_support = false, .cname_follow = true, .negative_cache = true,
};

const DnsFeatureFlags *dns_default_features(void) { return &default_features; }

typedef struct {
    const char *compiler, *os, *arch;
    bool is_debug;
} DnsBuildInfo;

#ifdef __clang__
#define DNS_COMPILER "Clang"
#elif defined(__GNUC__)
#define DNS_COMPILER "GCC"
#else
#define DNS_COMPILER "Unknown"
#endif

static const DnsBuildInfo build_info = { .compiler = DNS_COMPILER,
#ifdef __linux__
    .os = "Linux",
#elif defined(_WIN32)
    .os = "Windows",
#else
    .os = "Unknown",
#endif
#if defined(__x86_64__) || defined(_M_X64)
    .arch = "x86_64",
#elif defined(__aarch64__)
    .arch = "aarch64",
#else
    .arch = "unknown",
#endif
    .is_debug = true
};

const DnsBuildInfo *dns_build_info(void) { return &build_info; }