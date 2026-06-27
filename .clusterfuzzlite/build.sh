#!/bin/bash -eu
# Build script for ClusterFuzzLite

# Compile each source file individually
$CC $CFLAGS -std=c99 -I$SRC/src -c $SRC/src/dns_name.c -o $OUT/dns_name.o
$CC $CFLAGS -std=c99 -I$SRC/src -c $SRC/src/dns_rr.c -o $OUT/dns_rr.o
$CC $CFLAGS -std=c99 -I$SRC/src -c $SRC/src/dns_msg.c -o $OUT/dns_msg.o
$CC $CFLAGS -std=c99 -I$SRC/src -c $SRC/src/dns_cache.c -o $OUT/dns_cache.o
$CC $CFLAGS -std=c99 -I$SRC/src -c $SRC/src/dns_resolver.c -o $OUT/dns_resolver.o

# Link all object files into a single library object
$CC -r -o $OUT/dns_parser_lib.o \
  $OUT/dns_name.o $OUT/dns_rr.o $OUT/dns_msg.o \
  $OUT/dns_cache.o $OUT/dns_resolver.o

# Build harness 1: dns message parser fuzzer
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
  $SRC/fuzz/dns_msg_fuzzer.cc \
  $OUT/dns_parser_lib.o \
  -I$SRC/src \
  -o $OUT/dns_msg_fuzzer

# Build harness 2: dns cache fuzzer
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
  $SRC/fuzz/dns_cache_fuzzer.cc \
  $OUT/dns_parser_lib.o \
  -I$SRC/src \
  -o $OUT/dns_cache_fuzzer

# Package corpus
zip -j $OUT/dns_msg_fuzzer_seed_corpus.zip $SRC/fuzz/corpus/dns_msg_fuzzer/*
zip -j $OUT/dns_cache_fuzzer_seed_corpus.zip $SRC/fuzz/corpus/dns_cache_fuzzer/*
