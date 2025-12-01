#!/bin/bash -eu
# Build script for ClusterFuzzLite

# Compile all project source files into a single object
$CC $CFLAGS -std=c99 -I$SRC/src \
  $SRC/src/dns_name.c \
  $SRC/src/dns_rr.c \
  $SRC/src/dns_msg.c \
  $SRC/src/dns_cache.c \
  $SRC/src/dns_resolver.c \
  -c -o $OUT/dns_parser_lib.o

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
