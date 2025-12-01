cmake_minimum_required(VERSION 3.14)
project(dns_parser VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 17)

# Library
add_library(dns_parser
    src/dns_name.c
    src/dns_rr.c
    src/dns_msg.c
    src/dns_cache.c
    src/dns_resolver.c
)
target_include_directories(dns_parser PUBLIC src/)

# Tests
enable_testing()

add_executable(test_dns_name tests/test_dns_name.c)
target_link_libraries(test_dns_name dns_parser)
add_test(NAME test_dns_name COMMAND test_dns_name)

add_executable(test_dns_rr tests/test_dns_rr.c)
target_link_libraries(test_dns_rr dns_parser)
add_test(NAME test_dns_rr COMMAND test_dns_rr)

add_executable(test_dns_msg tests/test_dns_msg.c)
target_link_libraries(test_dns_msg dns_parser)
add_test(NAME test_dns_msg COMMAND test_dns_msg)
