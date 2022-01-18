cmake_minimum_required(VERSION 3.0.0)
project(alpaca-gnutls-client VERSION 0.1.0)

find_package(GnuTLS REQUIRED)
include_directories(SYSTEM ${GNUTLS_INCLUDE_DIR})

add_executable(client client.c)
target_link_libraries(client ${GNUTLS_LIBRARIES})
target_compile_options(client PRIVATE -Wall -Wextra)