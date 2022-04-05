cmake_minimum_required(VERSION 3.0.0)
project(server VERSION 0.1.0)

add_library(wolfssl STATIC IMPORTED)
set_target_properties(wolfssl PROPERTIES
    IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/wolfssl/src/.libs/libwolfssl.a"
    INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/wolfssl"
  )
add_executable(server server.c)
target_link_libraries(server wolfssl m)
target_compile_options(server PRIVATE -Wall -Wextra)
