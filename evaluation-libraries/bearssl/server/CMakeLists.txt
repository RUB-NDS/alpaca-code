cmake_minimum_required(VERSION 3.0.0)
project(server VERSION 0.1.0)

#include_directories(${CMAKE_SOURCE_DIR}/BearSSL/inc)
add_library(brssl STATIC IMPORTED)
set_target_properties(brssl PROPERTIES
    IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/BearSSL/build/libbearssl.a"
    INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/BearSSL/inc"
  )
add_executable(server server.c)
target_link_libraries(server brssl)
target_compile_options(server PRIVATE -Wall -Wextra)