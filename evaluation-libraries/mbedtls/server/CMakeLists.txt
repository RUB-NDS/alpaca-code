cmake_minimum_required(VERSION 3.0.0)
project(server VERSION 0.1.0)


add_library(mbedtls STATIC IMPORTED)
set_target_properties(mbedtls PROPERTIES
   IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/mbedtls/library/libmbedtls.a"
    INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/mbedtls/include"
  )
add_library(mbedx509 STATIC IMPORTED)
set_target_properties(mbedx509 PROPERTIES
    IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/mbedtls/library/libmbedx509.a"
    INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/mbedtls/include"
  )
add_library(mbedcrypto STATIC IMPORTED)
set_target_properties(mbedcrypto PROPERTIES
    IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/mbedtls/crypto/library/libmbedcrypto.a"
    INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/mbedtls/crypto/include"
  )

add_executable(server server.c)
target_link_libraries(server mbedx509 mbedtls mbedcrypto)
target_compile_options(server PRIVATE -Wall -Wextra)
