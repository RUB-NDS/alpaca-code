cmake_minimum_required(VERSION 3.0.0)
project(client VERSION 0.1.0)

find_package(OpenSSL REQUIRED)

add_executable(client client.c)
target_link_libraries(client ${CMAKE_DL_LIBS} ssl crypto pthread dl)
target_compile_options(client PRIVATE -Wall -Wextra)