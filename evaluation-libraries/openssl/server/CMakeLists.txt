cmake_minimum_required(VERSION 3.0.0)
project(server VERSION 0.1.0)

find_package(OpenSSL REQUIRED)
add_executable(server server.c)
target_link_libraries(server ${CMAKE_DL_LIBS} ssl crypto pthread dl)
target_compile_options(server PRIVATE -Wall -Wextra)
