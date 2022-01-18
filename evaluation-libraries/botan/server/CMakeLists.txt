cmake_minimum_required(VERSION 3.0.0)
project(alpaca-botan-server VERSION 0.1.0)

find_package(Botan2 REQUIRED)
include_directories(SYSTEM ${BOTAN2_INCLUDE_DIR})

add_executable(server server.cpp)
target_link_libraries(server pthread ${BOTAN2_LIBRARIES})
target_compile_options(server PRIVATE -Wall -Wextra)